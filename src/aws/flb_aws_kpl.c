/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

/*
 * Hand-written protobuf encoder for the KPL AggregatedRecord schema.
 *
 * We encode only the fields we use:
 *
 *   AggregatedRecord {
 *     repeated string partition_key_table = 1;   // wire type 2 (LEN)
 *     repeated Record records             = 3;   // wire type 2 (LEN)
 *   }
 *   Record {
 *     required uint64 partition_key_index = 1;   // wire type 0 (VARINT)
 *     required bytes  data                = 3;   // wire type 2 (LEN)
 *   }
 *
 * Protobuf wire format recap:
 *   tag   = (field_number << 3) | wire_type
 *   VARINT (wire_type 0): tag varint, then value varint
 *   LEN    (wire_type 2): tag varint, then length varint, then bytes
 *
 * All field numbers here are < 16, so every tag fits in one byte.
 */

#include <fluent-bit/aws/flb_aws_kpl.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto_constants.h>

#include <string.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Constants                                                           */
/* ------------------------------------------------------------------ */

const uint8_t flb_kpl_magic[FLB_KPL_MAGIC_LEN] = {0xF3, 0x89, 0x9A, 0xC2};

#define KPL_DEFAULT_MAX_SIZE  (1024 * 1024)   /* 1 MB */

/* Protobuf wire types */
#define PB_WIRE_VARINT  0
#define PB_WIRE_LEN     2

/* Protobuf field tags (one byte each — all field numbers < 16) */
#define TAG_AGG_PKEY_TABLE  ((1 << 3) | PB_WIRE_LEN)    /* field 1, LEN */
#define TAG_AGG_RECORDS     ((3 << 3) | PB_WIRE_LEN)    /* field 3, LEN */
#define TAG_REC_PKEY_INDEX  ((1 << 3) | PB_WIRE_VARINT) /* field 1, VARINT */
#define TAG_REC_DATA        ((3 << 3) | PB_WIRE_LEN)    /* field 3, LEN */

/* Initial capacities */
#define INIT_PKEY_CAP    8
#define INIT_RECORD_CAP  64

/* ------------------------------------------------------------------ */
/* Varint helpers                                                      */
/* ------------------------------------------------------------------ */

/*
 * Returns the number of bytes needed to encode v as a varint.
 */
static size_t varint_size(uint64_t v)
{
    size_t n = 1;
    while (v >= 0x80) {
        v >>= 7;
        n++;
    }
    return n;
}

/*
 * Encodes v as a varint into buf.
 * Returns the number of bytes written.
 * buf must have at least 10 bytes available.
 */
static size_t varint_encode(uint8_t *buf, uint64_t v)
{
    size_t n = 0;
    while (v >= 0x80) {
        buf[n++] = (uint8_t)((v & 0x7F) | 0x80);
        v >>= 7;
    }
    buf[n++] = (uint8_t)v;
    return n;
}

/* ------------------------------------------------------------------ */
/* Proto size accounting                                               */
/* ------------------------------------------------------------------ */

/*
 * Byte size of a LEN field: 1 (tag) + varint(len) + len
 */
static size_t pb_len_field_size(size_t payload_len)
{
    return 1 + varint_size((uint64_t)payload_len) + payload_len;
}

/*
 * Byte size of a VARINT field: 1 (tag) + varint(value)
 */
static size_t pb_varint_field_size(uint64_t value)
{
    return 1 + varint_size(value);
}

/*
 * Byte size of one encoded Record message (as a LEN field of AggregatedRecord).
 *   field 1 (pkey_index): VARINT
 *   field 3 (data):       LEN
 */
static size_t record_proto_size(uint64_t pkey_index, size_t data_len)
{
    size_t inner = pb_varint_field_size(pkey_index)
                 + pb_len_field_size(data_len);
    /* The Record itself is wrapped as a LEN field */
    return pb_len_field_size(inner);
}

/*
 * Byte size of one partition_key_table entry (LEN field of AggregatedRecord).
 */
static size_t pkey_proto_size(size_t key_len)
{
    return pb_len_field_size(key_len);
}

/* ------------------------------------------------------------------ */
/* Buffer write helpers                                                */
/* ------------------------------------------------------------------ */

static uint8_t *write_tag(uint8_t *p, uint8_t tag)
{
    *p++ = tag;
    return p;
}

static uint8_t *write_varint(uint8_t *p, uint64_t v)
{
    p += varint_encode(p, v);
    return p;
}

static uint8_t *write_len_field(uint8_t *p, uint8_t tag,
                                const uint8_t *data, size_t len)
{
    p = write_tag(p, tag);
    p = write_varint(p, (uint64_t)len);
    memcpy(p, data, len);
    return p + len;
}

/* ------------------------------------------------------------------ */
/* Public API                                                          */
/* ------------------------------------------------------------------ */

struct flb_kpl_aggregator *flb_kpl_aggregator_create(size_t max_size)
{
    struct flb_kpl_aggregator *agg;

    agg = flb_calloc(1, sizeof(*agg));
    if (!agg) {
        flb_errno();
        return NULL;
    }

    agg->max_size = (max_size > 0) ? max_size : KPL_DEFAULT_MAX_SIZE;

    agg->pkeys     = flb_calloc(INIT_PKEY_CAP, sizeof(char *));
    agg->pkey_lens = flb_calloc(INIT_PKEY_CAP, sizeof(size_t));
    if (!agg->pkeys || !agg->pkey_lens) {
        flb_errno();
        flb_kpl_aggregator_destroy(agg);
        return NULL;
    }
    agg->pkey_cap = INIT_PKEY_CAP;

    agg->records = flb_calloc(INIT_RECORD_CAP, sizeof(struct flb_kpl_record));
    if (!agg->records) {
        flb_errno();
        flb_kpl_aggregator_destroy(agg);
        return NULL;
    }
    agg->record_cap = INIT_RECORD_CAP;

    return agg;
}

void flb_kpl_aggregator_destroy(struct flb_kpl_aggregator *agg)
{
    size_t i;

    if (!agg) {
        return;
    }

    if (agg->pkeys) {
        for (i = 0; i < agg->pkey_count; i++) {
            flb_free(agg->pkeys[i]);
        }
        flb_free(agg->pkeys);
    }
    flb_free(agg->pkey_lens);

    if (agg->records) {
        for (i = 0; i < agg->record_count; i++) {
            flb_free(agg->records[i].data);
        }
        flb_free(agg->records);
    }

    flb_free(agg->last_pkey);
    flb_free(agg);
}

static void aggregator_reset(struct flb_kpl_aggregator *agg)
{
    size_t i;

    for (i = 0; i < agg->pkey_count; i++) {
        flb_free(agg->pkeys[i]);
        agg->pkeys[i] = NULL;
    }
    agg->pkey_count = 0;

    for (i = 0; i < agg->record_count; i++) {
        flb_free(agg->records[i].data);
    }
    agg->record_count = 0;
    agg->proto_size   = 0;
}

/*
 * Look up partition_key in the table.
 * Returns the index if found, or agg->pkey_count if not found.
 */
static size_t find_pkey(const struct flb_kpl_aggregator *agg,
                        const char *key, size_t key_len)
{
    size_t i;
    for (i = 0; i < agg->pkey_count; i++) {
        if (agg->pkey_lens[i] == key_len &&
            memcmp(agg->pkeys[i], key, key_len) == 0) {
            return i;
        }
    }
    return agg->pkey_count; /* not found */
}

int flb_kpl_aggregator_add(struct flb_kpl_aggregator *agg,
                           const char *partition_key, size_t pkey_len,
                           const uint8_t *data, size_t data_len)
{
    size_t    pkey_idx;
    size_t    new_pkey_proto = 0;
    size_t    new_record_proto;
    size_t    new_total;
    uint8_t  *data_copy;
    char     *pkey_copy;
    void     *tmp;

    if (!agg || !partition_key || pkey_len == 0 || !data || data_len == 0) {
        return -1;
    }

    /* Find or account for a new partition key */
    pkey_idx = find_pkey(agg, partition_key, pkey_len);
    if (pkey_idx == agg->pkey_count) {
        /* New key — calculate the extra proto bytes it would add */
        new_pkey_proto = pkey_proto_size(pkey_len);
    }

    new_record_proto = record_proto_size((uint64_t)pkey_idx, data_len);

    new_total = FLB_KPL_MAGIC_LEN + FLB_KPL_MD5_LEN
              + agg->proto_size + new_pkey_proto + new_record_proto;

    if (new_total > agg->max_size) {
        return 1; /* buffer full — caller must flush first */
    }

    /* Grow partition key table if needed */
    if (pkey_idx == agg->pkey_count) {
        if (agg->pkey_count == agg->pkey_cap) {
            size_t new_cap = agg->pkey_cap * 2;
            tmp = flb_realloc(agg->pkeys, new_cap * sizeof(char *));
            if (!tmp) {
                flb_errno();
                return -1;
            }
            agg->pkeys = tmp;
            tmp = flb_realloc(agg->pkey_lens, new_cap * sizeof(size_t));
            if (!tmp) {
                flb_errno();
                return -1;
            }
            agg->pkey_lens = tmp;
            agg->pkey_cap  = new_cap;
        }

        pkey_copy = flb_malloc(pkey_len + 1);
        if (!pkey_copy) {
            flb_errno();
            return -1;
        }
        memcpy(pkey_copy, partition_key, pkey_len);
        pkey_copy[pkey_len] = '\0';

        agg->pkeys[agg->pkey_count]     = pkey_copy;
        agg->pkey_lens[agg->pkey_count] = pkey_len;
        agg->pkey_count++;
        agg->proto_size += new_pkey_proto;
    }

    /* Grow record list if needed */
    if (agg->record_count == agg->record_cap) {
        size_t new_cap = agg->record_cap * 2;
        tmp = flb_realloc(agg->records, new_cap * sizeof(struct flb_kpl_record));
        if (!tmp) {
            flb_errno();
            return -1;
        }
        agg->records    = tmp;
        agg->record_cap = new_cap;
    }

    data_copy = flb_malloc(data_len);
    if (!data_copy) {
        flb_errno();
        return -1;
    }
    memcpy(data_copy, data, data_len);

    agg->records[agg->record_count].pkey_index = (uint64_t)pkey_idx;
    agg->records[agg->record_count].data       = data_copy;
    agg->records[agg->record_count].data_len   = data_len;
    agg->record_count++;
    agg->proto_size += new_record_proto;

    return 0;
}

int flb_kpl_aggregator_flush(struct flb_kpl_aggregator *agg,
                             uint8_t **out_buf, size_t *out_len,
                             const char **out_pkey)
{
    size_t    i;
    size_t    total_len;
    uint8_t  *buf;
    uint8_t  *p;
    uint8_t   md5[FLB_KPL_MD5_LEN];
    int       ret;

    /* Per-record inner sizes (needed to write the LEN prefix) */
    size_t    inner_size;

    if (!agg || agg->record_count == 0) {
        return -1;
    }

    total_len = FLB_KPL_MAGIC_LEN + agg->proto_size + FLB_KPL_MD5_LEN;

    buf = flb_malloc(total_len);
    if (!buf) {
        flb_errno();
        return -1;
    }
    p = buf;

    /* --- Magic number --- */
    memcpy(p, flb_kpl_magic, FLB_KPL_MAGIC_LEN);
    p += FLB_KPL_MAGIC_LEN;

    uint8_t *proto_start = p; /* remember where proto payload begins for MD5 */

    /* --- AggregatedRecord.partition_key_table (field 1, repeated LEN) --- */
    for (i = 0; i < agg->pkey_count; i++) {
        p = write_len_field(p, TAG_AGG_PKEY_TABLE,
                            (const uint8_t *)agg->pkeys[i],
                            agg->pkey_lens[i]);
    }

    /* --- AggregatedRecord.records (field 3, repeated LEN) --- */
    for (i = 0; i < agg->record_count; i++) {
        struct flb_kpl_record *rec = &agg->records[i];

        /* Calculate inner Record message size */
        inner_size = pb_varint_field_size(rec->pkey_index)
                   + pb_len_field_size(rec->data_len);

        /* Write outer LEN tag + length */
        p = write_tag(p, TAG_AGG_RECORDS);
        p = write_varint(p, (uint64_t)inner_size);

        /* Write Record.partition_key_index (field 1, VARINT) */
        p = write_tag(p, TAG_REC_PKEY_INDEX);
        p = write_varint(p, rec->pkey_index);

        /* Write Record.data (field 3, LEN) */
        p = write_len_field(p, TAG_REC_DATA, rec->data, rec->data_len);
    }

    /* --- MD5 of the protobuf payload --- */
    ret = flb_hash_simple(FLB_HASH_MD5,
                          proto_start,
                          (size_t)(p - proto_start),
                          md5,
                          sizeof(md5));
    if (ret != FLB_CRYPTO_SUCCESS) {
        flb_free(buf);
        return -1;
    }
    memcpy(p, md5, FLB_KPL_MD5_LEN);
    p += FLB_KPL_MD5_LEN;

    /* Sanity check */
    if ((size_t)(p - buf) != total_len) {
        flb_error("[kpl] flush size mismatch: expected=%zu actual=%zu",
                  total_len, (size_t)(p - buf));
        flb_free(buf);
        return -1;
    }

    *out_buf  = buf;
    *out_len  = total_len;

    /*
     * Save the partition key string into last_pkey before reset frees it.
     * The caller's *out_pkey pointer is valid until the next
     * flb_kpl_aggregator_add() or flb_kpl_aggregator_destroy() call.
     */
    flb_free(agg->last_pkey);
    agg->last_pkey = agg->pkeys[0];
    agg->pkeys[0]  = NULL;   /* prevent aggregator_reset() from freeing it */

    aggregator_reset(agg);

    *out_pkey = agg->last_pkey;
    return 0;
}

size_t flb_kpl_aggregator_count(const struct flb_kpl_aggregator *agg)
{
    if (!agg) {
        return 0;
    }
    return agg->record_count;
}
