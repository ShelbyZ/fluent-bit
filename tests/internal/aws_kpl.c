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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_crypto_constants.h>
#include <fluent-bit/aws/flb_aws_kpl.h>
#include "flb_tests_internal.h"

#include <string.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                             */
/* ------------------------------------------------------------------ */

#define KPL_MAGIC_0  0xF3
#define KPL_MAGIC_1  0x89
#define KPL_MAGIC_2  0x9A
#define KPL_MAGIC_3  0xC2
#define MD5_LEN      16

static void assert_magic(const uint8_t *buf, size_t len)
{
    TEST_CHECK(len >= 4 + MD5_LEN);
    TEST_CHECK(buf[0] == KPL_MAGIC_0);
    TEST_CHECK(buf[1] == KPL_MAGIC_1);
    TEST_CHECK(buf[2] == KPL_MAGIC_2);
    TEST_CHECK(buf[3] == KPL_MAGIC_3);
}

static void assert_md5(const uint8_t *buf, size_t len)
{
    uint8_t want[MD5_LEN];
    const uint8_t *proto    = buf + FLB_KPL_MAGIC_LEN;
    size_t         proto_len = len - FLB_KPL_MAGIC_LEN - MD5_LEN;
    const uint8_t *got      = buf + len - MD5_LEN;
    int ret;

    ret = flb_hash_simple(FLB_HASH_MD5,
                          (unsigned char *) proto, proto_len,
                          want, sizeof(want));
    TEST_CHECK(ret == FLB_CRYPTO_SUCCESS);
    TEST_CHECK(memcmp(got, want, MD5_LEN) == 0);
}

/*
 * Minimal varint reader — returns bytes consumed, -1 on error.
 */
static int read_varint(const uint8_t *buf, size_t len, size_t pos,
                       uint64_t *out)
{
    uint64_t result = 0;
    int      shift  = 0;
    size_t   start  = pos;

    while (pos < len) {
        uint8_t b = buf[pos++];
        result |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) {
            *out = result;
            return (int)(pos - start);
        }
        shift += 7;
        if (shift >= 64) return -1;
    }
    return -1;
}

/*
 * Count occurrences of a one-byte tag in a flat protobuf message.
 * Handles VARINT (wire 0) and LEN (wire 2) fields only.
 */
static int count_proto_field(const uint8_t *buf, size_t len, uint8_t want_tag)
{
    size_t   pos   = 0;
    int      count = 0;
    uint64_t tag, field_len;
    int      n;

    while (pos < len) {
        n = read_varint(buf, len, pos, &tag);
        if (n < 0) break;
        pos += n;

        uint8_t wire = tag & 0x07;
        if ((uint8_t)tag == want_tag) count++;

        if (wire == 0) {
            uint64_t v;
            n = read_varint(buf, len, pos, &v);
            if (n < 0) break;
            pos += n;
        }
        else if (wire == 2) {
            n = read_varint(buf, len, pos, &field_len);
            if (n < 0) break;
            pos += n;
            pos += (size_t)field_len;
        }
        else break;
    }
    return count;
}

/* ------------------------------------------------------------------ */
/* Tests                                                               */
/* ------------------------------------------------------------------ */

void test_kpl_magic_number()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    int ret = flb_kpl_aggregator_add(agg, "pk", 2,
                                     (const uint8_t *)"data", 4);
    TEST_CHECK(ret == 0);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out != NULL);

    assert_magic(out, olen);

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_md5_checksum()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    flb_kpl_aggregator_add(agg, "pk", 2, (const uint8_t *)"hello", 5);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    int ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == 0);

    assert_md5(out, olen);

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_single_record()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    const char *data = "{\"msg\":\"hello\"}";
    int ret = flb_kpl_aggregator_add(agg, "mykey", 5,
                                     (const uint8_t *)data, strlen(data));
    TEST_CHECK(ret == 0);
    TEST_CHECK(flb_kpl_aggregator_count(agg) == 1);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == 0);
    TEST_CHECK(out != NULL);
    TEST_CHECK(olen > FLB_KPL_MAGIC_LEN + MD5_LEN);
    TEST_CHECK(pkey != NULL);
    TEST_CHECK(strcmp(pkey, "mykey") == 0);

    assert_magic(out, olen);
    assert_md5(out, olen);

    /* proto payload should contain 1 record field (tag 0x1A) */
    const uint8_t *proto = out + FLB_KPL_MAGIC_LEN;
    size_t plen = olen - FLB_KPL_MAGIC_LEN - MD5_LEN;
    TEST_CHECK(count_proto_field(proto, plen, 0x1A) == 1);

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_multiple_records()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    for (int i = 0; i < 10; i++) {
        char data[32];
        snprintf(data, sizeof(data), "{\"n\":%d}", i);
        int ret = flb_kpl_aggregator_add(agg, "shard-0", 7,
                                         (const uint8_t *)data, strlen(data));
        TEST_CHECK(ret == 0);
    }
    TEST_CHECK(flb_kpl_aggregator_count(agg) == 10);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    int ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == 0);

    assert_magic(out, olen);
    assert_md5(out, olen);

    const uint8_t *proto = out + FLB_KPL_MAGIC_LEN;
    size_t plen = olen - FLB_KPL_MAGIC_LEN - MD5_LEN;
    /* 1 partition key entry, 10 record entries */
    TEST_CHECK(count_proto_field(proto, plen, 0x0A) == 1);
    TEST_CHECK(count_proto_field(proto, plen, 0x1A) == 10);

    TEST_CHECK(flb_kpl_aggregator_count(agg) == 0); /* reset after flush */

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_partition_key_dedup()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    /* 4 records, same key — table should have 1 entry */
    for (int i = 0; i < 4; i++) {
        flb_kpl_aggregator_add(agg, "same-key", 8,
                               (const uint8_t *)"x", 1);
    }

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);

    const uint8_t *proto = out + FLB_KPL_MAGIC_LEN;
    size_t plen = olen - FLB_KPL_MAGIC_LEN - MD5_LEN;
    TEST_CHECK(count_proto_field(proto, plen, 0x0A) == 1);
    TEST_CHECK(count_proto_field(proto, plen, 0x1A) == 4);

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_partition_key_multiple()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    flb_kpl_aggregator_add(agg, "key-A", 5, (const uint8_t *)"d1", 2);
    flb_kpl_aggregator_add(agg, "key-B", 5, (const uint8_t *)"d2", 2);
    flb_kpl_aggregator_add(agg, "key-C", 5, (const uint8_t *)"d3", 2);
    flb_kpl_aggregator_add(agg, "key-A", 5, (const uint8_t *)"d4", 2); /* dedup */

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);

    const uint8_t *proto = out + FLB_KPL_MAGIC_LEN;
    size_t plen = olen - FLB_KPL_MAGIC_LEN - MD5_LEN;
    TEST_CHECK(count_proto_field(proto, plen, 0x0A) == 3); /* A, B, C */
    TEST_CHECK(count_proto_field(proto, plen, 0x1A) == 4); /* 4 records */

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_buffer_full_triggers_flush()
{
    /* tiny max_size so the second add overflows */
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(64);
    TEST_CHECK(agg != NULL);

    const char *data = "this record is long enough to fill the tiny buffer";
    int ret = flb_kpl_aggregator_add(agg, "pk", 2,
                                     (const uint8_t *)data, strlen(data));
    /* first add may succeed or immediately return 1 */
    if (ret == 0) {
        ret = flb_kpl_aggregator_add(agg, "pk", 2,
                                     (const uint8_t *)data, strlen(data));
        TEST_CHECK(ret == 1);
    }
    else {
        TEST_CHECK(ret == 1);
    }

    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_size_accounting()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    flb_kpl_aggregator_add(agg, "pk", 2, (const uint8_t *)"abc", 3);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);

    /* total = magic(4) + proto(N) + md5(16); must be > 20 */
    TEST_CHECK(olen > FLB_KPL_MAGIC_LEN + MD5_LEN);
    /* proto size must equal olen - magic - md5 */
    size_t proto_len = olen - FLB_KPL_MAGIC_LEN - MD5_LEN;
    TEST_CHECK(proto_len > 0);

    assert_md5(out, olen);

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_empty_flush()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    int ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == -1);
    TEST_CHECK(out == NULL);

    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_reset_reuse()
{
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    flb_kpl_aggregator_add(agg, "pk1", 3, (const uint8_t *)"first", 5);

    uint8_t    *out  = NULL;
    size_t      olen = 0;
    const char *pkey = NULL;
    int ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == 0);
    flb_free(out);

    TEST_CHECK(flb_kpl_aggregator_count(agg) == 0);

    /* second cycle with a different key */
    ret = flb_kpl_aggregator_add(agg, "pk2", 3, (const uint8_t *)"second", 6);
    TEST_CHECK(ret == 0);
    TEST_CHECK(flb_kpl_aggregator_count(agg) == 1);

    out = NULL; olen = 0; pkey = NULL;
    ret = flb_kpl_aggregator_flush(agg, &out, &olen, &pkey);
    TEST_CHECK(ret == 0);
    TEST_CHECK(pkey != NULL);
    TEST_CHECK(strcmp(pkey, "pk2") == 0);

    assert_magic(out, olen);
    assert_md5(out, olen);

    flb_free(out);
    flb_kpl_aggregator_destroy(agg);
}

void test_kpl_null_params()
{
    /* create with 0 uses default */
    struct flb_kpl_aggregator *agg = flb_kpl_aggregator_create(0);
    TEST_CHECK(agg != NULL);

    /* NULL aggregator */
    TEST_CHECK(flb_kpl_aggregator_add(NULL, "pk", 2,
                                      (const uint8_t *)"d", 1) == -1);
    /* NULL key */
    TEST_CHECK(flb_kpl_aggregator_add(agg, NULL, 0,
                                      (const uint8_t *)"d", 1) == -1);
    /* zero key length */
    TEST_CHECK(flb_kpl_aggregator_add(agg, "pk", 0,
                                      (const uint8_t *)"d", 1) == -1);
    /* NULL data */
    TEST_CHECK(flb_kpl_aggregator_add(agg, "pk", 2, NULL, 1) == -1);
    /* zero data length */
    TEST_CHECK(flb_kpl_aggregator_add(agg, "pk", 2,
                                      (const uint8_t *)"d", 0) == -1);

    /* count on NULL */
    TEST_CHECK(flb_kpl_aggregator_count(NULL) == 0);

    /* destroy NULL should not crash */
    flb_kpl_aggregator_destroy(NULL);

    flb_kpl_aggregator_destroy(agg);
}

/* ------------------------------------------------------------------ */
/* Test list                                                           */
/* ------------------------------------------------------------------ */

TEST_LIST = {
    {"kpl_magic_number",              test_kpl_magic_number},
    {"kpl_md5_checksum",              test_kpl_md5_checksum},
    {"kpl_single_record",             test_kpl_single_record},
    {"kpl_multiple_records",          test_kpl_multiple_records},
    {"kpl_partition_key_dedup",       test_kpl_partition_key_dedup},
    {"kpl_partition_key_multiple",    test_kpl_partition_key_multiple},
    {"kpl_buffer_full_triggers_flush",test_kpl_buffer_full_triggers_flush},
    {"kpl_size_accounting",           test_kpl_size_accounting},
    {"kpl_empty_flush",               test_kpl_empty_flush},
    {"kpl_reset_reuse",               test_kpl_reset_reuse},
    {"kpl_null_params",               test_kpl_null_params},
    {NULL, NULL}
};
