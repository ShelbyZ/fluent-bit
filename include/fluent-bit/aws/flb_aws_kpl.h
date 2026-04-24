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
 * KPL (Kinesis Producer Library) aggregation format encoder.
 *
 * Wire format (https://github.com/awslabs/amazon-kinesis-producer/blob/master/aggregation-format.md):
 *
 *   [4 bytes]  Magic: 0xF3 0x89 0x9A 0xC2
 *   [N bytes]  Protobuf-encoded AggregatedRecord:
 *                partition_key_table (field 1): repeated string
 *                records             (field 3): repeated Record
 *                  Record.partition_key_index (field 1): uint64
 *                  Record.data                (field 3): bytes
 *   [16 bytes] MD5 checksum of the protobuf bytes
 *
 * The protobuf encoding is hand-written (no protobuf-c dependency).
 * The schema is frozen as part of the KPL wire format spec.
 */

#ifndef FLB_AWS_KPL_H
#define FLB_AWS_KPL_H

#include <stddef.h>
#include <stdint.h>

/* 4-byte magic number that KCL uses to detect aggregated records */
#define FLB_KPL_MAGIC_LEN  4
extern const uint8_t flb_kpl_magic[FLB_KPL_MAGIC_LEN];

/* 16-byte MD5 digest appended after the protobuf payload */
#define FLB_KPL_MD5_LEN   16

/*
 * Per-record entry stored in the aggregator.
 * data points into an internal heap buffer; freed on destroy/reset.
 */
struct flb_kpl_record {
    uint64_t  pkey_index;  /* index into partition_key_table */
    uint8_t  *data;        /* serialised record bytes (JSON + newline) */
    size_t    data_len;
};

/*
 * KPL aggregator context.
 * Accumulates records until flb_kpl_aggregator_flush() is called.
 */
struct flb_kpl_aggregator {
    /* partition key dedup table */
    char    **pkeys;           /* array of heap-allocated key strings */
    size_t   *pkey_lens;       /* byte length of each key */
    size_t    pkey_count;
    size_t    pkey_cap;

    /* record list */
    struct flb_kpl_record *records;
    size_t    record_count;
    size_t    record_cap;

    /* running protobuf payload size (excludes magic + MD5) */
    size_t    proto_size;

    /* maximum total KPL record size (magic + proto + MD5) */
    size_t    max_size;

    /* partition key from the last flush; valid until next add or destroy */
    char     *last_pkey;
};

/* ------------------------------------------------------------------ */

/*
 * Create a new aggregator.
 * max_size: maximum byte size of the final KPL record (magic+proto+MD5).
 *           Pass 0 to use the default (1 MB).
 */
struct flb_kpl_aggregator *flb_kpl_aggregator_create(size_t max_size);

/* Destroy aggregator and free all memory. */
void flb_kpl_aggregator_destroy(struct flb_kpl_aggregator *agg);

/*
 * Add one record to the aggregator.
 *
 * partition_key / pkey_len:
 *   The partition key for this record.  Must not be NULL or empty.
 *
 * data / data_len:
 *   Raw record bytes (already serialised, e.g. JSON + newline).
 *
 * Returns:
 *   0  – record added successfully
 *   1  – buffer would exceed max_size; caller must call
 *         flb_kpl_aggregator_flush() first, then retry this record
 *  -1  – fatal error (allocation failure, invalid args)
 */
int flb_kpl_aggregator_add(struct flb_kpl_aggregator *agg,
                           const char *partition_key, size_t pkey_len,
                           const uint8_t *data, size_t data_len);

/*
 * Serialise all buffered records into KPL wire format and reset the buffer.
 *
 * On success:
 *   *out_buf  – heap-allocated buffer (caller must flb_free() it)
 *   *out_len  – byte length of *out_buf
 *   *out_pkey – partition key to use for the Kinesis PutRecords entry
 *               (points into internal storage; valid until the next
 *                flb_kpl_aggregator_add() or destroy call)
 *
 * Returns:
 *   0  – success
 *  -1  – buffer is empty or serialisation failed
 */
int flb_kpl_aggregator_flush(struct flb_kpl_aggregator *agg,
                             uint8_t **out_buf, size_t *out_len,
                             const char **out_pkey);

/* Number of records currently buffered (0 if empty). */
size_t flb_kpl_aggregator_count(const struct flb_kpl_aggregator *agg);

#endif /* FLB_AWS_KPL_H */
