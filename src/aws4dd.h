#pragma once
#include "aws4.h"
#include <iowow/iwpool.h>

IW_EXTERN_C_START

typedef enum {
  _AWS4DD_ERROR_START = (IW_ERROR_START + 101000L),
  AWS4DD_ERROR_INVALID_ENTITY_NAME, ///< Invalid table/index/attr/tag name (AWS4DD_ERROR_INVALID_ENTITY_NAME)
  AWS4DD_ERROR_MAX_IDX_LIMIT,       ///< Number of allowed table indexes exceeds limits (AWS4DD_ERROR_MAX_IDX_LIMIT)
  AWS4DD_ERROR_NO_PARTITION_KEY,    ///< No partition key specified (AWS4DD_ERROR_NO_PARTITION_KEY)
  _AWS4DD_ERROR_END,
} aws4dd_ecode_e;


struct aws4dd_response {
  IWPOOL     *pool;
  JBL_NODE    data;
};

///
/// Table.
///

struct aws4dd_table_create;

iwrc aws4dd_table_create_op(
  struct aws4dd_table_create **rp,
  const char                  *name,
  const char                  *pk,
  const char                  *sk);

void aws4dd_table_create_op_destroy(struct aws4dd_table_create **rp);

#define AWS4DD_TABLE_BILLING_PROVISIONED 0x01U
#define AWS4DD_TABLE_BILLING_PER_REQUEST 0x02U
#define AWS4DD_TABLE_CLASS_STANDARD      0x04U
#define AWS4DD_TABLE_CLASS_INFREQUENT    0x08U
#define AWS4DD_TABLE_STREAM_KEYS_ONLY    0x10U
#define AWS4DD_TABLE_STREAM_NEW_IMAGE    0x20U
#define AWS4DD_TABLE_STREAM_OLD_IMAGE    0x40U

void aws4dd_table_flags_update(struct aws4dd_table_create *op, unsigned flags);

iwrc aws4dd_table_tag_add(struct aws4dd_table_create *op, const char *tag_name, const char *tag_value);

iwrc aws4dd_table_attribute_add(struct aws4dd_table_create *op, const char *spec);

iwrc aws4dd_table_attribute_string_add(struct aws4dd_table_create *op, const char *name);

iwrc aws4dd_table_attribute_number_add(struct aws4dd_table_create *op, const char *name);

iwrc aws4dd_table_attribute_binary_add(struct aws4dd_table_create *op, const char *name);

void aws4dd_table_provisioned_throughtput(
  struct aws4dd_table_create *op,
  long                        read_capacity_units,
  long                        write_capacity_units);

struct aws4dd_index_spec {
  const char  *name;
  const char  *pk;
  const char  *sk;
  const char **proj; ///< Zero terminated list of attributes
  bool project_all;  ///< Include all non key attributes into projection
  bool local;        ///< True if index is local
};

iwrc aws4dd_table_index_add(struct aws4dd_table_create *op, const struct aws4dd_index_spec *spec);

iwrc aws4dd_table_create(const struct aws4_request_spec *spec, struct aws4dd_table_create *op, struct aws4dd_response **rp);

struct aws4dd_response* aws4dd_table_describe(const struct aws4_request_spec *spec, const char *name);

struct aws4dd_response* aws4dd_table_remove(const struct aws4_request_spec *spec, const char *name);


IW_EXTERN_C_END
