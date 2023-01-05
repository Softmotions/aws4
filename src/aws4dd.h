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

/// Response of AWS4DD request.
struct aws4dd_response {
  IWPOOL  *pool;
  JBL_NODE data;
};

IW_EXPORT void aws4dd_response_destroy(struct aws4dd_response **rpp);

///
/// Table
///

struct aws4dd_table_create;

/// Create CreateTable operation handler.
/// NOTE: \c rpp must bet destroyed by aws4dd_table_create_op_destroy().
IW_EXPORT iwrc aws4dd_table_create_op(
  struct aws4dd_table_create **rpp,
  const char                  *name,
  const char                  *pk,
  const char                  *sk);

/// Destroy CreateTable operation handler.
IW_EXPORT void aws4dd_table_create_op_destroy(struct aws4dd_table_create **opp);

#define AWS4DD_TABLE_BILLING_PROVISIONED 0x01U
#define AWS4DD_TABLE_BILLING_PER_REQUEST 0x02U
#define AWS4DD_TABLE_CLASS_STANDARD      0x04U
#define AWS4DD_TABLE_CLASS_INFREQUENT    0x08U
#define AWS4DD_TABLE_STREAM_KEYS_ONLY    0x10U
#define AWS4DD_TABLE_STREAM_NEW_IMAGE    0x20U
#define AWS4DD_TABLE_STREAM_OLD_IMAGE    0x40U

/// Sets CreateTable opration flags specified above.
IW_EXPORT void aws4dd_table_flags_update(struct aws4dd_table_create *op, unsigned flags);

/// Adds a new tag to the table.
IW_EXPORT iwrc aws4dd_table_tag_add(struct aws4dd_table_create *op, const char *tag_name, const char *tag_value);

/// Adds a new attribute to the table.
/// Where spec is and attribute spec in the following format: `type:name`. Example: `S:myattr`.
IW_EXPORT iwrc aws4dd_table_attribute_add(struct aws4dd_table_create *op, const char *spec);

/// Adds a new string attribute to the table.
IW_EXPORT iwrc aws4dd_table_attribute_string_add(struct aws4dd_table_create *op, const char *name);

/// Adds a new number attribute to the table.
IW_EXPORT iwrc aws4dd_table_attribute_number_add(struct aws4dd_table_create *op, const char *name);

/// Adds a new binary attribute to the table.
IW_EXPORT iwrc aws4dd_table_attribute_binary_add(struct aws4dd_table_create *op, const char *name);

/// Sets a provisioned throughput for the table.
IW_EXPORT void aws4dd_table_provisioned_throughtput(
  struct aws4dd_table_create *op,
  long                        read_capacity_units,
  long                        write_capacity_units);

/// Table index basic specification.
struct aws4dd_index_spec {
  const char  *name;
  const char  *pk;
  const char  *sk;
  const char **proj; ///< Zero terminated list of attributes
  bool project_all;  ///< Include all non key attributes into projection
  bool local;        ///< True if index is local
};

/// Register a new table index.
IW_EXPORT iwrc aws4dd_table_index_add(struct aws4dd_table_create *op, const struct aws4dd_index_spec *spec);

/// Executes a CreateTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_create(
  const struct aws4_request_spec *spec,
  struct aws4dd_table_create     *op,
  struct aws4dd_response        **rpp);

/// Executes a DescribeTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_describe(
  const struct aws4_request_spec *spec, const char *name,
  struct aws4dd_response **rpp);

/// Executes a DeleteTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_delete(
  const struct aws4_request_spec *spec, const char *name,
  struct aws4dd_response **rpp);

//
// PutItem
//

struct aws4dd_item_put;

typedef enum {
  AWS4DD_RETURN_CONSUMED_NONE = 0,
  AWS4DD_RETURN_CONSUMED_TOTAL,
  AWS4DD_RETURN_CONSUMED_INDEXES,
} aws4dd_return_consumed_capacity_e;

typedef enum {
  AWS4DD_RETURN_COLLECTION_NONE = 0,
  AWS4DD_RETURN_COLLECTION_SIZE,
} aws4dd_return_collection_metrics_e;

typedef enum {
  AWS4DD_RETURN_VALUES_NONE = 0,
  AWS4DD_RETURN_VALUES_ALL_OLD,
  AWS4DD_RETURN_VALUES_ALL_NEW,
  AWS4DD_RETURN_VALUES_UPDATED_NEW,
  AWS4DD_RETURN_VALUES_UPDATED_OLD,
} aws4dd_return_values_e;

/// ItemPut operation specification.
struct aws4dd_item_put_spec {
  const char *table_name;
  const char *condition_expression;
  struct {
    aws4dd_return_values_e values;
    aws4dd_return_consumed_capacity_e  capacity;
    aws4dd_return_collection_metrics_e metrics;
  } ret;
};

/// Creates a new ItemPut operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_item_put_op_destroy().
IW_EXPORT iwrc aws4dd_item_put_op(struct aws4dd_item_put **opp, const struct aws4dd_item_put_spec *spec);

/// Destroys ItemPut operation handler.
IW_EXPORT void aws4dd_item_put_op_destroy(struct aws4dd_item_put **opp);

/// Sets an /Item or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_item_put_array(op, "/Item/Tags", "SS", (const char*[]) { "Update", "Multiple", "Help", 0 })
IW_EXPORT iwrc aws4dd_item_put_array(
  struct aws4dd_item_put *op,
  const char             *path,
  const char             *key,
  const char            **vals);

/// Sets an /Item or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_item_put_value(op, "/ExpressionAttributeValues/:f", "S", "Amazon DynamoDB");
/// Example: aws4dd_item_put_value(op, "/Item/Id", "N", "101");
IW_EXPORT iwrc aws4dd_item_put_value(
  struct aws4dd_item_put *op,
  const char             *path,
  const char             *key,
  const char             *val);

/// Add key-value pair to the given ExpressionAttributeNames part of ItemPut operation.
/// @param op ItemPut operation
/// @param key ExpressionAttributeNames key
/// @param val ExpressionAttributeNames value
IW_EXPORT iwrc aws4dd_item_put_expression_attr_name(struct aws4dd_item_put *op, const char *key, const char *value);

/// Executes an ItemPut operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_item_put(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_put         *op,
  struct aws4dd_response        **rpp);

//
// UpdateItem
//

/// ItemUpdate operation specification.
struct aws4dd_item_update_spec {
  const char *table_name;
  const char *condition_expression;
  const char *update_expression;
  struct {
    aws4dd_return_values_e values;
    aws4dd_return_consumed_capacity_e  capacity;
    aws4dd_return_collection_metrics_e metrics;
  } ret;
};

struct aws4dd_item_update;

/// Creates a new UpdateItem operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_item_update_op_destroy().
IW_EXPORT iwrc aws4dd_item_update_op(struct aws4dd_item_update **opp, const struct aws4dd_item_update_spec *spec);

/// Destroys UpdateItem operation handler.
IW_EXPORT void aws4dd_item_update_op_destroy(struct aws4dd_item_update **opp);

/// Sets an /Key or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_item_update_array(op, "/Key/Tags", "SS", (const char*[]) { "Update", "Multiple", "Help", 0 })
IW_EXPORT iwrc aws4dd_item_update_array(
  struct aws4dd_item_update *op,
  const char                *path,
  const char                *key,
  const char               **vals);

/// Sets an /Key or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_item_update_value(op, "/ExpressionAttributeValues/:f", "S", "Amazon DynamoDB");
/// Example: aws4dd_item_update_value(op, "/Key/Id", "N", "101");
IW_EXPORT iwrc aws4dd_item_update_value(
  struct aws4dd_item_update *op,
  const char                *path,
  const char                *key,
  const char                *val);

/// Add key-value pair to the given ExpressionAttributeNames part of ItemUpdate operation.
/// @param op ItemUpdate operation
/// @param key ExpressionAttributeNames key
/// @param val ExpressionAttributeNames value
IW_EXPORT iwrc aws4dd_item_update_expression_attr_name(
  struct aws4dd_item_update *op, const char *key,
  const char *value);

/// Executes an ItemUpdate operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_item_update(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_update      *op,
  struct aws4dd_response        **rpp);

//
// ItemGet
//

struct aws4dd_item_get;

/// ItemGet operation specification.
struct aws4dd_item_get_spec {
  const char *table_name;
  const char *projection_expression;
  aws4dd_return_consumed_capacity_e return_consumed_capacity;
  bool consistent_read;
};

/// Create ItemGet operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_item_get_op_destroy().
IW_EXPORT iwrc aws4dd_item_get_op(struct aws4dd_item_get **opp, const struct aws4dd_item_get_spec *spec);

/// Destroy ItemGet operation handler.
IW_EXPORT void aws4dd_item_get_op_destroy(struct aws4dd_item_get **opp);

/// Adds key-value pair to the given ExpressionAttributeNames part of ItemGet operation.
/// @param op ItemPut operation
/// @param key ExpressionAttributeNames key
/// @param val ExpressionAttributeNames value
IW_EXPORT iwrc aws4dd_item_get_expression_attr_name(struct aws4dd_item_get *op, const char *key, const char *value);

/// Sets /Key/ part of ItemGet operation.
IW_EXPORT iwrc aws4dd_item_get_key_array(
  struct aws4dd_item_get *op,
  const char             *path,
  const char             *key,
  const char            **values);

/// Sets /Key/ part of ItemGet operation.
IW_EXPORT iwrc aws4dd_item_get_key_value(
  struct aws4dd_item_get *op,
  const char             *path,
  const char             *key,
  const char             *value);

/// Executes ItemGet operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_item_get(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_get         *op,
  struct aws4dd_response        **rpp);

//
// Query
//

struct aws4dd_query;

typedef enum {
  AWS4DD_SELECT_SPECIFIC_ATTRIBUTES = 1,
  AWS4DD_SELECT_ALL_ATTRIBUTES,
  AWS4DD_SELECT_ALL_PROJECTED_ATTRIBUTES,
  AWS4DD_SELECT_COUNT,
} aws4dd_select_e;

/// Query operation specification.
struct aws4dd_query_spec {
  const char *table_name;
  const char *index_name;
  const char *key_condition_expression;
  const char *filter_expression;
  const char *projection_expression;
  aws4dd_return_consumed_capacity_e return_consumed_capacity;
  aws4dd_select_e select;
  bool     consistent_read;
  bool     scan_index_forward;
  uint32_t limit;
};

/// Create Query operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_query_op_destroy().
IW_EXPORT iwrc aws4dd_query_op(struct aws4dd_query **opp, const struct aws4dd_query_spec *spec);

/// Destroy Query operation handler.
IW_EXPORT void aws4dd_query_op_destroy(struct aws4dd_query **opp);

/// Adds key-value pair to the given ExpressionAttributeNames part of Query operation.
/// @param op Query operation
/// @param key ExpressionAttributeNames key
/// @param val ExpressionAttributeNames value
IW_EXPORT iwrc aws4dd_query_expression_attr_name(struct aws4dd_query *op, const char *key, const char *value);

/// Adds value to the /ExpressionAttributeValues or /ExclusiveStartKey part of Query operation.
/// Example: aws4dd_query_value(op, "/ExpressionAttributeValues/:v1", "S", "Amazon DynamoDB")
IW_EXPORT iwrc aws4dd_query_value(struct aws4dd_query *op, const char *path, const char *key, const char *value);

/// Adds values to the /ExpressionAttributeValues or /ExclusiveStartKey part of Query operation.
/// Example: aws4dd_query_array(op, "/ExpressionAttributeValues/:v1", "SS",
///                             (const char*[]) { "Update", "Multiple", "Help", 0 })
IW_EXPORT iwrc aws4dd_query_array(struct aws4dd_query *op, const char *path, const char *key, const char **values);

/// Executes a given Query operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_query(
  const struct aws4_request_spec *spec,
  struct aws4dd_query            *op,
  struct aws4dd_response        **rpp);

//
// DeleteItem
//

struct aws4dd_item_delete;

struct aws4dd_item_delete_spec {
  const char *table_name;
  const char *condition_expression;
  struct {
    aws4dd_return_consumed_capacity_e  consumed_capacity;
    aws4dd_return_collection_metrics_e collection_metrics;
    aws4dd_return_values_e values;
  } ret;
};

/// Creates a DeleteItem operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_item_delete_op_destroy().
IW_EXPORT iwrc aws4dd_item_delete_op(struct aws4dd_item_delete **opp, const struct aws4dd_item_delete_spec *spec);

/// Destroys DeleteItem operation handler.
IW_EXPORT void aws4dd_item_delete_op_destroy(struct aws4dd_item_delete **opp);

/// Adds key-value pair to the given ExpressionAttributeNames part of DeleteItem operation.
/// @param op DeleteItem operation
/// @param key ExpressionAttributeNames key
/// @param val ExpressionAttributeNames value
IW_EXPORT iwrc aws4dd_item_delete_expression_attr_name(
  struct aws4dd_item_delete *op, const char *key,
  const char *value);

/// Sets /Key or /ExpressionAttributeValues part of DeleteItem operation.
IW_EXPORT iwrc aws4dd_item_delete_value(
  struct aws4dd_item_delete *op, const char *path,
  const char *key, const char *value);

/// Sets /Key or /ExpressionAttributeValues part of DeleteItem operation.
IW_EXPORT iwrc aws4dd_item_delete_array(
  struct aws4dd_item_delete *op, const char *path,
  const char *key, const char **values);

/// Executes DeleteItem operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_item_delete(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_delete      *op,
  struct aws4dd_response        **rpp);

IW_EXTERN_C_END
