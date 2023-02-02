#pragma once
#include "aws4.h"
#include <iowow/iwpool.h>

IW_EXTERN_C_START

#define AWS4DD_RESOURCE_TABLE 0x01U
#define AWS4DD_RESOURCE_ATTR  0x02U
#define AWS4DD_RESOURCE_TAG   0x04U
#define AWS4DD_RESOURCE_INDEX 0x08U

typedef enum {
  _AWS4DD_ERROR_START = (IW_ERROR_START + 101000L),
  AWS4DD_ERROR_INVALID_RESOURCE_NAME, ///< Invalid table/index/attr/tag name (AWS4DD_ERROR_INVALID_RESOURCE_NAME)
  AWS4DD_ERROR_MAX_IDX_LIMIT,         ///< Number of allowed table indexes exceeds limits (AWS4DD_ERROR_MAX_IDX_LIMIT)
  AWS4DD_ERROR_NO_PARTITION_KEY,      ///< No partition key specified (AWS4DD_ERROR_NO_PARTITION_KEY)
  _AWS4DD_ERROR_END,
} aws4dd_ecode_e;

/// Response of AWS4DD request.
struct aws4dd_response {
  IWPOOL  *pool;
  JBL_NODE data;
  int      status_code;
};

/// Destroys an aws4dd operation response.
IW_EXPORT void aws4dd_response_destroy(struct aws4dd_response **rpp);

/// Returns error is given `name` cannot be used as AWS DynamoDB resource name.
IW_EXPORT iwrc aws4dd_resource_name_check(const char *name, int resource);

//
// Table
//

struct aws4dd_table_create;

#define AWS4DD_TABLE_BILLING_PROVISIONED 0x01U
#define AWS4DD_TABLE_BILLING_PER_REQUEST 0x02U
#define AWS4DD_TABLE_CLASS_STANDARD      0x04U
#define AWS4DD_TABLE_CLASS_INFREQUENT    0x08U
#define AWS4DD_TABLE_DONT_AWAIT_CREATION 0x10U ///< Don't wait while table will be available.
#define AWS4DD_TABLE_STREAM_KEYS_ONLY    0x20U
#define AWS4DD_TABLE_STREAM_NEW_IMAGE    0x40U
#define AWS4DD_TABLE_STREAM_OLD_IMAGE    0x80U
#define AWS4DD_TABLE_STREAM_DISABLED     0x100U
#define AWS4DD_TABLE_STREAM_ALL          ( \
    AWS4DD_TABLE_STREAM_KEYS_ONLY \
    | AWS4DD_TABLE_STREAM_NEW_IMAGE \
    | AWS4DD_TABLE_STREAM_OLD_IMAGE \
    | AWS4DD_TABLE_STREAM_DISABLED)

struct aws4dd_table_create_spec {
  const char *name;              ///< Table name
  const char *partition_key;     ///< Partition key spec. Eg: `ForumName:S`
  const char *sort_key;          ///< Sort key spec. Eg: `Subject:S`
  long     read_capacity_units;  ///< Read capacity units. Makes sense only if AWS4DD_TABLE_BILLING_PROVISIONED is set.
  long     write_capacity_units; ///< Write capacity units. Makes sense only if AWS4DD_TABLE_BILLING_PROVISIONED is set.
  unsigned flags;                ///< AWS4DD_TABLE_XXX
};

/// Create CreateTable operation handler.
/// NOTE: \c rpp must be destroyed by aws4dd_table_create_op_destroy().
/// @param rpp [out] Table create operation handler.
/// @param spec [in] Table create specification.
IW_EXPORT iwrc aws4dd_table_create_op(
  struct aws4dd_table_create           **rpp,
  const struct aws4dd_table_create_spec *spec);

/// Destroy CreateTable operation handler.
IW_EXPORT void aws4dd_table_create_op_destroy(struct aws4dd_table_create **opp);

/// Adds a new tag to the table.
IW_EXPORT iwrc aws4dd_table_tag_add(struct aws4dd_table_create *op, const char *tag_name, const char *tag_value);

/// Adds a new attribute to the table.
/// Where `spec` is and attribute spec in the following format: `type:name`. Example: `S:myattr`.
IW_EXPORT iwrc aws4dd_table_attribute_add(struct aws4dd_table_create *op, const char *spec);

/// Adds a new string attribute to the table.
IW_EXPORT iwrc aws4dd_table_attribute_string_add(struct aws4dd_table_create *op, const char *name);

/// Adds a new number attribute to the table.
IW_EXPORT iwrc aws4dd_table_attribute_number_add(struct aws4dd_table_create *op, const char *name);

/// Adds a new binary attribute to the table.
IW_EXPORT iwrc aws4dd_table_attribute_binary_add(struct aws4dd_table_create *op, const char *name);

#define AWS4DD_TABLE_INDEX_GLOBAL      0x01U ///< If index is global.
#define AWS4DD_TABLE_INDEX_PROJECT_ALL 0x02U ///< Include all non key attrinuted into projection.

/// Table index basic specification.
struct aws4dd_index_spec {
  const char  *name;
  const char  *pk;
  const char  *sk;
  const char **proj;             ///< Zero terminated list of attributes.
  long     read_capacity_units;  ///< Read capacity units. Makes sense only if AWS4DD_TABLE_INDEX_PROVISIONED is set.
  long     write_capacity_units; ///< Write capacity units. Makes sense only if AWS4DD_TABLE_INDEX_PROVISIONED is set.
  unsigned flags;                ///< AWS4DD_TABLE_INDEX_XXX
};

/// Register a new table index.
IW_EXPORT iwrc aws4dd_table_index_add(struct aws4dd_table_create *op, const struct aws4dd_index_spec *spec);

/// Executes a CreateTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_create(
  const struct aws4_request_spec *spec,
  struct aws4dd_table_create     *op,
  struct aws4dd_response        **rpp);

/// Waits while table will be created.
/// @param table_name [in] Table name.
/// @param max_wait_sec [in] Maximum wait time in seconds. If 0 then default value will be used (5min)
IW_EXPORT iwrc aws4dd_table_await_active(
  const struct aws4_request_spec *spec, const char *table_name,
  int max_wait_sec);

//
// DescribeTable
//

/// Executes a DescribeTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_describe(
  const struct aws4_request_spec *spec, const char *name,
  struct aws4dd_response **rpp);

//
// DeleteTable
//

/// Executes a DeleteTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_delete(
  const struct aws4_request_spec *spec, const char *name,
  struct aws4dd_response **rpp);

//
// TagResource
//

/// Tag a DynamoDB resource identified by \c resource_arn with given \c tag_pairs.
///
/// Example:
///
///   awd4dd_tag_resource(spec,
///                       "arn:aws:dynamodb:us-west-2:123456789012:table/Forum",
///                       (char*[]){"tag1", "value1", "tag2", "value2", 0});
///
/// @param spec [in] AWS4 request specification.
/// @param resource_arn [in] Resource ARN
/// @param tags_pairs Zero terminated array of tag key/value pairs
IW_EXPORT iwrc aws4dd_tag_resource(
  const struct aws4_request_spec *spec,
  const char                     *resource_arn,
  const char                     *tag_pairs[]);

//
// UntagResource
//

/// Untag a DynamoDB resource identified by \c resource_arn with given \c tag_keys.
///
/// Example:
///
///  awd4dd_untag_resource(spec,
///                        "arn:aws:dynamodb:us-west-2:123456789012:table/Forum",
///                        (char*[]){"tag1", "tag2", 0});
///
/// @param spec [in] AWS4 request specification.
/// @param resource_arn [in] Resource ARN
/// @param tags_keys Zero terminated array of tag keys.
IW_EXPORT iwrc aws4dd_untag_resource(
  const struct aws4_request_spec *spec,
  const char                     *resource_arn,
  const char                     *tag_keys[]);

//
// ListTables
//

/// Executes a ListTables operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_tables_list(
  const struct aws4_request_spec *spec,
  const char                     *exclusive_start_table_name,
  uint32_t                        limit,
  struct aws4dd_response        **rpp);

//
// UpdateTable
//

struct aws4dd_table_update;

struct aws4dd_table_update_spec {
  const char *name;              ///< Table name
  long     read_capacity_units;  ///< Read capacity units. Makes sense only if AWS4DD_TABLE_BILLING_PROVISIONED is set.
  long     write_capacity_units; ///< Write capacity units. Makes sense only if AWS4DD_TABLE_BILLING_PROVISIONED is set.
  uint32_t flags;                ///< AWS4DD_TABLE_XXX
};

/// Creates an UpdateTable operation handler.
/// NOTE: \c rpp must be destroyed by aws4dd_table_update_op_destroy().
/// @param rpp [out] Table update operation handler.
/// @param spec [in] Table update specification.
IW_EXPORT iwrc aws4dd_table_update_op(
  struct aws4dd_table_update           **rpp,
  const struct aws4dd_table_update_spec *spec);

/// Destroy UpdateTable operation handler.
IW_EXPORT void aws4dd_table_update_op_destroy(struct aws4dd_table_update **opp);

/// Adds a new attribute to the table (/AttributeDefinitions).
/// Where `spec` is and attribute spec in the following format: `type:name`. Example: `S:myattr`.
IW_EXPORT iwrc aws4dd_table_update_attribute_add(struct aws4dd_table_update *op, const char *spec);

/// Adds a new string attribute to the table (/AttributeDefinitions).
IW_EXPORT iwrc aws4dd_table_update_attribute_string_add(struct aws4dd_table_update *op, const char *name);

/// Adds a new number attribute to the table (/AttributeDefinitions).
IW_EXPORT iwrc aws4dd_table_update_attribute_number_add(struct aws4dd_table_update *op, const char *name);

/// Adds a new binary attribute to the table (/AttributeDefinitions).
IW_EXPORT iwrc aws4dd_table_update_attribute_binary_add(struct aws4dd_table_update *op, const char *name);

/// Adds a new index to the table.
IW_EXPORT iwrc aws4dd_table_update_index_create(struct aws4dd_table_update *op, const struct aws4dd_index_spec *spec);

/// Removes an index with given \c index_name from the table.
IW_EXPORT iwrc aws4dd_table_update_index_delete(struct aws4dd_table_update *op, const char *index_name);

/// Updates a capacity units for an existing index.
IW_EXPORT iwrc aws4dd_table_update_index_update(
  struct aws4dd_table_update *op,
  const char                 *index_name,
  long                        read_capacity_units,
  long                        write_capacity_units);

/// Executes an UpdateTable operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_table_update(
  const struct aws4_request_spec *spec,
  struct aws4dd_table_update     *op,
  struct aws4dd_response        **rpp);

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

/// Sets an /Item or /ExpressionAttributeValues integers parts to the item.
/// Example: aws4dd_item_put_i64(op, "/Item/Id", 101);
IW_EXPORT iwrc aws4dd_item_put_value_i64(struct aws4dd_item_put *op, const char *path, int64_t val);

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

/// Sets an /Key or /ExpressionAttributeValues integers parts to the item.
/// Example: aws4dd_item_update_i64(op, "/Key/Id", 101);
IW_EXPORT iwrc aws4dd_item_update_value_i64(struct aws4dd_item_update *op, const char *path, int64_t val);

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
// BatchWriteItem
//

/// BatchWriteItem operation specification.
struct aws4dd_batch_write_spec {
  struct {
    aws4dd_return_consumed_capacity_e  capacity;
    aws4dd_return_collection_metrics_e metrics;
  } ret;
};

struct aws4dd_batch_write;

/// Creates a new BatchWriteItem operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_batch_write_op_destroy().
IW_EXPORT iwrc aws4dd_batch_write_op(
  struct aws4dd_batch_write           **opp,
  const struct aws4dd_batch_write_spec *spec);

/// Destroys BatchWriteItem operation handler.
IW_EXPORT void aws4dd_batch_write_op_destroy(struct aws4dd_batch_write **opp);

/// Adds a new PutRequest/DeleteRequest to the BatchWriteItem operation.
///
/// Example:
///
///  aws4dd_batch_write_array(op, "MyTable",  "/DeleteRequest/Key/MyKeyTags",
///                                            "SS", (const char*[]){ "Update", "Help", 0 });
///
IW_EXPORT iwrc aws4dd_batch_write_array(
  struct aws4dd_item_update *op,
  const char                *table,
  const char                *path,
  const char                *key,
  const char               **vals);

/// Adds a new PutRequest/DeleteRequest to the BatchWriteItem operation.
///
/// Example:
///
///  aws4dd_batch_write_value(op, "MyTable", "/PutRequest/Item/Forum", "S", "Amazon DynamoDB");
///
IW_EXPORT iwrc aws4dd_batch_write_value(
  struct aws4dd_item_update *op,
  const char                *table,
  const char                *path,
  const char                *key,
  const char                *val);

/// Adds a new PutRequest/DeleteRequest to the BatchWriteItem operation.
///
/// Example:
///
///  aws4dd_batch_write_value_i64(op, "MyTable", "/PutRequest/Item/Id", 101);
///
IW_EXPORT iwrc aws4dd_batch_write_value_i64(
  struct aws4dd_item_update *op,
  const char                *table,
  const char                *path,
  int64_t                    val);

/// Executes a BatchWriteItem operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_bach_write(
  const struct aws4_request_spec *spec,
  struct aws4dd_batch_write      *op,
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

/// Sets /Key/ part of ItemGet operation.
IW_EXPORT iwrc aws4dd_item_get_key_value_i64(struct aws4dd_item_get *op, const char *path, int64_t val);

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
  const char *exclusive_start_key_json;
  aws4dd_return_consumed_capacity_e return_consumed_capacity;
  aws4dd_select_e select;
  bool     consistent_read;
  bool     scan_index_backward;
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

/// Adds value to the /ExpressionAttributeValues or part of Query operation.
/// Example: aws4dd_query_value(op, "/ExpressionAttributeValues/:v1", "S", "Amazon DynamoDB")
IW_EXPORT iwrc aws4dd_query_value(struct aws4dd_query *op, const char *path, const char *key, const char *value);

/// Adds value to the /ExpressionAttributeValues or part of Query operation.
/// Example: aws4dd_query_value_i64(op, "/ExpressionAttributeValues/:v1", 123)
IW_EXPORT iwrc aws4dd_query_value_i64(struct aws4dd_query *op, const char *path, int64_t value);

/// Adds values to the /ExpressionAttributeValues or part of Query operation.
/// Example: aws4dd_query_array(op, "/ExpressionAttributeValues/:v1", "SS",
///                             (const char*[]) { "Update", "Multiple", "Help", 0 })
IW_EXPORT iwrc aws4dd_query_array(struct aws4dd_query *op, const char *path, const char *key, const char **values);

/// Sets /ExclusiveStartKey/ part of Query operation.
IW_EXPORT iwrc aws4dd_query_exclusive_start_key(struct aws4dd_query *op, JBL_NODE key);

/// Executes a given Query operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy().
IW_EXPORT iwrc aws4dd_query(
  const struct aws4_request_spec *spec,
  struct aws4dd_query            *op,
  struct aws4dd_response        **rpp);

//
// Scan
//

struct aws4dd_scan;

struct aws4dd_scan_spec {
  const char *table_name;                ///< Table name.
  const char *index_name;                ///< Name of secondary index to scan.
  const char *projection_expression;     ///< A string that identifies one or more attributes to retrieve from the
                                         ///  specified table or index.
  const char     *filter_expression;     ///< FilterExpression.
  aws4dd_select_e select;                ///< Select. Default: AWS4DD_SELECT_ALL_ATTRIBUTES
  uint32_t segments_total;               ///< Total number of segments into which scan operation is divided.
  uint32_t segment;                      ///< Used only if segments_total specified.
  uint32_t limit;                        ///< The maximum number of items to evaluate (not necessarily the number of
                                         ///  matching items).
  aws4dd_return_consumed_capacity_e
       return_consumed_capacity; ///< ReturnConsumedCapacity.
  bool consistent_read;          ///< ConsistentRead.
};

/// Creates a Scan operation handler.
/// NOTE: \c opp must be destroyed by aws4dd_scan_op_destroy().
IW_EXPORT iwrc aws4dd_scan_op(struct aws4dd_scan **opp, const struct aws4dd_scan_spec *spec);

/// Destroys a Scan operation handler.
IW_EXPORT void aws4dd_scan_op_destroy(struct aws4dd_scan **opp);

/// Adds key-value pair to the given ExpressionAttributeNames part of Scan operation.
IW_EXPORT iwrc aws4dd_scan_expression_attr_name(struct aws4dd_scan *op, const char *key, const char *value);

/// Sets an /ExclusiveStartKey or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_scan_array(op, "/ExpressionAttributeValues/:v1", "SS",
///                             (const char*[]) { "Update", "Multiple", "Help", 0 })
IW_EXPORT iwrc aws4dd_scan_array(struct aws4dd_scan *op, const char *path, const char *key, const char **vals);

/// Sets an /ExclusiveStartKey or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_scan_value(op, "/ExpressionAttributeValues/:v1", "S", "Amazon DynamoDB")
IW_EXPORT iwrc aws4dd_scan_value(struct aws4dd_scan *op, const char *path, const char *key, const char *val);

/// Sets an /ExclusiveStartKey or /ExpressionAttributeValues parts to the item.
/// Example: aws4dd_scan_i64(op, "/ExpressionAttributeValues/:v1", 123)
IW_EXPORT iwrc aws4dd_scan_value_i64(struct aws4dd_scan *op, const char *path, int64_t val);

/// Executes a given Scan operation.
/// NOTE: \c rpp must be destroyed by aws4dd_response_destroy).
IW_EXPORT iwrc aws4dd_scan(const struct aws4_request_spec *spec, struct aws4dd_scan *op, struct aws4dd_response **rpp);

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
IW_EXPORT iwrc aws4dd_item_delete_value_i64(struct aws4dd_item_delete *op, const char *path, int64_t val);

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

//
// TimeToLive (TTL)
//

/// Updates TTL `enabled` state for a given `table_name` and `attribute_name`.
IW_EXPORT iwrc aws4dd_ttl_update(
  const struct aws4_request_spec *spec,
  const char                     *table_name,
  const char                     *attribute_name,
  bool                            enabled,
  bool                           *out_enabled);

IW_EXTERN_C_END
