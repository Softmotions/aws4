#define _GNU_SOURCE

#include "aws4.h"
#include "aws4dd.h"

#include <curl/curl.h>

#include <iowow/iwp.h>
#include <iwnet/iwn_tests.h>
#include <iwnet/iwn_poller.h>
#include <iwnet/iwn_proc.h>
#include <iwnet/iwn_curl.h>

#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pthread.h>

static int dynamodb_pid = -1;
static struct iwn_poller *poller;
static pthread_barrier_t start_br;

static struct aws4_request_spec request_spec = {
  .flags          = AWS_SERVICE_DYNAMODB | AWS_REQUEST_VERBOSE,
  .aws_region     = "us-east-1",
  .aws_key        = "fakeMyKeyId",
  .aws_secret_key = "fakeSecretAccessKey",
  .aws_url        = "http://localhost:8000"
};

static void _on_signal(int signo) {
  if (dynamodb_pid > -1) {
    kill(dynamodb_pid, SIGTERM);
  }
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static void _on_dynamodb_exit(const struct iwn_proc_ctx *ctx) {
  dynamodb_pid = -1;
  fprintf(stderr, "[DynamoDB] server exit\n");
  iwn_poller_shutdown_request(poller);
}

static void _on_dynamodb_output(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  fprintf(stderr, "[DynamoDB]: %.*s", (int) len, buf);
  static bool started = false;
  if (!started && memmem(buf, len, "shouldDelayTransientStatuses", IW_LLEN("shouldDelayTransientStatuses"))) {
    started = true;
    pthread_barrier_wait(&start_br);
  }
}

static iwrc _dynamodb_spawn(void) {
  return iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./run-dynamodb.sh",
    .on_stdout = _on_dynamodb_output,
    .on_stderr = _on_dynamodb_output,
    .on_exit = _on_dynamodb_exit,
    .parent_death_signal = SIGTERM,
  }, &dynamodb_pid);
}

static iwrc _test_basic_comm(void) {
  iwrc rc = 0;
  char *out = 0;
  int status_code = 0;

  rc = aws4_request_raw(&request_spec, &(struct aws4_request_payload) {
    .payload = "{}",
    .payload_len = IW_LLEN("{}"),
    .amz_target = "DynamoDB_20120810.ListTables"
  }, &out, &status_code);

  IWN_ASSERT(status_code == 200);
  IWN_ASSERT(rc == 0);
  IWN_ASSERT(out);

  if (out) {
    IWN_ASSERT(0 == strcmp(out, "{\"TableNames\":[]}"))
  }

  free(out);
  return rc;
}

static iwrc _test_table_item_delete(void) {
  iwrc rc = 0;
  JBL_NODE n;
  struct aws4dd_item_delete *op = 0;
  struct aws4dd_response *resp = 0;

  RCC(rc, finish, aws4dd_item_delete_op(&op, &(struct aws4dd_item_delete_spec) {
    .table_name = "Thread",
    .condition_expression = "attribute_not_exists(Replies)",
    .ret = {
      .values = AWS4DD_RETURN_VALUES_ALL_OLD
    }
  }));
  RCC(rc, finish, aws4dd_item_delete_value(op, "/Key/ForumName", "S", "Amazon DynamoDB"));
  RCC(rc, finish, aws4dd_item_delete_value(op, "/Key/Subject", "S", "How do I update multiple items?"));

  RCC(rc, finish, aws4dd_item_delete(&request_spec, op, &resp));

  RCC(rc, finish, jbn_at(resp->data, "/Attributes/Tags/SS/1", &n));
  IWN_ASSERT(n->type == JBV_STR);
  IWN_ASSERT(0 == strcmp(n->vptr, "Multiple"));

finish:
  aws4dd_response_destroy(&resp);
  aws4dd_item_delete_op_destroy(&op);
  return rc;
}

static iwrc _test_table_query(void) {
  iwrc rc = 0;
  JBL_NODE n;
  struct aws4dd_query *op = 0;
  struct aws4dd_response *resp = 0;

  RCC(rc, finish, aws4dd_query_op(&op, &(struct aws4dd_query_spec) {
    .table_name = "Thread",
    .key_condition_expression = "ForumName = :v1",
    .projection_expression = "Subject, Tags",
    .return_consumed_capacity = AWS4DD_RETURN_CONSUMED_TOTAL,
    .limit = 10,
    .consistent_read = true,
  }));

  RCC(rc, finish, aws4dd_query_value(op, "/ExpressionAttributeValues/:v1", "S", "Amazon DynamoDB"));

  RCC(rc, finish, aws4dd_query(&request_spec, op, &resp));

  // {"Items":[{"Subject":{"S":"How do I update multiple items?"}, "Tags":{"SS":["Help","Multiple","Update"]}}],
  //  "Count":1,"ScannedCount":1,"ConsumedCapacity":{"TableName":"Thread","CapacityUnits":1.0}}
  RCC(rc, finish, jbn_at(resp->data, "/Items/0/Subject/S", &n));
  IWN_ASSERT(n->type == JBV_STR);
  IWN_ASSERT(0 == strcmp(n->vptr, "How do I update multiple items?"));
  RCC(rc, finish, jbn_at(resp->data, "/Items/0/Tags/SS/1", &n));
  IWN_ASSERT(n->type == JBV_STR);
  IWN_ASSERT(0 == strcmp(n->vptr, "Multiple"));
  RCC(rc, finish, jbn_at(resp->data, "/Count", &n));
  IWN_ASSERT(n->type == JBV_I64);
  IWN_ASSERT(n->vi64 == 1);

finish:
  aws4dd_response_destroy(&resp);
  aws4dd_query_op_destroy(&op);
  return rc;
}

static iwrc _test_table_item_get(void) {
  iwrc rc = 0;
  struct aws4dd_item_get *op = 0;
  struct aws4dd_response *resp = 0;
  JBL_NODE n;

  RCC(rc, finish, aws4dd_item_get_op(&op, &(struct aws4dd_item_get_spec) {
    .table_name = "Thread",
    .consistent_read = true,
    .return_consumed_capacity = AWS4DD_RETURN_CONSUMED_TOTAL,
    .projection_expression = "LastPostDateTime, Message, Tags, LastPostedBy",
  }));

  RCC(rc, finish, aws4dd_item_get_key_value(op, "/Key/ForumName", "S", "Amazon DynamoDB"));
  RCC(rc, finish, aws4dd_item_get_key_value(op, "/Key/Subject", "S", "How do I update multiple items?"));


  RCC(rc, finish, aws4dd_item_get(&request_spec, op, &resp));
  RCC(rc, finish, jbn_at(resp->data, "/Item/Message/S", &n));
  IWN_ASSERT_FATAL(n->type == JBV_STR);
  IWN_ASSERT_FATAL(0 == strcmp(n->vptr, "I want to update multiple items in a single call."));
  RCC(rc, finish, jbn_at(resp->data, "/Item/LastPostDateTime/S", &n));
  IWN_ASSERT_FATAL(n->type == JBV_STR);
  RCC(rc, finish, jbn_at(resp->data, "/Item/Tags/SS/1", &n));
  IWN_ASSERT_FATAL(n->type == JBV_STR);
  IWN_ASSERT_FATAL(0 == strcmp(n->vptr, "Multiple"));

  RCC(rc, finish, jbn_at(resp->data, "/Item/LastPostedBy/S", &n));
  IWN_ASSERT_FATAL(n->type == JBV_STR);
  IWN_ASSERT_FATAL(0 == strcmp(n->vptr, "alice@example.com"));

  RCC(rc, finish, jbn_at(resp->data, "/ConsumedCapacity/CapacityUnits", &n));
  IWN_ASSERT_FATAL(n->type == JBV_F64);
  IWN_ASSERT_FATAL(n->vf64 == 1.0);
  RCC(rc, finish, jbn_at(resp->data, "/ConsumedCapacity/TableName", &n));
  IWN_ASSERT_FATAL(n->type == JBV_STR);
  IWN_ASSERT_FATAL(0 == strcmp(n->vptr, "Thread"));

finish:
  aws4dd_response_destroy(&resp);
  aws4dd_item_get_op_destroy(&op);
  return rc;
}

static iwrc _test_table_item_put(void) {
  iwrc rc = 0;
  struct aws4dd_item_put *op = 0;
  struct aws4dd_response *resp = 0;

  RCC(rc, finish, aws4dd_item_put_op(&op, &(struct aws4dd_item_put_spec) {
    .table_name = "Thread",
    .condition_expression = "ForumName <> :f and Subject <> :s"
  }));

  RCC(rc, finish, aws4dd_item_put_value(op, "/ExpressionAttributeValues/:f", "S", "Amazon DynamoDB"));
  RCC(rc, finish, aws4dd_item_put_value(op, "/ExpressionAttributeValues/:s", "S", "How do I update multiple items?"));

  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/LastPostDateTime", "S", "201303190422"));
  RCC(rc, finish, aws4dd_item_put_array(op, "/Item/Tags", "SS", (const char*[]) { "Update", "Multiple", "Help", 0 }));
  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/ForumName", "S", "Amazon DynamoDB"));
  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/Message", "S", "I want to update multiple items in a single call."));
  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/Subject", "S", "How do I update multiple items?"));
  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/LastPostedBy", "S", "fred@example.com"));

  RCC(rc, finish, aws4dd_item_put(&request_spec, op, &resp));

finish:
  aws4dd_response_destroy(&resp);
  aws4dd_item_put_op_destroy(&op);
  return rc;
}

static iwrc _test_table_item_update(void) {
  iwrc rc = 0;
  struct aws4dd_item_update *op = 0;
  struct aws4dd_response *resp = 0;

  RCC(rc, finish, aws4dd_item_update_op(&op, &(struct aws4dd_item_update_spec) {
    .table_name = "Thread",
    .update_expression = "set LastPostedBy = :val1",
    .condition_expression = "LastPostedBy = :val2",
    .ret = {
      .values = AWS4DD_RETURN_VALUES_ALL_NEW
    }
  }));

  RCC(rc, finish, aws4dd_item_update_value(op, "/ExpressionAttributeValues/:val1", "S", "alice@example.com"));
  RCC(rc, finish, aws4dd_item_update_value(op, "/ExpressionAttributeValues/:val2", "S", "fred@example.com"));

  RCC(rc, finish, aws4dd_item_update_value(op, "/Key/ForumName", "S", "Amazon DynamoDB"));
  RCC(rc, finish, aws4dd_item_update_value(op, "/Key/Subject", "S", "How do I update multiple items?"));

  RCC(rc, finish, aws4dd_item_update(&request_spec, op, &resp));

finish:
  aws4dd_response_destroy(&resp);
  aws4dd_item_update_op_destroy(&op);
  return rc;
}

static iwrc _test_table_update(void) {
  iwrc rc = 0;
  struct aws4dd_table_update *op = 0;
  struct aws4dd_response *resp = 0;
  JBL_NODE n;

  RCC(rc, finish, aws4dd_table_update_op(&op, &(struct aws4dd_table_update_spec) {
    .name = "Thread",
    .read_capacity_units = 10,
    .write_capacity_units = 10,
  }));

  RCC(rc, finish, aws4dd_table_update(&request_spec, op, &resp));

  RCC(rc, finish, jbn_at(resp->data, "/TableDescription/ProvisionedThroughput/ReadCapacityUnits", &n));
  IWN_ASSERT(n->type == JBV_I64);
  IWN_ASSERT(n->vi64 == 10);

  // TODO: More tests

finish:
  aws4dd_response_destroy(&resp);
  aws4dd_table_update_op_destroy(&op);
  return rc;
}

static iwrc _test_table_operations(void) {
  iwrc rc = 0;
  struct aws4dd_table_create *op = 0;
  struct aws4dd_response *resp = 0;

  RCC(rc, finish, aws4dd_table_create_op(&op, &(struct aws4dd_table_create_spec) {
    .name = "Thread",
    .partition_key = "ForumName:S",
    .sort_key = "Subject:S",
    .flags = AWS4DD_TABLE_BILLING_PROVISIONED,
    .read_capacity_units = 5,
    .write_capacity_units = 5
  }));
  RCC(rc, finish, aws4dd_table_attribute_string_add(op, "LastPostDateTime"));
  RCC(rc, finish, aws4dd_table_index_add(op, &(struct aws4dd_index_spec) {
    .name = "LastPostIndex",
    .pk = "ForumName",
    .sk = "LastPostDateTime",
  }));
  RCC(rc, finish, aws4dd_table_tag_add(op, "Owner", "BlueTeam"));

  RCC(rc, finish, aws4dd_table_create(&request_spec, op, &resp));
  IWN_ASSERT_FATAL(rc == 0);
  IWN_ASSERT_FATAL(resp->data);
  aws4dd_response_destroy(&resp);
  aws4dd_table_create_op_destroy(&op);

  RCC(rc, finish, aws4dd_table_describe(&request_spec, "Thread", &resp));
  aws4dd_response_destroy(&resp);

  RCC(rc, finish, _test_table_item_put());
  RCC(rc, finish, _test_table_item_update());
  RCC(rc, finish, _test_table_item_get());
  RCC(rc, finish, _test_table_query());
  RCC(rc, finish, _test_table_update());
  RCC(rc, finish, _test_table_item_delete());
  RCC(rc, finish, aws4dd_table_delete(&request_spec, "Thread", &resp));
  aws4dd_response_destroy(&resp);

finish:
  aws4dd_table_create_op_destroy(&op);
  aws4dd_response_destroy(&resp);
  return rc;
}

static void* _tests_run(void *d) {
  pthread_barrier_wait(&start_br);
  iwp_sleep(500); // Wait a bit to setup local dynamodb endpoint
  iwrc rc = 0;

  RCC(rc, finish, _test_basic_comm());
  RCC(rc, finish, _test_table_operations());

finish:
  IWN_ASSERT(rc == 0);
  _on_signal(SIGTERM);
  return 0;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGALRM, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  if (signal(SIGTERM, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }
  if (signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }
  iwlog_init();

  RCC(rc, finish, iwn_poller_create(4, 1, &poller));
  RCC(rc, finish, _dynamodb_spawn());

  pthread_barrier_init(&start_br, 0, 2);

  pthread_t th;
  pthread_create(&th, 0, _tests_run, 0);

  iwn_poller_poll(poller);
  pthread_join(th, 0);
  pthread_barrier_destroy(&start_br);

  iwn_proc_dispose();
  fprintf(stderr, "Poller exited\n");

finish:
  IWN_ASSERT(rc == 0);
  iwn_poller_destroy(&poller);
  return iwn_assertions_failed > 0 ? 1 : 0;
}
