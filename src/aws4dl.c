#include "aws4dl.h"
#include "aws4dd.h"

#include <iowow/iwp.h>
#include <iwnet/iwn_scheduler.h>

#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>

#define _LF_TICKET_ITEM_CREATE 0x01U

struct aws4dl_lock {
  struct aws4dl_lock_acquire_spec acquire_spec;
  IWPOOL  *pool;
  char     ticket[40];   ///< Acquired lock ticket.
  uint32_t flags;        ///< `_LF_XXX` state flags

  int heartbeat_fd;      ///< Poller heartbeat task file descriptor.
  pthread_mutex_t mtx;
  pthread_cond_t  cond;
};

static iwrc _lock_table_ensure(struct aws4dl_lock *lock) {
  iwrc rc = 0;

  struct aws4dd_response *resp = 0;
  struct aws4dd_table_create *op = 0;
  struct aws4_request_spec request_spec = lock->acquire_spec.request;
  struct aws4dl_lock_spec lock_spec = lock->acquire_spec.lock_spec;

  JBL_NODE n;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  const char *partition_key;
  const char *sort_key;

  RCB(finish, partition_key = iwpool_printf(pool, "%s:S", lock_spec.pk_name));
  RCB(finish, sort_key = iwpool_printf(pool, "%s:S", lock_spec.sk_name));

  RCC(rc, finish, aws4dd_table_create_op(&op, &(struct aws4dd_table_create_spec) {
    .name = lock_spec.table_name,
    .partition_key = partition_key,
    .sort_key = sort_key,
    .flags = AWS4DD_TABLE_BILLING_PER_REQUEST
  }));
  RCC(rc, finish, aws4dd_table_tag_add(op, "Type", "aws4dl"));

  request_spec.flags |= AWS_REQUEST_ACCEPT_ANY_STATUS_CODE;
  RCC(rc, finish, aws4dd_table_create(&request_spec, op, &resp));

  if (resp->status_code != 200) {
    if (resp->status_code == 400) {
      // Check if table is exists already
      RCC(rc, finish, jbn_at(resp->data, "/__type", &n));
      if (  n->type != JBV_STR
         || strcmp(n->vptr, "com.amazonaws.dynamodb.v20120810#ResourceInUseException") != 0) {
        rc = AWS4_API_REQUEST_ERROR;
        goto finish;
      }
    } else {
      rc = AWS4_API_REQUEST_ERROR;
      goto finish;
    }
  } else {
    bool ttl_enabled = false;
    rc = aws4dd_ttl_update(&request_spec, lock_spec.table_name, "expiresAt", true, &ttl_enabled);
    if (rc) {
      iwlog_ecode_warn(rc, "AWS4DL | Failed to enable 'expiresAt' TTL for table '%s'", lock_spec.table_name);
      rc = 0;
    } else if (!ttl_enabled) {
      iwlog_warn("AWS4DL | 'expiresAt' TTL is not enabled for table '%s'", lock_spec.table_name);
    }
  }

finish:
  aws4dd_table_create_op_destroy(&op);
  aws4dd_response_destroy(&resp);
  iwpool_destroy(pool);
  return rc;
}

static iwrc _lock_table_ticket_item_ensure(struct aws4dl_lock *lock) {
  iwrc rc = 0;

  struct aws4dd_response *resp = 0;
  struct aws4dd_item_put *op = 0;
  struct aws4_request_spec request_spec = lock->acquire_spec.request;
  struct aws4dl_lock_spec lock_spec = lock->acquire_spec.lock_spec;
  const char *condition_expression, *upk, *usk;

  JBL_NODE n;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  RCB(finish, condition_expression = iwpool_printf(pool, "attribute_not_exists(%s)", lock_spec.pk_name));

  RCC(rc, finish, aws4dd_item_put_op(&op, &(struct aws4dd_item_put_spec) {
    .table_name = lock_spec.table_name,
    .condition_expression = condition_expression,
  }));

  RCB(finish, upk = iwpool_printf(pool, "/Item/%s", lock_spec.pk_name));
  RCC(rc, finish, aws4dd_item_put_value(op, upk, "S", "e204f236-031c-4244-9634-cdd2aaf86960"));

  RCB(finish, usk = iwpool_printf(pool, "/Item/%s", lock_spec.sk_name));
  RCC(rc, finish, aws4dd_item_put_value(op, usk, "S", "bb7a739b-8ba7-44fd-8164-fbfe9f98bd0b"));

  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/ticketNumber", "N", "1"));

  request_spec.flags |= AWS_REQUEST_ACCEPT_ANY_STATUS_CODE;
  RCC(rc, finish, aws4dd_item_put(&request_spec, op, &resp));

  switch (resp->status_code) {
    case 400:
      RCC(rc, finish, jbn_at(resp->data, "/__type", &n));
      if (  n->type != JBV_STR
         || strcmp(n->vptr, "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException") != 0) {
        rc = AWS4_API_REQUEST_ERROR;
      }
      break;
    case 200:
      break;
    default:
      rc = AWS4_API_REQUEST_ERROR;
      break;
  }

finish:
  aws4dd_item_put_op_destroy(&op);
  aws4dd_response_destroy(&resp);
  iwpool_destroy(pool);
  return rc;
}

static iwrc _ticket_acquire(struct aws4dl_lock *lock) {
  iwrc rc = 0;

  const char *upk;
  const char *usk;

  IWPOOL *lpool = iwpool_create_empty();
  if (!lpool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  JBL_NODE n;
  struct aws4dd_response *resp = 0;
  struct aws4dd_item_update *op = 0;
  struct aws4_request_spec rspec = lock->acquire_spec.request;

  rspec.flags |= AWS_REQUEST_ACCEPT_ANY_STATUS_CODE;

  struct aws4dd_item_update_spec uspec = {
    .table_name        = lock->acquire_spec.lock_spec.table_name,
    .update_expression = "SET ticketNumber = ticketNumber + :ticketNumber",
    .ret               = {
      .values          = AWS4DD_RETURN_VALUES_UPDATED_NEW
    }
  };

  RCB(finish, uspec.condition_expression = iwpool_printf(lpool, "attribute_exists(%s)",
                                                         lock->acquire_spec.lock_spec.pk_name));
  RCC(rc, finish, aws4dd_item_update_op(&op, &uspec));
  RCC(rc, finish, aws4dd_item_update_value(op, "/ExpressionAttributeValues/:ticketNumber", "N", "1"));

  RCB(finish, upk = iwpool_printf(lpool, "/Key/%s", lock->acquire_spec.lock_spec.pk_name));
  RCC(rc, finish, aws4dd_item_update_value(op, upk, "S", "e204f236-031c-4244-9634-cdd2aaf86960"));

  RCB(finish, usk = iwpool_printf(lpool, "/Key/%s", lock->acquire_spec.lock_spec.sk_name));
  RCC(rc, finish, aws4dd_item_update_value(op, usk, "S", "bb7a739b-8ba7-44fd-8164-fbfe9f98bd0b"));

again:
  RCC(rc, finish, aws4dd_item_update(&rspec, op, &resp));

  switch (resp->status_code) {
    case 400:
      RCC(rc, finish, jbn_at(resp->data, "/__type", &n));
      if (  n->type == JBV_STR
         && strcmp(n->vptr, "com.amazonaws.dynamodb.v20120810#ResourceNotFoundException") == 0) {
        RCC(rc, finish, _lock_table_ensure(lock));
        aws4dd_response_destroy(&resp);
        sleep(1); // Give some time to create a table TODO: Review it.
        goto again;
      } else if (  !(lock->flags & _LF_TICKET_ITEM_CREATE)
                && n->type == JBV_STR
                && strcmp(n->vptr, "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException") == 0) {
        lock->flags |= _LF_TICKET_ITEM_CREATE;
        RCC(rc, finish, _lock_table_ticket_item_ensure(lock));
        aws4dd_response_destroy(&resp);
        goto again;
      } else {
        rc = AWS4_API_REQUEST_ERROR;
      }
      break;
    case 200:
      break;
    default:
      rc = AWS4_API_REQUEST_ERROR;
      break;
  }

  // Now examine the response
  RCC(rc, finish, jbn_at(resp->data, "/Attributes/ticketNumber/N", &n));
  if (n->type == JBV_STR) {
    if (n->vsize < 1 || n->vsize > sizeof(lock->ticket) - 2) {
      rc = IW_ERROR_UNEXPECTED_RESPONSE;
    }
    char *wp = lock->ticket;
    *wp = '/', ++wp;
    memset(wp, '0', sizeof(lock->ticket) - n->vsize - 2);
    wp += sizeof(lock->ticket) - n->vsize - 2;
    memcpy(wp, n->vptr, n->vsize);
    wp += n->vsize;
    *wp = '\0';
  } else {
    rc = IW_ERROR_UNEXPECTED_RESPONSE;
  }

finish:
  aws4dd_item_update_op_destroy(&op);
  aws4dd_response_destroy(&resp);
  iwpool_destroy(lpool);
  return rc;
}

static iwrc _lock_enqueue(struct aws4dl_lock *lock) {
  iwrc rc = 0;

  struct aws4dd_response *resp = 0;
  struct aws4dd_item_put *op = 0;
  struct aws4_request_spec request_spec = lock->acquire_spec.request;
  struct aws4dl_lock_spec lock_spec = lock->acquire_spec.lock_spec;
  const char *condition_expression, *upk, *usk;
  uint64_t time;

  JBL_NODE n;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  RCB(finish, condition_expression = iwpool_printf(pool, "attribute_not_exists(%s)", lock_spec.pk_name));

  RCC(rc, finish, aws4dd_item_put_op(&op, &(struct aws4dd_item_put_spec) {
    .table_name = lock_spec.table_name,
    .condition_expression = condition_expression,
  }));

  RCB(finish, upk = iwpool_printf(pool, "/Item/%s", lock_spec.pk_name));
  RCB(finish, usk = iwpool_printf(pool, "/Item/%s", lock_spec.sk_name));

  RCC(rc, finish, aws4dd_item_put_value(op, upk, "S", lock_spec.resource_name));
  RCC(rc, finish, aws4dd_item_put_value(op, usk, "S", lock->ticket));

  RCC(rc, finish, iwp_current_time_ms(&time, false));
  time /= 1000UL;
  RCB(finish, upk = iwpool_printf(pool, "%" PRIu64, time));
  time += lock_spec.lock_enqueued_ttl_sec;
  RCB(finish, usk = iwpool_printf(pool, "%" PRIu64, time));

  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/createdAt", "N", upk));
  RCC(rc, finish, aws4dd_item_put_value(op, "/Item/expiresAt", "N", usk));

  RCC(rc, finish, aws4dd_item_put(&request_spec, op, &resp));

finish:
  aws4dd_item_put_op_destroy(&op);
  aws4dd_response_destroy(&resp);
  iwpool_destroy(pool);
  return rc;
}

static void _heartbeat_cancel(void *d) {
  struct aws4dl_lock *lock = d;
  pthread_mutex_lock(&lock->mtx);
  if (lock->heartbeat_fd) {
    lock->heartbeat_fd = 0;
    pthread_cond_broadcast(&lock->cond);
  }
  pthread_mutex_unlock(&lock->mtx);
}

static void _heartbeat_fn(void *d) {
  iwrc rc = 0;
  JBL_NODE n;
  IWPOOL *pool;
  uint64_t time;
  const char *condition_expression, *val, *upk, *usk;

  struct aws4dl_lock *lock = d;
  struct aws4dd_response *resp = 0;
  struct aws4dd_item_update *op = 0;
  struct aws4dl_lock_spec lock_spec = lock->acquire_spec.lock_spec;
  struct aws4_request_spec request_spec = lock->acquire_spec.request;

  RCB(fatal, pool = iwpool_create_empty());
  RCB(fatal, condition_expression = iwpool_printf(pool, "attribute_exists(%s)", lock_spec.pk_name));

  RCC(rc, fatal, aws4dd_item_update_op(&op, &(struct aws4dd_item_update_spec) {
    .table_name = lock_spec.table_name,
    .condition_expression = condition_expression,
    .update_expression = "SET expiresAt = :expiresAt",
  }));

  RCC(rc, fatal, iwp_current_time_ms(&time, false));
  time /= 1000UL;
  time += lock_spec.lock_enqueued_ttl_sec;
  RCB(fatal, val = iwpool_printf(pool, "%" PRIu64, time));
  RCC(rc, fatal, aws4dd_item_update_value(op, "/ExpressionAttributeValues/:expiresAt", "N", val));

  RCB(fatal, upk = iwpool_printf(pool, "/Key/%s", lock_spec.pk_name));
  RCB(fatal, usk = iwpool_printf(pool, "/Key/%s", lock_spec.sk_name));

  RCC(rc, fatal, aws4dd_item_update_value(op, upk, "S", lock_spec.resource_name));
  RCC(rc, fatal, aws4dd_item_update_value(op, usk, "S", lock->ticket));

  request_spec.flags |= AWS_REQUEST_ACCEPT_ANY_STATUS_CODE;
  RCC(rc, finish, aws4dd_item_update(&request_spec, op, &resp));

  switch (resp->status_code) {
    case 400:
      RCC(rc, fatal, jbn_at(resp->data, "/__type", &n));
      if (  n->type != JBV_STR
         || strcmp(n->vptr, "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException") != 0) {
        goto fatal; /// Record doesn't exists.
      }
      break;
    default:
      break;
  }

finish:
  if (!(lock_spec.flags & AWS4DL_FLAG_HEARTBEAT_ONCE)) {
    // Engage next tick
    pthread_mutex_lock(&lock->mtx);
    if (lock->heartbeat_fd) {
      int fd = 0;
      iwrc rc2 = iwn_schedule2(&(struct iwn_scheduler_spec) {
        .task_fn = _heartbeat_fn,
        .on_cancel = _heartbeat_cancel,
        .poller = lock->acquire_spec.poller,
        .user_data = lock,
        .timeout_ms = lock_spec.lock_enqueued_ttl_sec / 3,
      }, &fd);
      if (!rc2) {
        lock->heartbeat_fd = fd;
        pthread_cond_broadcast(&lock->cond);
      } else {
        rc = rc2;
      }
    }
    pthread_mutex_unlock(&lock->mtx);
  }

fatal:
  if (rc) {
    iwlog_ecode_warn2(rc, "AWS4DL | Lock heartbeat request failed");
  }
  aws4dd_item_update_op_destroy(&op);
  aws4dd_response_destroy(&resp);
  iwpool_destroy(pool);
}

static iwrc _heartbeat_start(struct aws4dl_lock *lock) {
  if (lock->acquire_spec.lock_spec.flags & AWS4DL_FLAG_HEARTBEAT_ONCE) {
    _heartbeat_fn(lock);
    return 0;
  }

  iwrc rc = 0;
  pthread_mutex_lock(&lock->mtx);
  if (lock->heartbeat_fd) {
    rc = IW_ERROR_INVALID_STATE;
    goto finish;
  }

  RCC(rc, finish, iwn_schedule2(&(struct iwn_scheduler_spec) {
    .task_fn = _heartbeat_fn,
    .on_cancel = _heartbeat_cancel,
    .poller = lock->acquire_spec.poller,
    .user_data = lock,
    .timeout_ms = lock->acquire_spec.lock_spec.lock_enqueued_ttl_sec / 3,
  }, &lock->heartbeat_fd));

finish:
  pthread_mutex_unlock(&lock->mtx);
  return rc;
}

static void _lock_destroy(struct aws4dl_lock *lock) {
  if (!lock) {
    return;
  }
  // TODO: Stop heartbeat
  pthread_cond_destroy(&lock->cond);
  pthread_mutex_destroy(&lock->mtx);
  iwpool_destroy(lock->pool);
}

iwrc aws4dl_lock_acquire(const struct aws4dl_lock_acquire_spec *acquire_spec, struct aws4dl_lock **lpp) {
  if (!acquire_spec || !lpp || !acquire_spec->poller) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dl_lock *lock;
  RCB(finish, lock = iwpool_calloc(sizeof(*lock), pool));
  pthread_mutex_init(&lock->mtx, 0);
  pthread_cond_init(&lock->cond, 0);
  lock->pool = pool;
  memcpy(&lock->acquire_spec, acquire_spec, sizeof(*acquire_spec));

  struct aws4dl_lock_acquire_spec *acquire = &lock->acquire_spec;
  struct aws4dl_lock_spec *lock_spec = &acquire->lock_spec;

  if (!lock_spec->resource_name) {
    lock_spec->resource_name = "resource";
  }

  if (!lock_spec->table_name) {
    lock_spec->table_name = "aws4dl";
  }

  if (!lock_spec->pk_name) {
    lock_spec->pk_name = "pk";
  } else {
    RCC(rc, finish, aws4dd_resource_name_check(lock_spec->pk_name, AWS4DD_RESOURCE_ATTR));
  }

  if (!lock_spec->sk_name) {
    lock_spec->sk_name = "sk";
  } else {
    RCC(rc, finish, aws4dd_resource_name_check(lock_spec->sk_name, AWS4DD_RESOURCE_ATTR));
  }

  if (strcmp(lock_spec->pk_name, lock_spec->sk_name) == 0) {
    rc = IW_ERROR_INVALID_ARGS;
    goto finish;
  }

  if (lock_spec->lock_enqueued_ttl_sec == 0) {
    lock_spec->lock_enqueued_ttl_sec = 60;
  } else if (lock_spec->lock_enqueued_ttl_sec < 10) {
    lock_spec->lock_enqueued_ttl_sec = 10;
  }

  if (lock_spec->lock_enqueued_wait_sec == 0) {
    lock_spec->lock_enqueued_wait_sec = 120;
  } else if (lock_spec->lock_enqueued_wait_sec < 10) {
    lock_spec->lock_enqueued_wait_sec = 10;
  }

  RCC(rc, finish, _ticket_acquire(lock));
  RCC(rc, finish, _lock_enqueue(lock));

  if (!(lock_spec->flags & AWS4DL_FLAG_HEARTBEAT_NO)) {
    RCC(rc, finish, _heartbeat_start(lock));
  }

  // TODO:

  *lpp = lock;

finish:
  if (rc) {
    if (lock && lock->pool) {
      _lock_destroy(lock);
    } else {
      iwpool_destroy(pool);
    }
  }
  return rc;
}

iwrc aws4dl_lock_release(struct aws4dl_lock **lpp) {
  if (!lpp || !*lpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  struct aws4dl_lock *lock = *lpp;

  // TODO:

  *lpp = 0;
  _lock_destroy(lock);
  return rc;
}
