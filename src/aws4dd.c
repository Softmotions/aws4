#include "aws4dd.h"

#include <iowow/iwjson.h>
#include <iowow/iwarr.h>
#include <iowow/iwp.h>
#include <iwnet/iwn_pairs.h>

#include <errno.h>

static const char* _ecodefn(locale_t, uint32_t);

void aws4dd_response_destroy(struct aws4dd_response **rpp) {
  if (rpp && *rpp) {
    iwpool_destroy((*rpp)->pool);
    *rpp = 0;
  }
}

//
// TableCreate
//

struct aws4dd_table_create {
  IWPOOL     *pool;
  const char *name;       ///< Table name.
  const char *pk;         ///< Table partition key.
  const char *sk;         ///< Table sort key.
  struct iwn_pairs attrs; ///< Table attribute defs.
  struct iwn_pairs tags;  ///< Table tags.
  struct aws4dd_index_spec global_idx[20];
  struct aws4dd_index_spec local_idx[5];
  long     read_capacity_units;
  long     write_capacity_units;
  unsigned flags;
};

static iwrc _name_check(const char *name, int resource) {
  if (!name || *name == '\0') {
    return AWS4DD_ERROR_INVALID_RESOURCE_NAME;
  }
  unsigned long len = strlen(name);
  if (resource == AWS4DD_RESOURCE_TAG) {
    if (len > 128) {
      return AWS4DD_ERROR_INVALID_RESOURCE_NAME;
    } else {
      return 0;
    }
  }
  if (len > 255) {
    return AWS4DD_ERROR_INVALID_RESOURCE_NAME;
  }
  if ((resource == AWS4DD_RESOURCE_TABLE || resource == AWS4DD_RESOURCE_INDEX) && len < 3) {
    return AWS4DD_ERROR_INVALID_RESOURCE_NAME;
  }
  for (unsigned long i = 0; i < len; ++i) {
    if (  (name[i] < 'A' || name[i] > 'Z')
       && (name[i] < 'a' || name[i] > 'z')
       && (name[i] < '0' || name[i] > '9')
       && name[i] != '.' && name[i] != '_' && name[i] != '-') {
      return AWS4DD_ERROR_INVALID_RESOURCE_NAME;
    }
  }
  return 0;
}

iwrc aws4dd_resource_name_check(const char *name, int resource) {
  return _name_check(name, resource);
}

iwrc aws4dd_table_create_op(
  struct aws4dd_table_create           **rpp,
  const struct aws4dd_table_create_spec *spec
  ) {
  if (!rpp || !spec || !spec->name || !spec->partition_key) {
    return IW_ERROR_INVALID_ARGS;
  }

  *rpp = 0;
  RCR(_name_check(spec->name, AWS4DD_RESOURCE_TABLE));

  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  char *pks = 0;
  char *sks = 0;

  struct aws4dd_table_create *r;
  RCB(finish, r = iwpool_calloc(sizeof(*r), pool));
  r->pool = pool;

  r->flags = spec->flags;
  r->read_capacity_units = spec->read_capacity_units;
  r->write_capacity_units = spec->write_capacity_units;

  RCB(finish, r->name = iwpool_strdup2(pool, spec->name));
  RCB(finish, r->pk = iwpool_strdup2(pool, spec->partition_key));

  pks = strchr(r->pk, ':');
  if (spec->sort_key) {
    RCB(finish, r->sk = iwpool_strdup2(pool, spec->sort_key));
    sks = strchr(r->sk, ':');
  }

  if (pks) {
    RCC(rc, finish, aws4dd_table_attribute_add(r, r->pk));
    *pks = '\0'; // Trim up to ssemicolon
  } else {
    RCC(rc, finish, _name_check(r->pk, AWS4DD_RESOURCE_ATTR));
  }
  if (sks) {
    RCC(rc, finish, aws4dd_table_attribute_add(r, r->sk));
    *sks = '\0';
  } else {
    RCC(rc, finish, _name_check(r->sk, AWS4DD_RESOURCE_ATTR));
  }

  *rpp = r;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_table_create_op_destroy(struct aws4dd_table_create **opp) {
  if (opp && *opp) {
    iwpool_destroy((*opp)->pool);
    *opp = 0;
  }
}

iwrc aws4dd_table_tag_add(struct aws4dd_table_create *op, const char *tag_name, const char *tag_value) {
  if (!op || !tag_value) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_check(tag_name, AWS4DD_RESOURCE_TAG));
  return iwn_pair_add_pool_all(op->pool, &op->tags, tag_name, -1, tag_value, -1);
}

static iwrc _table_attribute_add(IWPOOL *pool, struct iwn_pairs *attrs, const char *name, const char *type) {
  RCR(_name_check(name, AWS4DD_RESOURCE_ATTR));
  if (!pool || !attrs || !type) {
    return IW_ERROR_INVALID_ARGS;
  }
  return iwn_pair_add_pool_all(pool, attrs, name, -1, type, -1);
}

iwrc aws4dd_table_attribute_string_add(struct aws4dd_table_create *op, const char *name) {
  return _table_attribute_add(op->pool, &op->attrs, name, "S");
}

iwrc aws4dd_table_attribute_number_add(struct aws4dd_table_create *op, const char *name) {
  return _table_attribute_add(op->pool, &op->attrs, name, "N");
}

iwrc aws4dd_table_attribute_binary_add(struct aws4dd_table_create *op, const char *name) {
  return _table_attribute_add(op->pool, &op->attrs, name, "B");
}

static iwrc _table_attribute_spec_add(IWPOOL *pool, struct iwn_pairs *attrs, const char *spec) {
  char *name = strdup(spec);
  if (!name) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  char *colon = strchr(name, ':');
  if (!colon) {
    free(name);
    return IW_ERROR_INVALID_ARGS;
  }
  *colon = '\0';
  iwrc rc = 0;
  switch (*(colon + 1)) {
    case 'S':
      rc = _table_attribute_add(pool, attrs, name, "S");
      break;
    case 'N':
      rc = _table_attribute_add(pool, attrs, name, "N");
      break;
    case 'B':
      rc = _table_attribute_add(pool, attrs, name, "B");
      break;
    default:
      rc = IW_ERROR_INVALID_ARGS;
      break;
  }

  free(name);
  return rc;
}

iwrc aws4dd_table_attribute_add(struct aws4dd_table_create *op, const char *spec) {
  return _table_attribute_spec_add(op->pool, &op->attrs, spec);
}

iwrc aws4dd_table_index_add(struct aws4dd_table_create *op, const struct aws4dd_index_spec *spec) {
  if (!op || !spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_check(spec->name, AWS4DD_RESOURCE_INDEX));
  RCR(_name_check(spec->pk, AWS4DD_RESOURCE_ATTR));

  iwrc rc = 0;
  struct aws4dd_index_spec *ps = 0;
  if (!(spec->flags & AWS4DD_TABLE_INDEX_GLOBAL)) {
    for (int i = 0; i < sizeof(op->local_idx) / sizeof(op->local_idx[0]); ++i) {
      if (op->local_idx[i].name == 0) {
        ps = &op->local_idx[i];
        break;
      }
    }
  } else {
    for (int i = 0; i < sizeof(op->global_idx) / sizeof(op->global_idx[0]); ++i) {
      if (op->global_idx[i].name == 0) {
        ps = &op->global_idx[i];
        break;
      }
    }
  }
  if (ps == 0) {
    return AWS4DD_ERROR_MAX_IDX_LIMIT;
  }

  ps->flags = spec->flags;
  ps->read_capacity_units = spec->read_capacity_units;
  ps->write_capacity_units = spec->write_capacity_units;

  RCB(finish, ps->name = iwpool_strdup2(op->pool, spec->name));
  RCB(finish, ps->pk = iwpool_strdup2(op->pool, spec->pk));
  if (spec->sk) {
    RCB(finish, ps->sk = iwpool_strdup2(op->pool, spec->sk));
  }
  if (spec->proj) {
    int c = 0;
    for ( ; spec->proj[c]; ++c);
    RCB(finish, ps->proj = iwpool_alloc(sizeof(spec->proj[0]) * (c + 1), op->pool));
    ps->proj[c] = 0;
    while (c-- > 0) {
      RCB(finish, ps->proj[c] = iwpool_strdup2(op->pool, spec->proj[c]));
    }
  }

finish:
  return rc;
}

static iwrc _table_await_active(const struct aws4_request_spec *spec, const char *table_name) {
  int64_t time_sleep = 500;           // 0.5 sec initially
  int64_t time_wait = 5L * 60 * 1000; // 5min
  int max_failures = 10;

  while (time_wait > 0) {
    iwrc rc = 0;

    RCR(iwp_sleep(time_sleep));
    time_wait -= time_sleep;

    if (time_sleep < 10000) {
      time_sleep *= 2;
    }

    JBL_NODE n;
    struct aws4dd_response *resp = 0;

    RCC(rc, fail, aws4dd_table_describe(spec, table_name, &resp));
    RCC(rc, fail, jbn_at(resp->data, "/Table/TableStatus", &n));
    if (n->type != JBV_STR) {
      rc = IW_ERROR_UNEXPECTED_RESPONSE;
      goto fail;
    }

    if (strcmp(n->vptr, "ACTIVE") == 0) {
      aws4dd_response_destroy(&resp);
      return 0;
    }

    aws4dd_response_destroy(&resp);
    continue;

fail:
    iwlog_ecode_warn(rc, "AWS4 | Failed to get status of table: %s", table_name);
    aws4dd_response_destroy(&resp);
    if (--max_failures < 0) {
      return rc;
    }
  }

  iwlog_ecode_error(IW_ERROR_OPERATION_TIMEOUT, "AWS4 | Timeout waiting for ACTIVE status of '%s' table", table_name);
  return IW_ERROR_OPERATION_TIMEOUT;
}

iwrc aws4dd_table_create(
  const struct aws4_request_spec *spec,
  struct aws4dd_table_create     *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }

  *rpp = 0;
  iwrc rc = 0;

  if (!op->pk) {
    return AWS4DD_ERROR_NO_PARTITION_KEY;
  }

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), op->pool);
  if (!resp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  resp->pool = op->pool;
  iwpool_ref(resp->pool);

  struct iwn_pair *pair = op->attrs.first;
  for ( ; pair; pair = pair->next) {
    if (strcmp(pair->key, op->pk) == 0) {
      break;
    }
  }
  if (!pair) {
    rc = AWS4DD_ERROR_NO_PARTITION_KEY;
    goto finish;
  }

  JBL_NODE n, n2, n3, n4, n5;
  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->name, -1, 0, op->pool));
  RCC(rc, finish, jbn_add_item_arr(n, "AttributeDefinitions", &n2, op->pool));

  for (pair = op->attrs.first; pair; pair = pair->next) {
    RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "AttributeName", pair->key, pair->key_len, 0, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "AttributeType", pair->val, pair->val_len, 0, op->pool));
  }

  if (op->flags & AWS4DD_TABLE_BILLING_PROVISIONED) {
    RCC(rc, finish, jbn_add_item_str(n, "BillingMode", "PROVISIONED", IW_LLEN("PROVISIONED"), 0, op->pool));
  } else if (op->flags & AWS4DD_TABLE_BILLING_PER_REQUEST) {
    RCC(rc, finish, jbn_add_item_str(n, "BillingMode", "PAY_PER_REQUEST", IW_LLEN("PAY_PER_REQUEST"), 0, op->pool));
  }

  for (int t = 0; t < 2; ++t) {
    int imax = 0;
    struct aws4dd_index_spec *idx = 0;
    if (t == 0) {
      idx = op->global_idx;
      imax = sizeof(op->global_idx) / sizeof(op->global_idx[0]);
    } else {
      idx = op->local_idx;
      imax = sizeof(op->local_idx) / sizeof(op->local_idx[0]);
    }
    if (!idx->name) {
      continue;
    }

    if (t == 0) {
      RCC(rc, finish, jbn_add_item_arr(n, "GlobalSecondaryIndexes", &n2, op->pool));
    } else {
      RCC(rc, finish, jbn_add_item_arr(n, "LocalSecondaryIndexes", &n2, op->pool));
    }

    for (int i = 0; i < imax && idx->name; ++i, ++idx) {
      RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
      RCC(rc, finish, jbn_add_item_str(n3, "IndexName", idx->name, -1, 0, op->pool));
      RCC(rc, finish, jbn_add_item_arr(n3, "KeySchema", &n4, op->pool));
      RCC(rc, finish, jbn_add_item_obj(n4, 0, &n5, op->pool));
      RCC(rc, finish, jbn_add_item_str(n5, "AttributeName", idx->pk, -1, 0, op->pool));
      RCC(rc, finish, jbn_add_item_str(n5, "KeyType", "HASH", IW_LLEN("HASH"), 0, op->pool));

      if (idx->sk) {
        RCC(rc, finish, jbn_add_item_obj(n4, 0, &n5, op->pool));
        RCC(rc, finish, jbn_add_item_str(n5, "AttributeName", idx->sk, -1, 0, op->pool));
        RCC(rc, finish, jbn_add_item_str(n5, "KeyType", "RANGE", IW_LLEN("RANGE"), 0, op->pool));
      }

      if (idx->flags & AWS4DD_TABLE_INDEX_PROJECT_ALL) {
        RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
        RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "ALL", IW_LLEN("ALL"), 0, op->pool));
      } else if (idx->proj && idx->proj[0]) {
        RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
        RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "INCLUDE", IW_LLEN("INCLUDE"), 0, op->pool));
        RCC(rc, finish, jbn_add_item_arr(n4, "NonKeyAttributes", &n5, op->pool));
        for (int i = 0; idx->proj[i]; ++i) {
          RCC(rc, finish, jbn_add_item_str(n5, 0, idx->proj[i], -1, 0, op->pool));
        }
      } else {
        RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
        RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "KEYS_ONLY", IW_LLEN("KEYS_ONLY"), 0, op->pool));
      }

      if (t == 0 && idx->read_capacity_units > 0 && idx->write_capacity_units > 0) {
        RCC(rc, finish, jbn_add_item_obj(n3, "ProvisionedThroughput", &n4, op->pool));
        RCC(rc, finish, jbn_add_item_i64(n4, "ReadCapacityUnits", idx->read_capacity_units, 0, op->pool));
        RCC(rc, finish, jbn_add_item_i64(n4, "WriteCapacityUnits", idx->write_capacity_units, 0, op->pool));
      }
    }
  }

  RCC(rc, finish, jbn_add_item_arr(n, "KeySchema", &n2, op->pool));
  RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
  RCC(rc, finish, jbn_add_item_str(n3, "AttributeName", op->pk, -1, 0, op->pool));
  RCC(rc, finish, jbn_add_item_str(n3, "KeyType", "HASH", IW_LLEN("HASH"), 0, op->pool));

  if (op->sk) {
    RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "AttributeName", op->sk, -1, 0, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "KeyType", "RANGE", IW_LLEN("RANGE"), 0, op->pool));
  }

  if ((op->flags & AWS4DD_TABLE_BILLING_PROVISIONED) && op->read_capacity_units > 0 && op->write_capacity_units > 0) {
    RCC(rc, finish, jbn_add_item_obj(n, "ProvisionedThroughput", &n2, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n2, "ReadCapacityUnits", op->read_capacity_units, 0, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n2, "WriteCapacityUnits", op->write_capacity_units, 0, op->pool));
  }

  if (op->flags & AWS4DD_TABLE_STREAM_ALL) {
    RCC(rc, finish, jbn_add_item_obj(n, "StreamSpecification", &n2, op->pool));
    RCC(rc, finish, jbn_add_item_bool(n2, "StreamEnabled", !(op->flags & AWS4DD_TABLE_STREAM_DISABLED), 0, op->pool));
    if (op->flags & AWS4DD_TABLE_STREAM_KEYS_ONLY) {
      RCC(rc, finish, jbn_add_item_str(n2, "StreamViewType", "KEYS_ONLY", IW_LLEN("KEYS_ONLY"), 0, op->pool));
    } else if ((op->flags & (AWS4DD_TABLE_STREAM_NEW_IMAGE | AWS4DD_TABLE_STREAM_OLD_IMAGE)) ==
               (AWS4DD_TABLE_STREAM_NEW_IMAGE | AWS4DD_TABLE_STREAM_OLD_IMAGE)) {
      RCC(rc, finish,
          jbn_add_item_str(n2, "StreamViewType", "NEW_AND_OLD_IMAGES", IW_LLEN("NEW_AND_OLD_IMAGES"), 0, op->pool));
    } else if (op->flags & AWS4DD_TABLE_STREAM_NEW_IMAGE) {
      RCC(rc, finish, jbn_add_item_str(n2, "StreamViewType", "NEW_IMAGE", IW_LLEN("NEW_IMAGE"), 0, op->pool));
    } else if (op->flags & AWS4DD_TABLE_STREAM_OLD_IMAGE) {
      RCC(rc, finish, jbn_add_item_str(n2, "StreamViewType", "OLD_IMAGE", IW_LLEN("OLD_IMAGE"), 0, op->pool));
    }
  }

  if (op->flags & (AWS4DD_TABLE_CLASS_STANDARD | AWS4DD_TABLE_CLASS_INFREQUENT)) {
    if (op->flags & AWS4DD_TABLE_CLASS_STANDARD) {
      RCC(rc, finish, jbn_add_item_str(n, "TableClass", "STANDARD", IW_LLEN("STANDARD"), 0, op->pool));
    } else if (op->flags & AWS4DD_TABLE_CLASS_INFREQUENT) {
      RCC(rc, finish, jbn_add_item_str(n, "TableClass",
                                       "STANDARD_INFREQUENT_ACCESS", IW_LLEN("STANDARD_INFREQUENT_ACCESS"), 0,
                                       op->pool));
    }
  }

  if (op->tags.first) {
    RCC(rc, finish, jbn_add_item_arr(n, "Tags", &n2, op->pool));
    for (pair = op->tags.first; pair; pair = pair->next) {
      RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
      RCC(rc, finish, jbn_add_item_str(n3, "Key", pair->key, pair->key_len, 0, op->pool));
      RCC(rc, finish, jbn_add_item_str(n3, "Value", pair->val, pair->val_len, 0, op->pool));
    }
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.CreateTable"
  }, op->pool, &resp->data, &resp->status_code));


  if (op->flags & AWS4DD_TABLE_DONT_AWAIT_CREATION) {
    *rpp = resp;
  } else {
    RCC(rc, finish, _table_await_active(spec, op->name));
    *rpp = resp;
  }

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// UpdateTable
//

struct aws4dd_table_update {
  IWPOOL     *pool;
  const char *name;                    ///< Table name.
  struct iwn_pairs attrs;              ///< UpdateTable create attributes.
  long read_capacity_units;            ///< UpdateTable read capacity units.
  long write_capacity_units;           ///< UpdateTable write capacity units.
  struct aws4dd_index_spec idx_create; ///< Index to create. Only one allowed.
  const char *idx_delete;              ///< Index name to delete
  IWULIST     idx_mod_list;            ///< Indexes to modify (struct aws4dd_index_spec)
  unsigned    flags;
};

iwrc aws4dd_table_update_op(
  struct aws4dd_table_update           **rpp,
  const struct aws4dd_table_update_spec *spec
  ) {
  if (!rpp || !spec || !spec->name) {
    return IW_ERROR_INVALID_ARGS;
  }

  *rpp = 0;
  RCR(_name_check(spec->name, AWS4DD_RESOURCE_TABLE));

  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_table_update *r;
  RCB(finish, r = iwpool_calloc(sizeof(*r), pool));

  r->pool = pool;
  r->flags = spec->flags;
  r->read_capacity_units = spec->read_capacity_units;
  r->write_capacity_units = spec->write_capacity_units;

  RCC(rc, finish, iwulist_init(&r->idx_mod_list, 1, sizeof(struct aws4dd_index_spec)));
  RCB(finish, r->name = iwpool_strdup2(pool, spec->name));

  *rpp = r;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_table_update_op_destroy(struct aws4dd_table_update **opp) {
  if (opp && *opp) {
    struct aws4dd_table_update *op = *opp;
    iwulist_destroy_keep(&op->idx_mod_list);
    iwpool_destroy(op->pool);
    *opp = 0;
  }
}

iwrc aws4dd_table_update_attribute_add(struct aws4dd_table_update *op, const char *spec) {
  return _table_attribute_spec_add(op->pool, &op->attrs, spec);
}

iwrc aws4dd_table_update_attribute_string_add(struct aws4dd_table_update *op, const char *name) {
  return _table_attribute_add(op->pool, &op->attrs, name, "S");
}

iwrc aws4dd_table_update_attribute_number_add(struct aws4dd_table_update *op, const char *name) {
  return _table_attribute_add(op->pool, &op->attrs, name, "N");
}

iwrc aws4dd_table_update_attribute_binary_add(struct aws4dd_table_update *op, const char *name) {
  return _table_attribute_add(op->pool, &op->attrs, name, "B");
}

iwrc aws4dd_table_update_index_create(struct aws4dd_table_update *op, const struct aws4dd_index_spec *spec) {
  if (!op || !spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_check(spec->name, AWS4DD_RESOURCE_INDEX));
  RCR(_name_check(spec->pk, AWS4DD_RESOURCE_ATTR));

  iwrc rc = 0;
  struct aws4dd_index_spec *ps = &op->idx_create;

  ps->flags = spec->flags;
  ps->read_capacity_units = spec->read_capacity_units;
  ps->write_capacity_units = spec->write_capacity_units;

  RCB(finish, ps->name = iwpool_strdup2(op->pool, spec->name));
  RCB(finish, ps->pk = iwpool_strdup2(op->pool, spec->pk));
  if (spec->sk) {
    RCB(finish, ps->sk = iwpool_strdup2(op->pool, spec->sk));
  }

  if (spec->proj) {
    int c = 0;
    for ( ; spec->proj[c]; ++c);
    RCB(finish, ps->proj = iwpool_alloc(sizeof(spec->proj[0]) * (c + 1), op->pool));
    ps->proj[c] = 0;
    while (c-- > 0) {
      RCB(finish, ps->proj[c] = iwpool_strdup2(op->pool, spec->proj[c]));
    }
  }

finish:
  return rc;
}

iwrc aws4dd_table_update_index_delete(struct aws4dd_table_update *op, const char *name) {
  if (!op || !name) {
    return IW_ERROR_INVALID_ARGS;
  }
  if (op->idx_delete) {
    return IW_ERROR_INVALID_STATE;
  }
  op->idx_delete = iwpool_strdup2(op->pool, name);
  if (!op->idx_delete) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  return 0;
}

iwrc aws4dd_table_update(
  const struct aws4_request_spec *spec,
  struct aws4dd_table_update     *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;
  iwrc rc = 0;

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), op->pool);
  if (!resp) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  resp->pool = op->pool;
  iwpool_ref(resp->pool);

  JBL_NODE n, n2, n22, n3, n4, n5;
  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->name, -1, 0, op->pool));

  if (op->flags & (AWS4DD_TABLE_CLASS_STANDARD | AWS4DD_TABLE_CLASS_INFREQUENT)) {
    if (op->flags & AWS4DD_TABLE_CLASS_STANDARD) {
      RCC(rc, finish, jbn_add_item_str(n, "TableClass", "STANDARD", IW_LLEN("STANDARD"), 0, op->pool));
    } else if (op->flags & AWS4DD_TABLE_CLASS_INFREQUENT) {
      RCC(rc, finish, jbn_add_item_str(n, "TableClass",
                                       "STANDARD_INFREQUENT_ACCESS", IW_LLEN("STANDARD_INFREQUENT_ACCESS"), 0,
                                       op->pool));
    }
  }

  if (op->flags & AWS4DD_TABLE_BILLING_PROVISIONED) {
    RCC(rc, finish, jbn_add_item_str(n, "BillingMode", "PROVISIONED", IW_LLEN("PROVISIONED"), 0, op->pool));
  } else if (op->flags & AWS4DD_TABLE_BILLING_PER_REQUEST) {
    RCC(rc, finish, jbn_add_item_str(n, "BillingMode", "PAY_PER_REQUEST", IW_LLEN("PAY_PER_REQUEST"), 0, op->pool));
  }

  if (op->read_capacity_units > 0 && op->write_capacity_units > 0) {
    RCC(rc, finish, jbn_add_item_obj(n, "ProvisionedThroughput", &n2, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n2, "ReadCapacityUnits", op->read_capacity_units, 0, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n2, "WriteCapacityUnits", op->write_capacity_units, 0, op->pool));
  }

  if (op->flags & AWS4DD_TABLE_STREAM_ALL) {
    RCC(rc, finish, jbn_add_item_obj(n, "StreamSpecification", &n2, op->pool));
    RCC(rc, finish, jbn_add_item_bool(n2, "StreamEnabled", !(op->flags & AWS4DD_TABLE_STREAM_DISABLED), 0, op->pool));
    if (op->flags & AWS4DD_TABLE_STREAM_KEYS_ONLY) {
      RCC(rc, finish, jbn_add_item_str(n2, "StreamViewType", "KEYS_ONLY", IW_LLEN("KEYS_ONLY"), 0, op->pool));
    } else if ((op->flags & (AWS4DD_TABLE_STREAM_NEW_IMAGE | AWS4DD_TABLE_STREAM_OLD_IMAGE)) ==
               (AWS4DD_TABLE_STREAM_NEW_IMAGE | AWS4DD_TABLE_STREAM_OLD_IMAGE)) {
      RCC(rc, finish,
          jbn_add_item_str(n2, "StreamViewType", "NEW_AND_OLD_IMAGES", IW_LLEN("NEW_AND_OLD_IMAGES"), 0, op->pool));
    } else if (op->flags & AWS4DD_TABLE_STREAM_NEW_IMAGE) {
      RCC(rc, finish, jbn_add_item_str(n2, "StreamViewType", "NEW_IMAGE", IW_LLEN("NEW_IMAGE"), 0, op->pool));
    } else if (op->flags & AWS4DD_TABLE_STREAM_OLD_IMAGE) {
      RCC(rc, finish, jbn_add_item_str(n2, "StreamViewType", "OLD_IMAGE", IW_LLEN("OLD_IMAGE"), 0, op->pool));
    }
  }

  if (op->attrs.first) {
    RCC(rc, finish, jbn_add_item_arr(n, "AttributeDefinitions", &n2, op->pool));
    for (struct iwn_pair *pair = op->attrs.first; pair; pair = pair->next) {
      RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
      RCC(rc, finish, jbn_add_item_str(n3, "AttributeName", pair->key, pair->key_len, 0, op->pool));
      RCC(rc, finish, jbn_add_item_str(n3, "AttributeType", pair->val, pair->val_len, 0, op->pool));
    }
  }

  if (op->idx_create.name || op->idx_delete || iwulist_length(&op->idx_mod_list)) {
    RCC(rc, finish, jbn_add_item_arr(n, "GlobalSecondaryIndexUpdates", &n22, op->pool));
  }

  if (op->idx_create.name) {
    RCC(rc, finish, jbn_add_item_obj(n22, 0, &n2, op->pool));

    struct aws4dd_index_spec *idx = &op->idx_create;
    RCC(rc, finish, jbn_add_item_obj(n2, "Create", &n3, op->pool));

    RCC(rc, finish, jbn_add_item_str(n3, "IndexName", idx->name, -1, 0, op->pool));
    RCC(rc, finish, jbn_add_item_arr(n3, "KeySchema", &n4, op->pool));
    RCC(rc, finish, jbn_add_item_obj(n4, 0, &n5, op->pool));
    RCC(rc, finish, jbn_add_item_str(n5, "AttributeName", idx->pk, -1, 0, op->pool));
    RCC(rc, finish, jbn_add_item_str(n5, "KeyType", "HASH", IW_LLEN("HASH"), 0, op->pool));

    if (idx->sk) {
      RCC(rc, finish, jbn_add_item_obj(n4, 0, &n5, op->pool));
      RCC(rc, finish, jbn_add_item_str(n5, "AttributeName", idx->sk, -1, 0, op->pool));
      RCC(rc, finish, jbn_add_item_str(n5, "KeyType", "RANGE", IW_LLEN("RANGE"), 0, op->pool));
    }
    if (idx->flags & AWS4DD_TABLE_INDEX_PROJECT_ALL) {
      RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
      RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "ALL", IW_LLEN("ALL"), 0, op->pool));
    } else if (idx->proj && idx->proj[0]) {
      RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
      RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "INCLUDE", IW_LLEN("INCLUDE"), 0, op->pool));
      RCC(rc, finish, jbn_add_item_arr(n4, "NonKeyAttributes", &n5, op->pool));
      for (int i = 0; idx->proj[i]; ++i) {
        RCC(rc, finish, jbn_add_item_str(n5, 0, idx->proj[i], -1, 0, op->pool));
      }
    } else {
      RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
      RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "KEYS_ONLY", IW_LLEN("KEYS_ONLY"), 0, op->pool));
    }
    if (idx->read_capacity_units > 0 && idx->write_capacity_units > 0) {
      RCC(rc, finish, jbn_add_item_obj(n3, "ProvisionedThroughput", &n4, op->pool));
      RCC(rc, finish, jbn_add_item_i64(n4, "ReadCapacityUnits", idx->read_capacity_units, 0, op->pool));
      RCC(rc, finish, jbn_add_item_i64(n4, "WriteCapacityUnits", idx->write_capacity_units, 0, op->pool));
    }
  }

  if (op->idx_delete) {
    RCC(rc, finish, jbn_add_item_obj(n22, 0, &n2, op->pool));
    RCC(rc, finish, jbn_add_item_obj(n2, "Delete", &n3, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "IndexName", op->idx_delete, -1, 0, op->pool));
  }

  for (size_t i = 0, l = iwulist_length(&op->idx_mod_list); i < l; ++i) {
    struct aws4dd_index_spec *idx = iwulist_at2(&op->idx_mod_list, i);
    RCC(rc, finish, jbn_add_item_obj(n22, 0, &n2, op->pool));
    RCC(rc, finish, jbn_add_item_obj(n2, "Update", &n3, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "IndexName", idx->name, -1, 0, op->pool));
    RCC(rc, finish, jbn_add_item_obj(n3, "ProvisionedThroughput", &n4, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n4, "ReadCapacityUnits", idx->read_capacity_units, 0, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n4, "WriteCapacityUnits", idx->write_capacity_units, 0, op->pool));
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.UpdateTable",
  }, op->pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

iwrc aws4dd_table_update_index_update(
  struct aws4dd_table_update *op,
  const char                 *name,
  long                        read_capacity_units,
  long                        write_capacity_units
  ) {
  if (!op || !name || read_capacity_units < 1 || write_capacity_units < 1) {
    return IW_ERROR_INVALID_ARGS;
  }
  struct aws4dd_index_spec ispec = {
    .name                 = iwpool_strdup2(op->pool, name),
    .read_capacity_units  = read_capacity_units,
    .write_capacity_units = write_capacity_units,
  };
  if (!ispec.name) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCR(iwulist_push(&op->idx_mod_list, &ispec));
  return 0;
}

//
// DescribeTable
//

iwrc aws4dd_table_describe(const struct aws4_request_spec *spec, const char *name, struct aws4dd_response **rpp) {
  if (!spec || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;
  RCR(_name_check(name, AWS4DD_RESOURCE_TABLE));
  iwrc rc = 0;

  IWPOOL *pool = iwpool_create_empty();
  RCB(finish, pool);

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);
  resp->pool = pool;

  JBL_NODE n;
  RCC(rc, finish, jbn_from_json("{}", &n, pool));
  RCC(rc, finish, jbn_add_item_str(n, "TableName", name, -1, 0, pool));
  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.DescribeTable"
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

//
// DeleteTable
//

iwrc aws4dd_table_delete(const struct aws4_request_spec *spec, const char *name, struct aws4dd_response **rpp) {
  if (!spec || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;
  RCR(_name_check(name, AWS4DD_RESOURCE_TABLE));
  iwrc rc = 0;

  IWPOOL *pool = iwpool_create_empty();
  RCB(finish, pool);

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);
  resp->pool = pool;

  JBL_NODE n;
  RCC(rc, finish, jbn_from_json("{}", &n, pool));
  RCC(rc, finish, jbn_add_item_str(n, "TableName", name, -1, 0, pool));
  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.DeleteTable"
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

//
// TagResource
//

iwrc aws4dd_tag_resource(
  const struct aws4_request_spec *spec,
  const char                     *resource_arn,
  const char                     *tag_pairs[]
  ) {
  if (!spec || !resource_arn || !tag_pairs) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  RCB(finish, pool);

  JBL_NODE n, n2;
  RCC(rc, finish, jbn_from_json("{}", &n, pool));
  RCC(rc, finish, jbn_add_item_str(n, "ResourceArn", resource_arn, -1, 0, pool));

  RCC(rc, finish, jbn_add_item_obj(n, "Tags", &n2, pool));
  for (int i = 0; tag_pairs[i]; ++i) {
    if (i % 2) {
      RCC(rc, finish, jbn_add_item_str(n2, tag_pairs[i - 1], tag_pairs[i], -1, 0, pool));
    }
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.TagResource"
  }, pool, &n2, 0));

finish:
  iwpool_destroy(pool);
  return rc;
}

//
// UntagResource
//

iwrc aws4dd_untag_resource(
  const struct aws4_request_spec *spec,
  const char                     *resource_arn,
  const char                     *tag_keys[]
  ) {
  if (!spec || !resource_arn || !tag_keys) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  RCB(finish, pool);

  JBL_NODE n, n2;
  RCC(rc, finish, jbn_from_json("{}", &n, pool));
  RCC(rc, finish, jbn_add_item_str(n, "ResourceArn", resource_arn, -1, 0, pool));

  RCC(rc, finish, jbn_add_item_arr(n, "TagKeys", &n2, pool));
  for (int i = 0; tag_keys[i]; ++i) {
    RCC(rc, finish, jbn_add_item_str(n2, 0, tag_keys[i], -1, 0, pool));
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.UntagResource"
  }, pool, &n2, 0));


finish:
  iwpool_destroy(pool);
  return rc;
}

//
// ListTables
//

iwrc aws4dd_tables_list(
  const struct aws4_request_spec *spec,
  const char                     *exclusive_start_table_name,
  uint32_t                        limit,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  if (exclusive_start_table_name) {
    RCR(_name_check(exclusive_start_table_name, AWS4DD_RESOURCE_TABLE));
  }

  IWPOOL *pool = iwpool_create_empty();
  RCB(finish, pool);

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);
  resp->pool = pool;

  JBL_NODE n;
  RCC(rc, finish, jbn_from_json("{}", &n, pool));
  if (exclusive_start_table_name) {
    RCC(rc, finish, jbn_add_item_str(n, "ExclusiveStartTableName", exclusive_start_table_name, -1, 0, pool));
  }
  if (limit) {
    RCC(rc, finish, jbn_add_item_i64(n, "Limit", limit, 0, pool));
  }
  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.ListTables"
  }, pool, &resp->data, 0));

  *rpp = resp;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

//
// PutItem
//

typedef enum {
  AWS4DD_ITEM_VALUE_BOOL = 1,
  AWS4DD_ITEM_VALUE_BS,
  AWS4DD_ITEM_VALUE_L,
  AWS4DD_ITEM_VALUE_M,
  AWS4DD_ITEM_VALUE_N,
  AWS4DD_ITEM_VALUE_NS,
  AWS4DD_ITEM_VALUE_NULL,
  AWS4DD_ITEM_VALUE_S,
  AWS4DD_ITEM_VALUE_SS,
} item_value_type_e;

struct aws4dd_item_put {
  IWPOOL *pool;
  struct aws4dd_item_put_spec spec;
  JBL_NODE n;                // JSON spec
};

void aws4dd_item_put_op_destroy(struct aws4dd_item_put **opp) {
  if (opp && *opp) {
    iwpool_destroy((*opp)->pool);
    *opp = 0;
  }
}

iwrc aws4dd_item_put_op(struct aws4dd_item_put **opp, const struct aws4dd_item_put_spec *spec) {
  iwrc rc = 0;
  if (!opp || !spec || !spec->table_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_item_put *op;
  RCB(finish, op = iwpool_calloc(sizeof(*op), pool));
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(op->spec));
  RCB(finish, op->spec.table_name = iwpool_strdup2(pool, spec->table_name));
  if (spec->condition_expression) {
    RCB(finish, op->spec.condition_expression = iwpool_strdup2(pool, spec->condition_expression));
  }

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));
  *opp = op;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

static iwrc _item_val(IWPOOL *pool, const char *key, const char **vals, JBL_NODE *out) {
  iwrc rc = 0;
  *out = 0;
  JBL_NODE n = 0;

  if (strcmp(key, "NULL") == 0 || strcmp(key, "BOOL") == 0) {
    bool vbool = strcmp("true", *vals) == 0;
    RCB(finish, n = iwpool_calloc(sizeof(*n), pool));
    RCB(finish, n->vptr = iwpool_strdup2(pool, *vals));
    n->type = JBV_BOOL;
    n->vbool = vbool;
  } else if (key[0] == 'L' || (strlen(key) == 2 && key[1] == 'S')) {
    // Process vals as array
    RCC(rc, finish, jbn_from_json("[]", &n, pool));
    for (const char *v = *vals; v; ++vals, v = *vals) {
      RCC(rc, finish, jbn_add_item_str(n, 0, v, -1, 0, pool));
    }
  } else {
    // Process vals as simple string
    RCB(finish, n = iwpool_calloc(sizeof(*n), pool));
    RCB(finish, n->vptr = iwpool_strdup2(pool, *vals));
    n->type = JBV_STR;
    n->vsize = (int) strlen(n->vptr);
  }

  RCB(finish, n->key = iwpool_strdup2(pool, key));
  n->klidx = (int) strlen(n->key);

  *out = n;

finish:
  return rc;
}

static iwrc _item_put(
  IWPOOL *pool, JBL_NODE target, const char *path, const char *key,
  const char **vals
  ) {
  iwrc rc = 0;
  JBL_NODE n;
  JBL_PATCH p = { .path = path, .op = JBP_ADD_CREATE };

  RCC(rc, finish, _item_val(pool, key, vals, &n));
  RCC(rc, finish, jbn_from_json("{}", &p.vnode, pool));
  jbn_add_item(p.vnode, n);

  RCC(rc, finish, jbn_patch(target, &p, 1, pool));

finish:
  return rc;
}

iwrc aws4dd_item_put_array(
  struct aws4dd_item_put *op,
  const char             *path,
  const char             *key,
  const char            **vals
  ) {
  if (!op || !path || !key || !vals) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _item_put(op->pool, op->n, path, key, vals);
}

iwrc aws4dd_item_put_value(
  struct aws4dd_item_put *op,
  const char             *path,
  const char             *key,
  const char             *val
  ) {
  return aws4dd_item_put_array(op, path, key, (const char*[]) { val, 0 });
}

iwrc aws4dd_item_put_expression_attr_name(struct aws4dd_item_put *op, const char *key, const char *val) {
  iwrc rc = 0;
  JBL_NODE n, n2;

  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_obj(n, "ExpressionAttributeNames", &n2, op->pool));
  RCC(rc, finish, jbn_add_item_str(n2, key, val, -1, 0, op->pool));
  RCC(rc, finish, jbn_patch_auto(op->n, n, op->pool));

finish:
  return rc;
}

iwrc aws4dd_item_put(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_put         *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;
  iwrc rc = 0;

  IWPOOL *pool = op->pool;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);

  JBL_NODE n = op->n;
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->spec.table_name, -1, 0, pool));

  if (op->spec.condition_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "ConditionExpression", op->spec.condition_expression, -1, 0, pool));
  }

  switch (op->spec.ret.values) {
    case AWS4DD_RETURN_VALUES_ALL_OLD:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnValues", "ALL_OLD", IW_LLEN("ALL_OLD"), 0, pool));
      break;
    case AWS4DD_RETURN_VALUES_NONE:
    default:
      break;
  }

  switch (op->spec.ret.metrics) {
    case AWS4DD_RETURN_COLLECTION_SIZE:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnItemCollectionMetrics", "SIZE", IW_LLEN("SIZE"), 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.ret.capacity) {
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", IW_LLEN("TOTAL"), 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", IW_LLEN("INDEXES"), 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_NONE:
      break;
  }


  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.PutItem"
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// GetItem
//

struct aws4dd_item_get {
  IWPOOL *pool;
  struct aws4dd_item_get_spec spec;
  JBL_NODE n; // JSON spec
};

iwrc aws4dd_item_get_op(struct aws4dd_item_get **opp, const struct aws4dd_item_get_spec *spec) {
  iwrc rc = 0;
  if (!opp || !spec || !spec->table_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_item_get *op = iwpool_calloc(sizeof(*op), pool);
  RCB(finish, op);
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(*spec));
  RCB(finish, op->spec.table_name = iwpool_strdup2(pool, spec->table_name));
  RCB(finish, op->spec.projection_expression = iwpool_strdup2(pool, spec->projection_expression));

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));

  *opp = op;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_item_get_op_destroy(struct aws4dd_item_get **opp) {
  if (opp && *opp) {
    struct aws4dd_item_get *op = *opp;
    *opp = 0;
    iwpool_destroy(op->pool);
  }
}

iwrc aws4dd_item_get_expression_attr_name(struct aws4dd_item_get *op, const char *key, const char *value) {
  iwrc rc = 0;
  JBL_NODE n, n2;

  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_obj(n, "ExpressionAttributeNames", &n2, op->pool));
  RCC(rc, finish, jbn_add_item_str(n2, key, value, -1, 0, op->pool));
  RCC(rc, finish, jbn_patch_auto(op->n, n, op->pool));

finish:
  return rc;
}

iwrc aws4dd_item_get_key_array(
  struct aws4dd_item_get *op,
  const char             *path,
  const char             *key,
  const char            **values
  ) {
  if (!op || !path || !key || !values) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _item_put(op->pool, op->n, path, key, values);
}

iwrc aws4dd_item_get_key_value(
  struct aws4dd_item_get *op,
  const char             *path,
  const char             *key,
  const char             *value
  ) {
  return aws4dd_item_get_key_array(op, path, key, (const char*[]) { value, 0 });
}

iwrc aws4dd_item_get(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_get         *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;
  iwrc rc = 0;

  IWPOOL *pool = op->pool;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);

  JBL_NODE n = op->n;
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->spec.table_name, -1, 0, pool));

  if (op->spec.projection_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "ProjectionExpression", op->spec.projection_expression, -1, 0, pool));
  }

  RCC(rc, finish, jbn_add_item_bool(n, "ConsistentRead", op->spec.consistent_read, 0, pool));

  switch (op->spec.return_consumed_capacity) {
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", IW_LLEN("TOTAL"), 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", IW_LLEN("INDEXES"), 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_NONE:
      break;
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.GetItem"
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// Query
//

struct aws4dd_query {
  IWPOOL *pool;
  struct aws4dd_query_spec spec;
  JBL_NODE n; // JSON spec
};

iwrc aws4dd_query_op(struct aws4dd_query **opp, const struct aws4dd_query_spec *spec) {
  iwrc rc = 0;
  if (!opp || !spec || !spec->table_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  *opp = 0;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_query *op = iwpool_calloc(sizeof(*op), pool);
  RCB(finish, op);
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(*spec));
  RCB(finish, op->spec.table_name = iwpool_strdup2(pool, spec->table_name));
  if (spec->index_name) {
    RCB(finish, op->spec.index_name = iwpool_strdup2(pool, spec->index_name));
  }
  if (spec->projection_expression) {
    RCB(finish, op->spec.projection_expression = iwpool_strdup2(pool, spec->projection_expression));
  }
  if (spec->filter_expression) {
    RCB(finish, op->spec.filter_expression = iwpool_strdup2(pool, spec->filter_expression));
  }
  if (spec->key_condition_expression) {
    RCB(finish, op->spec.key_condition_expression = iwpool_strdup2(pool, spec->key_condition_expression));
  }

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));
  *opp = op;

finish:
  if (rc) {
    aws4dd_query_op_destroy(&op);
  }
  return rc;
}

void aws4dd_query_op_destroy(struct aws4dd_query **opp) {
  if (opp && *opp) {
    struct aws4dd_query *op = *opp;
    *opp = 0;
    iwpool_destroy(op->pool);
  }
}

iwrc aws4dd_query_expression_attr_name(
  struct aws4dd_query *op,
  const char          *key,
  const char          *value
  ) {
  if (!op || !key || !value) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  JBL_NODE n, n2;

  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_obj(n, "ExpressionAttributeNames", &n2, op->pool));
  RCC(rc, finish, jbn_add_item_str(n2, key, value, -1, 0, op->pool));
  RCC(rc, finish, jbn_patch_auto(op->n, n, op->pool));

finish:
  return rc;
}

iwrc aws4dd_query_array(struct aws4dd_query *op, const char *path, const char *key, const char **values) {
  if (!op || !path || !key || !values) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _item_put(op->pool, op->n, path, key, values);
}

iwrc aws4dd_query_value(struct aws4dd_query *op, const char *path, const char *key, const char *value) {
  return aws4dd_query_array(op, path, key, (const char*[]) { value, 0 });
}

iwrc aws4dd_query_exclusive_start_key(struct aws4dd_query *op, JBL_NODE key) {
  if (!op || !key) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  JBL_NODE n;
  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_copy_path(key, "/", n, "/ExclusiveStartKey", true, false, op->pool));
  rc = jbn_patch_auto(op->n, n, op->pool);

finish:
  return rc;
}

iwrc aws4dd_query(
  const struct aws4_request_spec *spec,
  struct aws4dd_query *op, struct aws4dd_response **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;

  iwrc rc = 0;
  IWPOOL *pool = op->pool;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);

  JBL_NODE n = op->n;
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->spec.table_name, -1, 0, pool));

  if (op->spec.index_name) {
    RCC(rc, finish, jbn_add_item_str(n, "IndexName", op->spec.index_name, -1, 0, pool));
  }

  if (op->spec.projection_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "ProjectionExpression", op->spec.projection_expression, -1, 0, pool));
  }

  if (op->spec.filter_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "FilterExpression", op->spec.filter_expression, -1, 0, pool));
  }

  if (op->spec.key_condition_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "KeyConditionExpression", op->spec.key_condition_expression, -1, 0, pool));
  }

  if (op->spec.limit) {
    RCC(rc, finish, jbn_add_item_i64(n, "Limit", op->spec.limit, 0, pool));
  }

  if (op->spec.consistent_read) {
    RCC(rc, finish, jbn_add_item_bool(n, "ConsistentRead", op->spec.consistent_read, 0, pool));
  }

  if (op->spec.scan_index_forward) {
    RCC(rc, finish, jbn_add_item_bool(n, "ScanIndexForward", op->spec.scan_index_forward, 0, pool));
  }

  switch (op->spec.select) {
    case AWS4DD_SELECT_ALL_ATTRIBUTES:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "ALL_ATTRIBUTES", -1, 0, pool));
      break;
    case AWS4DD_SELECT_ALL_PROJECTED_ATTRIBUTES:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "ALL_PROJECTED_ATTRIBUTES", -1, 0, pool));
      break;
    case AWS4DD_SELECT_SPECIFIC_ATTRIBUTES:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "SPECIFIC_ATTRIBUTES", -1, 0, pool));
      break;
    case AWS4DD_SELECT_COUNT:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "COUNT", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.return_consumed_capacity) {
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_NONE:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "NONE", -1, 0, pool));
      break;
    default:
      break;
  }

  if (op->spec.exclusive_start_key_json && *op->spec.exclusive_start_key_json != '\0') {
    JBL_NODE n;
    RCC(rc, finish, jbn_from_json(op->spec.exclusive_start_key_json, &n, pool));
    RCC(rc, finish, aws4dd_query_exclusive_start_key(op, n));
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.Query",
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// Scan
//

struct aws4dd_scan {
  IWPOOL  *pool;
  JBL_NODE n;
  struct aws4dd_scan_spec spec;
};

iwrc aws4dd_scan_op(struct aws4dd_scan **opp, const struct aws4dd_scan_spec *spec) {
  iwrc rc = 0;
  if (!opp || !spec || !spec->table_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  *opp = 0;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_scan *op = iwpool_calloc(sizeof(*op), pool);
  RCB(finish, op);
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(*spec));
  RCB(finish, op->spec.table_name = iwpool_strdup2(pool, spec->table_name));
  if (spec->index_name) {
    RCB(finish, op->spec.index_name = iwpool_strdup2(pool, spec->index_name));
  }
  if (spec->projection_expression) {
    RCB(finish, op->spec.projection_expression = iwpool_strdup2(pool, spec->projection_expression));
  }
  if (spec->filter_expression) {
    RCB(finish, op->spec.filter_expression = iwpool_strdup2(pool, spec->filter_expression));
  }

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));
  *opp = op;

finish:
  if (rc) {
    aws4dd_scan_op_destroy(&op);
  }
  return rc;
}

void aws4dd_scan_op_destroy(struct aws4dd_scan **opp) {
  if (opp && *opp) {
    struct aws4dd_scan *op = *opp;
    *opp = 0;
    iwpool_destroy(op->pool);
  }
}

iwrc aws4dd_scan_expression_attr_name(struct aws4dd_scan *op, const char *key, const char *value) {
  if (!op || !key || !value) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  JBL_NODE n, n2;

  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_obj(n, "ExpressionAttributeNames", &n2, op->pool));
  RCC(rc, finish, jbn_add_item_str(n2, key, value, -1, 0, op->pool));
  RCC(rc, finish, jbn_patch_auto(op->n, n, op->pool));

finish:
  return rc;
}

iwrc aws4dd_scan_array(struct aws4dd_scan *op, const char *path, const char *key, const char **values) {
  if (!op || !path || !key || !values) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _item_put(op->pool, op->n, path, key, values);
}

iwrc aws4dd_scan_value(struct aws4dd_scan *op, const char *path, const char *key, const char *val) {
  return aws4dd_scan_array(op, path, key, (const char*[]) {});
}

iwrc aws4dd_scan(const struct aws4_request_spec *spec, struct aws4dd_scan *op, struct aws4dd_response **rpp) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;

  iwrc rc = 0;
  IWPOOL *pool = op->pool;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);

  JBL_NODE n = op->n;
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->spec.table_name, -1, 0, pool));

  if (op->spec.index_name) {
    RCC(rc, finish, jbn_add_item_str(n, "IndexName", op->spec.index_name, -1, 0, pool));
  }

  if (op->spec.projection_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "ProjectionExpression", op->spec.projection_expression, -1, 0, pool));
  }

  if (op->spec.filter_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "FilterExpression", op->spec.filter_expression, -1, 0, pool));
  }

  if (op->spec.limit) {
    RCC(rc, finish, jbn_add_item_i64(n, "Limit", op->spec.limit, 0, pool));
  }

  if (op->spec.segments_total) {
    RCC(rc, finish, jbn_add_item_i64(n, "TotalSegments", op->spec.segments_total, 0, pool));
    RCC(rc, finish, jbn_add_item_i64(n, "Segment", op->spec.segment, 0, pool));
  }

  if (op->spec.consistent_read) {
    RCC(rc, finish, jbn_add_item_bool(n, "ConsistentRead", true, 0, pool));
  }

  switch (op->spec.select) {
    case AWS4DD_SELECT_ALL_ATTRIBUTES:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "ALL_ATTRIBUTES", -1, 0, pool));
      break;
    case AWS4DD_SELECT_ALL_PROJECTED_ATTRIBUTES:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "ALL_PROJECTED_ATTRIBUTES", -1, 0, pool));
      break;
    case AWS4DD_SELECT_SPECIFIC_ATTRIBUTES:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "SPECIFIC_ATTRIBUTES", -1, 0, pool));
      break;
    case AWS4DD_SELECT_COUNT:
      RCC(rc, finish, jbn_add_item_str(n, "Select", "COUNT", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.return_consumed_capacity) {
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_NONE:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "NONE", -1, 0, pool));
      break;
    default:
      break;
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.Scan",
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// UpdateItem
//

struct aws4dd_item_update {
  IWPOOL *pool;
  struct aws4dd_item_update_spec spec;
  JBL_NODE n;
};

iwrc aws4dd_item_update_op(struct aws4dd_item_update **opp, const struct aws4dd_item_update_spec *spec) {
  iwrc rc = 0;
  if (!opp || !spec || !spec->table_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_item_update *op;
  RCB(finish, op = iwpool_calloc(sizeof(*op), pool));
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(*spec));
  RCB(finish, op->spec.table_name = iwpool_strdup2(pool, spec->table_name));

  if (spec->condition_expression) {
    RCB(finish, op->spec.condition_expression = iwpool_strdup2(pool, spec->condition_expression));
  }

  if (spec->update_expression) {
    RCB(finish, op->spec.update_expression = iwpool_strdup2(pool, spec->update_expression));
  }

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));

  *opp = op;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_item_update_op_destroy(struct aws4dd_item_update **opp) {
  if (opp && *opp) {
    iwpool_destroy((*opp)->pool);
    *opp = 0;
  }
}

iwrc aws4dd_item_update_array(
  struct aws4dd_item_update *op,
  const char                *path,
  const char                *key,
  const char               **vals
  ) {
  if (!op || !path || !key || !vals) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _item_put(op->pool, op->n, path, key, vals);
}

iwrc aws4dd_item_update_value(
  struct aws4dd_item_update *op,
  const char                *path,
  const char                *key,
  const char                *val
  ) {
  return aws4dd_item_update_array(op, path, key, (const char*[]) { val, 0 });
}

iwrc aws4dd_item_update_expression_attr_name(struct aws4dd_item_update *op, const char *key, const char *val) {
  iwrc rc = 0;
  JBL_NODE n, n2;

  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_obj(n, "ExpressionAttributeNames", &n2, op->pool));
  RCC(rc, finish, jbn_add_item_str(n2, key, val, -1, 0, op->pool));
  RCC(rc, finish, jbn_patch_auto(op->n, n, op->pool));

finish:
  return rc;
}

iwrc aws4dd_item_update(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_update      *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;

  iwrc rc = 0;
  IWPOOL *pool = op->pool;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);

  JBL_NODE n = op->n;
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->spec.table_name, -1, 0, pool));

  if (op->spec.condition_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "ConditionExpression", op->spec.condition_expression, -1, 0, pool));
  }

  if (op->spec.update_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "UpdateExpression", op->spec.update_expression, -1, 0, pool));
  }

  switch (op->spec.ret.values) {
    case AWS4DD_RETURN_VALUES_ALL_OLD:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnValues", "ALL_OLD", -1, 0, pool));
      break;
    case AWS4DD_RETURN_VALUES_UPDATED_OLD:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnValues", "UPDATED_OLD", -1, 0, pool));
      break;
    case AWS4DD_RETURN_VALUES_ALL_NEW:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnValues", "ALL_NEW", -1, 0, pool));
      break;
    case AWS4DD_RETURN_VALUES_UPDATED_NEW:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnValues", "UPDATED_NEW", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.ret.metrics) {
    case AWS4DD_RETURN_COLLECTION_SIZE:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnItemCollectionMetrics", "SIZE", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.ret.capacity) {
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", -1, 0, pool));
      break;
    default:
      break;
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.UpdateItem",
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// BatchWriteItem
//

struct aws4dd_batch_write {
  IWPOOL *pool;
  struct aws4dd_batch_write_spec spec;
  JBL_NODE n;
};

iwrc aws4dd_batch_write_op(
  struct aws4dd_batch_write           **opp,
  const struct aws4dd_batch_write_spec *spec
  ) {
  iwrc rc = 0;
  if (!opp || !spec) {
    return IW_ERROR_INVALID_ARGS;
  }

  *opp = 0;

  IWPOOL *pool = iwpool_create_empty();
  if (pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_batch_write *op = iwpool_calloc(sizeof(*op), pool);
  RCB(finish, op);
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(*spec));

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));

  *opp = op;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_batch_write_op_destroy(struct aws4dd_batch_write **opp) {
  if (opp && *opp) {
    iwpool_destroy((*opp)->pool);
    *opp = 0;
  }
}

iwrc aws4dd_batch_write_array(
  struct aws4dd_item_update *op,
  const char                *table,
  const char                *path,
  const char                *key,
  const char               **vals
  ) {
  if (!op || !table || !path || !key || !vals) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_check(table, AWS4DD_RESOURCE_TABLE));
  if (*path != '/') {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  JBL_NODE n, n2 = 0;
  IWXSTR *xstr = iwxstr_new_printf("/RequestItems/%s", table);
  RCB(finish, xstr);

  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, _item_put(op->pool, n, path, key, vals));

  if (jbn_at(op->n, iwxstr_ptr(xstr), &n2) || n2->type != JBV_ARRAY) {
    RCC(rc, finish, jbn_from_json("[]", &n2, op->pool));
    RCC(rc, finish, jbn_copy_path(n2, "/", op->n, iwxstr_ptr(xstr), true, true, op->pool));
  }

  jbn_add_item(n2, n);

finish:
  iwxstr_destroy(xstr);
  return rc;
}

iwrc aws4dd_batch_write_value(
  struct aws4dd_item_update *op,
  const char                *table,
  const char                *path,
  const char                *key,
  const char                *val
  ) {
  return aws4dd_batch_write_array(op, table, path, key, (const char*[]) { val, 0 });
}

iwrc aws4dd_bach_write(
  const struct aws4_request_spec *spec,
  struct aws4dd_batch_write      *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;

  iwrc rc = 0;
  IWPOOL *pool = op->pool;
  JBL_NODE n = op->n;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);


  switch (op->spec.ret.metrics) {
    case AWS4DD_RETURN_COLLECTION_SIZE:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnItemCollectionMetrics", "SIZE", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.ret.capacity) {
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", -1, 0, pool));
      break;
    default:
      break;
  }


  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.BatchWriteItem",
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

//
// DeleteItem
//

struct aws4dd_item_delete {
  IWPOOL *pool;
  struct aws4dd_item_delete_spec spec;
  JBL_NODE n; // JSON spec
};

iwrc aws4dd_item_delete_op(struct aws4dd_item_delete **opp, const struct aws4dd_item_delete_spec *spec) {
  iwrc rc = 0;
  if (!opp || !spec || !spec->table_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  *opp = 0;

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_item_delete *op = iwpool_calloc(sizeof(*op), pool);
  RCB(finish, op);
  op->pool = pool;

  memcpy(&op->spec, spec, sizeof(op->spec));
  RCB(finish, op->spec.table_name = iwpool_strdup2(pool, spec->table_name));

  if (spec->condition_expression) {
    RCB(finish, op->spec.condition_expression = iwpool_strdup2(pool, spec->condition_expression));
  }

  RCC(rc, finish, jbn_from_json("{}", &op->n, pool));

  *opp = op;

finish:
  if (rc) {
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_item_delete_op_destroy(struct aws4dd_item_delete **opp) {
  if (opp && *opp) {
    struct aws4dd_item_delete *op = *opp;
    *opp = 0;
    iwpool_destroy(op->pool);
  }
}

iwrc aws4dd_item_delete_array(
  struct aws4dd_item_delete *op, const char *path,
  const char *key, const char **values
  ) {
  if (!op || !path || !key || !values) {
    return IW_ERROR_INVALID_ARGS;
  }
  return _item_put(op->pool, op->n, path, key, values);
}

iwrc aws4dd_item_delete_value(
  struct aws4dd_item_delete *op, const char *path,
  const char *key, const char *value
  ) {
  if (!op || !path || !key || !value) {
    return IW_ERROR_INVALID_ARGS;
  }
  return aws4dd_item_delete_array(op, path, key, (const char*[]) { value, 0 });
}

iwrc aws4dd_item_delete(
  const struct aws4_request_spec *spec,
  struct aws4dd_item_delete      *op,
  struct aws4dd_response        **rpp
  ) {
  if (!spec || !op || !rpp) {
    return IW_ERROR_INVALID_ARGS;
  }
  *rpp = 0;

  iwrc rc = 0;
  IWPOOL *pool = op->pool;
  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);

  resp->pool = pool;
  iwpool_ref(pool);

  JBL_NODE n = op->n;
  RCC(rc, finish, jbn_add_item_str(n, "TableName", op->spec.table_name, -1, 0, pool));

  if (op->spec.condition_expression) {
    RCC(rc, finish, jbn_add_item_str(n, "ConditionExpression", op->spec.condition_expression, -1, 0, pool));
  }

  switch (op->spec.ret.values) {
    case AWS4DD_RETURN_VALUES_ALL_OLD:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnValues", "ALL_OLD", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.ret.consumed_capacity) {
    case AWS4DD_RETURN_CONSUMED_TOTAL:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "TOTAL", -1, 0, pool));
      break;
    case AWS4DD_RETURN_CONSUMED_INDEXES:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnConsumedCapacity", "INDEXES", -1, 0, pool));
      break;
    default:
      break;
  }

  switch (op->spec.ret.collection_metrics) {
    case AWS4DD_RETURN_COLLECTION_SIZE:
      RCC(rc, finish, jbn_add_item_str(n, "ReturnItemCollectionMetrics", "SIZE", -1, 0, pool));
      break;
    default:
      break;
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.DeleteItem",
  }, pool, &resp->data, &resp->status_code));

  *rpp = resp;

finish:
  if (rc && resp) {
    iwpool_destroy(resp->pool);
  }
  return rc;
}

iwrc aws4dd_ttl_update(
  const struct aws4_request_spec *spec,
  const char                     *table_name,
  const char                     *attribute_name,
  bool                            enabled,
  bool                           *out_enabled
  ) {
  if (!table_name || !attribute_name) {
    return IW_ERROR_INVALID_ARGS;
  }

  *out_enabled = !enabled;

  iwrc rc = 0;
  RCR(_name_check(table_name, AWS4DD_RESOURCE_TABLE));
  RCR(_name_check(attribute_name, AWS4DD_RESOURCE_ATTR));

  IWPOOL *pool = iwpool_create_empty();
  RCB(finish, pool);

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), pool);
  RCB(finish, resp);
  resp->pool = pool;

  JBL_NODE n, n2;
  RCC(rc, finish, jbn_from_json("{}", &n, pool));
  RCC(rc, finish, jbn_add_item_str(n, "TableName", table_name, -1, 0, pool));
  RCC(rc, finish, jbn_add_item_obj(n, "TimeToLiveSpecification", &n2, pool));
  RCC(rc, finish, jbn_add_item_str(n2, "AttributeName", attribute_name, -1, 0, pool));
  RCC(rc, finish, jbn_add_item_bool(n2, "Enabled", enabled, 0, pool));

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.UpdateTimeToLive",
  }, pool, &resp->data, &resp->status_code));

  RCC(rc, finish, jbn_at(resp->data, "/TimeToLiveSpecification/Enabled", &n));
  if (n->type == JBV_BOOL) {
    *out_enabled = n->vbool;
  }

finish:
  iwpool_destroy(pool);
  return rc;
}

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _AWS4DD_ERROR_START || ecode >= _AWS4DD_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case AWS4DD_ERROR_INVALID_RESOURCE_NAME:
      return "Invalid table/index/tag/attr name (AWS4DD_ERROR_INVALID_RESOURCE_NAME)";
    case AWS4DD_ERROR_MAX_IDX_LIMIT:
      return "Number of allowed table indexes exceeds limits (AWS4DD_ERROR_MAX_IDX_LIMIT)";
    case AWS4DD_ERROR_NO_PARTITION_KEY:
      return "No partition key specified (AWS4DD_ERROR_NO_PARTITION_KEY)";
  }
  return 0;
}

IW_CONSTRUCTOR void _aws4dd_init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    iwrc rc = iw_init();
    if (rc) {
      iwlog_ecode_error3(rc);
    }
    rc = iwlog_register_ecodefn(_ecodefn);
    if (rc) {
      iwlog_ecode_error3(rc);
    }
  }
}
