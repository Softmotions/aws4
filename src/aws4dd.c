#include "aws4dd.h"

#include <iowow/iwjson.h>
#include <iwnet/iwn_pairs.h>

#include <errno.h>

static const char* _ecodefn(locale_t, uint32_t);

IW_INLINE iwrc _init(void) {
  static bool _initialized;
  if (__sync_bool_compare_and_swap(&_initialized, false, true)) {
    RCR(iw_init());
    RCR(iwlog_register_ecodefn(_ecodefn));
  }
  return 0;
}

void aws4dd_response_destroy(struct aws4dd_response **rp) {
  if (rp && *rp) {
    struct aws4dd_response *r = *rp;
    *rp = 0;
    iwpool_destroy(r->pool);
  }
}

///
/// Table.
///

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

static iwrc _name_check(const char *name) {
  if (!name) {
    return AWS4DD_ERROR_INVALID_ENTITY_NAME;
  }
  unsigned long len = strlen(name);
  if (len < 3 || len > 255) {
    return AWS4DD_ERROR_INVALID_ENTITY_NAME;
  }
  for (unsigned long i = 0; i < len; ++i) {
    if (  (name[i] < 'A' || name[i] > 'Z')
       && (name[i] < 'a' || name[i] > 'z')
       && (name[i] < '0' || name[i] > '9')
       && name[i] != '.' && name[i] != '_' && name[i] != '-') {
      return AWS4DD_ERROR_INVALID_ENTITY_NAME;
    }
  }
  return 0;
}

static iwrc _name_tag_check(const char *name) {
  if (!name || *name == '\0' || strlen(name) > 128) {
    return AWS4DD_ERROR_INVALID_ENTITY_NAME;
  }
  return 0;
}

iwrc aws4dd_table_create_op(
  struct aws4dd_table_create **rp,
  const char                  *name,
  const char                  *partition_key,
  const char                  *sort_key
  ) {
  RCR(_init());
  if (!rp || !partition_key) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_check(name));

  iwrc rc = 0;
  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4dd_table_create *r;
  RCB(finish, r = iwpool_calloc(sizeof(*r), pool));
  RCB(finish, r->name = iwpool_strdup2(pool, name));
  RCB(finish, r->pk = iwpool_strdup2(pool, partition_key));
  if (sort_key) {
    RCB(finish, r->sk = iwpool_strdup2(pool, sort_key));
  }
  r->pool = pool;

  *rp = r;

finish:
  if (rc) {
    *rp = 0;
    iwpool_destroy(pool);
  }
  return rc;
}

void aws4dd_table_flags_update(struct aws4dd_table_create *op, unsigned flags) {
  if (op) {
    op->flags |= flags;
  }
}

void aws4dd_table_provisioned_throughtput(
  struct aws4dd_table_create *op,
  long                        read_capacity_units,
  long                        write_capacity_units
  ) {
  if (op) {
    op->read_capacity_units = read_capacity_units;
    op->write_capacity_units = write_capacity_units;
  }
}

iwrc aws4dd_table_tag_add(struct aws4dd_table_create *op, const char *tag_name, const char *tag_value) {
  if (!op || !tag_value) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_tag_check(tag_name));
  return iwn_pair_add_pool_all(op->pool, &op->tags, tag_name, -1, tag_value, -1);
}

static iwrc _table_attribute_add(struct aws4dd_table_create *op, const char *name, const char *type) {
  RCR(_init());
  RCR(_name_check(name));
  if (!op || type) {
    return IW_ERROR_INVALID_ARGS;
  }
  return iwn_pair_add_pool_all(op->pool, &op->attrs, name, -1, type, -1);
}

iwrc aws4dd_table_attribute_string_add(struct aws4dd_table_create *op, const char *name) {
  return _table_attribute_add(op, name, "S");
}

iwrc aws4dd_table_attribute_number_add(struct aws4dd_table_create *op, const char *name) {
  return _table_attribute_add(op, name, "N");
}

iwrc aws4dd_table_attribute_binary_add(struct aws4dd_table_create *op, const char *name) {
  return _table_attribute_add(op, name, "B");
}

iwrc aws4dd_table_index_add(struct aws4dd_table_create *op, const struct aws4dd_index_spec *spec) {
  RCR(_init());
  if (!op || !spec) {
    return IW_ERROR_INVALID_ARGS;
  }
  RCR(_name_check(spec->name));
  RCR(_name_check(spec->pk));

  iwrc rc = 0;
  struct aws4dd_index_spec *ps = 0;
  if (spec->local) {
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
  ps->local = spec->local;
  ps->project_all = spec->project_all;
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

struct aws4dd_response* aws4dd_table_create(const struct aws4_request_spec *spec, struct aws4dd_table_create *op) {
  iwrc rc = _init();
  if (rc) {
    iwlog_ecode_error3(rc);
    return 0;
  }

  struct aws4dd_response *resp = iwpool_calloc(sizeof(*resp), op->pool);
  if (!resp) {
    iwlog_ecode_error3(iwrc_set_errno(IW_ERROR_ALLOC, errno));
    return 0;
  }

  resp->pool = op->pool;
  if (!op->pk) {
    resp->rc = AWS4DD_ERROR_NO_PARTITION_KEY;
    return resp;
  }

  struct iwn_pair *pair = op->attrs.first;
  for ( ; pair; pair = pair->next) {
    if (strcmp(pair->key, op->pk) == 0) {
      break;
    }
  }
  if (!pair) {
    resp->rc = AWS4DD_ERROR_NO_PARTITION_KEY;
    return resp;
  }

  JBL_NODE n, n2, n3, n4, n5;
  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_arr(n, "AttributeDefinitions", &n2, op->pool));

  for (pair = op->attrs.first; pair; pair = pair->next) {
    RCC(rc, finish, jbn_add_item_obj(n2, 0, &n3, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "AttributeName", pair->key, pair->key_len, 0, op->pool));
    RCC(rc, finish, jbn_add_item_str(n3, "AttributeType", pair->val, pair->val_len, 0, op->pool));
  }

  {
    const char *bm = 0;
    if (op->flags & AWS4DD_TABLE_BILLING_PROVISIONED) {
      bm = "PROVISIONED";
    } else if (op->flags & AWS4DD_TABLE_BILLING_PER_REQUEST) {
      bm = "PAY_PER_REQUEST";
    }
    if (bm) {
      RCC(rc, finish, jbn_add_item_str(n, "BillingMode", bm, -1, 0, op->pool));
    }
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

      if (idx->project_all) {
        RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
        RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "ALL", IW_LLEN("ALL"), 0, op->pool));
      } else if (idx->proj && idx->proj[0]) {
        RCC(rc, finish, jbn_add_item_obj(n3, "Projection", &n4, op->pool));
        RCC(rc, finish, jbn_add_item_str(n4, "ProjectionType", "INCLUDE", IW_LLEN("INCLUDE"), 0, op->pool));
        RCC(rc, finish, jbn_add_item_arr(n4, "NonKeyAttributes", &n5, op->pool));
        for (int i = 0; idx->proj[i]; ++i) {
          RCC(rc, finish, jbn_add_item_str(n5, 0, idx->proj[i], -1, 0, op->pool));
        }
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

  if (op->flags & AWS4DD_TABLE_BILLING_PROVISIONED) {
    RCC(rc, finish, jbn_add_item_obj(n, "ProvisionedThroughput", &n2, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n2, "ReadCapacityUnits", op->read_capacity_units, 0, op->pool));
    RCC(rc, finish, jbn_add_item_i64(n2, "WriteCapacityUnits", op->write_capacity_units, 0, op->pool));
  }

  if (op->flags & (AWS4DD_TABLE_STREAM_KEYS_ONLY | AWS4DD_TABLE_STREAM_NEW_IMAGE | AWS4DD_TABLE_STREAM_OLD_IMAGE)) {
    RCC(rc, finish, jbn_add_item_obj(n, "StreamSpecification", &n2, op->pool));
    RCC(rc, finish, jbn_add_item_bool(n2, "Enabled", true, 0, op->pool));
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
      RCC(rc, finish, jbn_add_item_str(n2, "Key", pair->key, pair->key_len, 0, op->pool));
      RCC(rc, finish, jbn_add_item_str(n2, "Valuw", pair->val, pair->val_len, 0, op->pool));
    }
  }

  RCC(rc, finish, aws4_request_json(spec, &(struct aws4_request_json_payload) {
    .json = n,
    .amz_target = "DynamoDB_20120810.CreateTable"
  }, op->pool, &resp->data));


finish:
  if (rc) {
    if (resp && !resp->rc) {
      resp->rc = rc;
    } else {
      iwlog_ecode_error3(rc);
    }
  }
  return resp;
}

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _AWS4DD_ERROR_START || ecode >= _AWS4DD_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case AWS4DD_ERROR_INVALID_ENTITY_NAME:
      return "Invalid table/index/attr name (AWS4DD_ERROR_INVALID_ENTITY_NAME)";
    case AWS4DD_ERROR_MAX_IDX_LIMIT:
      return "Number of allowed table indexes exceeds limits (AWS4DD_ERROR_MAX_IDX_LIMIT)";
    case AWS4DD_ERROR_NO_PARTITION_KEY:
      return "No partition key specified (AWS4DD_ERROR_NO_PARTITION_KEY)";
  }
  return 0;
}
