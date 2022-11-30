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

struct aws4dd_response* aws4dd_table_create(const struct aws4_request_spec *req, struct aws4dd_table_create *op) {
  _init();
  if (!req || !op) {
    return 0;
  }
  iwrc rc = 0;
  struct aws4dd_response *resp = 0;
  JBL_NODE n, n2, n3;
  RCC(rc, finish, jbn_from_json("{}", &n, op->pool));
  RCC(rc, finish, jbn_add_item_arr(n, "AttributeDefinitions", &n2, op->pool));

  struct iwn_pair *pair = op->attrs.first;
  for ( ; pair; pair = pair->next) {
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

  if (op->global_idx[0].name) {
    RCC(rc, finish, jbn_add_item_arr(n, "GlobalSecondaryIndexes", &n2, op->pool));
    //  TODO:
  }



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
  }
  return 0;
}
