#pragma once
#include "aws4.h"
#include <iowow/iwpool.h>

struct aws4dd_response {
  IWPOOL     *pool;
  JBL_NODE   *data;
  const char *error;
  iwrc rc;
};

void aws4dd_response_destroy(struct aws4dd_response **rp);

///
/// Table.
///

struct aws4dd_table_create;

iwrc aws4dd_table_create_name_set(struct aws4dd_table_create *rp, const char *name);

struct aws4dd_response* aws4dd_table_create(const struct aws4_request_spec *spec, struct aws4dd_table_create *r);

struct aws4dd_response* aws4dd_table_describe(const struct aws4_request_spec *spec, const char *name);

struct aws4dd_response* aws4dd_table_remove(const struct aws4_request_spec *spec, const char *name);
