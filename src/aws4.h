#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwpool.h>
#include <iowow/iwjson.h>
#include <iwnet/iwn_curl.h>
#include <iwnet/iwn_pairs.h>

#define AWS_SERVICE_DYNAMODB 0x01U
#define AWS_SERVICE_S3       0x02U

struct aws4_request_spec {
  const char *aws_key;
  const char *aws_secret_key;
  const char *aws_host;
  const char *aws_region;
  const char *signed_headers; // `;` separated list of signed headers in lower case
  const char *target;

  JBL_NODE payload;
  struct xcurlreq xreq;
  iwrc rc;

  struct aws4_request_spec* (*set_aws_key)(struct aws4_request_spec *spec, const char *key);
  struct aws4_request_spec* (*set_aws_secret_key)(struct aws4_request_spec *spec, const char *secret_key);
  struct aws4_request_spec* (*set_aws_host)(struct aws4_request_spec *spec, const char *host);
  struct aws4_request_spec* (*set_aws_region)(struct aws4_request_spec *spec, const char *region);
  struct aws4_request_spec* (*set_signed_headers)(struct aws4_request_spec *spec, const char *headers);
  struct aws4_request_spec* (*set_target)(struct aws4_request_spec *spec, const char *target);

  IWPOOL  *pool;
  uint32_t aws_service;
};

iwrc aws4_request_create(struct aws4_request_spec **out_spec);

iwrc aws4_request_sign(struct aws4_request_spec *spec);
