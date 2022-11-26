#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwpool.h>
#include <iowow/iwjson.h>

#include <iwnet/iwn_curl.h>
#include <iwnet/iwn_url.h>
#include <iwnet/iwn_pairs.h>

#include <curl/curl.h>

#define AWS_SERVICE_DYNAMODB 0x01U
#define AWS_SERVICE_S3       0x02U

struct aws4_request;

struct aws4_request_spec {
  const char *aws_region;
  const char *aws_key;
  const char *aws_secret_key;
  const char *aws_url;
  unsigned    service;
  bool verbose;
};

struct aws4_request_payload {
  const char *payload;
  size_t      payload_len;
  const char *amz_target;
  const char *content_type;
};

iwrc aws4_request_create(
  const struct aws4_request_spec *spec,
  struct aws4_request           **out_req);

void aws4_request_destroy(struct aws4_request **reqp);

iwrc aws4_request_payload_set(struct aws4_request *req, const struct aws4_request_payload *payload);

iwrc aws4_request_perform(CURL *curl, struct aws4_request *req, char **out);

iwrc aws4_request(
  CURL                              *curl,
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  char                             **out);

iwrc aws4_request_json(
  CURL                              *curl,
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  IWPOOL                            *pool,
  JBL_NODE                          *out);
