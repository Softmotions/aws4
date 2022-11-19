#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwpool.h>
#include <iwnet/iwn_curl.h>
#include <iwnet/iwn_pairs.h>

#define AWS_SERVICE_DYNAMODB 0x01U
#define AWS_SERVICE_S3       0x02U

#define AWS_REQUEST_SIGNED 0x01U

struct aws4_request {
  const char *aws_key;
  const char *aws_secret_key;
  const char *aws_host;
  const char *aws_region;
  const char *signed_headers; // `;` separated list of signed headers in lower case
  const char *target;

  struct xcurlreq xreq;
  iwrc    rc;
  IWPOOL *pool;

  uint32_t aws_service;
  uint32_t status;
};

iwrc aws4_request_create(
  const char           *aws_host,
  const char           *aws_region,
  const char           *aws_key,
  const char           *aws_secret_key,
  struct aws4_request **out_req);

void aws4_request_destroy(struct aws4_request **reqp);

iwrc aws4_request_payload_set(struct aws4_request *req, const char *payload, size_t payload_len);

iwrc aws4_request_sign(struct aws4_request *req);
