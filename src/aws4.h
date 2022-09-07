#pragma once

#include <iowow/basedefs.h>
#include <iwnet/iwn_curl.h>
#include <iwnet/iwn_pairs.h>

#define AWS_SERVICE_DYNAMODB 0x01U
#define AWS_SERVICE_S3       0x02U

struct aws4_request_sign_spec {
  const char     *aws_key;
  const char     *aws_secret_key;
  const char     *aws_host;
  const char     *aws_region;
  struct iwn_vals headers_to_sign; ///< List of header names to sign
  uint32_t aws_service;
};

iwrc aws4_request_sign(const struct aws4_request_sign_spec *spec, struct xcurlreq *req);
