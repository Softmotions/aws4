#pragma once

#include <iowow/basedefs.h>
#include <iowow/iwpool.h>
#include <iowow/iwjson.h>

#include <iwnet/iwn_curl.h>
#include <iwnet/iwn_url.h>
#include <iwnet/iwn_pairs.h>

#include <curl/curl.h>

#define AWS_SERVICE_DYNAMODB 0x01U   ///< DynamoDB accessed
#define AWS_SERVICE_S3       0x02U   ///< AWS S3 accessed
#define AWS_CREDENTIALS_AUTO 0x04U   ///< Locate AWS credetials accourding to
                                     ///  https://docs.aws.amazon.com/sdkref/latest/guide/file-location.html
#define AWS_REQUEST_VERBOSE 0x08U
#define AWS_SERVICE_ALL     (AWS_SERVICE_S3 | AWS_SERVICE_DYNAMODB)


typedef enum {
  _AWS4_ERROR_START = (IW_ERROR_START + 100000L),
  AWS4_API_REQUEST_ERROR, ///< Failed to call AWS HTTP API endpoint (AWS4_API_REQUEST_ERROR)
  _AWS4_ERROR_END,
} aws4_ecode_e;

struct aws4_request;

struct aws4_request_spec {
  const char *aws_region;         ///< AWS region. Required if region is not specified in .aws/config.
  const char *aws_config_profile; ///< AWS configuration profile name. Optional.
  const char *aws_url;            ///< If not set endpoint URL is computed as follows:
                                  ///  https://<service>.<aws_region>.amazonaws.com
  const char *aws_key;            ///< Optional.
  const char *aws_secret_key;     ///< Optional.
  unsigned    flags;              ///< AWS_SERVICE_XXX flag is required.
};

struct aws4_request_payload {
  const char *payload;
  size_t      payload_len;
  const char *amz_target;
  const char *content_type;
};

struct aws4_request_json_payload {
  const char    *amz_target;
  const JBL_NODE json;
};

IW_EXPORT iwrc aws4_request_raw(
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  char                             **out);

IW_EXPORT iwrc aws4_request_raw_json_get(
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  IWPOOL                            *pool,
  JBL_NODE                          *out);

IW_EXPORT iwrc aws4_request_json(
  const struct aws4_request_spec         *spec,
  const struct aws4_request_json_payload *payload,
  IWPOOL                                 *pool,
  JBL_NODE                               *out);

IW_EXPORT iwrc aws4_request_create(
  const struct aws4_request_spec *spec,
  struct aws4_request           **out_req);

IW_EXPORT void aws4_request_destroy(struct aws4_request **reqp);

IW_EXPORT iwrc aws4_request_payload_set(struct aws4_request *req, const struct aws4_request_payload *payload);

IW_EXPORT iwrc aws4_request_payload_json_set(struct aws4_request *req, const char *amz_target, const JBL_NODE json);

IW_EXPORT iwrc aws4_request_perform(CURL *curl, struct aws4_request *req, char **out);
