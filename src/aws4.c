#include "aws4.h"
#include "config.h"

#include <iowow/iwlog.h>
#include <iowow/iwconv.h>
#include <iowow/iwarr.h>

#include <iwnet/iwn_codec.h>
#include <iwnet/bearssl_hash.h>
#include <iwnet/bearssl_hmac.h>

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <unistd.h>

#define AWS_DNS_SUFFIX      "amazonaws.com"
#define AWS_DYNAMODB_PREFIX "dynamodb"

#define RETRY_PAUSE 3

struct aws4_request {
  const char     *aws_key;
  const char     *aws_secret_key;
  const char     *aws_region;
  const char     *aws_url;
  const char     *signed_headers; // `;` separated list of signed headers in lower case
  const char     *service;
  struct xcurlreq xreq;
  struct iwn_url  url;
  IWPOOL  *pool;
  unsigned flags;
  bool     verbose;
};

struct _sign_ctx {
  IWXSTR *xstr;
  IWXSTR *signed_headers;
  struct xcurlreq *xreq;
  const struct aws4_request *req;
  char datetime[20]; ///< YYYYMMDD'T'HHMMSS'Z',
  char date[10];     ///< YYYYMMDD
};

static iwrc _sign_ctx_init(struct _sign_ctx *c) {
  iwrc rc = 0;
  time_t t;

  t = time(0);
  if (t == (time_t) -1) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }

  struct tm tm;
  if (!gmtime_r(&t, &tm)) {
    return iwrc_set_errno(IW_ERROR_ERRNO, errno);
  }

  // YYYYMMDD'T'HHMMSS'Z',
  if (strftime(c->datetime, sizeof(c->datetime), "%Y%m%dT%H%M%SZ", &tm) == 0) {
    return IW_ERROR_FAIL;
  }
  memcpy(c->date, c->datetime, 8);
  c->date[8] = '\0';

  bool host_found = false;
  bool accept_found = false;
  bool accept_encoding_found = false;
  bool user_agent_found = false;

  // Set host header
  for (struct curl_slist *h = c->xreq->headers; h; h = h->next) {
    if (strncasecmp(h->data, "host:", IW_LLEN("host:")) == 0) {
      host_found = true;
    } else if (strncasecmp(h->data, "accept:", IW_LLEN("accept:")) == 0) {
      accept_found = true;
    } else if (strncasecmp(h->data, "user-agent:", IW_LLEN("user-agent:")) == 0) {
      user_agent_found = false;
    }
  }

  if (!user_agent_found) {
    xcurlreq_hdr_add(c->xreq, "user-agent", IW_LLEN("user-agent"), "aws4/1.0", IW_LLEN("aws4/1.0"));
  }

  if (!host_found) {
    xcurlreq_hdr_add(c->xreq, "host", IW_LLEN("host"), c->req->url.host, -1);
  }

  if (!accept_found) {
    xcurlreq_hdr_add(c->xreq, "accept", IW_LLEN("accept"), "*/*", IW_LLEN("*/*"));
  }

  if (!accept_encoding_found) {
    xcurlreq_hdr_add(c->xreq, "accept-encoding", IW_LLEN("accept-encoding"), "identity", IW_LLEN("identity"));
  }

  xcurlreq_hdr_add(c->xreq, "x-amz-date", IW_LLEN("x-amz-date"), c->datetime, -1);

  return 0;
}

static iwrc _sr_method_add(struct _sign_ctx *c) {
  const char *method = "GET";
  if (c->xreq->flags & XCURLREQ_POST) {
    method = "POST";
  } else if (c->xreq->flags & XCURLREQ_PUT) {
    method = "PUT";
  } else if (c->xreq->flags & XCURLREQ_DEL) {
    method = "DELETE";
  } else if (c->xreq->flags & XCURLREQ_HEAD) {
    method = "HEAD";
  } else if (c->xreq->flags & XCURLREQ_OPTS) {
    method = "OPTIONS";
  }
  return iwxstr_printf(c->xstr, "%s\n", method);
}

static IW_ALLOC char* _uri_encode(const char *buf, size_t buf_len, int rounds) {
  char *res = iwn_url_encode_new(buf, buf_len);
  if (res) {
    for (int i = 1; i < rounds; ++i) {
      char *nres = iwn_url_encode_new(res, strlen(res));
      free(res);
      if (!nres) {
        return 0;
      }
      res = nres;
    }
  }
  return res;
}

static IW_ALLOC char* _sr_section_create(struct xcurlreq *req, const char *sp, const char *ep) {
  assert(ep > sp);
  int rounds = (req->flags & AWS_SERVICE_S3) ? 1 : 2;
  return _uri_encode(sp, ep - sp, rounds);
}

static iwrc _sr_uri_add(struct _sign_ctx *c) {
  const char *sp = c->xreq->path;
  const char *ep = sp;
  while (ep && *ep) {
    while (*ep && *ep == '/') {
      ++sp;
      ++ep;
    }
    while (*ep && *ep != '/') {
      ++ep;
    }
    if (ep > sp) {
      char *s = _sr_section_create(c->xreq, sp, ep);
      if (!s) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
      }
      RCR(iwxstr_printf(c->xstr, "/%s", s));
    } else if (sp == c->xreq->path) {
      RCR(iwxstr_cat(c->xstr, "/", 1));
      break;
    }
    sp = ep;
  }
  return iwxstr_cat(c->xstr, "\n", 1);
}

static int _cr_qs_pair_compare(const void *a, const void *b) {
  const struct iwn_pair *p1 = *(struct iwn_pair**) a;
  const struct iwn_pair *p2 = *(struct iwn_pair**) b;

  int ret = strncmp(p1->key, p2->key, MIN(p1->key_len, p2->key_len));
  if (ret) {
    return ret;
  }
  ret = p1->key_len > p2->key_len ? 1 : p1->key_len < p2->key_len ? -1 : 0;
  if (ret) {
    return ret;
  }

  ret = strncmp(p1->val, p2->val, MIN(p1->val_len, p2->val_len));
  if (ret) {
    return ret;
  }
  return p1->val_len > p2->val_len ? 1 : p1->val_len < p2->val_len ? -1 : 0;
}

static iwrc _sr_qs_add(struct _sign_ctx *c) {
  if (!c->xreq->_qxstr || iwxstr_size(c->xreq->_qxstr) == 0) {
    return iwxstr_cat(c->xstr, "\n", 1);
  }
  iwrc rc = 0;
  IWPOOL *pool = 0;
  struct iwn_pairs pairs;

  char *buf = 0;
  size_t buflen = 0;

  size_t len = iwxstr_size(c->xreq->_qxstr);
  RCB(finish, pool = iwpool_create_empty());

  char *qs = iwpool_strndup2(pool, iwxstr_ptr(c->xreq->_qxstr), len);
  RCB(finish, qs);
  RCC(rc, finish, iwn_wf_parse_query_inplace(pool, &pairs, qs, len));

  struct iwn_pair **parr = iwn_pairs_to_array(pool, &pairs, &len);
  RCB(finish, parr);

  for (size_t i = 0; i < len; ++i) {
    struct iwn_pair *p = parr[i];
    iwn_url_decode_inplace2((char*) p->key, (char*) p->key + p->key_len);
    iwn_url_decode_inplace2(p->val, p->val + p->val_len);
  }

  // NOLINTNEXTLINE
  qsort(parr, len, sizeof(parr[0]), _cr_qs_pair_compare);

  for (size_t i = 0; i < len; ++i) {
    struct iwn_pair *p = parr[i];
    len = iwn_url_encoded_len(p->key, p->key_len);
    if (len > buflen) {
      RCB(finish, buf = realloc(buf, len));
      buflen = len;
    }
    if (i) {
      RCC(rc, finish, iwxstr_cat(c->xstr, "&", 1));
    }
    iwn_url_encode(p->key, p->key_len, buf, buflen);
    RCC(rc, finish, iwxstr_cat(c->xstr, buf, len));
    RCC(rc, finish, iwxstr_cat(c->xstr, "=", 1));
    if (p->val_len) {
      len = iwn_url_encoded_aws_len(p->val, p->val_len);
      if (len > buflen) {
        RCB(finish, buf = realloc(buf, len));
        buflen = len;
      }
      iwn_url_encode_aws(p->val, p->val_len, buf, buflen);
      RCC(rc, finish, iwxstr_cat(c->xstr, buf, len));
    }
  }

  RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));

finish:
  free(buf);
  iwpool_destroy(pool);
  return rc;
}

static iwrc _cr_header_fill(IWPOOL *pool, const char *spec, struct iwn_pair *p) {
  memset(p, 0, sizeof(*p));

  size_t len = strlen(spec);
  char *buf = iwpool_alloc(len + 1, pool);
  if (!buf) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  memcpy(buf, spec, len);
  buf[len] = '\0';

  char *vp = 0;
  p->key = buf;

  for (int i = 0; i < len; ++i) {
    if (vp == 0) {
      if (buf[i] == ':') {
        buf[i] = '\0';
        p->key_len = i;
        p->val = vp = buf + i + 1;
      } else {
        buf[i] = tolower(buf[i]);
      }
    } else {
      if (!isspace(buf[i]) || !isspace(*vp)) {
        *vp = buf[i];
        vp++;
      }
    }
  }
  if (!vp) {
    return IW_ERROR_INVALID_VALUE;
  }
  if (*vp != '\0') {
    vp++;
    *vp = '\0';
  }
  p->val_len = vp - p->val;

  // Trim leading and trailing spaces
  while (isspace(*p->key)) {
    ++p->key;
    --p->key_len;
  }
  while (p->key_len && isspace(p->key[p->key_len - 1])) {
    --p->key_len;
    *((char*) p->key + p->key_len) = '\0';
  }
  while (isspace(*p->val)) {
    ++p->val;
    --p->val_len;
  }
  while (p->val_len && isspace(p->val[p->val_len - 1])) {
    --p->val_len;
    p->val[p->val_len] = '\0';
  }
  return 0;
}

static int _cr_header_pair_compare(const void *a, const void *b) {
  const struct iwn_pair *h1 = a;
  const struct iwn_pair *h2 = b;
  int ret = strncmp(h1->key, h2->key, MIN(h1->key_len, h2->key_len));
  if (ret) {
    return ret;
  }
  return h1->key_len > h2->key_len ? 1 : h1->key_len < h2->key_len ? -1 : 0;
}

static iwrc _sr_headers_add(struct _sign_ctx *c) {
  iwrc rc = 0;
  IWPOOL *pool = 0;
  RCB(finish, pool = iwpool_create_empty());
  size_t len = 0;
  for (struct curl_slist *h = c->xreq->headers; h; h = h->next) {
    ++len;
  }
  struct iwn_pair *harr;
  RCB(finish, harr = iwpool_alloc(sizeof(harr[0]) * len, pool));

  len = 0;
  for (struct curl_slist *h = c->xreq->headers; h; h = h->next) {
    RCC(rc, finish, _cr_header_fill(pool, h->data, &harr[len++]));
  }

  qsort(harr, len, sizeof(harr[0]), _cr_header_pair_compare);

  for (size_t i = 0; i < len; ++i) {
    RCC(rc, finish, iwxstr_cat(c->xstr, harr[i].key, harr[i].key_len));
    RCC(rc, finish, iwxstr_cat(c->xstr, ":", 1));
    RCC(rc, finish, iwxstr_cat(c->xstr, harr[i].val, harr[i].val_len));
    RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));
  }

  RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));

finish:
  iwpool_destroy(pool);
  return rc;
}

static int _sr_header_compare(const void *a, const void *b) {
  const char *p1 = *(const char**) a;
  const char *p2 = *(const char**) b;
  return strcmp(p1, p2);
}

static iwrc _sr_headers_signed_add(struct _sign_ctx *c) {
  iwrc rc = 0;
  int cnt = 0;
  IWPOOL *pool = 0;
  IWXSTR *xstr = 0;

  RCB(finish, pool = iwpool_create_empty());
  RCB(finish, c->signed_headers = iwxstr_new());
  RCB(finish, xstr = iwxstr_new_printf("content-type;host;x-amz-date"));
  if (c->req->signed_headers) {
    RCC(rc, finish, iwxstr_cat(xstr, ";", 1));
    RCC(rc, finish, iwxstr_cat2(xstr, c->req->signed_headers));
  }

  const char **tokens = iwpool_split_string(pool, iwxstr_ptr(xstr), ";", true);
  for (const char **hh = tokens; *hh; ++hh) {
    ++cnt;
  }

  qsort(tokens, cnt, sizeof(*tokens), _sr_header_compare);

  for (const char **hh = tokens, *ph = 0; *hh; ++hh) {
    if (ph && strcmp(*hh, ph) == 0) {
      continue;
    }
    ph = *hh;
    if (hh != tokens) {
      RCC(rc, finish, iwxstr_cat(c->xstr, ";", 1));
      RCC(rc, finish, iwxstr_cat(c->signed_headers, ";", 1));
    }
    RCC(rc, finish, iwxstr_cat2(c->xstr, *hh));
    RCC(rc, finish, iwxstr_cat2(c->signed_headers, *hh));
  }
  RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));

finish:
  iwxstr_destroy(xstr);
  iwpool_destroy(pool);
  return rc;
}

static iwrc _sr_payload_hash_add(struct _sign_ctx *c) {
  if (c->xreq->payload_len == 0) {
    return iwxstr_cat(c->xstr, "\n", 1);
  }
  char hash[br_sha256_SIZE * 2 + 1];
  uint8_t hash_bits[br_sha256_SIZE];
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, c->xreq->payload, c->xreq->payload_len);
  br_sha256_out(&ctx, hash_bits);
  iwbin2hex(hash, sizeof(hash), hash_bits, sizeof(hash_bits));
  RCR(iwxstr_cat(c->xstr, hash, sizeof(hash) - 1));
  RCR(iwxstr_cat(c->xstr, "\n", 1));
  return 0;
}

static void _sr_fill_request_hash(IWXSTR *xstr, char out[static br_sha256_SIZE * 2 + 1]) {
  uint8_t hash_bits[br_sha256_SIZE];
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, iwxstr_ptr(xstr), iwxstr_size(xstr));
  br_sha256_out(&ctx, hash_bits);
  iwbin2hex(out, br_sha256_SIZE * 2 + 1, hash_bits, sizeof(hash_bits));
}

static void _hmac(
  const char *key, ssize_t key_len,
  const char *data, ssize_t data_len,
  char out_buf[br_sha256_SIZE]
  ) {
  if (key_len < 0) {
    key_len = strlen(key);
  }
  if (data_len < 0) {
    data_len = strlen(data);
  }
  br_hmac_context hc;
  br_hmac_key_context kc;
  br_hmac_key_init(&kc, &br_sha256_vtable, key, key_len);
  br_hmac_init(&hc, &kc, 0);
  br_hmac_update(&hc, data, data_len);
  br_hmac_out(&hc, out_buf);
}

static iwrc _sign(struct aws4_request *req) {
  struct xcurlreq *xreq = &req->xreq;

  iwrc rc = 0;
  char hash[br_sha256_SIZE];
  char hashx[br_sha256_SIZE * 2 + 1]; // hex hash representation

  IWXSTR *xstr2 = 0, *xstr = iwxstr_new();
  RCB(finish, xstr);
  RCB(finish, xstr2 = iwxstr_new());

  struct _sign_ctx c = {
    .xreq = xreq,
    .req  = req,
    .xstr = xstr
  };

  RCC(rc, finish, _sign_ctx_init(&c));
  RCC(rc, finish, _sr_method_add(&c));
  RCC(rc, finish, _sr_uri_add(&c));
  RCC(rc, finish, _sr_qs_add(&c));
  RCC(rc, finish, _sr_headers_add(&c));
  RCC(rc, finish, _sr_headers_signed_add(&c));
  RCC(rc, finish, _sr_payload_hash_add(&c));

  _sr_fill_request_hash(xstr, hashx);

  // String to sign
  iwxstr_clear(xstr2);
  RCC(rc, finish, iwxstr_cat(xstr2, "AWS4-HMAC-SHA256\n", IW_LLEN("AWS4-HMAC-SHA256\n")));
  RCC(rc, finish, iwxstr_printf(xstr2, "%s\n", c.datetime));
  RCC(rc, finish, iwxstr_printf(xstr2, "%s/%s/%s/aws4_request\n", c.date, req->aws_region, req->service));
  RCC(rc, finish, iwxstr_cat(xstr2, hashx, br_sha256_SIZE * 2));

  // Calculate signing key
  iwxstr_clear(xstr);
  RCC(rc, finish, iwxstr_cat(xstr, "AWS4", IW_LLEN("AWS4")));
  RCC(rc, finish, iwxstr_cat(xstr, req->aws_secret_key, strlen(req->aws_secret_key)));
  _hmac(iwxstr_ptr(xstr), iwxstr_size(xstr), c.date, -1, hash);
  _hmac(hash, br_sha256_SIZE, req->aws_region, -1, hash);
  _hmac(hash, br_sha256_SIZE, req->service, -1, hash);
  _hmac(hash, br_sha256_SIZE, "aws4_request", IW_LLEN("aws4_request"), hash);

  // Calculate signature
  _hmac(hash, br_sha256_SIZE, iwxstr_ptr(xstr2), iwxstr_size(xstr2), hash);
  iwbin2hex(hashx, sizeof(hashx), (unsigned char*) hash, sizeof(hash));

  // Add signature Authorization header.
  // Authorization: algorithm Credential=access key ID/credential scope,
  //                SignedHeaders=SignedHeaders, Signature=signature
  iwxstr_clear(xstr);
  RCC(rc, finish,
      iwxstr_printf(xstr, "AWS-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
                    req->aws_key, c.date, req->aws_region, req->service,
                    iwxstr_ptr(c.signed_headers), hashx));


  xcurlreq_hdr_add(xreq, "Authorization", IW_LLEN("Authorization"), iwxstr_ptr(xstr), iwxstr_size(xstr));

finish:
  iwxstr_destroy(xstr);
  iwxstr_destroy(xstr2);
  iwxstr_destroy(c.signed_headers);
  return rc;
}

void aws4_request_destroy(struct aws4_request **reqp) {
  if (!reqp || !*reqp) {
    return;
  }
  struct aws4_request *req = *reqp;
  *reqp = 0;
  xcurlreq_destroy_keep(&req->xreq);
  if (req->xreq.payload) {
    free((void*) req->xreq.payload);
  }
  iwpool_destroy(req->pool);
}

iwrc aws4_request_create(const struct aws4_request_spec *spec, struct aws4_request **out_req) {
  if (!out_req) {
    return IW_ERROR_INVALID_ARGS;
  }

  *out_req = 0;

  if (!spec->aws_region) {
    iwlog_error2("Missing required aws_region");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->aws_key) {
    iwlog_error2("Missing required aws_key");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->aws_secret_key) {
    iwlog_error2("Missing required aws_secret_key");
    return IW_ERROR_INVALID_ARGS;
  }

  IWPOOL *pool = iwpool_create_empty();
  if (!pool) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  struct aws4_request *req = *out_req = iwpool_calloc(sizeof(**out_req), pool);
  if (!*out_req) {
    iwpool_destroy(pool);
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  iwrc rc = 0;
  req->pool = pool;
  req->flags = spec->flags;

  switch (req->flags) {
    case AWS_SERVICE_S3:
      req->service = "s3";
      break;
    case AWS_SERVICE_DYNAMODB:
      req->service = "dynamodb";
      break;
    default:
      iwlog_error("Invalid AWS service specified");
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
  }

  RCB(finish, req->aws_region = iwpool_strdup2(pool, spec->aws_region));
  RCB(finish, req->aws_key = iwpool_strdup2(pool, spec->aws_key));
  RCB(finish, req->aws_secret_key = iwpool_strdup2(pool, spec->aws_secret_key));

  {
    req->aws_url = spec->aws_url ? iwpool_strdup2(pool, spec->aws_url) : 0;
    if (!req->aws_url) {
      RCB(finish,
          req->aws_url = iwpool_printf(req->pool, "https://%s.%s.%s", req->service, req->aws_region, AWS_DNS_SUFFIX));
    }
    char *buf;
    RCB(finish, buf = iwpool_strdup2(pool, req->aws_url));
    if (iwn_url_parse(&req->url, buf)) {
      iwlog_error("Failed to parse aws url: %s", req->aws_url);
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
  }

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
    aws4_request_destroy(out_req);
  }
  return rc;
}

iwrc aws4_request_payload_set(struct aws4_request *req, const struct aws4_request_payload *payload) {
  if (req->xreq.payload) {
    return IW_ERROR_INVALID_STATE;
  }
  iwrc rc = 0;
  char *buf;

  RCB(finish, buf = malloc(payload->payload_len + 1));
  memcpy(buf, payload->payload, payload->payload_len);
  buf[payload->payload_len] = '\0';

  req->xreq.payload = buf;
  req->xreq.payload_len = payload->payload_len;

  const char *ctype = payload->content_type;
  if (!ctype) {
    ctype = "application/x-amz-json-1.0";
  }
  xcurlreq_hdr_add(&req->xreq, "content-type", IW_LLEN("content-type"), ctype, strlen(ctype));
  if (payload->amz_target) {
    xcurlreq_hdr_add(&req->xreq, "x-amz-target", IW_LLEN("x-amz-target"), payload->amz_target,
                     strlen(payload->amz_target));
    req->signed_headers = "x-amz-target";
  }

  req->xreq.flags = XCURLREQ_POST;

finish:
  return rc;
}

iwrc aws4_request_perform(CURL *curl, struct aws4_request *req, char **out) {
  if (!curl || !req || !out || !req->aws_url) {
    return IW_ERROR_INVALID_ARGS;
  }
  iwrc rc = 0;
  CURLcode cc = 0;
  IWXSTR *xstr;
  struct xcurl_cursor dcur;
  IWLIST resp_headers = { 0 };
  long response_code = 0;

  RCB(finish, xstr = iwxstr_new());
  RCC(rc, finish, _sign(req));

  curl_easy_reset(curl);

  XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_URL, req->aws_url));
  XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, xcurl_body_write_xstr));
  XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_WRITEDATA, xstr));
  XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, xcurl_hdr_write_iwlist));
  XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_HEADERDATA, &resp_headers));

  if (req->xreq.payload_len) {
    dcur.rp = req->xreq.payload;
    dcur.end = req->xreq.payload + req->xreq.payload_len;
    xcurlreq_hdr_add(&req->xreq, "Expect", IW_LLEN("Expect"), "", 0);
    XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_READFUNCTION, xcurl_read_cursor));
    XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_READDATA, &dcur));
    XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_INFILESIZE, dcur.end - dcur.rp));
    XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, dcur.end - dcur.rp));
    XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_POST, 1));
  }

  if (req->xreq.headers) {
    XCC(cc, finish, curl_easy_setopt(curl, CURLOPT_HTTPHEADER, req->xreq.headers));
  }

  for (int retry = 0; retry < 3; ++retry) {
    iwxstr_clear(xstr);
    iwlist_destroy_keep(&resp_headers);

    cc = curl_easy_perform(curl);
    if (cc) {
      iwlog_warn("AWS4 | HTTP request failed: %s %s%s",
                 req->aws_url,
                 curl_easy_strerror(cc),
                 retry < 2 ? " retrying in 3 sec" : "");
      if (retry < 2) {
        sleep(RETRY_PAUSE);
        continue;
      }
      XCC(cc, finish, cc);
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (!(response_code >= 200 && response_code < 300)) {
      iwlog_warn("AWS4 | HTTP request failed. Response: %ld %s %s", response_code, req->aws_url, iwxstr_ptr(xstr));
      rc = IW_ERROR_FAIL;
      goto finish;
    }
    break;
  }

finish:
  if (rc) {
    iwxstr_destroy(xstr);
    *out = 0;
  } else {
    *out = iwxstr_destroy_keep_ptr(xstr);
  }
  iwlist_destroy_keep(&resp_headers);
  return rc;
}

iwrc aws4_request(
  CURL                              *curl,
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  char                             **out
  ) {
  iwrc rc = 0;
  struct aws4_request *req = 0;
  if (out) {
    *out = 0;
  }
  RCC(rc, finish, aws4_request_create(spec, &req));
  if (payload) {
    RCC(rc, finish, aws4_request_payload_set(req, payload));
  }
  rc = aws4_request_perform(curl, req, out);

finish:
  aws4_request_destroy(&req);
  return rc;
}

iwrc aws4_request_json(
  CURL                              *curl,
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  IWPOOL                            *pool,
  JBL_NODE                          *out
  ) {
  iwrc rc = 0;
  char *out_buf = 0;

  RCC(rc, finish, aws4_request(curl, spec, payload, &out_buf));
  RCC(rc, finish, jbn_from_json(out_buf, out, pool));

finish:
  free(out_buf);
  return rc;
}
