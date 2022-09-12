#include "aws4.h"
#include "config.h"

#include <iowow/iwlog.h>
#include <iowow/iwconv.h>
#include <iwnet/iwn_codec.h>
#include <iwnet/bearssl_hash.h>
#include <iwnet/bearssl_hmac.h>

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct _ctx {
  IWXSTR *xstr;
  IWXSTR *signed_headers;
  struct xcurlreq *req;
  const struct aws4_request_sign_spec *spec;
  const char *service;
  char datetime[20]; ///< YYYYMMDD'T'HHMMSS'Z',
  char date[10];     ///< YYYYMMDD
};

static iwrc _ctx_init(struct _ctx *c) {
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
  bool user_agent_found = false;

  // Set host header
  for (struct curl_slist *h = c->req->headers; h; h = h->next) {
    if (strncasecmp(h->data, "host:", IW_LLEN("host:")) == 0) {
      host_found = true;
    } else if (strncasecmp(h->data, "accept:", IW_LLEN("accept:")) == 0) {
      accept_found = true;
    } else if (strncasecmp(h->data, "user-agent:", IW_LLEN("user-agent:")) == 0) {
      user_agent_found = false;
    }
  }

  if (!user_agent_found) {
    xcurlreq_hdr_add(c->req, "user-agent", IW_LLEN("user-agent"), "aws4/1.0", IW_LLEN("aws4/1.0"));
  }

  if (!host_found) {
    xcurlreq_hdr_add(c->req, "host", IW_LLEN("host"), c->spec->aws_host, -1);
  }

  if (!accept_found) {
    xcurlreq_hdr_add(c->req, "accept", IW_LLEN("accept"), "*/*", IW_LLEN("*/*"));
  }

  xcurlreq_hdr_add(c->req, "x-amz-date", IW_LLEN("x-amz-date"), c->datetime, -1);

  return 0;
}

static iwrc _sr_method_add(struct _ctx *c) {
  const char *method = "GET";
  if (c->req->flags & XCURLREQ_POST) {
    method = "POST";
  } else if (c->req->flags & XCURLREQ_PUT) {
    method = "PUT";
  } else if (c->req->flags & XCURLREQ_DEL) {
    method = "DELETE";
  } else if (c->req->flags & XCURLREQ_HEAD) {
    method = "HEAD";
  } else if (c->req->flags & XCURLREQ_OPTS) {
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

static iwrc _sr_uri_add(struct _ctx *c) {
  const char *sp = c->req->path;
  const char *ep = sp;
  while (*ep) {
    while (*ep && *ep == '/') {
      ++sp;
      ++ep;
    }
    while (*ep && *ep != '/') {
      ++ep;
    }
    if (ep > sp) {
      char *s = _sr_section_create(c->req, sp, ep);
      if (!s) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
      }
      RCR(iwxstr_printf(c->xstr, "/%s", s));
    } else if (sp == c->req->path) {
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
  int ret = p1->key_len > p2->key_len ? 1 : p1->key_len < p2->key_len ? -1 : 0;
  if (ret) {
    return ret;
  }
  ret = strncmp(p1->key, p2->key, p1->key_len);
  if (ret) {
    return ret;
  }
  ret = p1->val_len > p2->val_len ? 1 : p1->val_len < p2->val_len ? -1 : 0;
  if (ret) {
    return ret;
  }
  return strncmp(p1->val, p2->val, p1->val_len);
}

static iwrc _sr_qs_add(struct _ctx *c) {
  if (!c->req->_qxstr || iwxstr_size(c->req->_qxstr) == 0) {
    return iwxstr_cat(c->xstr, "\n", 1);
  }
  iwrc rc = 0;
  IWPOOL *pool = 0;
  struct iwn_pairs pairs;

  char *buf = 0;
  size_t buflen = 0;

  size_t len = iwxstr_size(c->req->_qxstr);
  RCB(finish, pool = iwpool_create_empty());

  char *qs = iwpool_strndup2(pool, iwxstr_ptr(c->req->_qxstr), len);
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
  int ret = h1->key_len > h2->key_len ? 1 : h1->key_len < h2->key_len ? -1 : 0;
  if (ret) {
    return ret;
  }
  return strncmp(h1->key, h2->key, h1->key_len);
}

static iwrc _sr_headers_add(struct _ctx *c) {
  iwrc rc = 0;
  IWPOOL *pool = 0;
  RCB(finish, pool = iwpool_create_empty());
  size_t len = 0;
  for (struct curl_slist *h = c->req->headers; h; h = h->next) {
    ++len;
  }
  struct iwn_pair *harr;
  RCB(finish, harr = iwpool_alloc(sizeof(harr[0]) * len, pool));

  len = 0;
  for (struct curl_slist *h = c->req->headers; h; h = h->next) {
    RCC(rc, finish, _cr_header_fill(pool, h->data, &harr[len++]));
  }

  qsort(harr, len, sizeof(harr[0]), _cr_header_pair_compare);

  for (size_t i = 0; i < len; ++i) {
    RCC(rc, finish, iwxstr_cat(c->xstr, harr[i].key, harr[i].key_len));
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

static iwrc _sr_headers_signed_add(struct _ctx *c) {
  iwrc rc = 0;
  int cnt = 0;
  IWPOOL *pool = 0;
  IWXSTR *xstr = 0;

  RCB(finish, pool = iwpool_create_empty());
  RCB(finish, xstr = iwxstr_new_printf("content-type;host;x-amz-date"));
  if (c->spec->signed_headers) {
    RCC(rc, finish, iwxstr_cat(xstr, ";", 1));
    RCC(rc, finish, iwxstr_cat2(xstr, c->spec->signed_headers));
  }

  const char **tokens = iwpool_split_string(pool, iwxstr_ptr(xstr), ";", true);
  for (const char **hh = tokens; hh; ++hh) {
    ++cnt;
  }

  qsort(tokens, cnt, sizeof(*tokens), _sr_header_compare);

  RCB(finish, c->signed_headers = iwxstr_new2(iwxstr_size(xstr)));
  for (const char **hh = tokens, *ph = 0; *hh; ++hh) {
    if (ph && strcmp(*hh, ph) == 0) {
      continue;
    }
    ph = *hh;
    if (hh != tokens) {
      RCC(rc, finish, iwxstr_cat(c->xstr, ";", 1));
    }
    RCC(rc, finish, iwxstr_cat2(c->xstr, *hh));
  }
  RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));

finish:
  iwxstr_destroy(xstr);
  iwpool_destroy(pool);
  return rc;
}

static iwrc _sr_payload_hash_add(struct _ctx *c) {
  if (c->req->payload_len == 0) {
    return iwxstr_cat(c->xstr, "\n", 1);
  }
  char hash[br_sha256_SIZE * 2 + 1];
  uint8_t hash_bits[br_sha256_SIZE];
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, c->req->payload, c->req->payload_len);
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
  iwbin2hex(out, br_sha256_SIZE * 2, hash_bits, sizeof(hash_bits));
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

iwrc aws4_request_sign(const struct aws4_request_sign_spec *spec, struct xcurlreq *req) {
  if (!spec->aws_host) {
    iwlog_error2("Missing required spec->aws_host");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->aws_region) {
    iwlog_error2("Missing required spec->aws_region");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->aws_key) {
    iwlog_error2("Missing required spec->aws_key");
    return IW_ERROR_INVALID_ARGS;
  }
  if (!spec->aws_secret_key) {
    iwlog_error2("Missing required spec->aws_secret_key");
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  char hash[br_sha256_SIZE];
  char hashx[br_sha256_SIZE * 2 + 1]; // hex hash representation

  IWXSTR *xstr2 = 0, *xstr = iwxstr_new();
  RCB(finish, xstr);
  RCB(finish, xstr2 = iwxstr_new());

  struct _ctx c = {
    .req  = req,
    .spec = spec,
    .xstr = xstr
  };

  switch (spec->aws_service) {
    case AWS_SERVICE_S3:
      c.service = "s3";
      break;
    case AWS_SERVICE_DYNAMODB:
      c.service = "dynamodb";
      break;
    default:
      iwlog_error("Invalid AWS service specidif");
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
  }

  RCC(rc, finish, _ctx_init(&c));
  RCC(rc, finish, _sr_method_add(&c));
  RCC(rc, finish, _sr_uri_add(&c));
  RCC(rc, finish, _sr_qs_add(&c));
  RCC(rc, finish, _sr_headers_add(&c));
  RCC(rc, finish, _sr_headers_signed_add(&c));
  RCC(rc, finish, _sr_payload_hash_add(&c));

  _sr_fill_request_hash(xstr, hashx);
  iwxstr_clear(xstr);

  // String to sign
  iwxstr_clear(xstr2);
  RCC(rc, finish, iwxstr_cat(xstr2, "AWS4-HMAC-SHA256\n", IW_LLEN("AWS4-HMAC-SHA256\n")));
  RCC(rc, finish, iwxstr_printf(xstr2, "%s\n", c.datetime));
  RCC(rc, finish, iwxstr_printf(xstr2, "%s/%s/%s/aws4_request\n", c.date, spec->aws_region, c.service));
  RCC(rc, finish, iwxstr_cat(xstr2, hashx, br_sha256_SIZE * 2));

  // Calculate signing key
  iwxstr_clear(xstr);
  RCC(rc, finish, iwxstr_cat(xstr, "AWS4", IW_LLEN("AWS4")));
  RCC(rc, finish, iwxstr_cat(xstr, spec->aws_secret_key, strlen(spec->aws_secret_key)));
  _hmac(iwxstr_ptr(xstr), iwxstr_size(xstr), c.date, -1, hash);
  _hmac(hash, br_sha256_SIZE, spec->aws_region, -1, hash);
  _hmac(hash, br_sha256_SIZE, c.service, -1, hash);
  _hmac(hash, br_sha256_SIZE, "aws4_request", IW_LLEN("aws4_request"), hash);

  // Calculate signature
  _hmac(hash, br_sha256_SIZE, iwxstr_ptr(xstr2), iwxstr_size(xstr2), hash);

  // Add signature Authorization header.
  // Authorization: algorithm Credential=access key ID/credential scope,
  //                SignedHeaders=SignedHeaders, Signature=signature
  iwxstr_clear(xstr);
  RCC(rc, finish,
      iwxstr_printf(xstr, "AWS-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
                    spec->aws_key, c.date, spec->aws_region, c.service,
                    iwxstr_ptr(c.signed_headers), iwxstr_ptr(xstr2)));

  xcurlreq_hdr_add(req, "Authorization", IW_LLEN("Authorization"), iwxstr_ptr(xstr), iwxstr_size(xstr));

finish:
  iwxstr_destroy(xstr);
  iwxstr_destroy(xstr2);
  iwxstr_destroy(c.signed_headers);
  return rc;
}
