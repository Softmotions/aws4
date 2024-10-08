#include "aws4.h"
#include "config.h"

#include <iowow/iwlog.h>
#include <iowow/iwconv.h>
#include <iowow/iwarr.h>
#include <iowow/iwini.h>

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
#include <ctype.h>

#define AWS_DNS_SUFFIX      "amazonaws.com"
#define AWS_DYNAMODB_PREFIX "dynamodb"

#define RETRY_PAUSE 3

struct aws4_request {
  const char     *aws_config_profile;
  const char     *aws_key;
  const char     *aws_secret_key;
  const char     *aws_region;
  const char     *aws_url;
  const char     *service;
  struct xcurlreq xreq;
  struct iwn_url  url;
  IWPOOL *pool;

  unsigned connect_attempt_timeout_sec;
  unsigned reconnect_attempts_max;
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
  if (ep) {
    while (*ep != '\0') {
      while (*ep == '/') {
        ++sp;
        ++ep;
      }
      while (*ep != '\0' && *ep != '/') {
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
  } else {
    RCR(iwxstr_cat(c->xstr, "/", 1));
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

  char *buf = 0, *nbuf = 0;
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
      RCB(finish, nbuf = realloc(buf, len));
      buf = nbuf;
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
        RCB(finish, nbuf = realloc(buf, len));
        buf = nbuf;
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
  //RCB(finish, xstr = iwxstr_new_printf("content-type;host;x-amz-date;x-amz-target"));
  iwrc rc = 0;
  IWPOOL *pool = 0;

  RCB(finish, c->signed_headers = iwxstr_new());
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
    const char *key = harr[i].key;
    if (  strcmp("content-type", key) == 0
       || strcmp("host", key) == 0
       || strcmp("x-amz-date", key) == 0
       || strcmp("x-amz-target", key) == 0) {
      RCC(rc, finish, iwxstr_cat(c->xstr, harr[i].key, harr[i].key_len));
      RCC(rc, finish, iwxstr_cat(c->xstr, ":", 1));
      RCC(rc, finish, iwxstr_cat(c->xstr, harr[i].val, harr[i].val_len));
      RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));
      if (iwxstr_size(c->signed_headers)) {
        RCC(rc, finish, iwxstr_cat(c->signed_headers, ";", 1));
      }
      RCC(rc, finish, iwxstr_cat(c->signed_headers, harr[i].key, harr[i].key_len));
    }
  }

  RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));
  RCC(rc, finish, iwxstr_cat(c->xstr, iwxstr_ptr(c->signed_headers), iwxstr_size(c->signed_headers)));
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

static iwrc _sr_payload_hash_add(struct _sign_ctx *c) {
  if (c->xreq->payload_len == 0) {
    return 0;
  }
  char hash[br_sha256_SIZE * 2 + 1];
  uint8_t hash_bits[br_sha256_SIZE];
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, c->xreq->payload, c->xreq->payload_len);
  br_sha256_out(&ctx, hash_bits);
  iwbin2hex(hash, sizeof(hash), hash_bits, sizeof(hash_bits));
  RCR(iwxstr_cat(c->xstr, hash, sizeof(hash) - 1));
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
  char out_buf[br_sha256_SIZE]) {
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
    .req = req,
    .xstr = xstr
  };

  RCC(rc, finish, _sign_ctx_init(&c));
  RCC(rc, finish, _sr_method_add(&c));
  RCC(rc, finish, _sr_uri_add(&c));
  RCC(rc, finish, _sr_qs_add(&c));
  RCC(rc, finish, _sr_headers_add(&c));
  RCC(rc, finish, _sr_payload_hash_add(&c));

  _sr_fill_request_hash(xstr, hashx);

  if (req->verbose) {
    iwlog_info("AWS4 | Canonical request:\n%s", iwxstr_ptr(xstr));
  }

  // String to sign
  iwxstr_clear(xstr2);
  RCC(rc, finish, iwxstr_cat(xstr2, "AWS4-HMAC-SHA256\n", IW_LLEN("AWS4-HMAC-SHA256\n")));
  RCC(rc, finish, iwxstr_printf(xstr2, "%s\n", c.datetime));
  RCC(rc, finish, iwxstr_printf(xstr2, "%s/%s/%s/aws4_request\n", c.date, req->aws_region, req->service));
  RCC(rc, finish, iwxstr_cat(xstr2, hashx, (size_t) br_sha256_SIZE * 2));


  if (req->verbose) {
    iwlog_info("AWS4 | String to sign:\n%s", iwxstr_ptr(xstr2));
  }

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
      iwxstr_printf(xstr, "AWS4-HMAC-SHA256 Credential=%s/%s/%s/%s/aws4_request, SignedHeaders=%s, Signature=%s",
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

static int _creds_ini_handler(void *d, const char *section, const char *name, const char *value) {
  struct aws4_request *req = d;
  if (!name) {
    return 0;
  }

  if (strncmp("profile", section, IW_LLEN("profile")) == 0) {
    if (isspace(*(section + IW_LLEN("profile")))) {
      section += IW_LLEN("profile");
      do {
        ++section;
      } while (*section != '\0' && isspace(*section));
      if (*section == '\0') {
        return 1;
      }
    }
  }

  if (  value
     && (  (req->aws_config_profile && strcmp(section, req->aws_config_profile) == 0)
        || (!req->aws_config_profile && (*section == '\0' || strcmp("default", section) == 0)))) {
    if (strcmp("aws_access_key_id", name) == 0 && !req->aws_key) {
      req->aws_key = iwpool_strdup2(req->pool, value);
    } else if (strcmp("aws_secret_access_key", name) == 0 && !req->aws_secret_key) {
      req->aws_secret_key = iwpool_strdup2(req->pool, value);
    }
  }

  return 1;
}

static int _config_ini_handler(void *d, const char *section, const char *name, const char *value) {
  struct aws4_request *req = d;
  if (!name) {
    return 0;
  }

  if (strncmp("profile", section, IW_LLEN("profile")) == 0) {
    if (isspace(*(section + IW_LLEN("profile")))) {
      section += IW_LLEN("profile");
      do {
        ++section;
      } while (*section != '\0' && isspace(*section));
      if (*section == '\0') {
        return 1;
      }
    }
  }

  if (  value
     && (  (req->aws_config_profile && strcmp(section, req->aws_config_profile) == 0)
        || (!req->aws_config_profile && (*section == '\0' || strcmp("default", section) == 0)))) {
    if (strcmp("region", name) == 0 && !req->aws_region) {
      req->aws_region = iwpool_strdup2(req->pool, value);
    }
  }

  return 1;
}

IW_INLINE bool _creds_try_load_file(struct aws4_request *req, const char *file) {
  return file && iwini_parse(file, _creds_ini_handler, req) == 0;
}

IW_INLINE bool _config_try_load_file(struct aws4_request *req, const char *file) {
  return file && iwini_parse(file, _config_ini_handler, req) == 0;
}

static bool _creds_try_load_dir(struct aws4_request *req, const char *base) {
  if (!base) {
    return false;
  }
#ifndef _WIN32
  IWXSTR *xstr = iwxstr_new_printf("%s/.aws/credentials", base);
#else
  IWXSTR *xstr = iwxstr_new_printf("%s\\.aws\\credentials", base);
#endif
  if (!xstr) {
    return false;
  }
  bool ret = _creds_try_load_file(req, iwxstr_ptr(xstr));
  iwxstr_destroy(xstr);
  return ret;
}

static bool _config_try_load_dir(struct aws4_request *req, const char *base) {
  if (!base) {
    return false;
  }
#ifndef _WIN32
  IWXSTR *xstr = iwxstr_new_printf("%s/.aws/config", base);
#else
  IWXSTR *xstr = iwxstr_new_printf("%s\\.aws\\config", base);
#endif
  if (!xstr) {
    return false;
  }
  bool ret = _config_try_load_file(req, iwxstr_ptr(xstr));
  iwxstr_destroy(xstr);
  return ret;
}

static iwrc _creds_load(const struct aws4_request_spec *spec, struct aws4_request *req) {
  iwrc rc = 0;
  IWPOOL *pool = req->pool;
  if (!req->aws_config_profile && spec->aws_config_profile) {
    RCB(finish, req->aws_config_profile = iwpool_strdup2(pool, spec->aws_config_profile));
  }
  if (spec->aws_key) {
    RCB(finish, req->aws_key = iwpool_strdup2(pool, spec->aws_key));
  }
  if (spec->aws_secret_key) {
    RCB(finish, req->aws_secret_key = iwpool_strdup2(pool, spec->aws_secret_key));
  }
  if (!req->aws_secret_key || !req->aws_key) {
    if (_creds_try_load_file(req, getenv("AWS_SHARED_CREDENTIALS_FILE"))) {
      goto finish;
    }
    if (_creds_try_load_dir(req, getenv("HOME"))) {
      goto finish;
    }
#ifdef _WIN32
    if (_creds_try_load_file(req, getenv("USERPROFILE"))) {
      goto finish;
    }
#endif
  }

finish:
  return rc;
}

static iwrc _config_load(const struct aws4_request_spec *spec, struct aws4_request *req) {
  iwrc rc = 0;
  IWPOOL *pool = req->pool;
  if (!req->aws_config_profile && spec->aws_config_profile) {
    RCB(finish, req->aws_config_profile = iwpool_strdup2(pool, spec->aws_config_profile));
  }
  if (spec->aws_region) {
    RCB(finish, req->aws_region = iwpool_strdup2(pool, spec->aws_region));
  } else {
    if (_config_try_load_file(req, getenv("AWS_CONFIG_FILE"))) {
      goto finish;
    }
    if (_config_try_load_dir(req, getenv("HOME"))) {
      goto finish;
    }
#ifdef _WIN32
    if (_config_try_load_file(req, getenv("USERPROFILE"))) {
      goto finish;
    }
#endif
  }

finish:
  return rc;
}

iwrc aws4_request_create(const struct aws4_request_spec *spec, struct aws4_request **out_req) {
  if (!out_req) {
    return IW_ERROR_INVALID_ARGS;
  }
  *out_req = 0;

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

  req->connect_attempt_timeout_sec = spec->connect_attempt_timeout_sec;
  if (!req->connect_attempt_timeout_sec) {
    req->connect_attempt_timeout_sec = 10U;
  }

  req->reconnect_attempts_max = spec->reconnect_attempts_max;
  if (!req->reconnect_attempts_max) {
    req->reconnect_attempts_max = 3U;
  }

  req->verbose = (spec->flags & AWS_REQUEST_VERBOSE) != 0;

  RCC(rc, finish, _creds_load(spec, req));
  RCC(rc, finish, _config_load(spec, req));

  if (!req->aws_region) {
    iwlog_error2("AWS4 | `aws_region` configuration key is not specified");
    return IW_ERROR_INVALID_ARGS;
  }

  if (!req->aws_key) {
    iwlog_error2("AWS4 | `aws_key` configuration key is not specified");
    rc = IW_ERROR_INVALID_ARGS;
    goto finish;
  }

  if (!req->aws_secret_key) {
    iwlog_error2("AWS4 | `aws_secret_key` configuration key is not specified");
    rc = IW_ERROR_INVALID_ARGS;
    goto finish;
  }

  switch (req->flags & AWS_SERVICE_ALL) {
    case AWS_SERVICE_S3:
      req->service = "s3";
      break;
    case AWS_SERVICE_DYNAMODB:
      req->service = "dynamodb";
      break;
    default:
      iwlog_error("AWS4 | Invalid AWS service specified");
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
  }

  {
    req->aws_url = spec->aws_url ? iwpool_strdup2(pool, spec->aws_url) : 0;
    if (!req->aws_url) {
      RCB(finish,
          req->aws_url = iwpool_printf(req->pool, "https://%s.%s.%s", req->service, req->aws_region, AWS_DNS_SUFFIX));
    }
    char *buf;
    RCB(finish, buf = iwpool_strdup2(pool, req->aws_url));
    if (iwn_url_parse(&req->url, buf)) {
      iwlog_error("AWS4 | Failed to parse aws url: %s", req->aws_url);
      rc = IW_ERROR_INVALID_ARGS;
      goto finish;
    }
  }

finish:
  if (rc) {
    iwlog_ecode_error2(rc, "AWS4 | Failed to create request");
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
  }

  req->xreq.flags = XCURLREQ_POST;

finish:
  return rc;
}

iwrc aws4_request_payload_json_set(struct aws4_request *req, const char *amz_target, JBL_NODE json) {
  if (!req || !json) {
    return IW_ERROR_INVALID_ARGS;
  }

  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  iwrc rc = jbn_as_json(json, jbl_xstr_json_printer, xstr, 0);
  if (!rc) {
    rc = aws4_request_payload_set(req, &(struct aws4_request_payload) {
      .payload = iwxstr_ptr(xstr),
      .payload_len = iwxstr_size(xstr),
      .content_type = "application/x-amz-json-1.0",
      .amz_target = amz_target,
    });
  }

  iwxstr_destroy(xstr);
  return rc;
}

iwrc aws4_request_perform(CURL *curl, struct aws4_request *req, char **out, int *out_scode) {
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

  if (req->verbose) {
    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
  }

  if (req->connect_attempt_timeout_sec) {
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, req->connect_attempt_timeout_sec);
  }

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

  for (int retry = 0; retry < req->reconnect_attempts_max; ++retry) {
    iwxstr_clear(xstr);
    iwlist_destroy_keep(&resp_headers);

    cc = curl_easy_perform(curl);
    if (cc) {
      iwlog_warn("AWS4 | HTTP request failed: %s %s%s",
                 req->aws_url,
                 curl_easy_strerror(cc),
                 retry < req->reconnect_attempts_max - 1 ? " retrying in 3 sec" : "");
      if (retry < req->reconnect_attempts_max - 1) {
        sleep(RETRY_PAUSE);
        continue;
      }
      XCC(cc, finish, cc);
    }
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
    if (out_scode) {
      *out_scode = response_code;
    }

    if (!(req->flags & AWS_REQUEST_ACCEPT_ANY_STATUS_CODE)) {
      if (!(response_code >= 200 && response_code < 300)) {
        iwlog_warn("AWS4 | HTTP request failed. Response: %ld %s %s", response_code, req->aws_url, iwxstr_ptr(xstr));
        rc = AWS4_API_REQUEST_ERROR;
        goto finish;
      }
    }

    break;
  }

  if (req->verbose) {
    iwlog_info("AWS4 | Response: %s", iwxstr_ptr(xstr));
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

iwrc aws4_request_raw(
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  char                             **out,
  int                               *out_scode) {
  if (!spec || !out) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  struct aws4_request *req = 0;
  *out = 0;

  CURL *curl;
  if (spec->curl) {
    curl_easy_reset(spec->curl);
    curl = spec->curl;
  } else {
    curl = curl_easy_init();
    if (!curl) {
      return IW_ERROR_FAIL;
    }
  }

  if (curl == spec->curl) {
    curl_easy_reset(curl);
  }

  RCC(rc, finish, aws4_request_create(spec, &req));

  if (payload) {
    RCC(rc, finish, aws4_request_payload_set(req, payload));
  }

  rc = aws4_request_perform(curl, req, out, out_scode);

finish:
  aws4_request_destroy(&req);
  if (curl == spec->curl) {
    curl_easy_reset(curl);
  } else {
    curl_easy_cleanup(curl);
  }
  return rc;
}

iwrc aws4_request_raw_json_get(
  const struct aws4_request_spec    *spec,
  const struct aws4_request_payload *payload,
  IWPOOL                            *pool,
  JBL_NODE                          *out,
  int                               *out_scode) {
  if (!spec || !pool || !out) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  char *out_buf = 0;

  RCC(rc, finish, aws4_request_raw(spec, payload, &out_buf, out_scode));
  RCC(rc, finish, jbn_from_json(out_buf, out, pool));

finish:
  free(out_buf);
  return rc;
}

iwrc aws4_request_json(
  const struct aws4_request_spec         *spec,
  const struct aws4_request_json_payload *json_payload,
  IWPOOL                                 *pool,
  JBL_NODE                               *out,
  int                                    *out_scode) {
  if (!spec || !pool || !out || (json_payload && !json_payload->json)) {
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  IWXSTR *xstr = 0;
  struct aws4_request_payload payload;
  bool verbose = spec->flags & (AWS_REQUEST_VERBOSE | AWS_REQUEST_JUST_PRINT);

  if (json_payload) {
    RCB(finish, xstr = iwxstr_new());
    RCC(rc, finish, jbn_as_json(json_payload->json, jbl_xstr_json_printer, xstr, verbose ? JBL_PRINT_PRETTY : 0));
    if (verbose) {
      iwlog_info("AWS4 | Payload: %s", iwxstr_ptr(xstr));
    }

    payload = (struct aws4_request_payload) {
      .payload = iwxstr_ptr(xstr),
      .payload_len = iwxstr_size(xstr),
      .content_type = "application/x-amz-json-1.0",
      .amz_target = json_payload->amz_target,
    };
  }

  if (!(spec->flags & AWS_REQUEST_JUST_PRINT)) {
    rc = aws4_request_raw_json_get(spec, json_payload ? &payload : 0, pool, out, out_scode);
  }

finish:
  iwxstr_destroy(xstr);
  return rc;
}

static const char* _ecodefn(locale_t locale, uint32_t ecode) {
  if (ecode <= _AWS4_ERROR_START || ecode >= _AWS4_ERROR_END) {
    return 0;
  }
  switch (ecode) {
    case AWS4_API_REQUEST_ERROR:
      return "Failed to call AWS HTTP API endpoint (AWS4_API_REQUEST_ERROR)";
  }
  return 0;
}

IW_CONSTRUCTOR void _aws4_init(void) {
  iwrc rc = iw_init();
  if (rc) {
    iwlog_ecode_error(rc, "AWS4 | Failed to initialize iowow");
    abort();
  }
  rc = iwlog_register_ecodefn(_ecodefn);
  if (rc) {
    iwlog_ecode_error(rc, "AWS4 | Failed to register ecodefn");
    abort();
  }
}
