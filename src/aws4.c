#include "aws4.h"
#include "config.h"

#include <iowow/iwlog.h>
#include <iowow/iwconv.h>
#include <iwnet/iwn_codec.h>
#include <iwnet/bearssl_hash.h>

#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

struct _ctx {
  IWXSTR *xstr;
  struct xcurlreq *req;
  const struct aws4_request_sign_spec *spec;
  char datetime[17]; ///< YYYYMMDD'T'HHMMSS'Z',
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

static int _cr_val_compare(const void *a, const void *b) {
  const struct iwn_val *v1 = a;
  const struct iwn_val *v2 = b;
  int ret = v1->len > v2->len ? 1 : v1->len < v2->len ? -1 : 0;
  if (ret) {
    return ret;
  }
  return strncmp(v1->buf, v2->buf, v1->len);
}

static iwrc _sr_headers_signed_add(struct _ctx *c) {
  iwrc rc = 0;
  size_t cnt = 0;
  struct iwn_val *vals = 0;
  struct iwn_vals hlist = c->spec->headers_to_sign;
  struct iwn_val host = { .buf = "host", .len = IW_LLEN("host") };
  if (!hlist.first) { // Add at least host headers
    hlist.first = &host;
  }

  for (struct iwn_val *v = hlist.first; v; v = v->next) {
    ++cnt;
  }

  vals = malloc(sizeof(*vals) * cnt);
  if (!vals) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }

  cnt = 0;
  for (struct iwn_val *v = hlist.first; v; v = v->next) {
    vals[cnt++] = *v;
  }

  qsort(vals, cnt, sizeof(vals[0]), _cr_val_compare);

  for (size_t i = 0; i < cnt; ++i) {
    if (i) {
      RCC(rc, finish, iwxstr_cat(c->xstr, ";", 1));
    }
    RCC(rc, finish, iwxstr_cat(c->xstr, vals[i].buf, vals[i].len));
    char *ep = iwxstr_ptr(c->xstr) + iwxstr_size(c->xstr);
    char *sp = ep - vals[i].len;
    for ( ; sp < ep; ++sp) {
      *sp = tolower(*sp);
    }
  }

  RCC(rc, finish, iwxstr_cat(c->xstr, "\n", 1));

finish:
  free(vals);
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

static void _sr_fill_request_hash(IWXSTR *xstr, char out[static br_sha256_SIZE * 2]) {
  uint8_t hash_bits[br_sha256_SIZE];
  br_sha256_context ctx;
  br_sha256_init(&ctx);
  br_sha256_update(&ctx, iwxstr_ptr(xstr), iwxstr_size(xstr));
  br_sha256_out(&ctx, hash_bits);
  iwbin2hex(out, br_sha256_SIZE * 2, hash_bits, sizeof(hash_bits));
}

iwrc aws4_request_sign(const struct aws4_request_sign_spec *spec, struct xcurlreq *req) {
  if (!spec->aws_host) {
    iwlog_error2("Missing required spec->aws_host value");
    return IW_ERROR_INVALID_ARGS;
  }

  iwrc rc = 0;
  char request_hash[br_sha256_SIZE * 2 + 1];
  IWXSTR *xstr = iwxstr_new();
  if (!xstr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  struct _ctx c = {
    .req  = req,
    .spec = spec,
    .xstr = xstr
  };

  RCC(rc, finish, _ctx_init(&c));
  RCC(rc, finish, _sr_method_add(&c));
  RCC(rc, finish, _sr_uri_add(&c));
  RCC(rc, finish, _sr_qs_add(&c));
  RCC(rc, finish, _sr_headers_add(&c));
  RCC(rc, finish, _sr_headers_signed_add(&c));
  RCC(rc, finish, _sr_payload_hash_add(&c));

  _sr_fill_request_hash(xstr, request_hash);
  request_hash[br_sha256_SIZE * 2] = '\0';
  iwxstr_clear(xstr);

  // String to sign
  RCC(rc, finish, iwxstr_cat(xstr, "AWS4-HMAC-SHA256\n", IW_LLEN("AWS4-HMAC-SHA256\n")));


finish:
  iwxstr_destroy(xstr);
  return rc;
}
