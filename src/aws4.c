#include "aws4.h"
#include "config.h"

#include <iowow/iwlog.h>
#include <iwnet/iwn_codec.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

static iwrc _cr_method_add(struct xcurlreq *req, IWXSTR *xstr) {
  const char *method = "GET";
  if (req->flags & XCURLREQ_POST) {
    method = "POST";
  } else if (req->flags & XCURLREQ_PUT) {
    method = "PUT";
  } else if (req->flags & XCURLREQ_DEL) {
    method = "DELETE";
  } else if (req->flags & XCURLREQ_HEAD) {
    method = "HEAD";
  } else if (req->flags & XCURLREQ_OPTS) {
    method = "OPTIONS";
  }
  return iwxstr_printf(xstr, "%s\n", method);
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

static IW_ALLOC char* _cr_section_create(struct xcurlreq *req, const char *sp, const char *ep) {
  assert(ep > sp);
  int rounds = (req->flags & AWS_SERVICE_S3) ? 1 : 2;
  return _uri_encode(sp, ep - sp, rounds);
}

static iwrc _cr_uri_add(struct xcurlreq *req, IWXSTR *xstr) {
  const char *sp = req->path;
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
      char *s = _cr_section_create(req, sp, ep);
      if (!s) {
        return iwrc_set_errno(IW_ERROR_ALLOC, errno);
      }
      RCR(iwxstr_printf(xstr, "/%s", s));
    } else if (sp == req->path) {
      RCR(iwxstr_cat(xstr, "/", 1));
      break;
    }
    sp = ep;
  }
  return iwxstr_cat(xstr, "\n", 1);
}

static int _cr_qs_pair_compare(const void *a, const void *b) {
  const struct iwn_pair *p1 = a;
  const struct iwn_pair *p2 = b;
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

static iwrc _cr_qs_add(struct xcurlreq *req, IWXSTR *xstr) {
  if (!req->_qxstr || iwxstr_size(req->_qxstr) == 0) {
    return iwxstr_cat(xstr, "\n", 1);
  }
  iwrc rc = 0;
  IWPOOL *pool = 0;
  struct iwn_pairs pairs;

  char *buf = 0;
  size_t buflen = 0;

  size_t len = iwxstr_size(req->_qxstr);
  RCB(finish, pool = iwpool_create_empty());

  char *qs = iwpool_strndup2(pool, iwxstr_ptr(req->_qxstr), len);
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
      RCC(rc, finish, iwxstr_cat(xstr, "&", 1));
    }
    iwn_url_encode(p->key, p->key_len, buf, buflen);
    RCC(rc, finish, iwxstr_cat(xstr, buf, len));
    RCC(rc, finish, iwxstr_cat(xstr, "=", 1));
    if (p->val_len) {
      len = iwn_url_encoded_aws_len(p->val, p->val_len);
      if (len > buflen) {
        RCB(finish, buf = realloc(buf, len));
        buflen = len;
      }
      iwn_url_encode_aws(p->val, p->val_len, buf, buflen);
      RCC(rc, finish, iwxstr_cat(xstr, buf, len));
    }
  }

  RCC(rc, finish, iwxstr_cat(xstr, "\n", 1));

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

static iwrc _cr_headers_add(struct xcurlreq *req, IWXSTR *xstr) {
  iwrc rc = 0;
  IWPOOL *pool = 0;
  RCB(finish, pool = iwpool_create_empty());
  size_t len = 0;
  for (struct curl_slist *h = req->headers; h; h = h->next) {
    ++len;
  }
  struct iwn_pair *harr;
  RCB(finish, harr = iwpool_alloc(sizeof(harr[0]) * len, pool));

  len = 0;
  for (struct curl_slist *h = req->headers; h; h = h->next) {
    RCC(rc, finish, _cr_header_fill(pool, h->data, &harr[len++]));
  }

finish:
  iwpool_destroy(pool);
  return rc;
}

iwrc aws4_request_sign(const struct aws4_request_sign_spec *spec, struct xcurlreq *req) {
  iwrc rc = 0;
  IWXSTR *cr = iwxstr_new();
  if (!cr) {
    return iwrc_set_errno(IW_ERROR_ALLOC, errno);
  }
  RCC(rc, finish, _cr_method_add(req, cr));
  RCC(rc, finish, _cr_uri_add(req, cr));
  RCC(rc, finish, _cr_qs_add(req, cr));
  RCC(rc, finish, _cr_headers_add(req, cr));

finish:
  iwxstr_destroy(cr);
  return rc;
}
