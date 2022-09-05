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

static iwrc _cr_qs_add(struct xcurlreq *req, IWXSTR *xstr) {
  if (!req->_qxstr || iwxstr_size(req->_qxstr) == 0) {
    return iwxstr_cat(xstr, "\n", 1);
  }
  iwrc rc = 0;
  


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


finish:
  iwxstr_destroy(cr);
  return rc;
}
