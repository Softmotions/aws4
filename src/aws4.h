#pragma once

#include <iowow/basedefs.h>
#include <iwnet/iwn_curl.h>


struct aws4_request_sign_spec {

};


iwrc aws4_request_sign(const struct aws4_request_sign_spec *spec, struct xcurlreq *req);













