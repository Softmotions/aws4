# AWS HTTP client library in pure C

AWS4 is an low level client library used for signing and sending 
to Amazon Webservices HTTP API. 

## Prerequisites

* libcurl with SSL enabled
* gcc or clang C11 compiler (tested on clang v14 / gcc v11) 
* cmake v3.18+, make or ninja

## Building

```sh
git clone https://github.com/Softmotions/aws4
cd ./aws4 && mkdir ./build
cmake -DCMAKE_BUILD_TYPE=Release  ..
make
```

## Example 

```c
  // ListTables request to DynamoDB AWS service
  // Testcase code snippet

  iwrc rc = 0;
  char *out = 0;
  CURL *curl = curl_easy_init();

  rc = aws4_request(curl, &(struct aws4_request_spec) {
    .flags = AWS_SERVICE_DYNAMODB | AWS_CREDENTIALS_AUTO,
    .aws_region = "us-east-1",
  }, &(struct aws4_request_payload) {
    .payload = "{}",
    .payload_len = IW_LLEN("{}"),
    .amz_target = "DynamoDB_20120810.ListTables"
  }, &out);

  IWN_ASSERT(rc == 0);
  if (out) {
    IWN_ASSERT(0 == strcmp(out, "{\"TableNames\":[]}"))
  }

  free(out);
  curl_easy_cleanup(curl);
}
```

