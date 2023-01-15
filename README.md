# AWS API client library in pure C

AWS4 is a C client library used for signing and sending requests to AWS HTTP APIs.
Also it offers a simple DynamoDB client API.

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
iwrc rc = 0;
char *out = 0;

rc = aws4_request_raw(&(struct aws4_request_spec) {
  .flags = AWS_SERVICE_DYNAMODB,
  .aws_region = "us-east-1",
  .aws_key = "fakeMyKeyId",
  .aws_secret_key = "fakeSecretAccessKey",
  .aws_url = "http://localhost:8000"
}, &(struct aws4_request_payload) {
  .payload = "{}",
  .payload_len = IW_LLEN("{}"),
  .amz_target = "DynamoDB_20120810.ListTables"
}, &out);

IWN_ASSERT(rc == 0);
IWN_ASSERT(out);

if (out) {
  IWN_ASSERT(0 == strcmp(out, "{\"TableNames\":[]}"))
}

free(out);
return rc;
```

