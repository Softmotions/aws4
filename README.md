# AWS API client library in pure C

**NOTE: Under development, not ready for production use**

AWS4 is a C client library used for signing and sending requests to AWS HTTP APIs (aws4.h).
Also it offers a simple DynamoDB client API (aws4dd.h) and Distributed Resources Locking API (aws4dl.h).

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

## Usage

Look into `./src/aws4.h` and `./src/aws4dd.h` for API documentation.

Also look into test cases in `./src/tests` directory.

### Examples

#### DynamoDB Put Item example.

```c
#include <aws4/aws4dd.h>

iwrc rc = 0;
struct aws4dd_item_put *op = 0;
struct aws4dd_response *resp = 0;

RCC(rc, finish, aws4dd_item_put_op(&op, &(struct aws4dd_item_put_spec) {
      .table_name = "Thread",
      .condition_expression = "ForumName <> :f and Subject <> :s"
      }));

RCC(rc, finish, aws4dd_item_put_value(op, "/ExpressionAttributeValues/:f", "S", "Amazon DynamoDB"));
RCC(rc, finish, aws4dd_item_put_value(op, "/ExpressionAttributeValues/:s", "S", "How do I update multiple items?"));

RCC(rc, finish, aws4dd_item_put_value(op, "/Item/LastPostDateTime", "S", "201303190422"));
RCC(rc, finish, aws4dd_item_put_array(op, "/Item/Tags", "SS", (const char*[]) { "Update", "Multiple", "Help", 0 }));
RCC(rc, finish, aws4dd_item_put_value(op, "/Item/ForumName", "S", "Amazon DynamoDB"));
RCC(rc, finish, aws4dd_item_put_value(op, "/Item/Message", "S", "I want to update multiple items in a single call."));
RCC(rc, finish, aws4dd_item_put_value(op, "/Item/Subject", "S", "How do I update multiple items?"));
RCC(rc, finish, aws4dd_item_put_value(op, "/Item/LastPostedBy", "S", "fred@example.com"));

RCC(rc, finish, aws4dd_item_put(&request_spec, op, &resp));

finish:
aws4dd_response_destroy(&resp);
aws4dd_item_put_op_destroy(&op);
return rc;
```

#### Example of using a low level universal AWS4 API

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

#### Distributed Resources Locking API example

```c
iwrc rc = 0;
struct aws4dl_lock *lock = 0;
struct aws4dl_lock_acquire_spec spec = {
  .request                  = request_spec,
  .poller                   = poller,
};

RCC(rc, finish, aws4dl_lock_acquire(&spec, &lock));

// Critical section...

RCC(rc, finish, aws4dl_lock_release(&lock));

finish:
if (rc) {
  iwlog_ecode_error3(rc);
}
return rc;
```

# License
```

MIT License

Copyright (c) 2012-2023 Softmotions Ltd <info@softmotions.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

```
