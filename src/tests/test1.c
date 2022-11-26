#define _GNU_SOURCE

#include "aws4.h"

#include <curl/curl.h>

#include <iowow/iwp.h>
#include <iwnet/iwn_tests.h>
#include <iwnet/iwn_poller.h>
#include <iwnet/iwn_proc.h>
#include <iwnet/iwn_curl.h>

#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pthread.h>

static int dynamodb_pid = -1;
static struct iwn_poller *poller;
static pthread_barrier_t start_br;

static void _on_signal(int signo) {
  if (dynamodb_pid > -1) {
    kill(dynamodb_pid, SIGTERM);
  }
  if (poller) {
    iwn_poller_shutdown_request(poller);
  }
}

static void _on_dynamodb_exit(const struct iwn_proc_ctx *ctx) {
  dynamodb_pid = -1;
  fprintf(stderr, "[DynamoDB] server exit\n");
  iwn_poller_shutdown_request(poller);
}

static void _on_dynamodb_output(const struct iwn_proc_ctx *ctx, const char *buf, size_t len) {
  fprintf(stderr, "[DynamoDB]: %.*s", (int) len, buf);
  static bool started = false;
  if (!started && memmem(buf, len, "shouldDelayTransientStatuses", IW_LLEN("shouldDelayTransientStatuses"))) {
    started = true;
    pthread_barrier_wait(&start_br);
  }
}

static iwrc _dynamodb_spawn(void) {
  return iwn_proc_spawn(&(struct iwn_proc_spec) {
    .poller = poller,
    .path = "./run-dynamodb.sh",
    .on_stdout = _on_dynamodb_output,
    .on_stderr = _on_dynamodb_output,
    .on_exit = _on_dynamodb_exit,
  }, &dynamodb_pid);
}

static iwrc _aws4_test1(void) {
  iwrc rc = 0;
  char *out = 0;
  CURL *curl = curl_easy_init();

  rc = aws4_request(curl, &(struct aws4_request_spec) {
    .service = AWS_SERVICE_DYNAMODB,
    .aws_region = "us-east-1",
    .aws_key = "fakeMyKeyId",
    .aws_secret_key = "fakeSecretAccessKey",
    .aws_url = "http://localhost:8000"
  }, &(struct aws4_request_payload) {
    .payload = "{}",
    .payload_len = IW_LLEN("{}"),
    .amz_target = "DynamoDB_20120810.ListTables22"
  }, &out);

  IWN_ASSERT(rc == 0);
  IWN_ASSERT(out);
  if (out) {
    IWN_ASSERT(0 == strcmp(out, "{\"TableNames\":[]}"))
  }

  free(out);
  curl_easy_cleanup(curl);
  return rc;
}

static void* _run_tests(void *d) {
  pthread_barrier_wait(&start_br);
  iwp_sleep(500); // Wait a bit to setup local dynamodb endpoint
  iwrc rc = 0;
  RCC(rc, finish, _aws4_test1());

finish:
  IWN_ASSERT(rc == 0);
  _on_signal(SIGTERM);
  return 0;
}

int main(int argc, char *argv[]) {
  iwrc rc = 0;
  signal(SIGPIPE, SIG_IGN);
  signal(SIGHUP, SIG_IGN);
  signal(SIGALRM, SIG_IGN);
  signal(SIGUSR1, SIG_IGN);
  signal(SIGUSR2, SIG_IGN);
  if (signal(SIGTERM, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }
  if (signal(SIGINT, _on_signal) == SIG_ERR) {
    return EXIT_FAILURE;
  }
  iwlog_init();

  RCC(rc, finish, iwn_poller_create(4, 1, &poller));
  RCC(rc, finish, _dynamodb_spawn());

  pthread_barrier_init(&start_br, 0, 2);

  pthread_t th;
  pthread_create(&th, 0, _run_tests, 0);

  iwn_poller_poll(poller);
  pthread_join(th, 0);
  pthread_barrier_destroy(&start_br);

  iwn_proc_dispose();
  fprintf(stderr, "Poller exited\n");

finish:
  IWN_ASSERT(rc == 0);
  iwn_poller_destroy(&poller);
  return iwn_assertions_failed > 0 ? 1 : 0;
}
