#define _GNU_SOURCE

#include "aws4dl.h"
#include "aws4dl_internal.h"

#include <iowow/iwp.h>
#include <iwnet/iwn_tests.h>
#include <iwnet/iwn_poller.h>
#include <iwnet/iwn_proc.h>

#include <signal.h>
#include <sys/types.h>
#include <stdlib.h>
#include <pthread.h>

iwrc _ticket_acquire(struct aws4dl_lock *lock);
iwrc _lock_enqueue(struct aws4dl_lock *lock);

static int dynamodb_pid = 1;
static struct iwn_poller *poller;
static pthread_barrier_t start_br;

static struct aws4_request_spec request_spec = {
  .flags          = AWS_SERVICE_DYNAMODB, // | AWS_REQUEST_VERBOSE,
  .aws_region     = "us-east-1",
  .aws_key        = "fakeMyKeyId",
  .aws_secret_key = "fakeSecretAccessKey",
  .aws_url        = "http://localhost:8000"
};

static void _on_signal(int signo) {
  if (dynamodb_pid > -1) {
    kill(dynamodb_pid, SIGTERM);
  }
  if (poller) {
    // NOLINTNEXTLINE
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
    .parent_death_signal = SIGTERM,
  }, &dynamodb_pid);
}

static iwrc _test_lock_acquire_release1(void) {
  iwrc rc = 0;
  struct aws4dl_lock *lock = 0;
  struct aws4dl_lock_acquire_spec spec = {
    .request                  = request_spec,
    .poller                   = poller,
    .lock_spec                = {
      .lock_enqueued_ttl_sec  = 100000, // high enough
      .lock_enqueued_wait_sec = 100000,
      .lock_enqueued_poll_ms  = 100000000,
      .flags                  = AWS4DL_FLAG_HEARTBEAT_NONE | AWS4DL_FLAG_TABLE_TTL_NOAUTO,
    }
  };

  RCC(rc, finish, aws4dl_lock_acquire(&spec, &lock));
  // In-lock
  RCC(rc, finish, aws4dl_lock_release(&lock));

finish:
  if (rc) {
    iwlog_ecode_error3(rc);
  }
  return rc;
}

static iwrc _test_lock_acquire_release2(void) {
  iwrc rc = 0;
  struct aws4dl_lock_acquire_spec exp_spec = {
    .request                  = request_spec,
    .poller                   = poller,
    .lock_spec                = {
      .table_name             = "aws4dl",
      .resource_name          = "r",
      .pk_name                = "pk",
      .sk_name                = "sk",
      .lock_check_page_size   = 10,
      .lock_enqueued_ttl_sec  = 0,
      .lock_enqueued_wait_sec = 1,
      .lock_enqueued_poll_ms  = 500,
      .flags                  = AWS4DL_FLAG_HEARTBEAT_NONE | AWS4DL_FLAG_TABLE_TTL_NOAUTO,
    }
  };

  // Generate a bunch of expired records
  const int expnum = 25;
  bool ttl_enabled = false;
  IWPOOL *pool = iwpool_create_empty();
  IWN_ASSERT_FATAL(pool);

  struct aws4dl_lock exp_lock = { .pool = pool };
  exp_lock.acquire_spec = exp_spec;
  pthread_mutex_init(&exp_lock.mtx, 0);
  pthread_cond_init(&exp_lock.cond, 0);

  for (int i = 0; i < expnum; ++i) {
    RCC(rc, finish, _ticket_acquire(&exp_lock));
    RCC(rc, finish, _lock_enqueue(&exp_lock));
  }

  pthread_mutex_destroy(&exp_lock.mtx);
  pthread_cond_destroy(&exp_lock.cond);
  iwpool_destroy(pool);

  sleep(1); // Sleep to expire all previous records

  // Now try to get a lock and iterate through expired records.
  struct aws4dl_lock *lock = 0;
  struct aws4dl_lock_acquire_spec spec = {
    .request                  = request_spec,
    .poller                   = poller,
    .lock_spec                = {
      .table_name             = "aws4dl",
      .lock_enqueued_ttl_sec  = 10,
      .lock_enqueued_wait_sec = 100000,
      .lock_enqueued_poll_ms  = 100000000,
      .lock_check_page_size   = 10,
      .flags                  = AWS4DL_FLAG_TABLE_TTL_NOAUTO,
    }
  };

  RCC(rc, finish, aws4dl_lock_acquire(&spec, &lock));
  IWN_ASSERT(!aws4dd_ttl_update(&request_spec, spec.lock_spec.table_name, "expiresAt", true, &ttl_enabled));
  IWN_ASSERT(ttl_enabled);

  // Allow heartbeat to work enough time to expire all records.
  sleep(20);

  // Verify lock table
  struct aws4dd_scan *sop = 0;
  rc = aws4dd_scan_op(&sop, &(struct aws4dd_scan_spec) {
    .table_name = "aws4dl"
  });
  IWN_ASSERT(!rc);
  if (!rc) {
    struct aws4dd_response *resp = 0;
    rc = aws4dd_scan(&request_spec, sop, &resp);
    IWN_ASSERT(!rc);
    if (!rc) {
      JBL_NODE n;
      uint64_t ctime;
      iwp_current_time_ms(&ctime, false);
      ctime /= 1000;
      // Only two records must be in a table
      IWN_ASSERT(!jbn_at(resp->data, "/Count", &n) && n->type == JBV_I64 && n->vi64 == 2);
      IWN_ASSERT(!jbn_at(resp->data, "/Items/1/expiresAt/N", &n) && n->type == JBV_STR);
      if (n) {
        int64_t etime = iwatoi(n->vptr);
        IWN_ASSERT(etime >= ctime && etime - ctime <= 10);
      }
    }
    aws4dd_scan_op_destroy(&sop);
    aws4dd_response_destroy(&resp);
  }

  RCC(rc, finish, aws4dl_lock_release(&lock));


finish:
  return rc;
}

static void* _tests_run(void *d) {
  pthread_barrier_wait(&start_br);
  iwp_sleep(500);
  iwrc rc = 0;

  RCC(rc, finish, _test_lock_acquire_release1());
  RCC(rc, finish, _test_lock_acquire_release2());

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
  pthread_create(&th, 0, _tests_run, 0);

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
