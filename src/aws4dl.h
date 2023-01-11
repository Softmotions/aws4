/// Distributed locking routines on AWS DynamoDB tables.
#pragma once
#include "aws4.h"

#include <iwnet/iwn_poller.h>

/// Distributed lock specification.
struct aws4dl_lock_spec {
  const char *resource_name;          ///< Locked resource name. Default: `resource`
  const char *table_name;             ///< Table name to store locking state. Default: `aws4dl`.
  const char *pk_name;                ///< Partition string key attribute name. Default: `pk`.
  const char *sk_name;                ///< Sort string key attribute name. Default: `sk`.
  uint32_t    lock_enqueued_ttl_sec;  ///< Time to live (TTL) in seconds for enqueued lock. Default: 60. Min: 10.
  uint32_t    lock_enqueued_wait_sec; ///< Max time to wait get a lock. Default: 120. Min: 10.
};

/// Distributed lock acquire specification.
struct aws4dl_lock_acquire_spec {
  CURL *curl;                       ///< Optional CURL handle.
  struct iwn_poller       *poller;  ///< Poller used for times. Required.
  struct aws4_request_spec request; ///< AWS connection spec.
  struct aws4dl_lock_spec  lock_spec;
};

struct aws4dl_lock;

iwrc aws4dl_lock_acquire(const struct aws4dl_lock_acquire_spec *spec, struct aws4dl_lock **lpp);

iwrc aws4dl_lock_release(struct aws4dl_lock **lpp);
