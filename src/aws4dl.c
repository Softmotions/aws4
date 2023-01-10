#include "aws4dl.h"

#include <iwnet/iwn_poller.h>

/// Distributed lock specification.
struct aws4dl_lock_spec {
  const char *table_name;             ///< Table name to store locking state.
  const char *pk_name;                ///< Partition string key attribute name. Default: `pk`.
  const char *sk_name;                ///< Sort string key attribute name. Default: `sk`.
  uint32_t    lock_enqueued_ttl_sec;  ///< Time to live (TTL) in seconds for enqueued lock. Default: 60. Min: 10.
  uint32_t    lock_enqueued_wait_sec; ///< Max time to wait for engueued lock. Default: 120. Zero means wait forever.
};

/// Distributed lock acquire specification.
struct aws4dl_lock_acquire_spec {
  struct iwn_poller       *poller;    ///< Poller used for times. Required.
  struct aws4_request_spec request;   ///< AWS connection spec.
  struct aws4dl_lock_spec  lock;
};

struct aws4dl_lock;

iwrc aws4dl_lock_acquire(const struct aws4dl_lock_acquire_spec *spec, struct aws4dl_lock **out_lock);

void aws4dl_lock_release(struct aws4dl_lock *lock);
