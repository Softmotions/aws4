/// Distributed locking on AWS DynamoDB tables.
#pragma once
#include "aws4.h"

#include <iwnet/iwn_poller.h>

#define AWS4DL_FLAG_HEARTBEAT_NONE 0x01U ///< Do not perform periodical locking heartbeat.
#define AWS4DL_FLAG_HEARTBEAT_ONCE 0x02U ///< Do only one locking heartbeat iteration. Used for testing.

/// Distributed lock specification.
struct aws4dl_lock_spec {
  const char *resource_name;          ///< Locked resource name. Default: `resource`.
  const char *table_name;             ///< Table name to store locking state. Default: `aws4dl`.
  const char *pk_name;                ///< Partition string key attribute name. Default: `pk`.
  const char *sk_name;                ///< Sort string key attribute name. Default: `sk`.
  uint32_t    lock_enqueued_ttl_sec;  ///< Time to live (TTL) in seconds for enqueued lock. Default: 60. Min: 10.
  uint32_t    lock_enqueued_wait_sec; ///< Max time to wait get a lock. Default: 120. Min: 10.
  uint32_t    lock_enqueued_poll_ms;  ///< Locks queue polling period in milliseconds. Default: 500. Min: 200.
  uint32_t    lock_check_page_size;   ///< Max number of records to fetch per lock check iteration.
                                      ///  Default: 100. Min: 10
  uint32_t flags;                     ///< Flags. See `AWS4DL_FLAG_*`.
};

/// Distributed lock acquire specification.
struct aws4dl_lock_acquire_spec {
  struct iwn_poller       *poller;    ///< Poller used for times. Required.
  struct aws4_request_spec request;   ///< AWS connection spec.
  struct aws4dl_lock_spec  lock_spec; ///< Distributed lock parameters.
};

struct aws4dl_lock;

/// Acquire a distributed AWS DynamoDB lock accourding to the given `spec`.
///
/// Routine will block until lock is acquired or timeout or error occurs.
/// Returned `out_lpp` must be released with `aws4dl_lock_release()`.
/// @param spec Lock acquire specification.
/// @param out_lpp [out] Pointer to the acquired lock.
iwrc aws4dl_lock_acquire(const struct aws4dl_lock_acquire_spec *spec, struct aws4dl_lock **out_lpp);

/// Releases the lock previously acquired with `aws4dl_lock_acquire()` and all of its resources.
iwrc aws4dl_lock_release(struct aws4dl_lock **lpp);
