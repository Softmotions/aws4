#pragma once

#include "aws4dl.h"
#include "aws4dd.h"

#define _LF_TICKET_ITEM_CREATE 0x01U

struct aws4dl_lock {
  struct aws4dl_lock_acquire_spec acquire_spec;
  IWPOOL  *pool;
  char     ticket[40];   ///< Acquired lock ticket.
  uint32_t flags;        ///< `_LF_XXX` state flags

  int heartbeat_fd;      ///< Poller heartbeat task file descriptor.
  pthread_mutex_t mtx;
  pthread_cond_t  cond;
};

