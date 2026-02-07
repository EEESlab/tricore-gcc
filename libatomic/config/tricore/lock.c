/* Bare-metal lock implementation for the Tricore target.
   Uses GCC __sync_* builtins to implement a spinlock.
*/

#include "libatomic_i.h"

/* Multiple locks indexed by size/address hashing. */
#ifndef LIBATOMIC_LOCKS
#define LIBATOMIC_LOCKS 64
#endif

static volatile unsigned int libat_locks[LIBATOMIC_LOCKS];

static inline unsigned int
lock_index (const void *ptr, size_t n)
{
  /* Simple hash: pointer xor size, then mask. */
  uintptr_t x = (uintptr_t)ptr;
  x ^= (uintptr_t)n * 0x9e3779b1u;
  return (unsigned int)(x & (LIBATOMIC_LOCKS - 1));
}

void
libat_lock_n (void *ptr, size_t n)
{
  volatile unsigned int *l = &libat_locks[lock_index (ptr, n)];

  while (__sync_lock_test_and_set (l, 1u))
    {
      /* Busy wait until it becomes 0 again.  */
      while (*l)
        ;
    }

  /* Barrier after taking the lock.  */
  __sync_synchronize ();
}

void
libat_unlock_n (void *ptr, size_t n)
{
  volatile unsigned int *l = &libat_locks[lock_index (ptr, n)];

  /* Barrier before releasing the lock.  */
  __sync_synchronize ();

  __sync_lock_release (l);
}

