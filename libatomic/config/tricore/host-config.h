/* Minimal bare-metal host config for libatomic on tricore-elf. */

#ifndef LIBATOMIC_HOST_CONFIG_H
#define LIBATOMIC_HOST_CONFIG_H

#define LIBATOMIC_HAVE_LOCKS 1

static inline void libat_full_barrier(void)
{
  __sync_synchronize();
}

#ifndef pre_barrier
static inline void pre_barrier(int model)
{
  if (model != __ATOMIC_RELAXED)
    libat_full_barrier();
}
#endif

#ifndef post_barrier
static inline void post_barrier(int model)
{
  if (model != __ATOMIC_RELAXED)
    libat_full_barrier();
}
#endif

#ifndef pre_seq_barrier
static inline void pre_seq_barrier(int model)
{
  if (model == __ATOMIC_SEQ_CST)
    libat_full_barrier();
}
#endif

#ifndef post_seq_barrier
static inline void post_seq_barrier(int model)
{
  if (model == __ATOMIC_SEQ_CST)
    libat_full_barrier();
}
#endif

#ifndef maybe_specialcase_relaxed
static inline int maybe_specialcase_relaxed (int model)
{
  (void) model;
  return 0;
}
#endif

#ifndef maybe_specialcase_acqrel
static inline int maybe_specialcase_acqrel (int model)
{
  (void) model;
  return 0;
}
#endif

#ifndef protect_start
static inline uintptr_t protect_start (void *ptr)
{
  (void) ptr;
  return 0;
}
#endif

#ifndef protect_end
static inline void protect_end (void *ptr, uintptr_t magic)
{
  (void) ptr;
  (void) magic;
}
#endif


#endif
