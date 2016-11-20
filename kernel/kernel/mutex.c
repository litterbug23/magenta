// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2008-2014 Travis Geiselbrecht
// Copyright (c) 2012-2012 Shantanu Gupta
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT


/**
 * @file
 * @brief  Mutex functions
 *
 * @defgroup mutex Mutex
 * @{
 */

#include <kernel/mutex.h>
#include <debug.h>
#include <assert.h>
#include <err.h>
#include <kernel/thread.h>

/**
 * @brief  Initialize a mutex_t
 */
void mutex_init(mutex_t *m)
{
    *m = (mutex_t)MUTEX_INITIAL_VALUE(*m);
}

/**
 * @brief  Destroy a mutex_t
 *
 * This function frees any resources that were allocated
 * in mutex_init().  The mutex_t object itself is not freed.
 */
void mutex_destroy(mutex_t *m)
{
    DEBUG_ASSERT(m->magic == MUTEX_MAGIC);

    THREAD_LOCK(state);
#if LK_DEBUGLEVEL > 0
    if (unlikely(m->count > 0)) {
        panic("mutex_destroy: thread %p (%s) tried to destroy locked mutex %p,"
              " locked by %p (%s)\n",
              get_current_thread(), get_current_thread()->name, m,
              m->holder, m->holder->name);
    }
#endif
    m->magic = 0;
    m->count = 0;
    wait_queue_destroy(&m->wait);
    THREAD_UNLOCK(state);
}

status_t mutex_acquire_internal(mutex_t *m)
{
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(spin_lock_held(&thread_lock));

    if (unlikely(++m->count > 1)) {
        status_t ret = wait_queue_block(&m->wait, INFINITE_TIME);
        if (unlikely(ret < NO_ERROR)) {
            /* mutexes are not interruptable and cannot time out, so it
             * is illegal to return with any error state.
             */
            spin_unlock(&thread_lock); /* drop the thread lock so the panic shell can proceed */
            panic("mutex_acquire_internal: wait_queue_block returns with error %d m %p, thr %p, sp %p\n",
                   ret, m, get_current_thread(), __GET_FRAME());
        }
    }

    m->holder = get_current_thread();

    return NO_ERROR;
}

/**
 * @brief  Acquire the mutex
 *
 * @return  NO_ERROR on success, other values on error
 */
status_t mutex_acquire(mutex_t *m)
{
    DEBUG_ASSERT(m->magic == MUTEX_MAGIC);
    DEBUG_ASSERT(!arch_in_int_handler());

#if LK_DEBUGLEVEL > 0
    if (unlikely(get_current_thread() == m->holder))
        panic("mutex_acquire: thread %p (%s) tried to acquire mutex %p it already owns.\n",
              get_current_thread(), get_current_thread()->name, m);
#endif

    THREAD_LOCK(state);
    status_t ret = mutex_acquire_internal(m);
    THREAD_UNLOCK(state);
    return ret;
}

void mutex_release_internal(mutex_t *m, bool reschedule)
{
    DEBUG_ASSERT(arch_ints_disabled());
    DEBUG_ASSERT(spin_lock_held(&thread_lock));

    m->holder = 0;

    if (unlikely(--m->count >= 1)) {
        /* release a thread */
        wait_queue_wake_one(&m->wait, reschedule, NO_ERROR);
    }
}

/**
 * @brief  Release mutex
 */
void mutex_release(mutex_t *m)
{
    DEBUG_ASSERT(m->magic == MUTEX_MAGIC);
    DEBUG_ASSERT(!arch_in_int_handler());

#if LK_DEBUGLEVEL > 0
    if (unlikely(get_current_thread() != m->holder)) {
        panic("mutex_release: thread %p (%s) tried to release mutex %p it doesn't own. owned by %p (%s)\n",
              get_current_thread(), get_current_thread()->name, m, m->holder, m->holder ? m->holder->name : "none");
    }
#endif

    THREAD_LOCK(state);
    mutex_release_internal(m, true);
    THREAD_UNLOCK(state);
}

