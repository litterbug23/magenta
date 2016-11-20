// Copyright 2016 The Fuchsia Authors
// Copyright (c) 2008-2014 Travis Geiselbrecht
//
// Use of this source code is governed by a MIT-style
// license that can be found in the LICENSE file or at
// https://opensource.org/licenses/MIT


/**
 * @file
 * @brief  Kernel timer subsystem
 * @defgroup timer Timers
 *
 * The timer subsystem allows functions to be scheduled for later
 * execution.  Each timer object is used to cause one function to
 * be executed at a later time.
 *
 * Timer callback functions are called in interrupt context.
 *
 * @{
 */
#include <debug.h>
#include <trace.h>
#include <assert.h>
#include <list.h>
#include <kernel/thread.h>
#include <kernel/timer.h>
#include <kernel/spinlock.h>
#include <platform/timer.h>
#include <platform.h>

#define LOCAL_TRACE 0

spin_lock_t timer_lock;

struct timer_state {
    struct list_node timer_queue;
} __CPU_ALIGN;

static struct timer_state timers[SMP_MAX_CPUS];

static enum handler_return timer_tick(void *arg, lk_time_t now);

/**
 * @brief  Initialize a timer object
 */
void timer_initialize(timer_t *timer)
{
    *timer = (timer_t)TIMER_INITIAL_VALUE(*timer);
}

static void insert_timer_in_queue(uint cpu, timer_t *timer)
{
    timer_t *entry;

    DEBUG_ASSERT(arch_ints_disabled());

    LTRACEF("timer %p, cpu %u, scheduled %u, periodic %u\n", timer, cpu, timer->scheduled_time, timer->periodic_time);

    list_for_every_entry(&timers[cpu].timer_queue, entry, timer_t, node) {
        if (TIME_GT(entry->scheduled_time, timer->scheduled_time)) {
            list_add_before(&entry->node, &timer->node);
            return;
        }
    }

    /* walked off the end of the list */
    list_add_tail(&timers[cpu].timer_queue, &timer->node);
}

static void timer_set(timer_t *timer, lk_time_t delay, lk_time_t period, timer_callback callback, void *arg)
{
    lk_time_t now;

    LTRACEF("timer %p, delay %u, period %u, callback %p, arg %p\n", timer, delay, period, callback, arg);

    DEBUG_ASSERT(timer->magic == TIMER_MAGIC);

    if (list_in_list(&timer->node)) {
        panic("timer %p already in list\n", timer);
    }

    /* Bump the delay, since we're probably straddling a millisecond */
    delay += 1;

    now = current_time();

    spin_lock_saved_state_t state;
    spin_lock_irqsave(&timer_lock, state);

    uint cpu = arch_curr_cpu_num();

    if (unlikely(timer->active_cpu == (int)cpu)) {
        /* the timer is active on our own cpu, we must be inside the callback */
        if (timer->cancel)
            goto out;
    } else if (unlikely(timer->active_cpu >= 0)) {
        panic("timer %p currently active on a different cpu %d\n", timer, timer->active_cpu);
    }

    /* set up the structure */
    timer->scheduled_time = now + delay;
    timer->periodic_time = period;
    timer->callback = callback;
    timer->arg = arg;
    timer->active_cpu = -1;
    timer->cancel = false;

    LTRACEF("scheduled time %u\n", timer->scheduled_time);

    insert_timer_in_queue(cpu, timer);

#if PLATFORM_HAS_DYNAMIC_TIMER
    if (list_peek_head_type(&timers[cpu].timer_queue, timer_t, node) == timer) {
        /* we just modified the head of the timer queue */
        LTRACEF("setting new timer for %u msecs\n", delay);
        platform_set_oneshot_timer(timer_tick, NULL, delay);
    }
#endif

out:
    spin_unlock_irqrestore(&timer_lock, state);
}

/**
 * @brief  Set up a timer that executes once
 *
 * This function specifies a callback function to be called after a specified
 * delay.  The function will be called one time.
 *
 * @param  timer The timer to use
 * @param  delay The delay, in ms, before the timer is executed
 * @param  callback  The function to call when the timer expires
 * @param  arg  The argument to pass to the callback
 *
 * The timer function is declared as:
 *   enum handler_return callback(struct timer *, lk_time_t now, void *arg) { ... }
 */
void timer_set_oneshot(timer_t *timer, lk_time_t delay, timer_callback callback, void *arg)
{
    if (delay == 0)
        delay = 1;
    timer_set(timer, delay, 0, callback, arg);
}

/**
 * @brief  Set up a timer that executes repeatedly
 *
 * This function specifies a callback function to be called after a specified
 * delay.  The function will be called repeatedly.
 *
 * @param  timer The timer to use
 * @param  delay The delay, in ms, before the timer is executed
 * @param  callback  The function to call when the timer expires
 * @param  arg  The argument to pass to the callback
 *
 * The timer function is declared as:
 *   enum handler_return callback(struct timer *, lk_time_t now, void *arg) { ... }
 */
void timer_set_periodic(timer_t *timer, lk_time_t period, timer_callback callback, void *arg)
{
    if (period == 0)
        period = 1;
    timer_set(timer, period, period, callback, arg);
}

/**
 * @brief  Cancel a pending timer
 */
void timer_cancel(timer_t *timer)
{
    DEBUG_ASSERT(timer->magic == TIMER_MAGIC);

    spin_lock_saved_state_t state;
    spin_lock_irqsave(&timer_lock, state);

    uint cpu = arch_curr_cpu_num();

    /* mark the timer as cancelled */
    timer->cancel = true;
    smp_mb();

    /* see if we're trying to cancel the timer we're currently in the middle of handling */
    if (unlikely(timer->active_cpu == (int)cpu)) {
        /* zero it out */
        timer->callback = NULL;
        timer->arg = NULL;
        timer->periodic_time = 0;

        /* we're done, so return back to the callback */
        spin_unlock_irqrestore(&timer_lock, state);
        return;
    }

    /* if the timer is in a queue, remove it and adjust hardware timers if needed */
    if (list_in_list(&timer->node)) {
#if PLATFORM_HAS_DYNAMIC_TIMER
        timer_t *oldhead = list_peek_head_type(&timers[cpu].timer_queue, timer_t, node);
#endif

        /* remove it from the queue */
        list_delete(&timer->node);

#if PLATFORM_HAS_DYNAMIC_TIMER
        /* see if we've just modified the head of this cpu's timer queue */
        /* if we modified another cpu's queue, we'll just let it fire and sort itself out */
        timer_t *newhead = list_peek_head_type(&timers[cpu].timer_queue, timer_t, node);
        if (newhead == NULL) {
            LTRACEF("clearing old hw timer, nothing in the queue\n");
            platform_stop_timer();
        } else if (newhead != oldhead) {
            lk_time_t delay;
            lk_time_t now = current_time();

            if (TIME_LT(newhead->scheduled_time, now))
                delay = 0;
            else
                delay = newhead->scheduled_time - now;

            LTRACEF("setting new timer to %u\n", (uint) delay);
            platform_set_oneshot_timer(timer_tick, NULL, delay);
        }
#endif
    }

    spin_unlock_irqrestore(&timer_lock, state);

    /* wait for the timer to become un-busy in case a callback is currently active on another cpu */
    while (timer->active_cpu >= 0) {
        arch_spinloop_pause();
    }

    /* zero it out */
    timer->callback = NULL;
    timer->arg = NULL;
    timer->periodic_time = 0;
}

/* called at interrupt time to process any pending timers */
static enum handler_return timer_tick(void *arg, lk_time_t now)
{
    timer_t *timer;
    enum handler_return ret = INT_NO_RESCHEDULE;

    DEBUG_ASSERT(arch_ints_disabled());

    THREAD_STATS_INC(timer_ints);

    uint cpu = arch_curr_cpu_num();

    LTRACEF("cpu %u now %u, sp %p\n", cpu, now, __GET_FRAME());

    spin_lock(&timer_lock);

    for (;;) {
        /* see if there's an event to process */
        timer = list_peek_head_type(&timers[cpu].timer_queue, timer_t, node);
        if (likely(timer == 0))
            break;
        LTRACEF("next item on timer queue %p at %u now %u (%p, arg %p)\n", timer, timer->scheduled_time, now, timer->callback, timer->arg);
        if (likely(TIME_LT(now, timer->scheduled_time)))
            break;

        /* process it */
        LTRACEF("timer %p\n", timer);
        DEBUG_ASSERT(timer && timer->magic == TIMER_MAGIC);
        list_delete(&timer->node);

        /* mark the timer busy */
        timer->active_cpu = cpu;
        /* spinlock below acts as a memory barrier */

        /* we pulled it off the list, release the list lock to handle it */
        spin_unlock(&timer_lock);

        LTRACEF("dequeued timer %p, scheduled %u periodic %u\n", timer, timer->scheduled_time, timer->periodic_time);

        THREAD_STATS_INC(timers);

        LTRACEF("timer %p firing callback %p, arg %p\n", timer, timer->callback, timer->arg);
        if (timer->callback(timer, now, timer->arg) == INT_RESCHEDULE)
            ret = INT_RESCHEDULE;

        DEBUG_ASSERT(arch_ints_disabled());
        /* it may have been requeued or periodic, grab the lock so we can safely inspect it */
        spin_lock(&timer_lock);

        /* record whether or not we've been cancelled in the meantime */
        bool cancelled = timer->cancel;

        /* mark it not busy */
        timer->active_cpu = -1;
        smp_mb();

        /* if we've been cancelled, it's not okay to touch the timer structure from now on out */
        if (!cancelled) {
            /* if it is a periodic timer and it hasn't been requeued
             * by the callback put it back in the list
             */
            if (timer->periodic_time > 0 && !list_in_list(&timer->node)) {
                LTRACEF("periodic timer, period %u\n", timer->periodic_time);
                timer->scheduled_time = now + timer->periodic_time;
                insert_timer_in_queue(cpu, timer);
            }
        }
    }

#if PLATFORM_HAS_DYNAMIC_TIMER
    /* reset the timer to the next event */
    timer = list_peek_head_type(&timers[cpu].timer_queue, timer_t, node);
    if (timer) {
        /* has to be the case or it would have fired already */
        DEBUG_ASSERT(TIME_GT(timer->scheduled_time, now));

        lk_time_t delay = timer->scheduled_time - now;

        LTRACEF("setting new timer for %u msecs for event %p\n", (uint)delay, timer);
        platform_set_oneshot_timer(timer_tick, NULL, delay);
    }

    /* we're done manipulating the timer queue */
    spin_unlock(&timer_lock);
#else
    /* release the timer lock before calling the tick handler */
    spin_unlock(&timer_lock);

    /* let the scheduler have a shot to do quantum expiration, etc */
    /* in case of dynamic timer, the scheduler will set up a periodic timer */
    if (thread_timer_tick() == INT_RESCHEDULE)
        ret = INT_RESCHEDULE;
#endif

    return ret;
}

void timer_transition_off_cpu(uint old_cpu)
{
    spin_lock_saved_state_t state;
    spin_lock_irqsave(&timer_lock, state);
    uint cpu = arch_curr_cpu_num();

    timer_t *old_head = list_peek_head_type(&timers[old_cpu].timer_queue, timer_t, node);

    timer_t *entry = NULL, *tmp_entry = NULL;
    /* Move all timers from old_cpu to this cpu */
    list_for_every_entry_safe(&timers[old_cpu].timer_queue, entry, tmp_entry, timer_t, node) {
        list_delete(&entry->node);
        insert_timer_in_queue(cpu, entry);
    }

#if PLATFORM_HAS_DYNAMIC_TIMER
    timer_t *new_head = list_peek_head_type(&timers[cpu].timer_queue, timer_t, node);
    if (new_head != NULL && new_head != old_head) {
        lk_time_t now = current_time();
        lk_time_t delay = 0;
        if (TIME_LT(now, new_head->scheduled_time)) {
            delay = new_head->scheduled_time - now;
        }

        /* we just modified the head of the timer queue */
        LTRACEF("setting new timer for %u msecs\n", delay);
        platform_set_oneshot_timer(timer_tick, NULL, delay);
    }
#endif

    spin_unlock_irqrestore(&timer_lock, state);
}

/* This function is to be invoked after resume on each CPU that may have
 * had timers still on it, in order to restart hardware timers. */
void timer_thaw_percpu(void)
{
#if PLATFORM_HAS_DYNAMIC_TIMER
    DEBUG_ASSERT(arch_ints_disabled());
    spin_lock(&timer_lock);

    uint cpu = arch_curr_cpu_num();

    timer_t *t = list_peek_head_type(&timers[cpu].timer_queue, timer_t, node);
    if (t) {
        lk_time_t now = current_time();
        lk_time_t delay = 0;
        if (TIME_LT(now, t->scheduled_time)) {
            delay = t->scheduled_time - now;
        }
        LTRACEF("rescheduling timer for %u msecs\n", delay);
        platform_set_oneshot_timer(timer_tick, NULL, delay);
    }

    spin_unlock(&timer_lock);
#endif
}

void timer_init(void)
{
    timer_lock = SPIN_LOCK_INITIAL_VALUE;
    for (uint i = 0; i < SMP_MAX_CPUS; i++) {
        list_initialize(&timers[i].timer_queue);
    }
#if !PLATFORM_HAS_DYNAMIC_TIMER
    /* register for a periodic timer tick */
    platform_set_periodic_timer(timer_tick, NULL, 10); /* 10ms */
#endif
}
