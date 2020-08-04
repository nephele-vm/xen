/******************************************************************************
 * profiling functions
 *
 * Copyright (c) 2020 Costin Lupu
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef __XENCLONE_PROFILE_H__
#define __XENCLONE_PROFILE_H__

#include <time.h>
#include <stdio.h>

#define XENCLONED_PROFILING 1

#if XENCLONED_PROFILING
#define NSECONDS_IN_SEC 1000000000.0
#define USECONDS_IN_SEC 1000000.0
#define MSECONDS_IN_SEC 1000.0

#define NSECONDS_IN_MSEC    (NSECONDS_IN_SEC / MSECONDS_IN_SEC)


static inline
time_t timespec_nsec(struct timespec *t)
{
	return t->tv_sec * NSECONDS_IN_SEC + t->tv_nsec;
}

static inline
double timespec_usec(struct timespec *t)
{
	return (double) t->tv_sec * USECONDS_IN_SEC + (double) t->tv_nsec / 1000.0;
}

static inline
time_t timespec_diff_nsec(struct timespec *start, struct timespec *end)
{
	return timespec_nsec(end) - timespec_nsec(start);
}

static inline
double timespec_diff_msec(struct timespec *start, struct timespec *end)
{
	return (double) timespec_diff_nsec(start, end) / NSECONDS_IN_MSEC;
}

static inline
double timespec_diff_sec(struct timespec *start, struct timespec *end)
{
	return (double) timespec_diff_nsec(start, end) / NSECONDS_IN_SEC;
}

struct profile {
	struct timespec start;
	struct timespec stop;
};

static inline int profile_start(struct profile *p)
{
	return clock_gettime(CLOCK_REALTIME, &p->start);
}

static inline int profile_stop(struct profile *p)
{
	return clock_gettime(CLOCK_REALTIME, &p->stop);
}

static inline double profile_msec(struct profile *p)
{
	return timespec_diff_msec(&p->start, &p->stop);
}

static inline time_t profile_sec(struct profile *p)
{
	return timespec_diff_sec(&p->start, &p->stop);
}

//TODO #define XENCLONED_PROFILING_TRACES 1

#if XENCLONED_PROFILING_TRACES

#define PROFILE_PREFIX   "XENCLONED_TRACE "

extern __thread int __profile_lvl;

#define PROFILE_NESTED_TICK(str) \
	{ \
		const char *_str = str; \
		struct timespec __profile_tick; \
		struct timespec __profile_tock; \
		double __profile_val; \
		__profile_lvl++; \
		clock_gettime(CLOCK_MONOTONIC, &__profile_tick); \

#define PROFILE_NESTED_TOCK_MSEC() \
		clock_gettime(CLOCK_MONOTONIC, &__profile_tock); \
		__profile_val = timespec_diff_msec(&__profile_tick, &__profile_tock); \
		INFO(PROFILE_PREFIX "%11.6lf %d %*s %s", \
			__profile_val, __profile_lvl, 2 * __profile_lvl, "", _str); \
		__profile_lvl--; \
	}

#else /* XENCLONED_PROFILING_TRACES */

#define PROFILE_NESTED_TICK(str)
#define PROFILE_NESTED_TOCK_MSEC()

#endif /* XENCLONED_PROFILING_TRACES */

#endif /* XENCLONED_PROFILING */

#endif /* __XENCLONE_PROFILE_H__ */
