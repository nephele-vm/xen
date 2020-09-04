#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef __USE_GNU
#define __USE_GNU
#endif
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <assert.h>
#include <link.h>
#include "profile.h"


#ifndef INSTRUMENTED_LIB_PATH
#error "Define INSTRUMENTED_LIB_PATH"
#endif
#ifndef PROFILE_TRIGGER_INIT_VALUE
#define PROFILE_TRIGGER_INIT_VALUE 0
#endif

__noinstrument int func_map_init(const char *filename);
__noinstrument const char *func_map_get(unsigned long address);

static unsigned long base_address;

static int __noinstrument
dl_iterate_phdr_callback(struct dl_phdr_info *info, size_t size, void *data)
{
    static int found = 0;

    if (found)
        goto out;

    if (!strcmp(info->dlpi_name, INSTRUMENTED_LIB_PATH)) {
        //TODO this was for libxl base_address = info->dlpi_addr + info->dlpi_phdr[0].p_vaddr;
        base_address = info->dlpi_addr;
        found = 1;
    }

out:
    return 0;
}


struct func_trace {
    struct timespec start;
    struct timespec stop;
	unsigned long func;
};

#define TRACE_NESTED_MAX 64
#define TRACE_NESTED_FILTER 10

static int started = 0;
static __thread struct func_trace nested_trace[TRACE_NESTED_MAX];
static __thread int current_level = -1;
static __thread int ignored_level = 0;

int profile_trigger = PROFILE_TRIGGER_INIT_VALUE;


void __noinstrument __cyg_profile_func_enter(void *func, void *caller)
{
    struct func_trace *trace;
    int rc;

    if (!profile_trigger)
        return;

    if (!started) {
        rc = func_map_init(INSTRUMENTED_LIB_PATH);
        if (rc) {
            fprintf(stderr, "Error creating functions map\n");
            return;
        }
        dl_iterate_phdr(dl_iterate_phdr_callback, NULL);
        started = 1;
    }

    if (current_level == TRACE_NESTED_FILTER) {
        ignored_level++;
        return;
    }

    current_level++;
    assert(current_level < TRACE_NESTED_MAX);

    trace = &nested_trace[current_level];

    rc = clock_gettime(CLOCK_REALTIME, &trace->start);
    assert(rc == 0);

    trace->func = (unsigned long) func;
}
 
void __noinstrument __cyg_profile_func_exit(void *func, void *caller)
{
    struct func_trace *trace;
    double duration;
    const char *func_name;
    int rc;

    if (!profile_trigger)
        return;

    if (current_level < 0)
        return;

    if (ignored_level) {
        ignored_level--;
        return;
    }

    trace = &nested_trace[current_level];
    assert(trace->func == (unsigned long) func);

    rc = clock_gettime(CLOCK_REALTIME, &trace->stop);
    assert(rc == 0);

    duration = timespec_diff_msec(&trace->start, &trace->stop);

    if (duration >= 1.0)
    {
        func_name = func_map_get(trace->func - base_address);

        fprintf(stderr, "%ld.%09ld %11.6lf %d %*s %s\n",
            trace->start.tv_sec, trace->start.tv_nsec,
            duration, current_level, 2 * current_level, "", func_name);
    }

    current_level--;
}
