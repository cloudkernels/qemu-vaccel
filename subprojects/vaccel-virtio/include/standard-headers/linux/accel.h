// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _ACCEL_H
#define _ACCEL_H

#include "standard-headers/linux/types.h"

#define TIMERS_NAME_MAX 64

/* IOCTLs */
#define ACCEL_SESS_CREATE _IOWR('@', 0, struct accel_op)
#define ACCEL_SESS_DESTROY _IOWR('@', 1, uint64_t)
#define ACCEL_DO_OP _IOWR('@', 2, struct accel_op)
#define ACCEL_GET_TIMERS _IOWR('@', 3, struct accel_op)

struct accel_arg {
    uint64_t buf;
    uint32_t len;
    uint32_t type;
    uint32_t custom_type_id;
};

struct accel_op {
    /* Session id */
    uint64_t id;

    /* User-defined operation code */
    uint32_t op_code;

    /* Number of out arguments */
    uint32_t out_nr;

    /* Number of in arguments */
    uint32_t in_nr;

    /* Pointer to out arguments */
    struct accel_arg *out;

    /* Pointer to in arguments */
    struct accel_arg *in;

    /* Operation return value */
    uint32_t ret;
};

struct accel_prof_sample {
    /* Timestamp (nsec) of entering the region */
    uint64_t start;

    /* Time (nsec) elapsed inside the region */
    uint64_t time;
};

struct accel_prof_region {
    /* Name of the region */
    char name[TIMERS_NAME_MAX];

    /* Number of collected samples */
    uint64_t nr_entries;

    /* Array of collected samples */
    struct accel_prof_sample *samples;

    /* Allocated size for the array */
    uint64_t size;
};

#endif /* _ACCEL_H */
