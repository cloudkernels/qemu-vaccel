// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _LINUX_VIRTIO_ACCEL_H
#define _LINUX_VIRTIO_ACCEL_H

#include <linux/ioctl.h>

#include "standard-headers/linux/types.h"
#include "standard-headers/linux/virtio_types.h"

/* IOCTLs */
#define VIRTIO_ACCEL_CREATE_SESSION _IOWR('@', 0, struct virtio_accel_op)
#define VIRTIO_ACCEL_DESTROY_SESSION _IOWR('@', 1, uint64_t)
#define VIRTIO_ACCEL_DO_OP _IOWR('@', 2, struct virtio_accel_op)
#define VIRTIO_ACCEL_GET_TIMERS _IOWR('@', 3, struct virtio_accel_op)

struct virtio_accel_arg {
    uint64_t buf;
    uint32_t len;
    uint32_t type;
    uint32_t custom_type_id;
};

struct virtio_accel_op {
    /* Session id */
    uint64_t session_id;

    /* User-defined operation code */
    uint32_t op_code;

    uint32_t padding;

    /* Number of out arguments */
    uint32_t nr_out;

    /* Number of in arguments */
    uint32_t nr_in;

    /* Pointer to out arguments (struct virtio_accel_arg *) */
    uint64_t out;

    /* Pointer to in arguments (struct virtio_accel_arg *) */
    uint64_t in;

    /* Operation return value */
    uint32_t ret;
};

struct virtio_accel_profiler_op {
    /* Session id */
    uint64_t session_id;

    /* Max number of allocated regions */
    uint32_t max_regions;

    /* Number of collected regions */
    uint32_t nr_regions;

    /* Array of collected regions
     * (struct virtio_accel_profiler_regions *) */
    uint64_t regions;

    /* Operation return value */
    uint32_t ret;
};

struct virtio_accel_profiler_sample {
    /* Timestamp (nsec) of entering the region */
    uint64_t start;

    /* Time (nsec) elapsed inside the region */
    uint64_t time;
};

#define VIRTIO_ACCEL_TIMERS_NAME_MAX 64

struct virtio_accel_profiler_region {
    /* Name of the region */
    char name[VIRTIO_ACCEL_TIMERS_NAME_MAX];

    /* Max number of allocated samples */
    uint32_t max_samples;

    /* Number of collected samples */
    uint32_t nr_samples;

    /* Array of collected samples
     * (struct virtio_accel_profiler_sample *) */
    uint64_t samples;
};

/* status */
#define VIRTIO_ACCEL_OK 0
#define VIRTIO_ACCEL_ERR 1
#define VIRTIO_ACCEL_BADMSG 2
#define VIRTIO_ACCEL_NOTSUPP 3
#define VIRTIO_ACCEL_INVSESS 4 /* Invalid session id */

struct virtio_accel_arg_header {
    __virtio32 len;
    __virtio32 type;
    __virtio32 custom_type_id;
};

struct virtio_accel_profiler_region_hdr {
    char name[VIRTIO_ACCEL_TIMERS_NAME_MAX];
    __virtio32 max_samples;
    __virtio32 nr_samples;
};

struct virtio_accel_profiler_sample_hdr {
    __virtio64 start;
    __virtio64 time;
};

struct virtio_accel_header {
    __virtio64 request_id;
    __virtio64 session_id;

#define VIRTIO_ACCEL_CMD_CREATE_SESSION 0
#define VIRTIO_ACCEL_CMD_DESTROY_SESSION 1
#define VIRTIO_ACCEL_CMD_DO_OP 2
#define VIRTIO_ACCEL_CMD_GET_TIMERS 3
#define VIRTIO_ACCEL_CMD_MAX 4
    __virtio32 cmd;
    union {
        struct {
            __virtio32 op_code;
            __virtio32 nr_out;
            __virtio32 nr_in;
        } op;

        struct {
            __virtio32 max_regions;
            __virtio64 padding;
        } profiler_op;
    };

    __virtio32 total_chunks;
};

struct virtio_accel_config {
    __virtio16 num_queues;
    __virtio16 max_req_descriptors;
};

#endif /* _LINUX_VIRTIO_ACCEL_H */
