#ifndef _VIRTIO_ACCEL_H
#define _VIRTIO_ACCEL_H

#include "standard-headers/linux/types.h"
#include "standard-headers/linux/virtio_types.h"

#define VIRTIO_ID_ACCEL 21

#define VIRTIO_ACCEL_S_HW_READY  (1 << 0)

/* status */
#define VIRTIO_ACCEL_OK        0
#define VIRTIO_ACCEL_ERR       1
#define VIRTIO_ACCEL_BADMSG    2
#define VIRTIO_ACCEL_NOTSUPP   3
#define VIRTIO_ACCEL_INVSESS   4 /* Invalid session id */

struct virtio_accel_arg_hdr {
    uint32_t len;
    uint32_t type;
    uint32_t custom_type_id;
};

struct virtio_accel_hdr {
    uint64_t request_id;
    uint32_t sess_id;

#define VIRTIO_ACCEL_NO_OP                   0
#define VIRTIO_ACCEL_CREATE_SESSION          1
#define VIRTIO_ACCEL_DESTROY_SESSION         2
#define VIRTIO_ACCEL_DO_OP                   3
#define VIRTIO_ACCEL_GET_TIMERS              4
    uint32_t op_type;

    uint32_t out_nr;
    uint32_t in_nr;

    uint32_t total_chunks;
};

struct virtio_accel_conf {
    uint32_t status;
    /* Supported service mask */
    uint32_t services;
    /* Maximum size of each crypto request's content */
    uint64_t max_size;
};

#endif /* _VIRTIO_ACCEL_H */
