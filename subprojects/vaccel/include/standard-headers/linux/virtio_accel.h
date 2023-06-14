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

struct virtio_accel_arg {
    uint32_t len;
    unsigned char *buf;
    unsigned char *usr_buf;
    unsigned char *usr_pages;
    uint32_t usr_npages;
    unsigned char padding[5];
};

struct virtio_accel_op {
    uint32_t in_nr;
    uint32_t out_nr;
    struct virtio_accel_arg *in;
    struct virtio_accel_arg *out;
};

struct virtio_accel_hdr {
    uint32_t sess_id;

#define VIRTIO_ACCEL_NO_OP                   0
#define VIRTIO_ACCEL_CREATE_SESSION          1
#define VIRTIO_ACCEL_DESTROY_SESSION         2
#define VIRTIO_ACCEL_DO_OP                   3
#define VIRTIO_ACCEL_GET_TIMERS              4
    uint32_t op_type;

    /* session create structs */
    struct virtio_accel_op op;
};

struct virtio_accel_conf {
    uint32_t status;
    /* Supported service mask */
    uint32_t services;
    /* Maximum size of each crypto request's content */
    uint64_t max_size;
};

#endif /* _VIRTIO_ACCEL_H */
