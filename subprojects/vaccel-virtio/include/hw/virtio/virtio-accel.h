// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _QEMU_VIRTIO_ACCEL_H
#define _QEMU_VIRTIO_ACCEL_H

#include "../../standard-headers/linux/virtio_accel.h"
#include "qemu/iov.h"
#include "hw/virtio/virtio.h"
#include "system/iothread.h"
#include "../../system/acceldev.h"

#define DEBUG_VIRTIO_ACCEL 1

#define VADPRINTF(fmt, ...)                                       \
    do {                                                          \
        if (DEBUG_VIRTIO_ACCEL) {                                 \
            fprintf(stderr, "virtio_accel: " fmt, ##__VA_ARGS__); \
        }                                                         \
    } while (0)

#define TYPE_VIRTIO_ACCEL "virtio-accel-device"
#define VIRTIO_ACCEL(obj) OBJECT_CHECK(VirtIOAccel, (obj), TYPE_VIRTIO_ACCEL)
#define VIRTIO_ACCEL_GET_PARENT_CLASS(obj) \
    OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_ACCEL)

typedef struct VirtIOAccelConf {
    AccelDevBackend *runtime;

    /* Supported service mask */
    uint32_t services;
    /* Maximum size of each crypto request's content */
    uint64_t max_size;
} VirtIOAccelConf;

struct VirtIOAccel;

typedef struct VirtIOAccelReq {
    /* elem should always be first */
    VirtQueueElement elem;

    VirtQueue *vq;
    struct VirtIOAccel *vaccel;

    struct virtio_accel_hdr hdr;
    QEMUIOVector out_qiov;
    QEMUIOVector in_qiov;
    struct iovec *in_data_iov;
    int in_data_niov;
    size_t in_iov_len;
    uint8_t *in_status;

    uint64_t request_id;
    uint32_t total_chunks;
    uint32_t received_chunks;
    struct VirtIOAccelReq **chunk_reqs;
    QEMUTimer *chunk_timer;

    uint32_t cmd;
    AccelDevBackendOpInfo info;

    QTAILQ_ENTRY(VirtIOAccelReq) next;
} VirtIOAccelReq;

typedef struct VirtIOAccelQueue {
    VirtQueue *dataq;
    QEMUBH *dataq_bh;
    struct VirtIOAccel *vaccel;
} VirtIOAccelQueue;

typedef QTAILQ_HEAD(, VirtIOAccelReq) VirtIOAccelReqList;

typedef struct VirtIOAccel {
    VirtIODevice parent_obj;

    VirtIOAccelQueue *vqs;
    VirtIOAccelConf conf;
    AccelDevBackend *runtime;

    QemuMutex pending_mutex;
    VirtIOAccelReqList pending_reqs;

    uint32_t max_queues;
    uint32_t status;

    int multiqueue;
    uint32_t curr_queue;
    size_t config_size;
} VirtIOAccel;

#endif /* _QEMU_VIRTIO_ACCEL_H */
