// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef _QEMU_VIRTIO_ACCEL_H
#define _QEMU_VIRTIO_ACCEL_H

#include "qemu/iov.h"
#include "hw/virtio/virtio.h"
#include "system/iothread.h"

#include "standard-headers/linux/virtio_accel.h"
#include "system/virtio-accel-backend.h"

#define TYPE_VIRTIO_ACCEL "virtio-accel-device"
#define VIRTIO_ACCEL(obj) OBJECT_CHECK(VirtIOAccel, (obj), TYPE_VIRTIO_ACCEL)
#define VIRTIO_ACCEL_GET_PARENT_CLASS(obj) \
    OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_ACCEL)

typedef struct VirtIOAccelConfig {
    VirtIOAccelBackend *backend;
    bool debug;
    uint32_t chunk_timeout;
    uint16_t num_queues;
    uint16_t queue_size;
    uint16_t max_req_descriptors;
} VirtIOAccelConfig;

struct VirtIOAccel;

typedef struct VirtIOAccelRequest {
    /* elem should always be first */
    VirtQueueElement elem;

    VirtQueue *vq;
    struct VirtIOAccel *dev;

    struct virtio_accel_header hdr;
    QEMUIOVector out_qiov;
    QEMUIOVector in_qiov;
    size_t in_iov_len;
    uint8_t *in_status;
    IOVDiscardUndo out_hdr_undo;
    IOVDiscardUndo in_status_undo;

    uint64_t request_id;
    uint32_t total_chunks;
    uint32_t received_chunks;
    struct VirtIOAccelRequest **chunk_reqs;
    QEMUTimer *chunk_timer;

    uint32_t cmd;
    VirtIOAccelBackendOp op;

    QTAILQ_ENTRY(VirtIOAccelRequest) next;
} VirtIOAccelRequest;

typedef struct VirtIOAccelQueue {
    VirtQueue *dataq;
    QEMUBH *dataq_bh;
    struct VirtIOAccel *dev;
} VirtIOAccelQueue;

typedef QTAILQ_HEAD(, VirtIOAccelRequest) VirtIOAccelRequestList;

typedef struct VirtIOAccel {
    VirtIODevice parent_obj;

    VirtIOAccelQueue *vqs;
    VirtIOAccelConfig config;
    VirtIOAccelBackend *backend;
    size_t config_size;

    QemuMutex pending_mutex;
    VirtIOAccelRequestList pending_reqs;
} VirtIOAccel;

#endif /* _QEMU_VIRTIO_ACCEL_H */
