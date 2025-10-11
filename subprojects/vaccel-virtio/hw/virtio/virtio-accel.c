// SPDX-License-Identifier: GPL-2.0-or-later

#include "qemu/osdep.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-access.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/iov.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "standard-headers/linux/virtio_ids.h"

#include "hw/virtio/virtio-accel.h"
#include "standard-headers/linux/virtio_accel.h"
#include "system/virtio-accel-backend.h"

#define VIRTIO_ACCEL_VM_VERSION 1
#define CHUNK_TIMEOUT_DEFAULT 5000

#define VADPRINTF(fmt, ...)                                       \
    do {                                                          \
        if (debug_enabled) {                                      \
            fprintf(stderr, "virtio_accel: " fmt, ##__VA_ARGS__); \
        }                                                         \
    } while (0)

static bool debug_enabled = false;

static void virtio_accel_init_request(VirtIOAccelRequest *req, VirtIOAccel *va,
                                      VirtQueue *vq)
{
    req->vq = vq;
    req->dev = va;

    memset(&req->hdr, 0x00, sizeof(req->hdr));
    qemu_iovec_init_external(&req->out_qiov, NULL, 0);
    qemu_iovec_init_external(&req->in_qiov, NULL, 0);
    req->in_iov_len = 0;
    req->in_status = NULL;

    req->request_id = 0;
    req->total_chunks = 0;
    qatomic_set(&req->received_chunks, 0);
    req->chunk_reqs = NULL;
    req->chunk_timer = NULL;

    req->cmd = 0;
    memset(&req->op, 0x00, sizeof(req->op));
}

static void virtio_accel_free_request(VirtIOAccelRequest *req)
{
    if (req->hdr.cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION ||
        req->hdr.cmd == VIRTIO_ACCEL_CMD_DO_OP ||
        req->hdr.cmd == VIRTIO_ACCEL_CMD_GET_TIMERS) {
        if (req->op.out)
            g_free(req->op.out);
        if (req->op.in)
            g_free(req->op.in);
    }

    if (req->out_qiov.nalloc != -1) {
        /* If nalloc is != -1 req->qiov is a local copy of the original
         * external iovec */
        qemu_iovec_destroy(&req->out_qiov);
    }
    if (req->in_qiov.nalloc != -1)
        qemu_iovec_destroy(&req->in_qiov);

    timer_free(req->chunk_timer);
    if (req->chunk_reqs)
        g_free(req->chunk_reqs);
    if (req)
        g_free(req);
}

static void virtio_accel_complete_request(VirtIOAccelRequest *req, int ret)
{
    VirtIOAccel *va = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(va);
    uint8_t status;

    if (ret < 0)
        status = (uint8_t)-ret;
    else
        status = (uint8_t)ret;
    stb_p(req->in_status, status);

    iov_discard_undo(&req->out_hdr_undo);
    iov_discard_undo(&req->in_status_undo);
    virtqueue_push(req->vq, &req->elem, req->in_iov_len);
    virtio_notify(vdev, req->vq);
}

static void virtio_accel_finalize_request(VirtIOAccelRequest *req, int ret)
{
    uint32_t received_chunks = qatomic_read(&req->received_chunks);
    for (uint32_t i = 1; i < received_chunks; i++) {
        VirtIOAccelRequest *chunk = req->chunk_reqs[i];

        virtqueue_push(chunk->vq, &chunk->elem, 0);
        virtio_accel_free_request(chunk);
    }

    virtio_accel_complete_request(req, ret);
    virtio_accel_free_request(req);
}

static int virtio_accel_handle_cmd(VirtIOAccelRequest *req)
{
    VirtIOAccel *va = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(va);
    VirtIOAccelBackend *backend = va->backend;
    VirtIOAccelBackendOp *op = &req->op;
    struct iovec *in_iov = req->in_qiov.iov;
    unsigned int in_niov = req->in_qiov.niov;
    int64_t ret = -VIRTIO_ACCEL_ERR;
    Error *local_err = NULL;
    uint32_t *in_op_ret = NULL;
    uint64_t *in_sess_id = NULL;
    IOVDiscardUndo in_op_ret_undo;
    IOVDiscardUndo in_sess_id_undo;
    struct virtio_accel_arg_header arg_h;
    size_t r;
    size_t offset = 0;

    VADPRINTF("handle cmd=%u, op_code=%u\n", req->cmd, op->op_code);

    if (in_iov[in_niov - 1].iov_len < sizeof(op->op_ret)) {
        virtio_error(vdev,
                     "virtio-accel ret SG too short; expected %zu got %zu",
                     sizeof(op->op_ret), in_iov[in_niov - 1].iov_len);
        return -VIRTIO_ACCEL_BADMSG;
    }

    in_op_ret = in_iov[in_niov - 1].iov_base;
    iov_discard_back_undoable(in_iov, &in_niov, in_iov[in_niov - 1].iov_len,
                              &in_op_ret_undo);

    switch (req->cmd) {
    case VIRTIO_ACCEL_CMD_CREATE_SESSION:
        if (in_iov[in_niov - 1].iov_len < sizeof(*in_sess_id)) {
            virtio_error(
                vdev,
                "virtio-accel session_id SG too short; expected %zuB got %zuB",
                sizeof(*in_sess_id), in_iov[in_niov - 1].iov_len);
            ret = -VIRTIO_ACCEL_BADMSG;
            goto out;
        }

        in_sess_id = in_iov[in_niov - 1].iov_base;
        iov_discard_back_undoable(in_iov, &in_niov, in_iov[in_niov - 1].iov_len,
                                  &in_sess_id_undo);

        ret = virtio_accel_backend_create_session(backend, op, &local_err);
        break;
    case VIRTIO_ACCEL_CMD_DO_OP:
        virtio_accel_backend_timer_start(backend, op->session_id, "do op",
                                         &local_err);
        ret = virtio_accel_backend_operation(backend, op, &local_err);
        break;
    case VIRTIO_ACCEL_CMD_DESTROY_SESSION:
        ret = virtio_accel_backend_destroy_session(backend, op->session_id,
                                                   &local_err);
        break;
    case VIRTIO_ACCEL_CMD_GET_TIMERS:
        ret = virtio_accel_backend_get_timers(backend, op, &local_err);
        break;
    default:
        error_report("virtio-accel unsupported cmd: %u", req->cmd);
        ret = -VIRTIO_ACCEL_NOTSUPP;
        break;
    }

    if (ret >= 0) {
        for (uint32_t i = 0; i < op->nr_in; i++) {
            virtio_stl_p(vdev, &arg_h.len, op->in[i].data_len);
            virtio_stl_p(vdev, &arg_h.type, op->in[i].type);
            virtio_stl_p(vdev, &arg_h.custom_type_id, op->in[i].custom_type_id);

            r = iov_from_buf(in_iov, in_niov, offset, &arg_h, sizeof(arg_h));
            if (unlikely(r != sizeof(arg_h))) {
                virtio_error(vdev, "virtio-accel in[%d] arg header too short",
                             i);
                ret = -VIRTIO_ACCEL_BADMSG;
                goto out;
            }

            offset += r;
        }

        for (uint32_t i = 0; i < op->nr_in; i++) {
            r = iov_from_buf(in_iov, in_niov, offset, op->in[i].buf,
                             op->in[i].len);
            if (unlikely(r != op->in[i].len)) {
                virtio_error(
                    vdev,
                    "virtio-accel in[%d] too short; expected %uB got %zuB", i,
                    op->in[i].len, r);
                ret = -VIRTIO_ACCEL_BADMSG;
                goto out;
            }

            offset += r;
        }

        if (req->cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) {
            virtio_stq_p(vdev, in_sess_id, ret);
            ret = 0;
        }

        VADPRINTF("cmd session_id=%" PRIu64 " successful\n", op->session_id);
    } else {
        VADPRINTF("cmd failed\n");

        if (local_err)
            error_report_err(local_err);
    }

    if (ret < 0 && op->op_ret)
        virtio_stl_p(vdev, in_op_ret, op->op_ret);

out:
    if (in_sess_id)
        iov_discard_undo(&in_sess_id_undo);
    iov_discard_undo(&in_op_ret_undo);

    virtio_accel_backend_timer_stop(backend, op->session_id, "do op",
                                    &local_err);

    return ret;
}

static int virtio_accel_handle_req_data(VirtIOAccelRequest *req)
{
    VirtIOAccel *va = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(va);
    QEMUIOVector *out_qiov = &req->out_qiov;
    QEMUIOVector *in_qiov = &req->in_qiov;
    VirtIOAccelBackendOp *op = &req->op;
    struct virtio_accel_arg_header arg_h;
    VirtIOAccelBackendArg *gop_arg;
    size_t offset;
    size_t r;
    int i;

    if (op->nr_out > 0) {
        gop_arg = g_new0(VirtIOAccelBackendArg, op->nr_out);
        offset = 0;
        for (i = 0; i < op->nr_out; i++) {
            r = iov_to_buf(out_qiov->iov, out_qiov->niov, offset, &arg_h,
                           sizeof(arg_h));
            if (unlikely(r != sizeof(arg_h))) {
                virtio_error(vdev, "virtio-accel out[%d] arg header too short",
                             i);
                return VIRTIO_ACCEL_BADMSG;
            }
            offset += r;

            gop_arg[i].len = virtio_ldl_p(vdev, &arg_h.len);
            gop_arg[i].data_len = gop_arg[i].len;
            gop_arg[i].type = virtio_ldl_p(vdev, &arg_h.type);
            gop_arg[i].custom_type_id =
                virtio_ldl_p(vdev, &arg_h.custom_type_id);
        }

        for (i = 0; i < op->nr_out; i++) {
            gop_arg[i].buf = g_malloc0(gop_arg[i].len);
            r = iov_to_buf(out_qiov->iov, out_qiov->niov, offset,
                           gop_arg[i].buf, gop_arg[i].len);
            if (unlikely(r != gop_arg[i].len)) {
                virtio_error(
                    vdev,
                    "virtio-accel gop_arg[%d] too short; expected %uB got %zuB",
                    i, gop_arg[i].len, r);
                return VIRTIO_ACCEL_BADMSG;
            }
            offset += r;
        }
        op->out = gop_arg;
    }

    if (op->nr_in > 0) {
        gop_arg = g_new0(VirtIOAccelBackendArg, op->nr_in);
        offset = 0;
        for (i = 0; i < op->nr_in; i++) {
            r = iov_to_buf(in_qiov->iov, in_qiov->niov, offset, &arg_h,
                           sizeof(arg_h));
            if (unlikely(r != sizeof(arg_h))) {
                virtio_error(vdev, "virtio-accel in[%d] arg header too short",
                             i);
                return VIRTIO_ACCEL_BADMSG;
            }
            offset += r;

            gop_arg[i].len = virtio_ldl_p(vdev, &arg_h.len);
            gop_arg[i].data_len = gop_arg[i].len;
            gop_arg[i].type = virtio_ldl_p(vdev, &arg_h.type);
            gop_arg[i].custom_type_id =
                virtio_ldl_p(vdev, &arg_h.custom_type_id);
        }

        for (i = 0; i < op->nr_in; i++) {
            gop_arg[i].buf = g_malloc0(gop_arg[i].len);
            r = iov_to_buf(in_qiov->iov, in_qiov->niov, offset, gop_arg[i].buf,
                           gop_arg[i].len);
            if (unlikely(r != gop_arg[i].len)) {
                virtio_error(
                    vdev,
                    "virtio-accel gop_arg[%d] too short; expected %uB got %zuB",
                    i, gop_arg[i].len, r);
                return VIRTIO_ACCEL_BADMSG;
            }
            offset += r;
        }
        op->in = gop_arg;
    }

    return VIRTIO_ACCEL_OK;
}

static void virtio_accel_handle_req_hdr(VirtIOAccelRequest *req)
{
    VirtIOAccel *va = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(va);
    VirtIOAccelBackendOp *op = &req->op;
    struct virtio_accel_header *h = &req->hdr;

    req->cmd = virtio_ldl_p(vdev, &h->cmd);
    req->request_id = virtio_ldq_p(vdev, &h->request_id);
    req->total_chunks = virtio_ldl_p(vdev, &h->total_chunks);

    op->op_code = virtio_ldl_p(vdev, &h->op_code);
    op->session_id = virtio_ldq_p(vdev, &h->session_id);
    op->nr_out = virtio_ldl_p(vdev, &h->nr_out);
    op->nr_in = virtio_ldl_p(vdev, &h->nr_in);
    op->op_ret = 0;
}

static VirtIOAccelRequest *get_pending_req(uint64_t request_id, VirtIOAccel *va)
{
    VirtIOAccelRequest *req;

    QTAILQ_FOREACH(req, &va->pending_reqs, next)
    {
        if (req->request_id == request_id)
            return req;
    }
    return NULL;
}

static void chunked_req_timeout(void *opaque)
{
    VirtIOAccelRequest *req = opaque;
    VirtIOAccel *va = req->dev;

    qemu_mutex_lock(&va->pending_mutex);
    QTAILQ_REMOVE(&va->pending_reqs, req, next);
    qemu_mutex_unlock(&va->pending_mutex);

    virtio_accel_finalize_request(req, VIRTIO_ACCEL_ERR);
}

static void merge_req_chunks(VirtIOAccelRequest *req)
{
    QEMUIOVector *out_qiov = &req->out_qiov;
    QEMUIOVector *in_qiov = &req->in_qiov;
    int out_niov = 0;
    int in_niov = 0;
    uint32_t i;

    for (i = 0; i < req->total_chunks; i++) {
        out_niov += req->chunk_reqs[i]->out_qiov.niov;
        in_niov += req->chunk_reqs[i]->in_qiov.niov;
    }

    if (out_niov > 1) {
        struct iovec *tmp_iov = out_qiov->iov;
        int tmp_niov = out_qiov->niov;

        /* parent qiov was initialized from external so we can't
         * modify it here. We need to initialize it locally and then add the
         * external iovecs. */
        qemu_iovec_init(out_qiov, out_niov);

        for (i = 0; i < tmp_niov; i++)
            qemu_iovec_add(out_qiov, tmp_iov[i].iov_base, tmp_iov[i].iov_len);

        for (i = 1; i < req->total_chunks; i++) {
            qemu_iovec_concat(out_qiov, &req->chunk_reqs[i]->out_qiov, 0,
                              req->chunk_reqs[i]->out_qiov.size);
        }
    }

    if (in_niov > 1) {
        struct iovec *tmp_iov = in_qiov->iov;
        int tmp_niov = in_qiov->niov;

        qemu_iovec_init(in_qiov, in_niov);

        for (i = 0; i < tmp_niov; i++)
            qemu_iovec_add(in_qiov, tmp_iov[i].iov_base, tmp_iov[i].iov_len);

        for (i = 1; i < req->total_chunks; i++) {
            qemu_iovec_concat(in_qiov, &req->chunk_reqs[i]->in_qiov, 0,
                              req->chunk_reqs[i]->in_qiov.size);
        }
    }

    req->in_iov_len =
        iov_size(req->in_qiov.iov, req->in_qiov.niov) + sizeof(*req->in_status);
}

static VirtIOAccelRequest *virtio_accel_handle_chunk(VirtIOAccelRequest *req)
{
    VirtIOAccel *va = req->dev;
    VirtIOAccelConfig *config = &va->config;
    uint32_t received_chunks;

    qemu_mutex_lock(&va->pending_mutex);
    VirtIOAccelRequest *parent_req = get_pending_req(req->request_id, va);
    if (!parent_req) {
        QTAILQ_INSERT_TAIL(&va->pending_reqs, req, next);
        parent_req = req;
    }
    qemu_mutex_unlock(&va->pending_mutex);

    if (parent_req == req) {
        parent_req->chunk_reqs =
            g_new0(VirtIOAccelRequest *, parent_req->total_chunks);

        parent_req->chunk_timer =
            timer_new_ms(QEMU_CLOCK_VIRTUAL, chunked_req_timeout, req);
    }

    timer_mod(parent_req->chunk_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + config->chunk_timeout);

    received_chunks = qatomic_fetch_inc(&parent_req->received_chunks);
    parent_req->chunk_reqs[received_chunks] = req;

    if (received_chunks + 1 < parent_req->total_chunks)
        return parent_req;

    timer_del(parent_req->chunk_timer);

    merge_req_chunks(parent_req);

    qemu_mutex_lock(&va->pending_mutex);
    QTAILQ_REMOVE(&va->pending_reqs, parent_req, next);
    qemu_mutex_unlock(&va->pending_mutex);

    return parent_req;
}

static int virtio_accel_handle_request(VirtIOAccelRequest *req)
{
    VirtIOAccel *va = req->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(va);
    VirtIOAccelBackend *backend = va->backend;
    VirtQueueElement *elem = &req->elem;
    struct iovec *out_iov = elem->out_sg;
    struct iovec *in_iov = elem->in_sg;
    unsigned out_num = elem->out_num;
    unsigned in_num = elem->in_num;
    Error *local_err = NULL;
    uint8_t status = VIRTIO_ACCEL_OK;
    size_t r;
    int ret;

    if (out_num < 1 || in_num < 1) {
        virtio_error(
            vdev,
            "virtio-accel request missing headers/status (out_num=%u, in_num=%u)",
            out_num, in_num);
        return -1;
    }

    VADPRINTF("handle request out_num=%u, in_num=%u\n", out_num, in_num);

    r = iov_to_buf(out_iov, out_num, 0, &req->hdr, sizeof(req->hdr));
    if (unlikely(r != sizeof(req->hdr))) {
        virtio_error(
            vdev, "virtio-accel request hdr too short; expected %zuB got %zuB",
            sizeof(req->hdr), r);
        return -1;
    }
    iov_discard_front_undoable(&out_iov, &out_num, sizeof(req->hdr),
                               &req->out_hdr_undo);

    virtio_accel_handle_req_hdr(req);

    if (req->cmd == VIRTIO_ACCEL_CMD_DO_OP) {
        virtio_accel_backend_timer_start(backend, req->op.session_id,
                                         "prepare header", &local_err);
    }

    VADPRINTF("request id=%" PRId64 " session_id=%" PRId64 "\n",
              req->request_id, req->op.session_id);

    if (in_iov[in_num - 1].iov_len < sizeof(status)) {
        virtio_error(
            vdev,
            "virtio-accel incorrect request status size; expected %zu got %zu",
            sizeof(status), in_iov[in_num - 1].iov_len);
        iov_discard_undo(&req->out_hdr_undo);
        return -1;
    }

    /* We always touch the last byte, so just see how big in_iov is. */
    req->in_iov_len = iov_size(in_iov, in_num);
    req->in_status = (void *)in_iov[in_num - 1].iov_base +
                     in_iov[in_num - 1].iov_len - sizeof(*req->in_status);
    iov_discard_back_undoable(in_iov, &in_num, sizeof(*req->in_status),
                              &req->in_status_undo);

    qemu_iovec_init_external(&req->out_qiov, out_iov, out_num);
    qemu_iovec_init_external(&req->in_qiov, in_iov, in_num);

    if (req->request_id > 0) {
        VirtIOAccelRequest *chunk = req;
        VADPRINTF("handle chunked request out_num=%u, in_num=%u\n", out_num,
                  in_num);

        req = virtio_accel_handle_chunk(chunk);
        VADPRINTF("chunked request received=%u, total=%u\n",
                  qatomic_read(&req->received_chunks), req->total_chunks);

        if (req->received_chunks < req->total_chunks) {
            iov_discard_undo(&chunk->out_hdr_undo);
            iov_discard_undo(&chunk->in_status_undo);
            return 0;
        }
    }

    ret = virtio_accel_handle_req_data(req);
    if (ret)
        goto out;

    virtio_accel_backend_timer_stop(backend, req->op.session_id,
                                    "prepare header", &local_err);

    ret = virtio_accel_handle_cmd(req);
    if (ret == -EFAULT) {
        /* Serious errors, need to reset virtio accel device */
        iov_discard_undo(&req->out_hdr_undo);
        iov_discard_undo(&req->in_status_undo);
        return -1;
    }

out:
    virtio_accel_finalize_request(req, ret);
    return 0;
}

static VirtIOAccelRequest *virtio_accel_get_request(VirtIOAccel *va,
                                                    VirtQueue *vq)
{
    VirtIOAccelRequest *req = virtqueue_pop(vq, sizeof(VirtIOAccelRequest));

    if (req) {
        virtio_accel_init_request(req, va, vq);
    }
    return req;
}

static void virtio_accel_handle_dataq(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOAccel *va = VIRTIO_ACCEL(vdev);
    VirtIOAccelRequest *req;

    while ((req = virtio_accel_get_request(va, vq))) {
        if (virtio_accel_handle_request(req) < 0) {
            virtqueue_detach_element(req->vq, &req->elem, 0);
            virtio_accel_free_request(req);
            break;
        }
    }
}

static void virtio_accel_dataq_bh_callback(void *opaque)
{
    VirtIOAccelQueue *q = opaque;
    VirtIOAccel *va = q->dev;
    VirtIODevice *vdev = VIRTIO_DEVICE(va);

    /* This happens when device was stopped but BH wasn't. */
    if (!vdev->vm_running)
        return;

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK)))
        return;

    for (;;) {
        virtio_accel_handle_dataq(vdev, q->dataq);
        virtio_queue_set_notification(q->dataq, 1);

        /* Are we done or did the guest add more buffers? */
        if (virtio_queue_empty(q->dataq))
            break;

        virtio_queue_set_notification(q->dataq, 0);
    }
}

static void virtio_accel_dataq_callback(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOAccel *va = VIRTIO_ACCEL(vdev);
    VirtIOAccelQueue *q = &va->vqs[virtio_get_queue_index(vq)];

    /* This happens when device was stopped but VCPU wasn't. */
    if (!vdev->vm_running)
        return;

    virtio_queue_set_notification(vq, 0);
    qemu_bh_schedule(q->dataq_bh);
}

static uint64_t virtio_accel_get_features(VirtIODevice *vdev, uint64_t features,
                                          Error **errp)
{
    return features;
}

static void virtio_accel_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOAccel *va = VIRTIO_ACCEL(dev);
    VirtIOAccelConfig *config = &va->config;
    int i;

    va->backend = config->backend;
    if (va->backend == NULL) {
        error_setg(errp, "'backend' parameter expects a valid object");
        return;
    } else if (virtio_accel_backend_is_used(va->backend)) {
        error_setg(
            errp, "Cannot use already used virtio-accel backend: %s",
            object_get_canonical_path_component(OBJECT(config->backend)));
        return;
    }

    debug_enabled = config->debug;

    if (config->chunk_timeout < 1000) {
        error_setg(errp,
                   "Invalid chunk-timeout property (%" PRIu32 "); "
                   "must be >= 1000",
                   config->chunk_timeout);
        return;
    }

    if (config->num_queues != 1) {
        error_setg(errp, "Only a single virtqueue is supported");
        return;
    }

    if (config->queue_size <= 2) {
        error_setg(errp,
                   "Invalid queue-size property (%" PRIu16 "); "
                   "must be > 2",
                   config->queue_size);
        return;
    }
    if (!is_power_of_2(config->queue_size) ||
        config->queue_size > VIRTQUEUE_MAX_SIZE) {
        error_setg(errp,
                   "Invalid queue-size property (%" PRIu16 "); "
                   "must be a power of 2 (max %d)",
                   config->queue_size, VIRTQUEUE_MAX_SIZE);
        return;
    }

    if (config->max_req_descriptors > config->queue_size) {
        error_setg(errp,
                   "Invalid max-req-descriptors property (%" PRIu16 "); "
                   "cannot be > queue-size property",
                   config->max_req_descriptors);
        return;
    }

    virtio_init(vdev, VIRTIO_ID_ACCEL, va->config_size);

    va->vqs = g_new0(VirtIOAccelQueue, config->num_queues);
    for (i = 0; i < config->num_queues; i++) {
        va->vqs[i].dataq = virtio_add_queue(vdev, config->queue_size,
                                            virtio_accel_dataq_callback);
        va->vqs[i].dataq_bh =
            qemu_bh_new(virtio_accel_dataq_bh_callback, &va->vqs[i]);
        va->vqs[i].dev = va;
    }

    virtio_accel_backend_set_used(va->backend, true);

    qemu_mutex_init(&va->pending_mutex);
    QTAILQ_INIT(&va->pending_reqs);
}

static void virtio_accel_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOAccel *va = VIRTIO_ACCEL(dev);
    VirtIOAccelConfig *config = &va->config;
    VirtIOAccelRequest *req;

    qemu_mutex_lock(&va->pending_mutex);
    QTAILQ_FOREACH(req, &va->pending_reqs, next)
    {
        QTAILQ_REMOVE(&va->pending_reqs, req, next);
        virtio_accel_free_request(req);
    }
    qemu_mutex_unlock(&va->pending_mutex);
    qemu_mutex_destroy(&va->pending_mutex);

    for (uint16_t i = 0; i < config->num_queues; i++) {
        virtio_delete_queue(va->vqs[i].dataq);
        qemu_bh_delete(va->vqs[i].dataq_bh);
    }
    g_free(va->vqs);

    virtio_cleanup(vdev);
    virtio_accel_backend_set_used(va->backend, false);
}

static const VMStateDescription vmstate_virtio_accel = {
    .name = "virtio-accel",
    .unmigratable = 1,
    .minimum_version_id = VIRTIO_ACCEL_VM_VERSION,
    .version_id = VIRTIO_ACCEL_VM_VERSION,
    .fields = (VMStateField[]){ VMSTATE_VIRTIO_DEVICE, VMSTATE_END_OF_LIST() },
};

static const Property virtio_accel_properties[] = {

    DEFINE_PROP_LINK("backend", VirtIOAccel, config.backend,
                     TYPE_VIRTIO_ACCEL_BACKEND, VirtIOAccelBackend *),
    DEFINE_PROP_BOOL("debug", VirtIOAccel, config.debug, false),
    DEFINE_PROP_UINT32("chunk-timeout", VirtIOAccel, config.chunk_timeout,
                       CHUNK_TIMEOUT_DEFAULT),
    DEFINE_PROP_UINT16("num-queues", VirtIOAccel, config.num_queues, 1),
    DEFINE_PROP_UINT16("queue-size", VirtIOAccel, config.queue_size,
                       VIRTQUEUE_MAX_SIZE),
    DEFINE_PROP_UINT16("max-req-descriptors", VirtIOAccel,
                       config.max_req_descriptors, VIRTQUEUE_MAX_SIZE),
};

static void virtio_accel_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOAccel *va = VIRTIO_ACCEL(vdev);
    struct virtio_accel_config cfg;

    memset(&cfg, 0, sizeof(cfg));

    virtio_stw_p(vdev, &cfg.num_queues, va->config.num_queues);
    virtio_stw_p(vdev, &cfg.max_req_descriptors,
                 va->config.max_req_descriptors);

    memcpy(config, &cfg, va->config_size);
}

static void virtio_accel_set_config(VirtIODevice *vdev, const uint8_t *config)
{
    VirtIOAccel *va = VIRTIO_ACCEL(vdev);
    struct virtio_accel_config cfg;

    memcpy(&cfg, config, va->config_size);
}

static void virtio_accel_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    device_class_set_props(dc, virtio_accel_properties);
    dc->vmsd = &vmstate_virtio_accel;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_accel_device_realize;
    vdc->unrealize = virtio_accel_device_unrealize;
    vdc->get_config = virtio_accel_get_config;
    vdc->set_config = virtio_accel_set_config;
    vdc->get_features = virtio_accel_get_features;
}

static void virtio_accel_instance_init(Object *obj)
{
    VirtIOAccel *va = VIRTIO_ACCEL(obj);

    va->config_size = sizeof(struct virtio_accel_config);
}

static const TypeInfo virtio_accel_info = {
    .name = TYPE_VIRTIO_ACCEL,
    .parent = TYPE_VIRTIO_DEVICE,
    .instance_size = sizeof(VirtIOAccel),
    .instance_init = virtio_accel_instance_init,
    .class_init = virtio_accel_class_init,
};

static void virtio_register_types(void)
{
    type_register_static(&virtio_accel_info);
}

type_init(virtio_register_types)
