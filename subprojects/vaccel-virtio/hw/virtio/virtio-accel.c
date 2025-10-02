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

#include "hw/virtio/virtio-accel.h"
#include "standard-headers/linux/virtio_ids.h"

#define VIRTIO_ACCEL_VM_VERSION 1

// FIXME: move this to conf
#define CHUNK_TIMEOUT_MS 5000

static void virtio_accel_init_request(VirtIOAccelReq *req, VirtIOAccel *vaccel,
                                      VirtQueue *vq)
{
    req->vq = vq;
    req->vaccel = vaccel;

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
    memset(&req->info, 0x00, sizeof(req->info));
}

static void virtio_accel_free_request(VirtIOAccelReq *req)
{
    if (req->hdr.cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION ||
        req->hdr.cmd == VIRTIO_ACCEL_CMD_DO_OP ||
        req->hdr.cmd == VIRTIO_ACCEL_CMD_GET_TIMERS) {
        if (req->info.out)
            g_free(req->info.out);
        if (req->info.in)
            g_free(req->info.in);
    }

    if (req->out_qiov.nalloc != -1) {
        /* If nalloc is != -1 req->qiov is a local copy of the original
         * external iovec */
        qemu_iovec_destroy(&req->out_qiov);
    }
    if (req->in_qiov.nalloc != -1) {
        qemu_iovec_destroy(&req->in_qiov);
    }

    if (req->chunk_reqs)
        g_free(req->chunk_reqs);
    if (req)
        g_free(req);
}

static void virtio_accel_complete_request(VirtIOAccelReq *req, int ret)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    uint8_t status;

    if (ret < 0)
        status = (uint8_t)-ret;
    else
        status = (uint8_t)ret;

    stb_p(req->in_status, status);
    virtqueue_push(req->vq, &req->elem, req->in_iov_len);
    virtio_notify(vdev, req->vq);
}

static void virtio_accel_finalize_request(VirtIOAccelReq *req, int ret)
{
    uint32_t received_chunks = qatomic_read(&req->received_chunks);
    for (uint32_t i = 1; i < received_chunks; i++) {
        VirtIOAccelReq *chunk = req->chunk_reqs[i];

        virtqueue_push(chunk->vq, &chunk->elem, 0);
        virtio_accel_free_request(chunk);
    }

    virtio_accel_complete_request(req, ret);
    virtio_accel_free_request(req);
}

static int virtio_accel_handle_cmd(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    int queue_index = virtio_get_queue_index(req->vq);
    AccelDevBackendOpInfo *info = &req->info;
    struct iovec *in_iov = req->in_qiov.iov;
    unsigned int in_niov = req->in_qiov.niov;
    int64_t ret = -VIRTIO_ACCEL_ERR;
    Error *local_err = NULL;
    uint32_t *in_op_ret = NULL;
    uint64_t *in_sess_id = NULL;
    IOVDiscardUndo in_op_ret_undo;
    IOVDiscardUndo in_sess_id_undo;
    struct virtio_accel_arg_hdr arg_h;
    size_t r;
    size_t offset = 0;

    VADPRINTF("handle request cmd=%u, op_code=%u\n", req->cmd, info->op_code);

    if (in_iov[in_niov - 1].iov_len != sizeof(info->op_ret)) {
        virtio_error(vdev,
                     "virtio-accel ret SG too short; expected %zu got %zu",
                     sizeof(info->op_ret), in_iov[in_niov - 1].iov_len);
        return -VIRTIO_ACCEL_BADMSG;
    }

    in_op_ret = in_iov[in_niov - 1].iov_base;
    iov_discard_back_undoable(in_iov, &in_niov, in_iov[in_niov - 1].iov_len,
                              &in_op_ret_undo);

    switch (req->cmd) {
    case VIRTIO_ACCEL_CMD_CREATE_SESSION:
        if (in_iov[in_niov - 1].iov_len != sizeof(*in_sess_id)) {
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

        ret = acceldev_backend_create_session(vaccel->runtime, info,
                                              queue_index, &local_err);
        break;
    case VIRTIO_ACCEL_CMD_DO_OP:
        acceldev_backend_timer_start(vaccel->runtime, info->session_id, "do op",
                                     queue_index, &local_err);
        ret = acceldev_backend_operation(vaccel->runtime, info, queue_index,
                                         &local_err);
        break;
    case VIRTIO_ACCEL_CMD_DESTROY_SESSION:
        ret = acceldev_backend_destroy_session(
            vaccel->runtime, info->session_id, queue_index, &local_err);
        break;
    case VIRTIO_ACCEL_CMD_GET_TIMERS:
        ret = acceldev_backend_get_timers(vaccel->runtime, info, queue_index,
                                          &local_err);
        break;
    default:
        error_report("virtio-accel unsupported cmd: %u", req->cmd);
        ret = -VIRTIO_ACCEL_NOTSUPP;
        break;
    }

    if (ret >= 0) {
        for (uint32_t i = 0; i < info->in_nr; i++) {
            virtio_stl_p(vdev, &arg_h.len, info->in[i].data_len);
            virtio_stl_p(vdev, &arg_h.type, info->in[i].type);
            virtio_stl_p(vdev, &arg_h.custom_type_id,
                         info->in[i].custom_type_id);

            r = iov_from_buf(in_iov, in_niov, offset, &arg_h, sizeof(arg_h));
            if (unlikely(r != sizeof(arg_h))) {
                virtio_error(vdev, "virtio-accel in[%d] arg header too short",
                             i);
                ret = -VIRTIO_ACCEL_BADMSG;
                goto out;
            }

            offset += r;
        }

        for (uint32_t i = 0; i < info->in_nr; i++) {
            r = iov_from_buf(in_iov, in_niov, offset, info->in[i].buf,
                             info->in[i].len);
            if (unlikely(r != info->in[i].len)) {
                virtio_error(
                    vdev,
                    "virtio-accel in[%d] too short; expected %uB got %zuB", i,
                    info->in[i].len, r);
                ret = -VIRTIO_ACCEL_BADMSG;
                goto out;
            }

            offset += r;
        }

        if (req->cmd == VIRTIO_ACCEL_CMD_CREATE_SESSION) {
            virtio_stq_p(vdev, in_sess_id, ret);
            ret = 0;
        }

        VADPRINTF("runtime cmd=%u session_id=%" PRIu64 " successful\n",
                  req->cmd, info->session_id);
    } else {
        VADPRINTF("runtime cmd=%u failed\n", req->cmd);

        if (local_err)
            error_report_err(local_err);
    }

    if (ret < 0 && info->op_ret)
        virtio_stl_p(vdev, in_op_ret, info->op_ret);

out:
    if (in_sess_id)
        iov_discard_undo(&in_sess_id_undo);
    iov_discard_undo(&in_op_ret_undo);

    acceldev_backend_timer_stop(vaccel->runtime, info->session_id, "do op",
                                queue_index, &local_err);

    return ret;
}

static int virtio_accel_handle_req_data(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    QEMUIOVector *out_qiov = &req->out_qiov;
    QEMUIOVector *in_qiov = &req->in_qiov;
    AccelDevBackendOpInfo *info = &req->info;
    struct virtio_accel_arg_hdr arg_h;
    AccelDevBackendArg *gop_arg;
    size_t offset;
    size_t r;
    int i;

    if (info->out_nr > 0) {
        gop_arg = g_new0(AccelDevBackendArg, info->out_nr);
        offset = 0;
        for (i = 0; i < info->out_nr; i++) {
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

        for (i = 0; i < info->out_nr; i++) {
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
        info->out = gop_arg;
    }

    if (info->in_nr > 0) {
        gop_arg = g_new0(AccelDevBackendArg, info->in_nr);
        offset = 0;
        for (i = 0; i < info->in_nr; i++) {
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

        for (i = 0; i < info->in_nr; i++) {
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
        info->in = gop_arg;
    }

    return VIRTIO_ACCEL_OK;
}

static void virtio_accel_handle_req_hdr(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    AccelDevBackendOpInfo *info = &req->info;
    struct virtio_accel_hdr *h = &req->hdr;

    req->cmd = virtio_ldl_p(vdev, &h->cmd);
    req->request_id = virtio_ldq_p(vdev, &h->request_id);
    req->total_chunks = virtio_ldl_p(vdev, &h->total_chunks);

    info->op_code = virtio_ldl_p(vdev, &h->op_code);
    info->session_id = virtio_ldq_p(vdev, &h->session_id);
    info->out_nr = virtio_ldl_p(vdev, &h->out_nr);
    info->in_nr = virtio_ldl_p(vdev, &h->in_nr);
    info->op_ret = 0;
}

static VirtIOAccelReq *get_pending_req(uint64_t request_id, VirtIOAccel *vaccel)
{
    VirtIOAccelReq *req;

    QTAILQ_FOREACH(req, &vaccel->pending_reqs, next)
    {
        if (req->request_id == request_id) {
            return req;
        }
    }
    return NULL;
}

static void chunked_req_timeout(void *opaque)
{
    VirtIOAccelReq *req = opaque;
    VirtIOAccel *vaccel = req->vaccel;

    qemu_mutex_lock(&vaccel->pending_mutex);
    QTAILQ_REMOVE(&vaccel->pending_reqs, req, next);
    qemu_mutex_unlock(&vaccel->pending_mutex);

    virtio_accel_finalize_request(req, VIRTIO_ACCEL_ERR);
}

static void merge_req_chunks(VirtIOAccelReq *req)
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

static VirtIOAccelReq *virtio_accel_handle_chunk(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    uint32_t received_chunks;

    qemu_mutex_lock(&vaccel->pending_mutex);
    VirtIOAccelReq *parent_req = get_pending_req(req->request_id, vaccel);
    if (!parent_req) {
        QTAILQ_INSERT_TAIL(&vaccel->pending_reqs, req, next);
        parent_req = req;
    }
    qemu_mutex_unlock(&vaccel->pending_mutex);

    if (parent_req == req) {
        parent_req->chunk_reqs =
            g_new0(VirtIOAccelReq *, parent_req->total_chunks);

        parent_req->chunk_timer =
            timer_new_ms(QEMU_CLOCK_VIRTUAL, chunked_req_timeout, req);
    }

    timer_mod(parent_req->chunk_timer,
              qemu_clock_get_ms(QEMU_CLOCK_VIRTUAL) + CHUNK_TIMEOUT_MS);

    received_chunks = qatomic_fetch_inc(&parent_req->received_chunks);
    parent_req->chunk_reqs[received_chunks] = req;

    if (received_chunks + 1 < parent_req->total_chunks)
        return parent_req;

    timer_del(parent_req->chunk_timer);

    merge_req_chunks(parent_req);

    qemu_mutex_lock(&vaccel->pending_mutex);
    QTAILQ_REMOVE(&vaccel->pending_reqs, parent_req, next);
    qemu_mutex_unlock(&vaccel->pending_mutex);

    return parent_req;
}

static int virtio_accel_handle_request(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    VirtQueueElement *elem = &req->elem;
    struct iovec *out_iov = elem->out_sg;
    struct iovec *in_iov = elem->in_sg;
    unsigned out_num = elem->out_num;
    unsigned in_num = elem->in_num;
    int queue_index = virtio_get_queue_index(req->vq);
    Error *local_err = NULL;
    uint8_t status = VIRTIO_ACCEL_OK;
    size_t r;
    int ret;
    int i;

    if (out_num < 1 || in_num < 1) {
        virtio_error(
            vdev,
            "virtio-accel request missing headers/status (out_num=%u, in_num=%u)",
            out_num, in_num);
        return -1;
    }

    VADPRINTF("handle request out_num=%u, in_num=%u\n", out_num, in_num);

    for (i = 0; i < out_num; i++) {
        VADPRINTF("out_iov[%d].len: %zu\n", i, out_iov[i].iov_len);
    }
    for (i = 0; i < in_num; i++) {
        VADPRINTF("in_iov[%d].len: %zu\n", i, in_iov[i].iov_len);
    }

    r = iov_to_buf(out_iov, out_num, 0, &req->hdr, sizeof(req->hdr));
    if (unlikely(r != sizeof(req->hdr))) {
        virtio_error(
            vdev, "virtio-accel request hdr too short; expected %zuB got %zuB",
            sizeof(req->hdr), r);
        return -1;
    }
    iov_discard_front(&out_iov, &out_num, sizeof(req->hdr));

    virtio_accel_handle_req_hdr(req);

    if (req->cmd == VIRTIO_ACCEL_CMD_DO_OP) {
        acceldev_backend_timer_start(vaccel->runtime, req->info.session_id,
                                     "prepare header", queue_index, &local_err);
    }

    VADPRINTF("handle request id=%" PRId64 " session_id=%" PRId64 "\n",
              req->request_id, req->info.session_id);

    if (in_iov[in_num - 1].iov_len != sizeof(status)) {
        virtio_error(
            vdev,
            "virtio-accel incorrect request status size; expected %zu got %zu",
            sizeof(status), in_iov[in_num - 1].iov_len);
        return -1;
    }

    /* We always touch the last byte, so just see how big in_iov is. */
    req->in_iov_len = iov_size(in_iov, in_num);
    req->in_status = (void *)in_iov[in_num - 1].iov_base +
                     in_iov[in_num - 1].iov_len - sizeof(*req->in_status);
    iov_discard_back(in_iov, &in_num, sizeof(*req->in_status));

    qemu_iovec_init_external(&req->out_qiov, out_iov, out_num);
    qemu_iovec_init_external(&req->in_qiov, in_iov, in_num);

    if (req->request_id > 0) {
        req = virtio_accel_handle_chunk(req);
        VADPRINTF("handle chunked request received: %u, total: %u\n",
                  qatomic_read(&req->received_chunks), req->total_chunks);
        if (req->received_chunks < req->total_chunks)
            return 0;

        VADPRINTF("handle chunked request out_num=%u, in_num=%u\n", out_num,
                  in_num);
        for (i = 0; i < out_num; i++) {
            VADPRINTF("chunked out_iov[%d].len: %zu\n", i, out_iov[i].iov_len);
        }
        for (i = 0; i < in_num; i++) {
            VADPRINTF("chunked in_iov[%d].len: %zu\n", i, in_iov[i].iov_len);
        }
    }

    ret = virtio_accel_handle_req_data(req);
    if (ret)
        goto out;

    acceldev_backend_timer_stop(vaccel->runtime, req->info.session_id,
                                "prepare header", queue_index, &local_err);

    ret = virtio_accel_handle_cmd(req);
    if (ret == -EFAULT) {
        /* Serious errors, need to reset virtio accel device */
        return -1;
    }

out:
    virtio_accel_finalize_request(req, ret);
    return 0;
}

static VirtIOAccelReq *virtio_accel_get_request(VirtIOAccel *va, VirtQueue *vq)
{
    VirtIOAccelReq *req = virtqueue_pop(vq, sizeof(VirtIOAccelReq));

    if (req) {
        virtio_accel_init_request(req, va, vq);
    }
    return req;
}

static void virtio_accel_handle_dataq(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);
    VirtIOAccelReq *req;

    while ((req = virtio_accel_get_request(vaccel, vq))) {
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
    VirtIOAccel *vaccel = q->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);

    /* This happens when device was stopped but BH wasn't. */
    if (!vdev->vm_running) {
        return;
    }

    /* Just in case the driver is not ready on more */
    if (unlikely(!(vdev->status & VIRTIO_CONFIG_S_DRIVER_OK))) {
        return;
    }

    for (;;) {
        virtio_accel_handle_dataq(vdev, q->dataq);
        virtio_queue_set_notification(q->dataq, 1);

        /* Are we done or did the guest add more buffers? */
        if (virtio_queue_empty(q->dataq)) {
            break;
        }

        virtio_queue_set_notification(q->dataq, 0);
    }
}

static void virtio_accel_dataq_callback(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);
    VirtIOAccelQueue *q = &vaccel->vqs[virtio_get_queue_index(vq)];

    /* This happens when device was stopped but VCPU wasn't. */
    if (!vdev->vm_running) {
        return;
    }
    virtio_queue_set_notification(vq, 0);
    qemu_bh_schedule(q->dataq_bh);
}

static uint64_t virtio_accel_get_features(VirtIODevice *vdev, uint64_t features,
                                          Error **errp)
{
    return features;
}

static void virtio_accel_reset(VirtIODevice *vdev)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);
    /* multiqueue is disabled by default */
    vaccel->curr_queue = 1;
    if (!acceldev_backend_is_ready(vaccel->runtime)) {
        vaccel->status &= ~VIRTIO_ACCEL_S_HW_READY;
    } else {
        vaccel->status |= VIRTIO_ACCEL_S_HW_READY;
    }
}

static void virtio_accel_init_config(VirtIODevice *vdev)
{
    //VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);

    // FIXME
    //vaccel->conf.services =
    //              vaccel->conf.crypto->conf.services;
    //vaccel->conf.max_size = vaccel->conf.crypto->conf.max_size;
    //
}

static void virtio_accel_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOAccel *vaccel = VIRTIO_ACCEL(dev);
    int i;

    vaccel->runtime = vaccel->conf.runtime;
    if (vaccel->runtime == NULL) {
        error_setg(errp, "'runtime' parameter expects a valid object");
        return;
    } else if (acceldev_backend_is_used(vaccel->runtime)) {
        error_setg(
            errp, "can't use already used accel backend: %s",
            object_get_canonical_path_component(OBJECT(vaccel->conf.runtime)));
        return;
    }

    vaccel->max_queues = MAX(vaccel->runtime->conf.peers.queues, 1);
    if (vaccel->max_queues + 1 > VIRTIO_QUEUE_MAX) {
        error_setg(errp,
                   "Invalid number of queues (= %" PRIu32 "), "
                   "must be a positive integer less than %d.",
                   vaccel->max_queues, VIRTIO_QUEUE_MAX);
        return;
    }

    virtio_init(vdev, VIRTIO_ID_ACCEL, vaccel->config_size);
    vaccel->curr_queue = 1;
    vaccel->vqs = g_new0(VirtIOAccelQueue, vaccel->max_queues);
    for (i = 0; i < vaccel->max_queues; i++) {
        vaccel->vqs[i].dataq = virtio_add_queue(vdev, VIRTQUEUE_MAX_SIZE,
                                                virtio_accel_dataq_callback);
        vaccel->vqs[i].dataq_bh =
            qemu_bh_new(virtio_accel_dataq_bh_callback, &vaccel->vqs[i]);
        vaccel->vqs[i].vaccel = vaccel;
    }

    if (!acceldev_backend_is_ready(vaccel->runtime)) {
        vaccel->status &= ~VIRTIO_ACCEL_S_HW_READY;
    } else {
        vaccel->status |= VIRTIO_ACCEL_S_HW_READY;
    }

    virtio_accel_init_config(vdev);
    acceldev_backend_set_used(vaccel->runtime, true);

    if (virtio_vdev_has_feature(vdev, VIRTIO_F_RING_PACKED))
        VADPRINTF("HAS VIRTIO_F_RING_PACKED\n");
    else
        VADPRINTF("NO VIRTIO_F_RING_PACKED\n");

    qemu_mutex_init(&vaccel->pending_mutex);
    QTAILQ_INIT(&vaccel->pending_reqs);
}

static void virtio_accel_device_unrealize(DeviceState *dev)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOAccel *vaccel = VIRTIO_ACCEL(dev);
    VirtIOAccelQueue *q;
    int i, max_queues;

    max_queues = vaccel->multiqueue ? vaccel->max_queues : 1;
    for (i = 0; i < max_queues; i++) {
        virtio_delete_queue(vaccel->vqs[i].dataq);
        q = &vaccel->vqs[i];
        qemu_bh_delete(q->dataq_bh);
    }

    g_free(vaccel->vqs);

    virtio_cleanup(vdev);
    acceldev_backend_set_used(vaccel->runtime, false);
}

static const VMStateDescription vmstate_virtio_accel = {
    .name = "virtio-accel",
    .unmigratable = 1,
    .minimum_version_id = VIRTIO_ACCEL_VM_VERSION,
    .version_id = VIRTIO_ACCEL_VM_VERSION,
    .fields = (VMStateField[]){ VMSTATE_VIRTIO_DEVICE, VMSTATE_END_OF_LIST() },
};

static const Property virtio_accel_properties[] = {

    DEFINE_PROP_LINK("runtime", VirtIOAccel, conf.runtime,
                     TYPE_ACCELDEV_BACKEND, AccelDevBackend *),
};

static void virtio_accel_get_config(VirtIODevice *vdev, uint8_t *config)
{
    VirtIOAccel *va = VIRTIO_ACCEL(vdev);
    struct virtio_accel_conf cfg = {};

    // TODO:
    /*
     * Virtio-crypto device conforms to VIRTIO 1.0 which is always LE,
     * so we can use LE accessors directly.
     */
    //
    stl_le_p(&cfg.status, va->status);
    //stl_le_p(&cfg.max_dataqueues, va->max_queues);
    stl_le_p(&cfg.services, va->conf.services);
    stq_le_p(&cfg.max_size, va->conf.max_size);

    memcpy(config, &cfg, va->config_size);
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
    vdc->get_features = virtio_accel_get_features;
    vdc->reset = virtio_accel_reset;
}

static void virtio_accel_instance_init(Object *obj)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(obj);

    /*
     * The default config_size is sizeof(struct virtio_crypto_config).
     * Can be overriden with virtio_crypto_set_config_size.
     */
    vaccel->config_size = sizeof(struct virtio_accel_conf);
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
