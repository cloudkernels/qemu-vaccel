#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "qemu/main-loop.h"
#include "qemu/module.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-accel.h"
#include "hw/virtio/virtio-access.h"
#include "hw/qdev-properties.h"
#include "standard-headers/linux/virtio_ids.h"

#define VIRTIO_ACCEL_VM_VERSION 1

static void virtio_accel_init_request(VirtIOAccelReq *req,
                    VirtIOAccel *vaccel, VirtQueue *vq)
{
    req->flags = 0;
    req->vq = vq;
    req->vaccel = vaccel;
    req->in_iov = NULL;
    req->out_iov = NULL;
    req->in_niov = 0;
    req->out_niov = 0;
    req->in_iov_len = 0;
    req->in_status = NULL;
}

static void virtio_accel_free_request(VirtIOAccelReq *req)
{
    if (req->hdr.op_type == VIRTIO_ACCEL_CREATE_SESSION ||
            req->hdr.op_type == VIRTIO_ACCEL_DO_OP) {
        if (req->hdr.op.in)
            g_free(req->hdr.op.in);
        if (req->hdr.op.out)
            g_free(req->hdr.op.out);
    }
    if (req)
        g_free(req);
}

static void virtio_accel_complete_request(VirtIOAccelReq *req, int ret)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    uint32_t status;

    if (ret < 0)
        status = (uint32_t)-ret;
    else
        status = (uint32_t)ret;

    virtio_stl_p(vdev, req->in_status, status);
    virtqueue_push(req->vq, &req->elem, req->in_iov_len);
    virtio_notify(vdev, req->vq);
}

static VirtIOAccelReq *
virtio_accel_get_request(VirtIOAccel *va, VirtQueue *vq)
{
    VirtIOAccelReq *req = virtqueue_pop(vq, sizeof(VirtIOAccelReq));

    if (req) {
        virtio_accel_init_request(req, va, vq);
    }
    return req;
}

static int
virtio_accel_vaccel_create_session(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(req->vq);
    AccelDevBackendSessionInfo info;
    int64_t sess_id;
    int ret = -VIRTIO_ACCEL_ERR;
    size_t r;
    Error *local_err = NULL;

    info.op_type = h->op_type;
    info.op.in = (AccelDevBackendArg *)h->op.in;
    info.op.out = (AccelDevBackendArg *)h->op.out;
    info.op.in_nr = h->op.in_nr;
    info.op.out_nr = h->op.out_nr;
    sess_id = acceldev_backend_create_session(
                                     vaccel->runtime,
                                     &info, queue_index, &local_err);
    if (sess_id >= 0) {
        req->hdr.sess_id = (uint32_t)sess_id;
        for (int i = 0; i < h->op.in_nr; i++) {
                r = iov_from_buf(req->in_iov, req->in_niov, 0, info.op.in[i].buf,
                                info.op.in[i].len);
                if (unlikely(r != info.op.in[i].len)) {
                    virtio_error(vdev, "virtio-accel in[%d] data incorrect", i);
		    return -VIRTIO_ACCEL_ERR;
		}

                iov_discard_front(&req->in_iov, &req->in_niov,
                                info.op.in[i].len);
        }

        VADPRINTF("runtime create session_id=%" PRIu32 " successful\n",
                  req->hdr.sess_id);
        ret = VIRTIO_ACCEL_OK;
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
        ret = (int)sess_id;
    }

    return ret;
}

static int
virtio_accel_vaccel_destroy_session(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(req->vq);
    int ret = -VIRTIO_ACCEL_ERR;
    Error *local_err = NULL;

    ret = acceldev_backend_destroy_session(
                                     vaccel->runtime,
                                     h->sess_id,
                                     queue_index, &local_err);
    if (ret >= 0) {
        VADPRINTF("runtime destroy session_id=%" PRIu32 " successful\n",
                req->hdr.sess_id);
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
    }

    return ret;
}

static int
virtio_accel_vaccel_do_op(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(req->vq);
    AccelDevBackendOpInfo info;
    int ret = -VIRTIO_ACCEL_ERR;
    size_t r;
    Error *local_err = NULL;

    info.op_type = h->op_type;
    info.sess_id = h->sess_id;
    info.op.in = (AccelDevBackendArg *)h->op.in;
    info.op.out = (AccelDevBackendArg *)h->op.out;
    info.op.in_nr = h->op.in_nr;
    info.op.out_nr = h->op.out_nr;
    ret = acceldev_backend_operation(vaccel->runtime, &info, queue_index,
                                        &local_err);

    if (ret >= 0) {
        for (int i = 0; i < h->op.in_nr; i++) {
                r = iov_from_buf(req->in_iov, req->in_niov, 0, info.op.in[i].buf,
                                info.op.in[i].len);
                if (unlikely(r != info.op.in[i].len)) {
                    virtio_error(vdev, "virtio-accel in[%d] data incorrect", i);
		    return -VIRTIO_ACCEL_ERR;
		}

                iov_discard_front(&req->in_iov, &req->in_niov,
                                info.op.in[i].len);
        }

        VADPRINTF("runtime op session_id=%" PRIu32 " successful\n",
                info.sess_id);
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
    }

    return ret;
}

static void
virtio_accel_handle_req_header_data(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    struct virtio_accel_hdr *h = &req->hdr;
    int i;
    size_t r;
    AccelDevBackendArg *gop_arg;

    h->op_type = virtio_ldl_p(vdev, &h->op_type);
    switch (h->op_type) {
    case VIRTIO_ACCEL_CREATE_SESSION:
    case VIRTIO_ACCEL_DO_OP:
        h->op.in_nr = virtio_ldl_p(
                vdev, &h->op.in_nr);
        h->op.out_nr = virtio_ldl_p(
                vdev, &h->op.out_nr);
        // TODO: free g_new0/g_malloc0'ed buffers
        if (h->op.out_nr > 0) {
            gop_arg = g_new0(AccelDevBackendArg,
                                    h->op.out_nr);
            for (i = 0; i < h->op.out_nr; i++) {
                gop_arg[i].buf = g_malloc0(h->op.out[i].len);
                r = iov_to_buf(req->out_iov, req->out_niov, 0, gop_arg[i].buf,
                                h->op.out[i].len);
                if (unlikely(r !=  h->op.out[i].len)) {
                    virtio_error(vdev, "virtio-accel gop_arg[%d] too short", i);
                    return;
                }
                gop_arg[i].len = h->op.out[i].len;
                iov_discard_front(&req->out_iov, &req->out_niov,
                                h->op.out[i].len);
            }
            h->op.out = (struct virtio_accel_arg *)gop_arg;
        }
        if (h->op.in_nr > 0) {
            gop_arg = g_new0(AccelDevBackendArg, h->op.in_nr);
            for (i = 0; i < h->op.in_nr; i++) {
                gop_arg[i].buf = g_malloc0(h->op.in[i].len);
                gop_arg[i].len = h->op.in[i].len;
            }
            h->op.in = (struct virtio_accel_arg *)gop_arg;
        }
        break;
    case VIRTIO_ACCEL_DESTROY_SESSION:
        h->sess_id = virtio_ldl_p(vdev, &h->sess_id);
        break;
    default:
        break;
    }
}

static int
virtio_accel_handle_request(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    VirtQueueElement *elem = &req->elem;
    int ret;
    struct iovec *in_iov, *out_iov;
    unsigned int in_niov, out_niov;
    uint32_t status = VIRTIO_ACCEL_ERR;

    if (elem->out_num < 1 || elem->in_num < 1) {
        virtio_error(vdev, "virtio-accel request missing headers");
        return -1;
    }

    out_iov = elem->out_sg;
    out_niov = elem->out_num;
    in_iov = elem->in_sg;
    in_niov = elem->in_num;

    VADPRINTF("handle request in_iovs=%u, out_iovs=%u\n", in_niov, out_niov);
    if (unlikely(iov_to_buf(out_iov, out_niov, 0, &req->hdr,
                            sizeof(req->hdr)) != sizeof(req->hdr))) {
        virtio_error(vdev, "virtio-accel request hdr too short");
        return -1;
    }
    iov_discard_front(&out_iov, &out_niov, sizeof(req->hdr));

    if (req->hdr.op.out_nr > 0) {
        req->hdr.op.out = out_iov[0].iov_base;
        iov_discard_front(&out_iov, &out_niov, req->hdr.op.out_nr * sizeof(*req->hdr.op.out));
    }
    if (req->hdr.op.in_nr > 0) {
        req->hdr.op.in = out_iov[0].iov_base;
        iov_discard_front(&out_iov, &out_niov, req->hdr.op.in_nr * sizeof(*req->hdr.op.in));
    }

    if (in_iov[in_niov - 1].iov_len !=
            sizeof(status)) {
        virtio_error(vdev, "virtio-accel request status size incorrect");
        return -1;
    }
    /* We always touch the last byte, so just see how big in_iov is. */
    req->in_iov_len = iov_size(in_iov, in_niov);
    req->in_status = (void *)in_iov[in_niov - 1].iov_base
              + in_iov[in_niov - 1].iov_len
              - sizeof(*req->in_status);
    iov_discard_back(in_iov, &in_niov, sizeof(*req->in_status));

    req->in_iov = in_iov;
    req->in_niov = in_niov;
    req->out_iov = out_iov;
    req->out_niov = out_niov;

    virtio_accel_handle_req_header_data(req);
    VADPRINTF("handle request op=%u\n", req->hdr.op_type);
    switch (req->hdr.op_type) {
    case VIRTIO_ACCEL_CREATE_SESSION:
    case VIRTIO_ACCEL_DO_OP:
        if (req->hdr.op_type == VIRTIO_ACCEL_CREATE_SESSION) {
            ret = virtio_accel_vaccel_create_session(req);
            if (ret >= 0)
                virtio_stq_p(vdev, in_iov->iov_base, req->hdr.sess_id);
        } else {
            ret = virtio_accel_vaccel_do_op(req);
        }
        /* Serious errors, need to reset virtio accel device */
        if (ret == -EFAULT)
            return -1;
        
        virtio_accel_complete_request(req, ret);
        virtio_accel_free_request(req);
        break;
    case VIRTIO_ACCEL_DESTROY_SESSION:
        ret = virtio_accel_vaccel_destroy_session(req);
        /* Serious errors, need to reset virtio accel device */
        if (ret == -EFAULT)
            return -1;

        virtio_accel_complete_request(req, ret);
        virtio_accel_free_request(req);
        break;
    default:
        error_report("virtio-accel unsupported opcode: %u",
                     req->hdr.op_type);
        virtio_accel_complete_request(req, VIRTIO_ACCEL_NOTSUPP);
        virtio_accel_free_request(req);
    }

    return 0;
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

static void
virtio_accel_dataq_callback(VirtIODevice *vdev, VirtQueue *vq)
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

static uint64_t virtio_accel_get_features(VirtIODevice *vdev,
                                           uint64_t features,
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
        char *path = object_get_canonical_path_component(OBJECT(
				                         vaccel->conf.runtime));
        error_setg(errp, "can't use already used accel backend: %s", path);
        g_free(path);
	return;
    }


    vaccel->max_queues = MAX(vaccel->runtime->conf.peers.queues, 1);
    if (vaccel->max_queues + 1 > VIRTIO_QUEUE_MAX) {
        error_setg(errp, "Invalid number of queues (= %" PRIu32 "), "
                   "must be a positive integer less than %d.",
                   vaccel->max_queues, VIRTIO_QUEUE_MAX);
        return;
    }

    virtio_init(vdev, "virtio-accel", VIRTIO_ID_ACCEL, vaccel->config_size);
    vaccel->curr_queue = 1;
    vaccel->vqs = g_malloc0(sizeof(VirtIOAccelQueue) * vaccel->max_queues);
    for (i = 0; i < vaccel->max_queues; i++) {
        vaccel->vqs[i].dataq =
                 virtio_add_queue(vdev, VIRTQUEUE_MAX_SIZE, virtio_accel_dataq_callback);
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
}

static void virtio_accel_device_unrealize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOAccel *vaccel = VIRTIO_ACCEL(dev);
    VirtIOAccelQueue *q;
    int i, max_queues;

    max_queues = vaccel->multiqueue ? vaccel->max_queues : 1;
    for (i = 0; i < max_queues; i++) {
        virtio_del_queue(vdev, i);
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
    .fields = (VMStateField[]) {
        VMSTATE_VIRTIO_DEVICE,
        VMSTATE_END_OF_LIST()
    },
};

static Property virtio_accel_properties[] = {

    DEFINE_PROP_LINK("runtime", VirtIOAccel, conf.runtime,
                     TYPE_ACCELDEV_BACKEND, AccelDevBackend *),
    DEFINE_PROP_END_OF_LIST(),
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

static void virtio_accel_class_init(ObjectClass *klass, void *data)
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
