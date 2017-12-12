#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-accel.h"
#include "hw/virtio/virtio-access.h"

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
virtio_accel_crypto_create_session(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
	struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(req->vq);
    AccelDevBackendSessionInfo info;
    int64_t sess_id;
	int ret = -VIRTIO_ACCEL_ERR;
    Error *local_err = NULL;

	if (h->u.crypto_sess.keylen > vaccel->conf.u.crypto.max_cipher_key_len) {
        error_report("virtio-accel length of cipher key is too big: %u",
                     h->u.crypto_sess.keylen);
        return -VIRTIO_ACCEL_ERR;
    }

	if (h->u.crypto_sess.keylen > 0) {
		size_t s;
		h->u.crypto_sess.key = g_malloc(h->u.crypto_sess.keylen);
		s = iov_to_buf(req->in_iov, req->in_niov, 0, h->u.crypto_sess.key,
				h->u.crypto_sess.keylen);
        if (unlikely(s != h->u.crypto_sess.keylen)) {
            virtio_error(vdev, "virtio-accel cipher key incorrect");
            ret = -EFAULT;
			goto out;
        }
	}

    info.u.crypto.cipher_key = h->u.crypto_sess.key;
    info.u.crypto.keylen = h->u.crypto_sess.keylen;
    info.u.crypto.cipher = h->u.crypto_sess.cipher;
	sess_id = acceldev_backend_create_session(
                                     vaccel->crypto,
                                     &info, queue_index, &local_err);
    if (sess_id >= 0) {
		req->hdr.session_id = (uint32_t)sess_id;
        DPRINTF("crypto create session_id=%" PRIu32 " successful\n",
                req->hdr.session_id);
		ret = VIRTIO_ACCEL_OK;
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
		ret = (int)sess_id;
    }

out:
    g_free(info.u.crypto.cipher_key);
    return ret;
}

static int
virtio_accel_crypto_destroy_session(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
	struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(req->vq);
	int ret = -VIRTIO_ACCEL_ERR;
    Error *local_err = NULL;

	ret = acceldev_backend_destroy_session(
                                     vaccel->crypto,
                                     h->session_id,
									 queue_index, &local_err);
    if (ret >= 0) {
        DPRINTF("crypto destroy session_id=%" PRIu32 " successful\n",
                req->hdr.session_id);
    } else {
        if (local_err) {
            error_report_err(local_err);
		}
    }

    return ret;
}

static int
virtio_accel_crypto_do_op(VirtIOAccelReq *req)
{
	VirtIOAccel *vaccel = req->vaccel;
	struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(req->vq);
    AccelDevBackendOpInfo info;
    Error *local_err = NULL;
    int ret;

	info.op = h->op;
	info.session_id = h->session_id;
	info.u.crypto.src_len = h->u.crypto_op.src_len;
	info.u.crypto.src = h->u.crypto_op.src;
	info.u.crypto.dst_len = h->u.crypto_op.dst_len;
	info.u.crypto.dst = h->u.crypto_op.dst;
    switch (req->hdr.op) {
	case VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT:
	case VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT:
		ret = acceldev_backend_operation(vaccel->crypto,
								&info, queue_index, &local_err);
		break;
	default:
        error_report("virtio-crypto unsupported cipher operation");
        return -VIRTIO_ACCEL_NOTSUPP;
    }
	
    if (ret >= 0) {
        DPRINTF("crypto op session_id=%" PRIu32 " successful\n",
                info.session_id);
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
    }

    return ret;
}

static int
virtio_accel_handle_request(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    VirtQueueElement *elem = &req->elem;
    struct virtio_accel_hdr hdr;
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

    if (unlikely(iov_to_buf(out_iov, out_niov, 0, &hdr,
                            sizeof(hdr)) != sizeof(hdr))) {
        virtio_error(vdev, "virtio-accel request hdr too short");
        return -1;
    }
    iov_discard_front(&out_iov, &out_niov, sizeof(hdr));

    if (in_iov[in_niov - 1].iov_len <
            sizeof(status)) {
        virtio_error(vdev, "virtio-accel request status too short");
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

    req->hdr.op = virtio_ldl_p(vdev, &hdr.op);
    switch (req->hdr.op) {
	case VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION:
		req->hdr.u.crypto_sess.cipher = virtio_ldl_p(
				vdev, &hdr.u.crypto_sess.cipher);
		req->hdr.u.crypto_sess.keylen = virtio_ldl_p(
				vdev, &hdr.u.crypto_sess.keylen);
		
		ret = virtio_accel_crypto_create_session(req);
		if (ret >= 0) {
			virtio_stq_p(vdev, in_iov->iov_base, req->hdr.session_id);
		} else {
			/* Serious errors, need to reset virtio crypto device */
			if (ret == -EFAULT)
            	return -1;
		}
        virtio_accel_complete_request(req, ret);
        virtio_accel_free_request(req);
		break;
	case VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION:
		req->hdr.session_id = virtio_ldl_p(vdev, &hdr.session_id);
		
		ret = virtio_accel_crypto_destroy_session(req);
		/* Serious errors, need to reset virtio crypto device */
		if (ret == -EFAULT)
			return -1;

        virtio_accel_complete_request(req, ret);
        virtio_accel_free_request(req);
		break;
    case VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT:
    case VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT:
		req->hdr.session_id = virtio_ldl_p(vdev, &hdr.session_id);
		req->hdr.u.crypto_op.src_len = virtio_ldl_p(
				vdev, &hdr.u.crypto_op.src_len);
		req->hdr.u.crypto_op.src = in_iov[0].iov_base;
		req->hdr.u.crypto_op.dst_len = virtio_ldl_p(
				vdev, &hdr.u.crypto_op.dst_len);
		req->hdr.u.crypto_op.dst = in_iov[1].iov_base;

		ret = virtio_accel_crypto_do_op(req);
		/* Serious errors, need to reset virtio crypto device */
 		if (ret == -EFAULT)
			return -1;

        virtio_accel_complete_request(req, ret);
        virtio_accel_free_request(req);
		break;
	case VIRTIO_ACCEL_C_OP_HASH_CREATE_SESSION:
	case VIRTIO_ACCEL_C_OP_MAC_CREATE_SESSION:
	case VIRTIO_ACCEL_C_OP_AEAD_CREATE_SESSION:
	case VIRTIO_ACCEL_C_OP_HASH_DESTROY_SESSION:
	case VIRTIO_ACCEL_C_OP_MAC_DESTROY_SESSION:
	case VIRTIO_ACCEL_C_OP_AEAD_DESTROY_SESSION:
    case VIRTIO_ACCEL_C_OP_HASH:
    case VIRTIO_ACCEL_C_OP_MAC:
    case VIRTIO_ACCEL_C_OP_AEAD_ENCRYPT:
    case VIRTIO_ACCEL_C_OP_AEAD_DECRYPT:
    default:
        error_report("virtio-accel unsupported opcode: %u",
                     req->hdr.op);
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
    if (!acceldev_backend_is_ready(vaccel->crypto)) {
        vaccel->status &= ~VIRTIO_ACCEL_S_HW_READY;
    } else {
        vaccel->status |= VIRTIO_ACCEL_S_HW_READY;
    }
}

static void virtio_accel_init_config(VirtIODevice *vdev)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);

    vaccel->conf.services =
                     vaccel->conf.crypto->conf.services;
    vaccel->conf.u.crypto.max_cipher_key_len =
                  vaccel->conf.crypto->conf.u.crypto.max_cipher_key_len;
    vaccel->conf.u.crypto.max_auth_key_len =
                  vaccel->conf.crypto->conf.u.crypto.max_auth_key_len;
    vaccel->conf.max_size = vaccel->conf.crypto->conf.max_size;
}

static void virtio_accel_device_realize(DeviceState *dev, Error **errp)
{
    VirtIODevice *vdev = VIRTIO_DEVICE(dev);
    VirtIOAccel *vaccel = VIRTIO_ACCEL(dev);
    int i;

    vaccel->crypto = vaccel->conf.crypto;
    if (vaccel->crypto == NULL) {
        error_setg(errp, "'crypto' parameter expects a valid object");
        return;
    }

    vaccel->max_queues = MAX(vaccel->crypto->conf.peers.queues, 1);
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
                 virtio_add_queue(vdev, 1024, virtio_accel_dataq_callback);
        vaccel->vqs[i].dataq_bh =
                 qemu_bh_new(virtio_accel_dataq_bh_callback, &vaccel->vqs[i]);
		vaccel->vqs[i].vaccel = vaccel;
    }

    if (!acceldev_backend_is_ready(vaccel->crypto)) {
        vaccel->status &= ~VIRTIO_ACCEL_S_HW_READY;
    } else {
        vaccel->status |= VIRTIO_ACCEL_S_HW_READY;
    }

    virtio_accel_init_config(vdev);
    acceldev_backend_set_used(vaccel->crypto, true);
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
    acceldev_backend_set_used(vaccel->crypto, false);
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
    stl_le_p(&cfg.u.crypto.max_cipher_key_len,
			va->conf.u.crypto.max_cipher_key_len);
    stl_le_p(&cfg.u.crypto.max_auth_key_len,
			va->conf.u.crypto.max_auth_key_len);
    stq_le_p(&cfg.max_size, va->conf.max_size);

    memcpy(config, &cfg, va->config_size);
}

static void virtio_accel_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioDeviceClass *vdc = VIRTIO_DEVICE_CLASS(klass);

    dc->props = virtio_accel_properties;
    dc->vmsd = &vmstate_virtio_accel;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    vdc->realize = virtio_accel_device_realize;
    vdc->unrealize = virtio_accel_device_unrealize;
    vdc->get_config = virtio_accel_get_config;
    vdc->get_features = virtio_accel_get_features;
    vdc->reset = virtio_accel_reset;
}

static void
virtio_accel_check_crypto_is_used(Object *obj, const char *name,
                                      Object *val, Error **errp)
{
    if (acceldev_backend_is_used(ACCELDEV_BACKEND(val))) {
        char *path = object_get_canonical_path_component(val);
        error_setg(errp,
            "can't use already used accel backend: %s", path);
        g_free(path);
    } else {
        qdev_prop_allow_set_link_before_realize(obj, name, val, errp);
    }
}

static void virtio_accel_instance_init(Object *obj)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(obj);

    /*
     * The default config_size is sizeof(struct virtio_crypto_config).
     * Can be overriden with virtio_crypto_set_config_size.
     */
    vaccel->config_size = sizeof(struct virtio_accel_conf);

    object_property_add_link(obj, "crypto",
                             TYPE_ACCELDEV_BACKEND,
                             (Object **)&vaccel->conf.crypto,
                             virtio_accel_check_crypto_is_used,
                             OBJ_PROP_LINK_UNREF_ON_RELEASE, NULL);
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
