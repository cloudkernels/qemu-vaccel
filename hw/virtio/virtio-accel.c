/*
 * Virtio crypto Support
 *
 * Copyright (c) 2016 HUAWEI TECHNOLOGIES CO., LTD.
 *
 * Authors:
 *    Gonglei <arei.gonglei@huawei.com>
 *
 * This work is licensed under the terms of the GNU GPL, version 2 or
 * (at your option) any later version.  See the COPYING file in the
 * top-level directory.
 */
#include "qemu/osdep.h"
#include "qemu/iov.h"
#include "hw/qdev.h"
#include "qapi/error.h"
#include "qemu/error-report.h"

#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-crypto.h"
#include "hw/virtio/virtio-access.h"
#include "standard-headers/linux/virtio_ids.h"

#define VIRTIO_CRYPTO_VM_VERSION 1

/*
 * Transfer virtqueue index to crypto queue index.
 * The control virtqueue is after the data virtqueues
 * so the input value doesn't need to be adjusted
 */
static inline int virtio_accel_vq2q(int queue_index)
{
    return queue_index;
}

static int
virtio_crypto_cipher_session_helper(VirtIODevice *vdev,
           CryptoDevBackendSymSessionInfo *info,
           struct virtio_crypto_cipher_session_para *cipher_para,
           struct iovec **iov, unsigned int *out_num)
{
    VirtIOCrypto *vcrypto = VIRTIO_CRYPTO(vdev);
    unsigned int num = *out_num;

    info->cipher_alg = ldl_le_p(&cipher_para->algo);
    info->key_len = ldl_le_p(&cipher_para->keylen);
    info->direction = ldl_le_p(&cipher_para->op);
    DPRINTF("cipher_alg=%" PRIu32 ", info->direction=%" PRIu32 "\n",
             info->cipher_alg, info->direction);

    if (info->key_len > vcrypto->conf.max_cipher_key_len) {
        error_report("virtio-crypto length of cipher key is too big: %u",
                     info->key_len);
        return -VIRTIO_CRYPTO_ERR;
    }
    /* Get cipher key */
    if (info->key_len > 0) {
        size_t s;
        DPRINTF("keylen=%" PRIu32 "\n", info->key_len);

        info->cipher_key = g_malloc(info->key_len);
        s = iov_to_buf(*iov, num, 0, info->cipher_key, info->key_len);
        if (unlikely(s != info->key_len)) {
            virtio_error(vdev, "virtio-crypto cipher key incorrect");
            return -EFAULT;
        }
        iov_discard_front(iov, &num, info->key_len);
        *out_num = num;
    }

    return 0;
}

static int64_t
virtio_accel_crypto_create_session(VirtIOAccelReq *req)
{
    VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    VirtQueueElement *elem = &req->elem;
	struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(vaccel->vq);
    AccelDevBackendSessionInfo info;
    int64_t session_id;
    Error *local_err = NULL;
    int ret;

	if (h->crypto_sess.keylen > vaccel->conf.max_cipher_key_len) {
        error_report("virtio-accel length of cipher key is too big: %u",
                     h->crypto_sess.keylen);
        return -VIRTIO_CRYPTO_ERR;
    }

	if (h->crypto_sess.keylen > 0) {
		size_t s;
		h->crypto_sess.key = g_malloc(h->crypto_sess.keylen);
		s = iov_to_buf(req->in_iov, req->in_niov, 0, h->crypto_sess.key,
				h->crypto_sess.keylen);
        if (unlikely(s != h->crypto_sess.keylen)) {
            virtio_error(vdev, "virtio-accel cipher key incorrect");
            ret = -EFAULT;
			goto out;
        }
	}

    info.u.crypto.cipher_key = h->crypto_sess.key;
    info.u.crypto.keylen = h->crypto_sess.keylen;
    info.u.crypto.cipher = h->crypto_sess.cipher;
	sess_id = acceldev_backend_create_session(
                                     vaccel->crypto,
                                     &info, queue_index, &local_err);
    if (sess_id >= 0) {
        DPRINTF("crypto create session_id=%" PRIu64 " successful\n",
                sess_id);

        ret = sess_id;
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
        ret = -VIRTIO_ACCEL_ERR;
    }

out:
    g_free(info.u.crypto.cipher_key);
    return ret;
}

static uint8_t
virtio_crypto_handle_close_session(VirtIOCrypto *vcrypto,
         struct virtio_crypto_destroy_session_req *close_sess_req,
         uint32_t queue_id)
{
    int ret;
    uint64_t session_id;
    uint32_t status;
    Error *local_err = NULL;

    session_id = ldq_le_p(&close_sess_req->session_id);
    DPRINTF("close session, id=%" PRIu64 "\n", session_id);

    ret = cryptodev_backend_sym_close_session(
              vcrypto->crypto, session_id, queue_id, &local_err);
    if (ret == 0) {
        status = VIRTIO_CRYPTO_OK;
    } else {
        if (local_err) {
            error_report_err(local_err);
        } else {
            error_report("destroy session failed");
        }
        status = VIRTIO_CRYPTO_ERR;
    }

    return status;
}

static void virtio_crypto_handle_ctrl(VirtIODevice *vdev, VirtQueue *vq)
{
    VirtIOCrypto *vcrypto = VIRTIO_CRYPTO(vdev);
    struct virtio_crypto_op_ctrl_req ctrl;
    VirtQueueElement *elem;
    struct iovec *in_iov;
    struct iovec *out_iov;
    unsigned in_num;
    unsigned out_num;
    uint32_t queue_id;
    uint32_t opcode;
    struct virtio_crypto_session_input input;
    int64_t session_id;
    uint8_t status;
    size_t s;

    for (;;) {
        elem = virtqueue_pop(vq, sizeof(VirtQueueElement));
        if (!elem) {
            break;
        }
        if (elem->out_num < 1 || elem->in_num < 1) {
            virtio_error(vdev, "virtio-crypto ctrl missing headers");
            virtqueue_detach_element(vq, elem, 0);
            g_free(elem);
            break;
        }

        out_num = elem->out_num;
        out_iov = elem->out_sg;
        in_num = elem->in_num;
        in_iov = elem->in_sg;
        if (unlikely(iov_to_buf(out_iov, out_num, 0, &ctrl, sizeof(ctrl))
                    != sizeof(ctrl))) {
            virtio_error(vdev, "virtio-crypto request ctrl_hdr too short");
            virtqueue_detach_element(vq, elem, 0);
            g_free(elem);
            break;
        }
        iov_discard_front(&out_iov, &out_num, sizeof(ctrl));

        opcode = ldl_le_p(&ctrl.header.opcode);
        queue_id = ldl_le_p(&ctrl.header.queue_id);

        switch (opcode) {
        case VIRTIO_CRYPTO_CIPHER_CREATE_SESSION:
            memset(&input, 0, sizeof(input));
            session_id = virtio_crypto_create_sym_session(vcrypto,
                             &ctrl.u.sym_create_session,
                             queue_id, opcode,
                             out_iov, out_num);
            /* Serious errors, need to reset virtio crypto device */
            if (session_id == -EFAULT) {
                virtqueue_detach_element(vq, elem, 0);
                break;
            } else if (session_id == -VIRTIO_CRYPTO_NOTSUPP) {
                stl_le_p(&input.status, VIRTIO_CRYPTO_NOTSUPP);
            } else if (session_id == -VIRTIO_CRYPTO_ERR) {
                stl_le_p(&input.status, VIRTIO_CRYPTO_ERR);
            } else {
                /* Set the session id */
                stq_le_p(&input.session_id, session_id);
                stl_le_p(&input.status, VIRTIO_CRYPTO_OK);
            }

            s = iov_from_buf(in_iov, in_num, 0, &input, sizeof(input));
            if (unlikely(s != sizeof(input))) {
                virtio_error(vdev, "virtio-crypto input incorrect");
                virtqueue_detach_element(vq, elem, 0);
                break;
            }
            virtqueue_push(vq, elem, sizeof(input));
            virtio_notify(vdev, vq);
            break;
        case VIRTIO_CRYPTO_CIPHER_DESTROY_SESSION:
        case VIRTIO_CRYPTO_HASH_DESTROY_SESSION:
        case VIRTIO_CRYPTO_MAC_DESTROY_SESSION:
        case VIRTIO_CRYPTO_AEAD_DESTROY_SESSION:
            status = virtio_crypto_handle_close_session(vcrypto,
                   &ctrl.u.destroy_session, queue_id);
            /* The status only occupy one byte, we can directly use it */
            s = iov_from_buf(in_iov, in_num, 0, &status, sizeof(status));
            if (unlikely(s != sizeof(status))) {
                virtio_error(vdev, "virtio-crypto status incorrect");
                virtqueue_detach_element(vq, elem, 0);
                break;
            }
            virtqueue_push(vq, elem, sizeof(status));
            virtio_notify(vdev, vq);
            break;
        case VIRTIO_CRYPTO_HASH_CREATE_SESSION:
        case VIRTIO_CRYPTO_MAC_CREATE_SESSION:
        case VIRTIO_CRYPTO_AEAD_CREATE_SESSION:
        default:
            error_report("virtio-crypto unsupported ctrl opcode: %d", opcode);
            memset(&input, 0, sizeof(input));
            stl_le_p(&input.status, VIRTIO_CRYPTO_NOTSUPP);
            s = iov_from_buf(in_iov, in_num, 0, &input, sizeof(input));
            if (unlikely(s != sizeof(input))) {
                virtio_error(vdev, "virtio-crypto input incorrect");
                virtqueue_detach_element(vq, elem, 0);
                break;
            }
            virtqueue_push(vq, elem, sizeof(input));
            virtio_notify(vdev, vq);

            break;
        } /* end switch case */

        g_free(elem);
    } /* end for loop */
}

static void virtio_accel_init_request(VirtIOAccel *vaccel, VirtQueue *vq,
                                VirtIOAccelReq *req)
{
    req->vaccel = vaccel;
    req->vq = vq;
    req->in = NULL;
    req->in_iov = NULL;
    req->in_num = 0;
    req->in_len = 0;
    req->flags = CRYPTODEV_BACKEND_ALG__MAX;
    req->u.sym_op_info = NULL;
}

static void virtio_crypto_free_request(VirtIOCryptoReq *req)
{
    if (req) {
        if (req->flags == CRYPTODEV_BACKEND_ALG_SYM) {
            size_t max_len;
            CryptoDevBackendSymOpInfo *op_info = req->u.sym_op_info;

            max_len = op_info->iv_len +
                      op_info->aad_len +
                      op_info->src_len +
                      op_info->dst_len +
                      op_info->digest_result_len;

            /* Zeroize and free request data structure */
            memset(op_info, 0, sizeof(*op_info) + max_len);
            g_free(op_info);
        }
        g_free(req);
    }
}

static void
virtio_crypto_sym_input_data_helper(VirtIODevice *vdev,
                VirtIOCryptoReq *req,
                uint32_t status,
                CryptoDevBackendSymOpInfo *sym_op_info)
{
    size_t s, len;

    if (status != VIRTIO_CRYPTO_OK) {
        return;
    }

    len = sym_op_info->src_len;
    /* Save the cipher result */
    s = iov_from_buf(req->in_iov, req->in_num, 0, sym_op_info->dst, len);
    if (s != len) {
        virtio_error(vdev, "virtio-crypto dest data incorrect");
        return;
    }

    iov_discard_front(&req->in_iov, &req->in_num, len);

    if (sym_op_info->op_type ==
                      VIRTIO_CRYPTO_SYM_OP_ALGORITHM_CHAINING) {
        /* Save the digest result */
        s = iov_from_buf(req->in_iov, req->in_num, 0,
                         sym_op_info->digest_result,
                         sym_op_info->digest_result_len);
        if (s != sym_op_info->digest_result_len) {
            virtio_error(vdev, "virtio-crypto digest result incorrect");
        }
    }
}

static void virtio_crypto_req_complete(VirtIOCryptoReq *req, uint8_t status)
{
    VirtIOCrypto *vcrypto = req->vcrypto;
    VirtIODevice *vdev = VIRTIO_DEVICE(vcrypto);

    if (req->flags == CRYPTODEV_BACKEND_ALG_SYM) {
        virtio_crypto_sym_input_data_helper(vdev, req, status,
                                            req->u.sym_op_info);
    }
    stb_p(&req->in->status, status);
    virtqueue_push(req->vq, &req->elem, req->in_len);
    virtio_notify(vdev, req->vq);
}

static VirtIOAccelReq *
virtio_accel_get_request(VirtIOAccel *va, VirtQueue *vq)
{
    VirtIOAccelReq *req = virtqueue_pop(vq, sizeof(VirtIOCryptoReq));

    if (req) {
        virtio_accel_init_request(va, vq, req);
    }
    return req;
}

static CryptoDevBackendSymOpInfo *
virtio_crypto_sym_op_helper(VirtIODevice *vdev,
           struct virtio_crypto_cipher_para *cipher_para,
           struct virtio_crypto_alg_chain_data_para *alg_chain_para,
           struct iovec *iov, unsigned int out_num)
{
    VirtIOCrypto *vcrypto = VIRTIO_CRYPTO(vdev);
    CryptoDevBackendSymOpInfo *op_info;
    uint32_t src_len = 0, dst_len = 0;
    uint32_t iv_len = 0;
    uint32_t aad_len = 0, hash_result_len = 0;
    uint32_t hash_start_src_offset = 0, len_to_hash = 0;
    uint32_t cipher_start_src_offset = 0, len_to_cipher = 0;

    uint64_t max_len, curr_size = 0;
    size_t s;

    /* Plain cipher */
    if (cipher_para) {
        iv_len = ldl_le_p(&cipher_para->iv_len);
        src_len = ldl_le_p(&cipher_para->src_data_len);
        dst_len = ldl_le_p(&cipher_para->dst_data_len);
    } else if (alg_chain_para) { /* Algorithm chain */
        iv_len = ldl_le_p(&alg_chain_para->iv_len);
        src_len = ldl_le_p(&alg_chain_para->src_data_len);
        dst_len = ldl_le_p(&alg_chain_para->dst_data_len);

        aad_len = ldl_le_p(&alg_chain_para->aad_len);
        hash_result_len = ldl_le_p(&alg_chain_para->hash_result_len);
        hash_start_src_offset = ldl_le_p(
                         &alg_chain_para->hash_start_src_offset);
        cipher_start_src_offset = ldl_le_p(
                         &alg_chain_para->cipher_start_src_offset);
        len_to_cipher = ldl_le_p(&alg_chain_para->len_to_cipher);
        len_to_hash = ldl_le_p(&alg_chain_para->len_to_hash);
    } else {
        return NULL;
    }

    max_len = (uint64_t)iv_len + aad_len + src_len + dst_len + hash_result_len;
    if (unlikely(max_len > vcrypto->conf.max_size)) {
        virtio_error(vdev, "virtio-crypto too big length");
        return NULL;
    }

    op_info = g_malloc0(sizeof(CryptoDevBackendSymOpInfo) + max_len);
    op_info->iv_len = iv_len;
    op_info->src_len = src_len;
    op_info->dst_len = dst_len;
    op_info->aad_len = aad_len;
    op_info->digest_result_len = hash_result_len;
    op_info->hash_start_src_offset = hash_start_src_offset;
    op_info->len_to_hash = len_to_hash;
    op_info->cipher_start_src_offset = cipher_start_src_offset;
    op_info->len_to_cipher = len_to_cipher;
    /* Handle the initilization vector */
    if (op_info->iv_len > 0) {
        DPRINTF("iv_len=%" PRIu32 "\n", op_info->iv_len);
        op_info->iv = op_info->data + curr_size;

        s = iov_to_buf(iov, out_num, 0, op_info->iv, op_info->iv_len);
        if (unlikely(s != op_info->iv_len)) {
            virtio_error(vdev, "virtio-crypto iv incorrect");
            goto err;
        }
        iov_discard_front(&iov, &out_num, op_info->iv_len);
        curr_size += op_info->iv_len;
    }

    /* Handle additional authentication data if exists */
    if (op_info->aad_len > 0) {
        DPRINTF("aad_len=%" PRIu32 "\n", op_info->aad_len);
        op_info->aad_data = op_info->data + curr_size;

        s = iov_to_buf(iov, out_num, 0, op_info->aad_data, op_info->aad_len);
        if (unlikely(s != op_info->aad_len)) {
            virtio_error(vdev, "virtio-crypto additional auth data incorrect");
            goto err;
        }
        iov_discard_front(&iov, &out_num, op_info->aad_len);

        curr_size += op_info->aad_len;
    }

    /* Handle the source data */
    if (op_info->src_len > 0) {
        DPRINTF("src_len=%" PRIu32 "\n", op_info->src_len);
        op_info->src = op_info->data + curr_size;

        s = iov_to_buf(iov, out_num, 0, op_info->src, op_info->src_len);
        if (unlikely(s != op_info->src_len)) {
            virtio_error(vdev, "virtio-crypto source data incorrect");
            goto err;
        }
        iov_discard_front(&iov, &out_num, op_info->src_len);

        curr_size += op_info->src_len;
    }

    /* Handle the destination data */
    op_info->dst = op_info->data + curr_size;
    curr_size += op_info->dst_len;

    DPRINTF("dst_len=%" PRIu32 "\n", op_info->dst_len);

    /* Handle the hash digest result */
    if (hash_result_len > 0) {
        DPRINTF("hash_result_len=%" PRIu32 "\n", hash_result_len);
        op_info->digest_result = op_info->data + curr_size;
    }

    return op_info;

err:
    g_free(op_info);
    return NULL;
}

static int
virtio_accel_crypto_do_op(VirtIOAccelReq *req,
               struct virtio_crypto_sym_data_req *req,
               CryptoDevBackendSymOpInfo **sym_op_info,
               struct iovec *iov, unsigned int out_num)
{
	VirtIOAccel *vaccel = req->vaccel;
    VirtIODevice *vdev = VIRTIO_DEVICE(vaccel);
    VirtQueueElement *elem = &req->elem;
	struct virtio_accel_hdr *h = &req->hdr;
    int queue_index = virtio_get_queue_index(vaccel->vq);
    AccelDevBackendOpInfo info;
    Error *local_err = NULL;
    int ret;

	info.op = req->hdr.op;
	info.session_id = req->hdr.session_id;
	info.u.crypto.src_len = req->hdr.crypto_op.src_len;
	info.u.crypto.src = info.u.crypto.dst = req->hdr.crypto_op.src;
    switch (req->hdr.op) {
	case VIRTIO_ACCEL_CRYPTO_CIPHER_ENCRYPT:
		ret = acceldev_backend_crypto_operation(vaccel->crypto,
								&info, queue_index, &local_err);
		break;
	default:
        error_report("virtio-crypto unsupported cipher operation");
        return -VIRTIO_ACCEL_NOTSUPP;
    }
	
    if (ret >= 0) {
        DPRINTF("crypto op session_id=%" PRIu64 " successful\n",
                info.session_id);
    } else {
        if (local_err) {
            error_report_err(local_err);
        }
        ret = -VIRTIO_ACCEL_ERR;
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
    uint32_t op, sess_id, status = VIRTIO_ACCEL_ERR;
    CryptoDevBackendSymOpInfo *sym_op_info = NULL;
    Error *local_err = NULL;

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
    iov_discard_front(&out_iov, &out_niov, sizeof(*hdr));

    if (in_iov[in_niov - 1].iov_len <
            sizeof(status)) {
        virtio_error(vdev, "virtio-accel request status too short");
        return -1;
    }
    /* We always touch the last byte, so just see how big in_iov is. */
    req->in_iov_len = iov_size(in_iov, in_niov);
    req->status = (void *)in_iov[in_niov - 1].iov_base
              + in_iov[in_niov - 1].iov_len
              - sizeof(*req->status);
    iov_discard_back(in_iov, &in_niov, sizeof(*req->status));

	req->in_iov = in_iov;
	req->in_niov = in_niov;
	req->out_iov = out_iov;
	req->out_niov = out_niov;

    req->hdr.op = virtio_ldl_p(vdev, &hdr.op);
    switch (op) {
	case VIRTIO_ACCEL_CRYPTO_CIPHER_CREATE_SESSION:
		req->hdr.crypto_sess.cipher = virtio_ldl_p(
				vdev, &hdr.crypto_sess.cipher);
		req->hdr.crypto_sess.keylen = virtio_ldl_p(
				vdev, &hdr.crypto_sess.keylen);
		sess_id = virtio_accel_crypto_create_session(req);
		/* Serious errors, need to reset virtio crypto device */
		if (sess_id == -EFAULT) {
			virtqueue_detach_element(vq, elem, 0);
			break;
		} else if (sess_id == -VIRTIO_ACCEL_NOTSUPP) {
			virtio_stl_p(req->status, VIRTIO_ACCEL_NOTSUPP);
		} else if (sess_id == -VIRTIO_ACCEL_ERR) {
			virtio_stl_p(req->status, VIRTIO_ACCEL_ERR);
		} else {
			/* Set the session id */
			virtio_stq_p(in_iov->iov_base, sess_id);
			virtio_stl_p(req->status, VIRTIO_ACCEL_OK);
		}
        virtio_accel_req_complete(req, status);
        virtio_accel_free_request(requ);
		break;
    case VIRTIO_ACCEL_CRYPTO_CIPHER_ENCRYPT:
    case VIRTIO_ACCEL_CRYPTO_CIPHER_DECRYPT:
		req->hdr.session_id = virtio_ldl_p(vdev, &hdr.session_id);
		req->hdr.crypto_op.src_len = virtio_ldl_p(
				vdev, &hdr.crypto_op.src_len);
		req->hdr.crypto_op.src = in_iov->iov_base;
		ret = virtio_accel_crypto_do_op(req);
        /* Serious errors, need to reset virtio crypto device */
        if (ret == -EFAULT) {
            return -1;
        } else if (ret == -VIRTIO_ACCEL_NOTSUPP) {
            virtio_accel_req_complete(req, VIRTIO_ACCEL_NOTSUPP);
            virtio_accel_free_request(req);
        } else {
            sym_op_info->session_id = session_id;

            /* Set request's parameter */
            request->flags = CRYPTODEV_BACKEND_ALG_SYM;
            request->u.sym_op_info = sym_op_info;
            ret = cryptodev_backend_crypto_operation(vcrypto->crypto,
                                    request, queue_index, &local_err);
            if (ret < 0) {
                status = -ret;
                if (local_err) {
                    error_report_err(local_err);
                }
            } else { /* ret == VIRTIO_CRYPTO_OK */
                status = ret;
            }
            virtio_crypto_req_complete(request, status);
            virtio_crypto_free_request(request);
        }

		break;
	
	case VIRTIO_CRYPTO_CIPHER_ENCRYPT:
    case VIRTIO_CRYPTO_CIPHER_DECRYPT:
        ret = virtio_crypto_handle_sym_req(vcrypto,
                         &req.u.sym_req,
                         &sym_op_info,
                         out_iov, out_num);
        /* Serious errors, need to reset virtio crypto device */
        if (ret == -EFAULT) {
            return -1;
        } else if (ret == -VIRTIO_CRYPTO_NOTSUPP) {
            virtio_crypto_req_complete(request, VIRTIO_CRYPTO_NOTSUPP);
            virtio_crypto_free_request(request);
        } else {
            sym_op_info->session_id = session_id;

            /* Set request's parameter */
            request->flags = CRYPTODEV_BACKEND_ALG_SYM;
            request->u.sym_op_info = sym_op_info;
            ret = cryptodev_backend_crypto_operation(vcrypto->crypto,
                                    request, queue_index, &local_err);
            if (ret < 0) {
                status = -ret;
                if (local_err) {
                    error_report_err(local_err);
                }
            } else { /* ret == VIRTIO_CRYPTO_OK */
                status = ret;
            }
            virtio_crypto_req_complete(request, status);
            virtio_crypto_free_request(request);
        }
        break;
    case VIRTIO_ACCEL_CRYPTO_HASH:
    case VIRTIO_ACCEL_CRYPTO_MAC:
    case VIRTIO_ACCEL_CRYPTO_AEAD_ENCRYPT:
    case VIRTIO_ACCEL_CRYPTO_AEAD_DECRYPT:
    default:
        error_report("virtio-accel unsupported opcode: %u",
                     opcode);
        virtio_accel_req_complete(req, VIRTIO_ACCEL_NOTSUPP);
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
    VirtIOAccelQueue *q =
         &vaccel->vqs[virtio_accel_vq2q(virtio_get_queue_index(vq))];

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

static void virtio_accel_reset(VirtIOAccel *vdev)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);
    /* multiqueue is disabled by default */
    vaccel->curr_queues = 1;
    if (!acceldev_backend_is_ready(vaccel->accel)) {
        vaccel->status &= ~VIRTIO_ACCEL_S_HW_READY;
    } else {
        vaccel->status |= VIRTIO_ACCEL_S_HW_READY;
    }
}

static void virtio_accel_init_config(VirtIODevice *vdev)
{
    VirtIOAccel *vaccel = VIRTIO_ACCEL(vdev);

    vaccel->conf.accel_services =
                     vaccel->conf.accel->conf.accel_services;
    vaccel->conf.max_cipher_key_len =
                  vaccel->conf.accel->conf.max_cipher_key_len;
    vaccel->conf.max_auth_key_len =
                  vaccel->conf.accel->conf.max_auth_key_len;
    vaccel->conf.max_size = vaccel->conf.accel->conf.max_size;
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

    vaccel->max_queues = MAX(vaccel->accel->conf.peers.queues, 1);
    if (vaccel->max_queues + 1 > VIRTIO_QUEUE_MAX) {
        error_setg(errp, "Invalid number of queues (= %" PRIu32 "), "
                   "must be a positive integer less than %d.",
                   vaccel->max_queues, VIRTIO_QUEUE_MAX);
        return;
    }

    virtio_init(vdev, "virtio-accel", VIRTIO_ID_ACCEL, vaccel->config_size);
    //vaccel->curr_queues = 1;
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
    struct virtio_accel_config accel_cfg = {};

	// TODO:
    /*
     * Virtio-crypto device conforms to VIRTIO 1.0 which is always LE,
     * so we can use LE accessors directly.
     */
	//
    stl_le_p(&accel_cfg.status, va->status);
    stl_le_p(&accel_cfg.max_dataqueues, va->max_queues);
    stl_le_p(&accel_cfg.crypto_services, va->conf.crypto_services);
    stl_le_p(&accel_cfg.max_cipher_key_len, va->conf.max_cipher_key_len);
    stl_le_p(&accel_cfg.max_auth_key_len, va->conf.max_auth_key_len);
    stq_le_p(&accel_cfg.max_size, va->conf.max_size);

    memcpy(config, &accel_cfg, va->config_size);
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
    if (acceldev_backend_is_used(ACCEL_BACKEND(val))) {
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
    vaccel->config_size = sizeof(struct virtio_accel_config);

    object_property_add_link(obj, "crypto",
                             TYPE_ACCEL_BACKEND,
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
