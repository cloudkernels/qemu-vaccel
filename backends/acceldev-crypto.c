#include "qemu/osdep.h"
#include "sysemu/acceldev.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "standard-headers/linux/virtio_accel.h"
#include "crypto/cipher.h"


/**
 * @TYPE_ACCELDEV_BACKEND_CRYPTO:
 * name of backend that uses QEMU cipher API
 */
#define TYPE_ACCELDEV_BACKEND_CRYPTO "acceldev-backend-crypto"

#define ACCELDEV_BACKEND_CRYPTO(obj) \
    OBJECT_CHECK(AccelDevBackendCrypto, \
                 (obj), TYPE_ACCELDEV_BACKEND_CRYPTO)

typedef struct AccelDevBackendCrypto
                         AccelDevBackendCrypto;

typedef struct AccelDevBackendCryptoSession {
    QCryptoCipher *cipher;
    uint8_t type; /* cipher? hash? aead? */
    QTAILQ_ENTRY(AccelDevBackendCryptoSession) next;
} AccelDevBackendCryptoSession;

/* Max number of symmetric sessions */
#define MAX_NUM_SESSIONS 256

#define ACCELDEV_CRYPTO_MAX_AUTH_KEY_LEN    512
#define ACCELDEV_CRYPTO_MAX_CIPHER_KEY_LEN  64

struct AccelDevBackendCrypto {
    AccelDevBackend parent_obj;

    AccelDevBackendCryptoSession *sessions[MAX_NUM_SESSIONS];
};

static void acceldev_crypto_init(
             AccelDevBackend *ab, Error **errp)
{
    /* Only support one queue */
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    if (queues != 1) {
        error_setg(errp,
                  "Only support one queue in acceldev-crypto backend");
        return;
    }

    c = acceldev_backend_new_client(
              "acceldev-crypto", NULL);
    c->info_str = g_strdup_printf("acceldev-crypto0");
    c->queue_index = 0;
    ab->conf.peers.ccs[0] = c;
	
	// TODO
    //ab->conf.services = 1u << VIRTIO_ACCEL_SERVICE_CRYPTO;
	//
    /*
     * Set the Maximum length of crypto request.
     * Why this value? Just avoid to overflow when
     * memory allocation for each crypto request.
     */
    ab->conf.max_size = LONG_MAX - sizeof(AccelDevBackendOpInfo);
    ab->conf.u.crypto.max_cipher_key_len = ACCELDEV_CRYPTO_MAX_CIPHER_KEY_LEN;
    ab->conf.u.crypto.max_auth_key_len = ACCELDEV_CRYPTO_MAX_AUTH_KEY_LEN;

    acceldev_backend_set_ready(ab, true);
}

static int
acceldev_crypto_get_unused_session_index(
                 AccelDevBackendCrypto *crypto)
{
    size_t i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (crypto->sessions[i] == NULL) {
            return i;
        }
    }

    return -1;
}

#define AES_KEYSIZE_128 16
#define AES_KEYSIZE_192 24
#define AES_KEYSIZE_256 32
#define AES_KEYSIZE_128_XTS AES_KEYSIZE_256
#define AES_KEYSIZE_256_XTS 64

static int
acceldev_crypto_get_aes_algo(uint32_t key_len, int mode, Error **errp)
{
    int algo;

    if (key_len == AES_KEYSIZE_128) {
        algo = QCRYPTO_CIPHER_ALG_AES_128;
    } else if (key_len == AES_KEYSIZE_192) {
        algo = QCRYPTO_CIPHER_ALG_AES_192;
    } else if (key_len == AES_KEYSIZE_256) { /* equals AES_KEYSIZE_128_XTS */
        if (mode == QCRYPTO_CIPHER_MODE_XTS) {
            algo = QCRYPTO_CIPHER_ALG_AES_128;
        } else {
            algo = QCRYPTO_CIPHER_ALG_AES_256;
        }
    } else if (key_len == AES_KEYSIZE_256_XTS) {
        if (mode == QCRYPTO_CIPHER_MODE_XTS) {
            algo = QCRYPTO_CIPHER_ALG_AES_256;
        } else {
            goto err;
        }
    } else {
        goto err;
    }

    return algo;

err:
   error_setg(errp, "Unsupported key length :%u", key_len);
   return -1;
}

static int acceldev_crypto_cipher_create_session(
                    AccelDevBackendCrypto *crypto,
                    AccelDevBackendSessionInfo *info,
                    Error **errp)
{
    int algo;
    int mode;
    QCryptoCipher *cipher;
    int index;
    AccelDevBackendCryptoSession *sess;

    if (info->op != VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT ||
			info->op != VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT) {
        error_setg(errp, "Unsupported optype :%u", info->op);
        return -VIRTIO_ACCEL_ERR;
    }

    index = acceldev_crypto_get_unused_session_index(crypto);
    if (index < 0) {
        error_setg(errp, "Total number of sessions created exceeds %u",
                  MAX_NUM_SESSIONS);
        return -VIRTIO_ACCEL_ERR;
    }

    switch (info->u.crypto.cipher) {
    case VIRTIO_ACCEL_C_CIPHER_AES_ECB:
        mode = QCRYPTO_CIPHER_MODE_ECB;
        algo = acceldev_crypto_get_aes_algo(info->u.crypto.keylen,
                                                    mode, errp);
        if (algo < 0)  {
            return -VIRTIO_ACCEL_ERR;
        }
        break;
    case VIRTIO_ACCEL_C_CIPHER_AES_CBC:
        mode = QCRYPTO_CIPHER_MODE_CBC;
        algo = acceldev_crypto_get_aes_algo(info->u.crypto.keylen,
                                                    mode, errp);
        if (algo < 0)  {
            return -VIRTIO_ACCEL_ERR;
        }
        break;
    case VIRTIO_ACCEL_C_CIPHER_AES_CTR:
        mode = QCRYPTO_CIPHER_MODE_CTR;
        algo = acceldev_crypto_get_aes_algo(info->u.crypto.keylen,
                                                    mode, errp);
        if (algo < 0)  {
            return -VIRTIO_ACCEL_ERR;
        }
        break;
/*
    case VIRTIO_ACCEL_C_CIPHER_AES_XTS:
        mode = QCRYPTO_CIPHER_MODE_XTS;
        algo = cryptodev_builtin_get_aes_algo(info->u.crypto.keylen,
                                                    mode, errp);
        if (algo < 0)  {
            return -1;
        }
        break;
    case VIRTIO_ACCEL_C_CIPHER_3DES_ECB:
        mode = QCRYPTO_CIPHER_MODE_ECB;
        algo = QCRYPTO_CIPHER_ALG_3DES;
        break;
    case VIRTIO_ACCEL_C_CIPHER_3DES_CBC:
        mode = QCRYPTO_CIPHER_MODE_CBC;
        algo = QCRYPTO_CIPHER_ALG_3DES;
        break;
    case VIRTIO_ACCEL_C_CIPHER_3DES_CTR:
        mode = QCRYPTO_CIPHER_MODE_CTR;
        algo = QCRYPTO_CIPHER_ALG_3DES;
        break;
*/
	default:
        error_setg(errp, "Unsupported cipher alg :%u",
                   info->u.crypto.cipher);
        return -VIRTIO_ACCEL_ERR;
    }

    cipher = qcrypto_cipher_new(algo, mode,
                               info->u.crypto.cipher_key,
                               info->u.crypto.keylen,
                               errp);
    if (!cipher) {
        return -VIRTIO_ACCEL_ERR;
    }

    sess = g_new0(AccelDevBackendCryptoSession, 1);
    sess->cipher = cipher;

    crypto->sessions[index] = sess;

    return index;
}

static int64_t acceldev_crypto_sym_create_session(
           AccelDevBackend *ab,
           AccelDevBackendSessionInfo *info,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendCrypto *crypto =
                      ACCELDEV_BACKEND_CRYPTO(ab);
    int32_t sess_id = -VIRTIO_ACCEL_ERR;
    int ret;

    switch (info->op) {
    case VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION:
        ret = acceldev_crypto_cipher_create_session(
                           crypto, info, errp);
        if (ret < 0) {
            return ret;
        } else {
            sess_id = ret;
        }
        break;
    default:
        error_setg(errp, "Unsupported opcode :%" PRIu32 "",
                   info->op);
        return -VIRTIO_ACCEL_ERR;
    }

    return sess_id;
}

static int acceldev_crypto_sym_destroy_session(
           AccelDevBackend *ab,
           uint32_t sess_id,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendCrypto *crypto =
                      ACCELDEV_BACKEND_CRYPTO(ab);

    if (sess_id >= MAX_NUM_SESSIONS ||
              crypto->sessions[sess_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    qcrypto_cipher_free(crypto->sessions[sess_id]->cipher);
    g_free(crypto->sessions[sess_id]);
    crypto->sessions[sess_id] = NULL;

    return VIRTIO_ACCEL_OK;
}

static int acceldev_crypto_sym_operation(
                 AccelDevBackend *ab,
                 AccelDevBackendOpInfo *info,
                 uint32_t queue_index, Error **errp)
{
    AccelDevBackendCrypto *crypto =
                      ACCELDEV_BACKEND_CRYPTO(ab);
    AccelDevBackendCryptoSession *sess;
    int ret;

    if (info->session_id >= MAX_NUM_SESSIONS ||
              crypto->sessions[info->session_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu64 "",
                   info->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    sess = crypto->sessions[info->session_id];

	/* TODO
    if (info->iv_len > 0) {
        ret = qcrypto_cipher_setiv(sess->cipher, op_info->iv,
                                   op_info->iv_len, errp);
        if (ret < 0) {
            return -VIRTIO_CRYPTO_ERR;
        }
    }
	*/

    if (info->op == VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT) {
        ret = qcrypto_cipher_encrypt(sess->cipher, info->u.crypto.src,
                                     info->u.crypto.dst, 
									 info->u.crypto.src_len, errp);
        if (ret < 0) {
            return -VIRTIO_ACCEL_ERR;
        }
    } else {
        ret = qcrypto_cipher_decrypt(sess->cipher, info->u.crypto.src,
                                     info->u.crypto.dst,
									 info->u.crypto.src_len, errp);
        if (ret < 0) {
            return -VIRTIO_ACCEL_ERR;
        }
    }
    return VIRTIO_ACCEL_OK;
}

static void acceldev_crypto_cleanup(
             AccelDevBackend *ab,
             Error **errp)
{
    AccelDevBackendCrypto *crypto =
                      ACCELDEV_BACKEND_CRYPTO(ab);
    size_t i;
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (crypto->sessions[i] != NULL) {
            acceldev_crypto_sym_destroy_session(
                    ab, i, 0, errp);
        }
    }

    for (i = 0; i < queues; i++) {
        c = ab->conf.peers.ccs[i];
        if (c) {
            acceldev_backend_free_client(c);
            ab->conf.peers.ccs[i] = NULL;
        }
    }

    acceldev_backend_set_ready(ab, false);
}

static void
acceldev_crypto_class_init(ObjectClass *oc, void *data)
{
    AccelDevBackendClass *abc = ACCELDEV_BACKEND_CLASS(oc);

    abc->init = acceldev_crypto_init;
    abc->cleanup = acceldev_crypto_cleanup;
    abc->create_session = acceldev_crypto_sym_create_session;
    abc->destroy_session = acceldev_crypto_sym_destroy_session;
    abc->do_op = acceldev_crypto_sym_operation;
}

static const TypeInfo acceldev_crypto_info = {
    .name = TYPE_ACCELDEV_BACKEND_CRYPTO,
    .parent = TYPE_ACCELDEV_BACKEND,
    .class_init = acceldev_crypto_class_init,
    .instance_size = sizeof(AccelDevBackendCrypto),
};

static void
acceldev_crypto_register_types(void)
{
    type_register_static(&acceldev_crypto_info);
}

type_init(acceldev_crypto_register_types);
