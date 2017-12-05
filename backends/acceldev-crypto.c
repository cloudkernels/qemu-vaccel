#include "qemu/osdep.h"
#include "sysemu/accel.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "standard-headers/linux/virtio_accel.h"
#include "crypto/cipher.h"


/**
 * @TYPE_ACCELDEV_BACKEND_CRYPTO:
 * name of backend that uses QEMU cipher API
 */
#define TYPE_ACCELDEV_BACKEND_CRYPTO "cryptodev-backend-builtin"

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

#define ACCEL_BUITLIN_MAX_AUTH_KEY_LEN    512
#define ACCEL_BUITLIN_MAX_CIPHER_KEY_LEN  64

struct AccelDevBackendCrypto {
    AccelDevBackend parent_obj;

    AccelDevBackendCryptoSession *sessions[MAX_NUM_SESSIONS];
};

static void cryptodev_builtin_init(
             CryptoDevBackend *backend, Error **errp)
{
    /* Only support one queue */
    int queues = backend->conf.peers.queues;
    CryptoDevBackendClient *cc;

    if (queues != 1) {
        error_setg(errp,
                  "Only support one queue in cryptdov-builtin backend");
        return;
    }

    cc = cryptodev_backend_new_client(
              "cryptodev-builtin", NULL);
    cc->info_str = g_strdup_printf("cryptodev-builtin0");
    cc->queue_index = 0;
    backend->conf.peers.ccs[0] = cc;

    backend->conf.crypto_services =
                         1u << VIRTIO_CRYPTO_SERVICE_CIPHER |
                         1u << VIRTIO_CRYPTO_SERVICE_HASH |
                         1u << VIRTIO_CRYPTO_SERVICE_MAC;
    backend->conf.cipher_algo_l = 1u << VIRTIO_CRYPTO_CIPHER_AES_CBC;
    backend->conf.hash_algo = 1u << VIRTIO_CRYPTO_HASH_SHA1;
    /*
     * Set the Maximum length of crypto request.
     * Why this value? Just avoid to overflow when
     * memory allocation for each crypto request.
     */
    backend->conf.max_size = LONG_MAX - sizeof(CryptoDevBackendSymOpInfo);
    backend->conf.max_cipher_key_len = ACCEL_BUITLIN_MAX_CIPHER_KEY_LEN;
    backend->conf.max_auth_key_len = ACCEL_BUITLIN_MAX_AUTH_KEY_LEN;

    cryptodev_backend_set_ready(backend, true);
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

static int acceldev_crypto_create_cipher_session(
                    AccelDevBackendCrypto *crypto,
                    AccelDevBackendCreateSessionInfo *sess_info,
                    Error **errp)
{
    int algo;
    int mode;
    QCryptoCipher *cipher;
    int index;
    AccelDevBackendCryptoSession *sess;

    if (sess_info->op != VIRTIO_ACCEL_CRYPTO_ENCRYPT ||
			sess_info->op != VIRTIO_ACCEL_CRYPTO_DECRYPT) {
        error_setg(errp, "Unsupported optype :%u", sess_info->op_type);
        return -1;
    }

    index = acceldev_crypto_get_unused_session_index(crypto);
    if (index < 0) {
        error_setg(errp, "Total number of sessions created exceeds %u",
                  MAX_NUM_SESSIONS);
        return -1;
    }

    switch (sess_info->cipher) {
    case VIRTIO_ACCEL_CIPHER_AES_ECB:
        mode = QCRYPTO_CIPHER_MODE_ECB;
        algo = acceldev_crypto_get_aes_algo(sess_info->key_len,
                                                    mode, errp);
        if (algo < 0)  {
            return -1;
        }
        break;
    case VIRTIO_ACCEL_CIPHER_AES_CBC:
        mode = QCRYPTO_CIPHER_MODE_CBC;
        algo = acceldev_crypto_get_aes_algo(sess_info->key_len,
                                                    mode, errp);
        if (algo < 0)  {
            return -1;
        }
        break;
    case VIRTIO_ACCEL_CIPHER_AES_CTR:
        mode = QCRYPTO_CIPHER_MODE_CTR;
        algo = acceldev_crypto_get_aes_algo(sess_info->key_len,
                                                    mode, errp);
        if (algo < 0)  {
            return -1;
        }
        break;
/*
    case VIRTIO_ACCEL_CIPHER_AES_XTS:
        mode = QCRYPTO_CIPHER_MODE_XTS;
        algo = cryptodev_builtin_get_aes_algo(sess_info->key_len,
                                                    mode, errp);
        if (algo < 0)  {
            return -1;
        }
        break;
    case VIRTIO_ACCEL_CIPHER_3DES_ECB:
        mode = QCRYPTO_CIPHER_MODE_ECB;
        algo = QCRYPTO_CIPHER_ALG_3DES;
        break;
    case VIRTIO_ACCEL_CIPHER_3DES_CBC:
        mode = QCRYPTO_CIPHER_MODE_CBC;
        algo = QCRYPTO_CIPHER_ALG_3DES;
        break;
    case VIRTIO_ACCEL_CIPHER_3DES_CTR:
        mode = QCRYPTO_CIPHER_MODE_CTR;
        algo = QCRYPTO_CIPHER_ALG_3DES;
        break;
*/
	default:
        error_setg(errp, "Unsupported cipher alg :%u",
                   sess_info->cipher_alg);
        return -1;
    }

    cipher = qcrypto_cipher_new(algo, mode,
                               sess_info->cipher_key,
                               sess_info->key_len,
                               errp);
    if (!cipher) {
        return -1;
    }

    sess = g_new0(AccelDevBackendCryptoSession, 1);
    sess->cipher = cipher;

    crypto->sessions[index] = sess;

    return index;
}

static int64_t acceldev_crypto_sym_create_session(
           AccelDevBackend *ab,
           AccelDevBackendCreateSessionInfo *sess_info,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendCrypto *crypto =
                      ACCELDEV_BACKEND_CRYPTO(ab);
    int32_t sess_id = -1;
    int ret;

    switch (sess_info->op_code) {
    case VIRTIO_ACCEL_CRYPTO_CIPHER_CREATE_SESSION:
        ret = acceldev_crypto_cipher_create_session(
                           crypto, sess_info, errp);
        if (ret < 0) {
            return ret;
        } else {
            sess_id = ret;
        }
        break;
    default:
        error_setg(errp, "Unsupported opcode :%" PRIu32 "",
                   sess_info->op_code);
        return -1;
    }

    return sess_id;
}

static int cryptodev_builtin_sym_close_session(
           CryptoDevBackend *backend,
           uint64_t session_id,
           uint32_t queue_index, Error **errp)
{
    CryptoDevBackendBuiltin *builtin =
                      ACCELDEV_BACKEND_CRYPTO(backend);

    if (session_id >= MAX_NUM_SESSIONS ||
              builtin->sessions[session_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu64 "",
                      session_id);
        return -1;
    }

    qcrypto_cipher_free(builtin->sessions[session_id]->cipher);
    g_free(builtin->sessions[session_id]);
    builtin->sessions[session_id] = NULL;
    return 0;
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

    if (info.op == VIRTIO_ACCEL_CRYPTO_CIPHER_ENCRYPT) {
        ret = qcrypto_cipher_encrypt(sess->cipher, info->src,
                                     info->dst, info->src_len, errp);
        if (ret < 0) {
            return -VIRTIO_ACCEL_ERR;
        }
    } else {
        ret = qcrypto_cipher_decrypt(sess->cipher, op_info->src,
                                     op_info->dst, op_info->src_len, errp);
        if (ret < 0) {
            return -VIRTIO_ACCEL_ERR;
        }
    }
    return VIRTIO_ACCEL_OK;
}

static void cryptodev_builtin_cleanup(
             CryptoDevBackend *backend,
             Error **errp)
{
    CryptoDevBackendBuiltin *builtin =
                      ACCELDEV_BACKEND_CRYPTO(backend);
    size_t i;
    int queues = backend->conf.peers.queues;
    CryptoDevBackendClient *cc;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (builtin->sessions[i] != NULL) {
            cryptodev_builtin_sym_close_session(
                    backend, i, 0, errp);
        }
    }

    for (i = 0; i < queues; i++) {
        cc = backend->conf.peers.ccs[i];
        if (cc) {
            cryptodev_backend_free_client(cc);
            backend->conf.peers.ccs[i] = NULL;
        }
    }

    cryptodev_backend_set_ready(backend, false);
}

static void
cryptodev_builtin_class_init(ObjectClass *oc, void *data)
{
    CryptoDevBackendClass *bc = ACCELDEV_BACKEND_CLASS(oc);

    bc->init = cryptodev_builtin_init;
    bc->cleanup = cryptodev_builtin_cleanup;
    bc->create_session = acceldev_crypto_sym_create_session;
    bc->close_session = acceldev_crypto_sym_close_session;
    bc->do_op = acceldev_crypto_sym_operation;
}

static const TypeInfo cryptodev_builtin_info = {
    .name = TYPE_ACCELDEV_BACKEND_CRYPTO,
    .parent = TYPE_ACCELDEV_BACKEND,
    .class_init = cryptodev_builtin_class_init,
    .instance_size = sizeof(CryptoDevBackendBuiltin),
};

static void
cryptodev_builtin_register_types(void)
{
    type_register_static(&cryptodev_builtin_info);
}

type_init(cryptodev_builtin_register_types);
