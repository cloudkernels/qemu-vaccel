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

struct virtio_accel_crypto_sess {
#define VIRTIO_ACCEL_C_NO_CIPHER      0
#define VIRTIO_ACCEL_C_CIPHER_AES_ECB 1
#define VIRTIO_ACCEL_C_CIPHER_AES_CBC 2
#define VIRTIO_ACCEL_C_CIPHER_AES_CTR 3
#define VIRTIO_ACCEL_C_CIPHER_AES_XTS 4
	uint32_t cipher;
	uint32_t keylen;
	unsigned char *key;
	unsigned char padding[7];
};

struct virtio_accel_crypto_op {
	uint32_t src_len;
	uint32_t dst_len;
	uint32_t iv_len;
	unsigned char *src;
	unsigned char *dst;
	unsigned char *iv;
	unsigned char padding;
};
struct virtio_accel_gen_op_arg {
    uint32_t len;
    unsigned char *buf;
    unsigned char padding[3];
};

struct virtio_accel_gen_op {
    uint32_t in_nr;
    uint32_t out_nr;
    struct virtio_accel_gen_op_arg *in;
    struct virtio_accel_gen_op_arg *out;
};

struct virtio_accel_hdr {
	uint32_t session_id;

#define VIRTIO_ACCEL_NO_OP                        0
#define VIRTIO_ACCEL_G_OP_CREATE_SESSION          1
#define VIRTIO_ACCEL_G_OP_DESTROY_SESSION         2
#define VIRTIO_ACCEL_G_OP_DO_OP                   3
#define VIRTIO_ACCEL_C_OP_CIPHER_CREATE_SESSION   4
#define VIRTIO_ACCEL_C_OP_CIPHER_DESTROY_SESSION  5
#define VIRTIO_ACCEL_C_OP_CIPHER_ENCRYPT          6
#define VIRTIO_ACCEL_C_OP_CIPHER_DECRYPT          7
#define VIRTIO_ACCEL_C_OP_HASH_CREATE_SESSION     8
#define VIRTIO_ACCEL_C_OP_MAC_CREATE_SESSION      9
#define VIRTIO_ACCEL_C_OP_AEAD_CREATE_SESSION    10
#define VIRTIO_ACCEL_C_OP_HASH_DESTROY_SESSION   11
#define VIRTIO_ACCEL_C_OP_MAC_DESTROY_SESSION    12
#define VIRTIO_ACCEL_C_OP_AEAD_DESTROY_SESSION   13
#define VIRTIO_ACCEL_C_OP_HASH                   14
#define VIRTIO_ACCEL_C_OP_MAC                    15
#define VIRTIO_ACCEL_C_OP_AEAD_ENCRYPT           16
#define VIRTIO_ACCEL_C_OP_AEAD_DECRYPT           17
	uint32_t op;
	/* session create structs */
	union {
		struct virtio_accel_crypto_sess crypto_sess;
		struct virtio_accel_crypto_op crypto_op;
		struct virtio_accel_gen_op gen_op;
	} u;
};

struct virtio_accel_crypto_conf {
    /* Maximum length of cipher key */
    uint32_t max_cipher_key_len;
    /* Maximum length of authenticated key */
    uint32_t max_auth_key_len;
};

struct virtio_accel_conf {
	uint32_t status;
    /* Supported service mask */
    uint32_t services;
    /* Maximum size of each crypto request's content */
    uint64_t max_size;

    union {
        struct virtio_accel_crypto_conf crypto;
    } u;
};

#endif /* _VIRTIO_ACCEL_H */
