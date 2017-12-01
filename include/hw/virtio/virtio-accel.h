#ifndef _QEMU_VIRTIO_ACCEL_H
#define _QEMU_VIRTIO_ACCEL_H

#include "standard-headers/linux/virtio_crypto.h"
#include "hw/virtio/virtio.h"
#include "sysemu/iothread.h"
#include "sysemu/cryptodev.h"


#define DEBUG_VIRTIO_ACCEL 0

#define DPRINTF(fmt, ...) \
do { \
    if (DEBUG_VIRTIO_ACCEL) { \
        fprintf(stderr, "virtio_accel: " fmt, ##__VA_ARGS__); \
    } \
} while (0)


#define TYPE_VIRTIO_ACCEL "virtio-accel-device"
#define VIRTIO_ACCEL(obj) \
        OBJECT_CHECK(VirtIOAccel, (obj), TYPE_VIRTIO_ACCEL)
#define VIRTIO_ACCEL_GET_PARENT_CLASS(obj) \
        OBJECT_GET_PARENT_CLASS(obj, TYPE_VIRTIO_ACCEL)


typedef struct VirtIOCryptoConf {
    CryptoDevBackend *cryptodev;

    /* Supported service mask */
    uint32_t crypto_services;

    /* Detailed algorithms mask */
    uint32_t cipher_algo_l;
    uint32_t cipher_algo_h;
    uint32_t hash_algo;
    uint32_t mac_algo_l;
    uint32_t mac_algo_h;
    uint32_t aead_algo;

    /* Maximum length of cipher key */
    uint32_t max_cipher_key_len;
    /* Maximum length of authenticated key */
    uint32_t max_auth_key_len;
    /* Maximum size of each crypto request's content */
    uint64_t max_size;
} VirtIOCryptoConf;

struct VirtIOAccel;

typedef struct VirtIOAccelReq {
    VirtQueueElement elem;
    /* flags of operation, such as type of algorithm */
    uint32_t flags;

	struct virtio_accel_hdr hdr;
	struct VirtIOAccel *vaccel;
	struct iovec *in_iov;
	struct iovec *out_iov;
	unsigned int in_niov;
	unsigned int out_niov;
    size_t in_iov_len;
	unsigned int status;

    union {
        CryptoDevBackendSymOpInfo *sym_op_info;
    } u;
} VirtIOAccelReq;

typedef struct VirtIOCryptoQueue {
    VirtQueue *dataq;
    QEMUBH *dataq_bh;
    struct VirtIOCrypto *vcrypto;
} VirtIOCryptoQueue;

typedef struct VirtIOAccel {
    VirtIODevice parent_obj;

    VirtQueue *vq;
    VirtIOAccelQueue *vqs;
    VirtIOAccelConf conf;
    AccelBackend *crypto;

    uint32_t max_queues;
    uint32_t status;

    int multiqueue;
    uint32_t curr_queues;
    size_t config_size;
} VirtIOAccel;

#endif /* _QEMU_VIRTIO_ACCEL_H */
