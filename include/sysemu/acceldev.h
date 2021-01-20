#ifndef ACCELDEV_H
#define ACCELDEV_H

#include "qemu/queue.h"
#include "qom/object.h"

#define TYPE_ACCELDEV_BACKEND "acceldev-backend"

#define ACCELDEV_BACKEND(obj) \
    OBJECT_CHECK(AccelDevBackend, \
                 (obj), TYPE_ACCELDEV_BACKEND)
#define ACCELDEV_BACKEND_GET_CLASS(obj) \
    OBJECT_GET_CLASS(AccelDevBackendClass, \
                 (obj), TYPE_ACCELDEV_BACKEND)
#define ACCELDEV_BACKEND_CLASS(klass) \
    OBJECT_CLASS_CHECK(AccelDevBackendClass, \
                (klass), TYPE_ACCELDEV_BACKEND)


#define MAX_ACCEL_QUEUE_NUM  64

typedef struct AccelDevBackendConf AccelDevBackendConf;
typedef struct AccelDevBackendPeers AccelDevBackendPeers;
typedef struct AccelDevBackendClient AccelDevBackendClient;
typedef struct AccelDevBackend AccelDevBackend;

typedef struct AccelDevBackendArg {
    uint8_t *buf;
    uint32_t len;
} AccelDevBackendArg;

typedef struct AccelDevBackendInfo {
    uint32_t in_nr;
    uint32_t out_nr;
    AccelDevBackendArg *in;
    AccelDevBackendArg *out;
} AccelDevBackendInfo;

typedef struct AccelDevBackendSessionInfo {
    uint32_t op_type;
    AccelDevBackendInfo op;
} AccelDevBackendSessionInfo;

typedef struct AccelDevBackendOpInfo {
    uint32_t op_type;
    uint32_t sess_id;
    AccelDevBackendInfo op;
} AccelDevBackendOpInfo;


typedef struct AccelDevBackendClass {
    ObjectClass parent_class;

    void (*init)(AccelDevBackend *ab, Error **errp);
    void (*cleanup)(AccelDevBackend *ab, Error **errp);

    int64_t (*create_session)(AccelDevBackend *ab,
                       AccelDevBackendSessionInfo *sess_info,
                       uint32_t queue_index, Error **errp);
    int (*destroy_session)(AccelDevBackend *ab,
                           uint32_t session_id,
                           uint32_t queue_index, Error **errp);
    int (*do_op)(AccelDevBackend *ab,
                     AccelDevBackendOpInfo *op_info,
                     uint32_t queue_index, Error **errp);
} AccelDevBackendClass;


struct AccelDevBackendClient {
    char *model;
    char *name;
    char *info_str;
    unsigned int queue_index;
    QTAILQ_ENTRY(AccelDevBackendClient) next;
};

struct AccelDevBackendPeers {
    AccelDevBackendClient *ccs[MAX_ACCEL_QUEUE_NUM];
    uint32_t queues;
};

struct AccelDevBackendConf {
    AccelDevBackendPeers peers;

    /* Supported service mask */
    uint32_t services;
    /* Maximum size of each accel request's content */
    uint64_t max_size;
};

struct AccelDevBackend {
    Object parent_obj;

    bool ready;
    /* Tag the acceldev backend is used by virtio-accel or not */
    bool is_used;
    AccelDevBackendConf conf;
};

/**
 * acceldev_backend_new_client:
 * @model: the acceldev backend model
 * @name: the acceldev backend name, can be NULL
 *
 * Creates a new acceldev backend client object
 * with the @name in the model @model.
 *
 * The returned object must be released with
 * acceldev_backend_free_client() when no
 * longer required
 *
 * Returns: a new acceldev backend client object
 */
AccelDevBackendClient *
acceldev_backend_new_client(const char *model, const char *name);

/**
 * acceldev_backend_free_client:
 * @cc: the acceldev backend client object
 *
 * Release the memory associated with @cc that
 * was previously allocated by acceldev_backend_new_client()
 */
void acceldev_backend_free_client(AccelDevBackendClient *c);

/**
 * acceldev_backend_cleanup:
 * @backend: the acceldev backend object
 * @errp: pointer to a NULL-initialized error object
 *
 * Clean the resouce associated with @backend that realizaed
 * by the specific backend's init() callback
 */
void acceldev_backend_cleanup(
           AccelDevBackend *ab,
           Error **errp);

/**
 * acceldev_backend_sym_create_session:
 * @backend: the acceldev backend object
 * @sess_info: parameters needed by session creating
 * @queue_index: queue index of acceldev backend client
 * @errp: pointer to a NULL-initialized error object
 *
 * Create a session for symmetric algorithms
 *
 * Returns: session id on success, or -1 on error
 */
int64_t acceldev_backend_create_session(
           AccelDevBackend *ab,
           AccelDevBackendSessionInfo *sess_info,
           uint32_t queue_index, Error **errp);

/**
 * acceldev_backend_sym_destroy_session:
 * @backend: the acceldev backend object
 * @session_id: the session id
 * @queue_index: queue index of acceldev backend client
 * @errp: pointer to a NULL-initialized error object
 *
 * Close a session for symmetric algorithms which was previously
 * created by acceldev_backend_sym_create_session()
 *
 * Returns: 0 on success, or Negative on error
 */
int acceldev_backend_destroy_session(
           AccelDevBackend *ab,
           uint64_t session_id,
           uint32_t queue_index, Error **errp);

/**
 * acceldev_backend_crypto_operation:
 * @backend: the acceldev backend object
 * @opaque: pointer to a VirtIOCryptoReq object
 * @queue_index: queue index of acceldev backend client
 * @errp: pointer to a NULL-initialized error object
 *
 * Do crypto operation, such as encryption and
 * decryption
 *
 * Returns: VIRTIO_CRYPTO_OK on success,
 *         or -VIRTIO_CRYPTO_* on error
 */
int acceldev_backend_operation(
                 AccelDevBackend *ab,
				 AccelDevBackendOpInfo *op_info,
                 uint32_t queue_index, Error **errp);

/**
 * acceldev_backend_set_used:
 * @backend: the acceldev backend object
 * @used: ture or false
 *
 * Set the acceldev backend is used by virtio-crypto or not
 */
void acceldev_backend_set_used(AccelDevBackend *ab, bool used);

/**
 * acceldev_backend_is_used:
 * @backend: the acceldev backend object
 *
 * Return the status that the acceldev backend is used
 * by virtio-crypto or not
 *
 * Returns: true on used, or false on not used
 */
bool acceldev_backend_is_used(AccelDevBackend *ab);

/**
 * acceldev_backend_set_ready:
 * @backend: the acceldev backend object
 * @ready: ture or false
 *
 * Set the acceldev backend is ready or not, which is called
 * by the children of the acceldev banckend interface.
 */
void acceldev_backend_set_ready(AccelDevBackend *ab, bool ready);

/**
 * acceldev_backend_is_ready:
 * @backend: the acceldev backend object
 *
 * Return the status that the acceldev backend is ready or not
 *
 * Returns: true on ready, or false on not ready
 */
bool acceldev_backend_is_ready(AccelDevBackend *ab);

#endif /* ACCELDEV_H */
