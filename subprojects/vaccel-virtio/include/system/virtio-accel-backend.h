// SPDX-License-Identifier: GPL-2.0-or-later

#ifndef VIRTIO_ACCEL_BACKEND_H
#define VIRTIO_ACCEL_BACKEND_H

#include "qom/object.h"

#define TYPE_VIRTIO_ACCEL_BACKEND "virtio-accel-backend"

OBJECT_DECLARE_TYPE(VirtIOAccelBackend, VirtIOAccelBackendClass,
                    VIRTIO_ACCEL_BACKEND)

typedef struct VirtIOAccelBackend VirtIOAccelBackend;

typedef struct VirtIOAccelBackendArg {
    void *buf;
    uint32_t len;
    uint32_t data_len;
    uint32_t type;
    uint32_t custom_type_id;
} VirtIOAccelBackendArg;

typedef struct VirtIOAccelBackendOp {
    int64_t session_id;
    uint32_t op_code;
    uint32_t nr_out;
    uint32_t nr_in;
    VirtIOAccelBackendArg *out;
    VirtIOAccelBackendArg *in;
    uint32_t op_ret;
} VirtIOAccelBackendOp;

typedef struct VirtIOAccelBackendProfilerSample {
    uint64_t start;
    uint64_t time;
} VirtIOAccelBackendProfilerSample;

#define VIRTIO_ACCEL_BACKEND_TIMERS_NAME_MAX 64

typedef struct VirtIOAccelBackendProfilerRegion {
    char name[VIRTIO_ACCEL_BACKEND_TIMERS_NAME_MAX];
    uint32_t max_samples;
    uint32_t nr_samples;
    VirtIOAccelBackendProfilerSample *samples;
} VirtIOAccelBackendProfilerRegion;

typedef struct VirtIOAccelBackendProfilerOp {
    int64_t session_id;
    uint32_t max_regions;
    uint32_t nr_regions;
    VirtIOAccelBackendProfilerRegion *regions;
    uint32_t op_ret;
} VirtIOAccelBackendProfilerOp;

typedef struct VirtIOAccelBackendTimer {
    void *opaque;
    char name[VIRTIO_ACCEL_BACKEND_TIMERS_NAME_MAX];
    QTAILQ_ENTRY(VirtIOAccelBackendTimer) next;
} VirtIOAccelBackendTimer;

typedef struct VirtIOAccelBackendSession {
    void *opaque;
    int64_t id;
    QTAILQ_HEAD(, VirtIOAccelBackendTimer) timers;
    uint32_t nr_timers;
    QTAILQ_ENTRY(VirtIOAccelBackendSession) next;
} VirtIOAccelBackendSession;

typedef struct VirtIOAccelBackendClass {
    ObjectClass parent_class;

    void (*init)(VirtIOAccelBackend *b, Error **errp);
    void (*cleanup)(VirtIOAccelBackend *b, Error **errp);

    int64_t (*create_session)(VirtIOAccelBackend *b, VirtIOAccelBackendOp *op,
                              void **handle, Error **errp);
    int (*destroy_session)(VirtIOAccelBackend *b,
                           VirtIOAccelBackendSession *sess, Error **errp);
    int (*do_op)(VirtIOAccelBackend *b, VirtIOAccelBackendSession *sess,
                 VirtIOAccelBackendOp *op, Error **errp);

    bool (*timers_enabled)(VirtIOAccelBackend *b);
    int (*timer_create)(VirtIOAccelBackend *b, const char *name, void **handle,
                        Error **errp);
    void (*timer_destroy)(VirtIOAccelBackend *b,
                          VirtIOAccelBackendTimer *timer);
    int (*timer_start)(VirtIOAccelBackend *b, VirtIOAccelBackendTimer *timer,
                       Error **errp);
    int (*timer_stop)(VirtIOAccelBackend *b, VirtIOAccelBackendTimer *timer,
                      Error **errp);
    int (*get_timers)(VirtIOAccelBackend *b, VirtIOAccelBackendSession *sess,
                      VirtIOAccelBackendProfilerOp *op, Error **errp);
} VirtIOAccelBackendClass;

struct VirtIOAccelBackend {
    Object parent_obj;
    QTAILQ_HEAD(, VirtIOAccelBackendSession) sessions;
    bool is_used;
};

/**
 * virtio_accel_backend_create_session:
 * @b: the virtio-accel backend object
 * @op: parameters needed for session creation
 * @errp: pointer to a NULL-initialized error object
 *
 * Create an virtio-accel session
 *
 * Returns: session id on success,
 *         or -VIRTIO_ACCEL_* on error
 */
int64_t virtio_accel_backend_create_session(VirtIOAccelBackend *b,
                                            VirtIOAccelBackendOp *op,
                                            Error **errp);

/**
 * virtio_accel_backend_destroy_session:
 * @b: the virtio-accel backend object
 * @sess_id: the session id
 * @errp: pointer to a NULL-initialized error object
 *
 * Close an virtio-accel session which was previously
 * created by virtio_accel_backend_create_session()
 *
 * Returns: VIRTIO_ACCEL_OK on success,
 *         or -VIRTIO_ACCEL_* on error
 */
int virtio_accel_backend_destroy_session(VirtIOAccelBackend *b, int64_t sess_id,
                                         Error **errp);

/**
 * virtio_accel_backend_operation:
 * @b: the virtio-accel backend object
 * @op: parameters needed to execute an operation 
 * @errp: pointer to a NULL-initialized error object
 *
 * Execute virtio-accel operation
 *
 * Returns: VIRTIO_ACCEL_OK on success,
 *         or -VIRTIO_ACCEL_* on error
 */
int virtio_accel_backend_operation(VirtIOAccelBackend *b,
                                   VirtIOAccelBackendOp *op, Error **errp);

/**
 * virtio_accel_backend_timer_start:
 * @b: the virtio-accel backend object
 * @sess_id: the session id
 * @name: the timer name
 * @errp: pointer to a NULL-initialized error object
 *
 * Start a virtio-accel timer
 *
 * Returns: VIRTIO_ACCEL_OK on success,
 *         or -VIRTIO_ACCEL_* on error
 */
int virtio_accel_backend_timer_start(VirtIOAccelBackend *b, int64_t sess_id,
                                     const char *name, Error **errp);

/**
 * virtio_accel_backend_timer_stop:
 * @b: the virtio-accel backend object
 * @sess_id: the session id
 * @name: the timer name
 * @errp: pointer to a NULL-initialized error object
 *
 * Stop a virtio-accel timer
 *
 * Returns: VIRTIO_ACCEL_OK on success,
 *         or -VIRTIO_ACCEL_* on error
 */
int virtio_accel_backend_timer_stop(VirtIOAccelBackend *b, int64_t sess_id,
                                    const char *name, Error **errp);

/**
 * virtio_accel_backend_get_timers:
 * @b: the virtio-accel backend object
 * @op: parameters needed to execute an operation 
 * @errp: pointer to a NULL-initialized error object
 *
 * Append virtio-accel timers to the request
 *
 * Returns: VIRTIO_ACCEL_OK on success,
 *         or -VIRTIO_ACCEL_* on error
 */
int virtio_accel_backend_get_timers(VirtIOAccelBackend *b,
                                    VirtIOAccelBackendProfilerOp *op,
                                    Error **errp);

/**
 * virtio_accel_backend_set_used:
 * @b: the virtio-accel backend object
 * @used: true or false
 *
 * Set if the virtio-accel backend is used by virtio-accel or not
 */
void virtio_accel_backend_set_used(VirtIOAccelBackend *b, bool used);

/**
 * virtio_accel_backend_is_used:
 * @b: the virtio-accel backend object
 *
 * Return if the virtio-accel backend is used
 * by virtio-accel or not
 *
 * Returns: true on used, or false on not used
 */
bool virtio_accel_backend_is_used(VirtIOAccelBackend *b);

#endif /* VIRTIO_ACCEL_BACKEND_H */
