// SPDX-License-Identifier: GPL-2.0-or-later

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/config-file.h"
#include "qom/object_interfaces.h"

#include "hw/virtio/virtio-accel.h"
#include "system/virtio-accel-backend.h"

static VirtIOAccelBackendTimer *
timer_create_and_add(VirtIOAccelBackendSession *sess, const char *name,
                     void *handle)
{
    static VirtIOAccelBackendTimer *timer;

    timer = g_new0(VirtIOAccelBackendTimer, 1);
    timer->opaque = handle;
    g_snprintf(timer->name, VIRTIO_ACCEL_BACKEND_TIMERS_NAME_MAX, "%s", name);

    QTAILQ_INSERT_TAIL(&sess->timers, timer, next);
    sess->nr_timers++;

    return timer;
}

static void timer_remove_and_delete(VirtIOAccelBackendSession *sess,
                                    VirtIOAccelBackendTimer *timer)
{
    QTAILQ_REMOVE(&sess->timers, timer, next);

    sess->nr_timers--;
    g_free(timer);
}

static VirtIOAccelBackendTimer *timer_find(VirtIOAccelBackendSession *sess,
                                           const char *name)
{
    VirtIOAccelBackendTimer *timer, *tmp;

    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        if (strcmp(timer->name, name) == 0) {
            return timer;
        }
    }
    return NULL;
}

static VirtIOAccelBackendSession *session_find(VirtIOAccelBackend *b,
                                               int64_t id)
{
    VirtIOAccelBackendSession *sess, *tmp;

    QTAILQ_FOREACH_SAFE(sess, &b->sessions, next, tmp)
    {
        if (sess->id == id)
            return sess;
    }
    return NULL;
}

static bool virtio_accel_backend_timers_enabled(VirtIOAccelBackend *b)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (!bc->timers_enabled)
        return false;

    return bc->timers_enabled;
}

static VirtIOAccelBackendTimer *
virtio_accel_backend_timer_create(VirtIOAccelBackend *b,
                                  VirtIOAccelBackendSession *sess,
                                  const char *name, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    void *opaque = NULL;
    int ret;

    if (!bc->timer_create)
        return NULL;

    ret = bc->timer_create(b, name, &opaque, errp);
    if (ret)
        return NULL;

    return timer_create_and_add(sess, name, opaque);
}

static void virtio_accel_backend_timer_destroy(VirtIOAccelBackend *b,
                                               VirtIOAccelBackendSession *sess,
                                               VirtIOAccelBackendTimer *timer)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (!bc->timer_destroy)
        return;

    bc->timer_destroy(b, timer);
    timer_remove_and_delete(sess, timer);
}

int virtio_accel_backend_timer_start(VirtIOAccelBackend *b, int64_t sess_id,
                                     const char *name, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess;
    VirtIOAccelBackendTimer *timer;

    if (!virtio_accel_backend_timers_enabled(b))
        return VIRTIO_ACCEL_OK;

    if (!bc->timer_start)
        return -VIRTIO_ACCEL_ERR;

    sess = session_find(b, sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    timer = timer_find(sess, name);
    if (!timer) {
        timer = virtio_accel_backend_timer_create(b, sess, name, errp);
        if (!timer)
            return -VIRTIO_ACCEL_ERR;
    }

    return bc->timer_start(b, timer, errp);
}

int virtio_accel_backend_timer_stop(VirtIOAccelBackend *b, int64_t sess_id,
                                    const char *name, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess;
    VirtIOAccelBackendTimer *timer;

    if (!virtio_accel_backend_timers_enabled(b))
        return VIRTIO_ACCEL_OK;

    if (bc->timer_stop)
        return -VIRTIO_ACCEL_ERR;

    sess = session_find(b, sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    timer = timer_find(sess, name);
    if (!timer)
        return VIRTIO_ACCEL_OK;

    return bc->timer_stop(b, timer, errp);
}

int virtio_accel_backend_get_timers(VirtIOAccelBackend *b,
                                    VirtIOAccelBackendProfilerOp *op,
                                    Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess;

    if (!virtio_accel_backend_timers_enabled(b))
        return VIRTIO_ACCEL_OK;

    if (!bc->do_op)
        return -VIRTIO_ACCEL_ERR;

    sess = session_find(b, op->session_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   op->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (!op->max_regions) {
        op->nr_regions = sess->nr_timers;
        return VIRTIO_ACCEL_OK;
    }

    if (!op->regions) {
        error_setg(errp, "Invalid profiler regions");
        return -VIRTIO_ACCEL_ERR;
    }

    return bc->get_timers(b, sess, op, errp);
}

static VirtIOAccelBackendSession *
session_create_and_add(VirtIOAccelBackend *b, int64_t id, void *handle)
{
    VirtIOAccelBackendSession *sess = g_new0(VirtIOAccelBackendSession, 1);

    sess->opaque = handle;
    sess->id = id;
    QTAILQ_INIT(&sess->timers);
    sess->nr_timers = 0;

    QTAILQ_INSERT_TAIL(&b->sessions, sess, next);
    return sess;
}

static void session_remove_and_delete(VirtIOAccelBackend *b,
                                      VirtIOAccelBackendSession *sess)
{
    VirtIOAccelBackendTimer *timer, *tmp;

    QTAILQ_REMOVE(&b->sessions, sess, next);
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        virtio_accel_backend_timer_destroy(b, sess, timer);
    }
    g_free(sess);
}

int64_t virtio_accel_backend_create_session(VirtIOAccelBackend *b,
                                            VirtIOAccelBackendOp *op,
                                            Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess;
    void *data = NULL;
    int64_t id = 0;

    if (!bc->create_session)
        return -VIRTIO_ACCEL_ERR;

    id = bc->create_session(b, op, &data, errp);
    if (id <= 0)
        return id;

    sess = session_create_and_add(b, id, data);
    return sess->id;
}

int virtio_accel_backend_destroy_session(VirtIOAccelBackend *b, int64_t sess_id,
                                         Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess;
    int ret;

    if (!bc->destroy_session)
        return -VIRTIO_ACCEL_ERR;

    sess = session_find(b, sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    ret = bc->destroy_session(b, sess, errp);
    if (ret)
        return ret;

    session_remove_and_delete(b, sess);
    return VIRTIO_ACCEL_OK;
}

int virtio_accel_backend_operation(VirtIOAccelBackend *b,
                                   VirtIOAccelBackendOp *op, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess;

    if (!bc->do_op)
        return -VIRTIO_ACCEL_ERR;

    sess = session_find(b, op->session_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   op->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    return bc->do_op(b, sess, op, errp);
}

static void virtio_accel_backend_complete(UserCreatable *uc, Error **errp)
{
    VirtIOAccelBackend *b = VIRTIO_ACCEL_BACKEND(uc);
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(uc);

    if (bc->init)
        bc->init(b, errp);

    QTAILQ_INIT(&b->sessions);
}

static void virtio_accel_backend_cleanup(VirtIOAccelBackend *b, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);
    VirtIOAccelBackendSession *sess, *tmp;

    if (bc->cleanup)
        bc->cleanup(b, errp);

    QTAILQ_FOREACH_SAFE(sess, &b->sessions, next, tmp)
    {
        virtio_accel_backend_destroy_session(b, sess->id, errp);
    }
}

void virtio_accel_backend_set_used(VirtIOAccelBackend *b, bool used)
{
    b->is_used = used;
}

bool virtio_accel_backend_is_used(VirtIOAccelBackend *b)
{
    return b->is_used;
}

static bool virtio_accel_backend_can_be_deleted(UserCreatable *uc)
{
    return !virtio_accel_backend_is_used(VIRTIO_ACCEL_BACKEND(uc));
}

static void virtio_accel_backend_instance_init(Object *obj)
{
    /* Initialize devices' queues property to 1 */
    object_property_set_int(obj, "queues", 1, NULL);
}

static void virtio_accel_backend_finalize(Object *obj)
{
    VirtIOAccelBackend *b = VIRTIO_ACCEL_BACKEND(obj);

    virtio_accel_backend_cleanup(b, NULL);
}

static void virtio_accel_backend_class_init(ObjectClass *oc, const void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->complete = virtio_accel_backend_complete;
    ucc->can_be_deleted = virtio_accel_backend_can_be_deleted;
}

static const TypeInfo virtio_accel_backend_info = {
    .name = TYPE_VIRTIO_ACCEL_BACKEND,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(VirtIOAccelBackend),
    .instance_init = virtio_accel_backend_instance_init,
    .instance_finalize = virtio_accel_backend_finalize,
    .class_size = sizeof(VirtIOAccelBackendClass),
    .class_init = virtio_accel_backend_class_init,
    .interfaces = (const InterfaceInfo[]){ { TYPE_USER_CREATABLE }, {} }
};

static void virtio_accel_backend_register_types(void)
{
    type_register_static(&virtio_accel_backend_info);
}

type_init(virtio_accel_backend_register_types);
