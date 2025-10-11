// SPDX-License-Identifier: GPL-2.0-or-later

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/config-file.h"
#include "qom/object_interfaces.h"

#include "hw/virtio/virtio-accel.h"
#include "system/virtio-accel-backend.h"

void virtio_accel_backend_cleanup(VirtIOAccelBackend *b, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->cleanup)
        bc->cleanup(b, errp);
}

int64_t virtio_accel_backend_create_session(VirtIOAccelBackend *b,
                                            VirtIOAccelBackendOp *op,
                                            Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->create_session)
        return bc->create_session(b, op, errp);

    return -VIRTIO_ACCEL_ERR;
}

int virtio_accel_backend_destroy_session(VirtIOAccelBackend *b, int64_t sess_id,
                                         Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->destroy_session)
        return bc->destroy_session(b, sess_id, errp);

    return -VIRTIO_ACCEL_ERR;
}

int virtio_accel_backend_operation(VirtIOAccelBackend *b,
                                   VirtIOAccelBackendOp *op, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->do_op)
        return bc->do_op(b, op, errp);

    return -VIRTIO_ACCEL_ERR;
}

int virtio_accel_backend_timer_start(VirtIOAccelBackend *b, int64_t sess_id,
                                     const char *name, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->timer_start)
        return bc->timer_start(b, sess_id, name, errp);

    return -VIRTIO_ACCEL_ERR;
}

int virtio_accel_backend_timer_stop(VirtIOAccelBackend *b, int64_t sess_id,
                                    const char *name, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->timer_stop)
        return bc->timer_stop(b, sess_id, name, errp);

    return -VIRTIO_ACCEL_ERR;
}

int virtio_accel_backend_get_timers(VirtIOAccelBackend *b,
                                    VirtIOAccelBackendOp *op, Error **errp)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(b);

    if (bc->do_op)
        return bc->timers_get(b, op, errp);

    return -VIRTIO_ACCEL_ERR;
}

static void virtio_accel_backend_complete(UserCreatable *uc, Error **errp)
{
    VirtIOAccelBackend *b = VIRTIO_ACCEL_BACKEND(uc);
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_GET_CLASS(uc);

    if (bc->init)
        bc->init(b, errp);

    return;
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
