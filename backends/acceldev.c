#include "qemu/osdep.h"
#include "sysemu/acceldev.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qemu/config-file.h"
#include "qom/object_interfaces.h"
#include "hw/virtio/virtio-accel.h"


static QTAILQ_HEAD(, AccelDevBackendClient) accel_clients;


AccelDevBackendClient *
acceldev_backend_new_client(const char *model, const char *name)
{
    AccelDevBackendClient *c;

    c = g_malloc0(sizeof(AccelDevBackendClient));
    c->model = g_strdup(model);
    if (name) {
        c->name = g_strdup(name);
    }

    QTAILQ_INSERT_TAIL(&accel_clients, c, next);

    return c;
}

void acceldev_backend_free_client(AccelDevBackendClient *c)
{
    QTAILQ_REMOVE(&accel_clients, c, next);
    g_free(c->name);
    g_free(c->model);
    g_free(c->info_str);
    g_free(c);
}

void acceldev_backend_cleanup(AccelDevBackend *ab, Error **errp)
{
    AccelDevBackendClass *abc =
                  ACCELDEV_BACKEND_GET_CLASS(ab);

    if (abc->cleanup) {
        abc->cleanup(ab, errp);
    }
}

int64_t acceldev_backend_create_session(
           AccelDevBackend *ab,
           AccelDevBackendSessionInfo *sess_info,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendClass *abc =
                      ACCELDEV_BACKEND_GET_CLASS(ab);

    if (abc->create_session) {
        return abc->create_session(ab, sess_info, queue_index, errp);
    }

    return -VIRTIO_ACCEL_ERR;
}

int acceldev_backend_destroy_session(
           AccelDevBackend *ab,
           uint64_t session_id,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendClass *abc =
                      ACCELDEV_BACKEND_GET_CLASS(ab);

    if (abc->destroy_session) {
        return abc->destroy_session(ab, session_id, queue_index, errp);
    }

    return -VIRTIO_ACCEL_ERR;
}

int acceldev_backend_operation(
                 AccelDevBackend *ab,
                 AccelDevBackendOpInfo *op_info,
                 uint32_t queue_index, Error **errp)
{
	AccelDevBackendClass *abc =
                      ACCELDEV_BACKEND_GET_CLASS(ab);

    if (abc->do_op) {
        return abc->do_op(ab, op_info, queue_index, errp);
	}
    
	return -VIRTIO_ACCEL_ERR;
}

static void
acceldev_backend_get_queues(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    AccelDevBackend *ab = ACCELDEV_BACKEND(obj);
    uint32_t value = ab->conf.peers.queues;

    visit_type_uint32(v, name, &value, errp);
}

static void
acceldev_backend_set_queues(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    AccelDevBackend *ab = ACCELDEV_BACKEND(obj);
    Error *local_err = NULL;
    uint32_t value;

    visit_type_uint32(v, name, &value, &local_err);
    if (local_err)
        goto out;

    if (!value) {
        error_setg(&local_err, "Property '%s.%s' doesn't take value '%"
                   PRIu32 "'", object_get_typename(obj), name, value);
        goto out;
    }
    ab->conf.peers.queues = value;
out:
    error_propagate(errp, local_err);
}

static void
acceldev_backend_complete(UserCreatable *uc, Error **errp)
{
    AccelDevBackend *ab = ACCELDEV_BACKEND(uc);
    AccelDevBackendClass *abc = ACCELDEV_BACKEND_GET_CLASS(uc);
    Error *local_err = NULL;

    if (abc->init) {
        abc->init(ab, &local_err);
        if (local_err)
    		error_propagate(errp, local_err);
    }

    return;
}

void acceldev_backend_set_used(AccelDevBackend *ab, bool used)
{
    ab->is_used = used;
}

bool acceldev_backend_is_used(AccelDevBackend *ab)
{
    return ab->is_used;
}

void acceldev_backend_set_ready(AccelDevBackend *ab, bool ready)
{
    ab->ready = ready;
}

bool acceldev_backend_is_ready(AccelDevBackend *ab)
{
    return ab->ready;
}

static bool
acceldev_backend_can_be_deleted(UserCreatable *uc)
{
    return !acceldev_backend_is_used(ACCELDEV_BACKEND(uc));
}

static void acceldev_backend_instance_init(Object *obj)
{
    object_property_add(obj, "queues", "int",
                          acceldev_backend_get_queues,
                          acceldev_backend_set_queues,
                          NULL, NULL, NULL);
    /* Initialize devices' queues property to 1 */
    object_property_set_int(obj, 1, "queues", NULL);
}

static void acceldev_backend_finalize(Object *obj)
{
    AccelDevBackend *ab = ACCELDEV_BACKEND(obj);

    acceldev_backend_cleanup(ab, NULL);
}

static void
acceldev_backend_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->complete = acceldev_backend_complete;
    ucc->can_be_deleted = acceldev_backend_can_be_deleted;

    QTAILQ_INIT(&accel_clients);
}

static const TypeInfo acceldev_backend_info = {
    .name = TYPE_ACCELDEV_BACKEND,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(AccelDevBackend),
    .instance_init = acceldev_backend_instance_init,
    .instance_finalize = acceldev_backend_finalize,
    .class_size = sizeof(AccelDevBackendClass),
    .class_init = acceldev_backend_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void
acceldev_backend_register_types(void)
{
    type_register_static(&acceldev_backend_info);
}

type_init(acceldev_backend_register_types);
