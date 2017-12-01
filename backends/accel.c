#include "qemu/osdep.h"
#include "sysemu/accel.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "qapi/visitor.h"
#include "qapi-types.h"
#include "qapi-visit.h"
#include "qemu/config-file.h"
#include "qom/object_interfaces.h"
#include "hw/virtio/virtio-accel.h"


static QTAILQ_HEAD(, CryptoDevBackendClient) crypto_clients;


CryptoDevBackendClient *
cryptodev_backend_new_client(const char *model,
                                    const char *name)
{
    CryptoDevBackendClient *cc;

    cc = g_malloc0(sizeof(CryptoDevBackendClient));
    cc->model = g_strdup(model);
    if (name) {
        cc->name = g_strdup(name);
    }

    QTAILQ_INSERT_TAIL(&crypto_clients, cc, next);

    return cc;
}

void cryptodev_backend_free_client(
                  CryptoDevBackendClient *cc)
{
    QTAILQ_REMOVE(&crypto_clients, cc, next);
    g_free(cc->name);
    g_free(cc->model);
    g_free(cc->info_str);
    g_free(cc);
}

void cryptodev_backend_cleanup(
             CryptoDevBackend *backend,
             Error **errp)
{
    CryptoDevBackendClass *bc =
                  CRYPTODEV_BACKEND_GET_CLASS(backend);

    if (bc->cleanup) {
        bc->cleanup(backend, errp);
    }
}

int64_t accel_backend_create_session(
           AccelBackend *ab,
           AccelBackendSessionInfo *sess_info,
           uint32_t queue_index, Error **errp)
{
    AccelBackendClass *abc =
                      Accel_BACKEND_GET_CLASS(backend);

    if (abc->create_session) {
        return abc->create_session(ab, sess_info, queue_index, errp);
    }

    return -1;
}

int accel_backend_close_session(
           AccelBackend *ab,
           uint64_t session_id,
           uint32_t queue_index, Error **errp)
{
    AccelBackendClass *abc =
                      ACCEL_BACKEND_GET_CLASS(ab);

    if (bc->close_session) {
        return bc->close_session(ab, session_id, queue_index, errp);
    }

    return -1;
}

static int cryptodev_backend_sym_operation(
                 CryptoDevBackend *backend,
                 CryptoDevBackendSymOpInfo *op_info,
                 uint32_t queue_index, Error **errp)
{
    CryptoDevBackendClass *bc =
                      CRYPTODEV_BACKEND_GET_CLASS(backend);

    if (bc->do_sym_op) {
        return bc->do_sym_op(backend, op_info, queue_index, errp);
    }

    return -VIRTIO_CRYPTO_ERR;
}

int cryptodev_backend_crypto_operation(
                 CryptoDevBackend *backend,
                 void *opaque,
                 uint32_t queue_index, Error **errp)
{
    VirtIOCryptoReq *req = opaque;

    if (req->flags == CRYPTODEV_BACKEND_ALG_SYM) {
        CryptoDevBackendSymOpInfo *op_info;
        op_info = req->u.sym_op_info;

        return cryptodev_backend_sym_operation(backend,
                         op_info, queue_index, errp);
    } else {
        error_setg(errp, "Unsupported cryptodev alg type: %" PRIu32 "",
                   req->flags);
       return -VIRTIO_CRYPTO_NOTSUPP;
    }

    return -VIRTIO_CRYPTO_ERR;
}

static void
accel_backend_get_queues(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    AccelBackend *ab = ACCEL_BACKEND(obj);
    uint32_t value = ab->conf.peers.queues;

    visit_type_uint32(v, name, &value, errp);
}

static void
accel_backend_set_queues(Object *obj, Visitor *v, const char *name,
                             void *opaque, Error **errp)
{
    AccelBackend *ab = ACCEL_BACKEND(obj);
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
accel_backend_complete(UserCreatable *uc, Error **errp)
{
    AccelDevBackend *ab = ACCEL_BACKEND(uc);
    AccelBackendClass *abc = ACCEL_BACKEND_GET_CLASS(uc);
    Error *local_err = NULL;

    if (abc->init) {
        abc->init(ab, &local_err);
        if (local_err)
    		error_propagate(errp, local_err);
    }

    return;
}

void accel_backend_set_used(AccelBackend *ab, bool used)
{
    ab->is_used = used;
}

bool accel_backend_is_used(AccelBackend *ab)
{
    return ab->is_used;
}

void accel_backend_set_ready(AccelBackend *ab, bool ready)
{
    ab->ready = ready;
}

bool accel_backend_is_ready(AccelBackend *ab)
{
    return ab->ready;
}

static bool
accel_backend_can_be_deleted(UserCreatable *uc, Error **errp)
{
    return !accel_backend_is_used(ACCEL_BACKEND(uc));
}

static void accel_backend_instance_init(Object *obj)
{
    object_property_add(obj, "queues", "int",
                          accel_backend_get_queues,
                          accel_backend_set_queues,
                          NULL, NULL, NULL);
    /* Initialize devices' queues property to 1 */
    object_property_set_int(obj, 1, "queues", NULL);
}

static void accel_backend_finalize(Object *obj)
{
    AccelBackend *ab = CRYPTODEV_BACKEND(obj);

    accel_backend_cleanup(ab, NULL);
}

static void
accel_backend_class_init(ObjectClass *oc, void *data)
{
    UserCreatableClass *ucc = USER_CREATABLE_CLASS(oc);

    ucc->complete = accel_backend_complete;
    ucc->can_be_deleted = accel_backend_can_be_deleted;

    QTAILQ_INIT(&accel_clients);
}

static const TypeInfo accel_backend_info = {
    .name = TYPE_ACCEL_BACKEND,
    .parent = TYPE_OBJECT,
    .instance_size = sizeof(AccelBackend),
    .instance_init = accel_backend_instance_init,
    .instance_finalize = accel_backend_finalize,
    .class_size = sizeof(AccelBackendClass),
    .class_init = accel_backend_class_init,
    .interfaces = (InterfaceInfo[]) {
        { TYPE_USER_CREATABLE },
        { }
    }
};

static void
accel_backend_register_types(void)
{
    type_register_static(&accel_backend_info);
}

type_init(accel_backend_register_types);
