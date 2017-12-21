#include "qemu/osdep.h"
#include "sysemu/acceldev.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "standard-headers/linux/virtio_accel.h"


/**
 * @TYPE_ACCELDEV_BACKEND_GENERIC:
 */
#define TYPE_ACCELDEV_BACKEND_GENERIC "acceldev-backend-generic"

#define ACCELDEV_BACKEND_GENERIC(obj) \
    OBJECT_CHECK(AccelDevBackendGeneric, \
                 (obj), TYPE_ACCELDEV_BACKEND_GENERIC)

typedef struct AccelDevBackendGeneric
                         AccelDevBackendGeneric;

typedef struct AccelDevBackendGenericSession {
    void *opaque;
    uint8_t type; /* cipher? hash? aead? */
    QTAILQ_ENTRY(AccelDevBackendGenericSession) next;
} AccelDevBackendGenericSession;

/* Max number of symmetric sessions */
#define MAX_NUM_SESSIONS 256

struct AccelDevBackendGeneric {
    AccelDevBackend parent_obj;

    AccelDevBackendGenericSession *sessions[MAX_NUM_SESSIONS];
};

static void acceldev_generic_init(
             AccelDevBackend *ab, Error **errp)
{
    /* Only support one queue */
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    if (queues != 1) {
        error_setg(errp,
                  "Only support one queue in acceldev-generic backend");
        return;
    }

    c = acceldev_backend_new_client(
              "acceldev-generic", NULL);
    c->info_str = g_strdup_printf("acceldev-generic0");
    c->queue_index = 0;
    ab->conf.peers.ccs[0] = c;
	
	// TODO
    //ab->conf.services = 1u << VIRTIO_ACCEL_SERVICE_GENERIC;
	//
    ab->conf.max_size = LONG_MAX - sizeof(AccelDevBackendOpInfo);

    acceldev_backend_set_ready(ab, true);
}

static int
acceldev_generic_get_unused_session_index(
                 AccelDevBackendGeneric *generic)
{
    size_t i;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (generic->sessions[i] == NULL) {
            return i;
        }
    }

    return -1;
}

static int64_t acceldev_generic_create_session(
           AccelDevBackend *ab,
           AccelDevBackendSessionInfo *info,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendGeneric *generic =
                      ACCELDEV_BACKEND_GENERIC(ab);
	void *sess_data = NULL;
    int ret, index = -VIRTIO_ACCEL_ERR;
    AccelDevBackendGenericSession *sess;

    index = acceldev_generic_get_unused_session_index(generic);
    if (index < 0) {
        error_setg(errp, "Total number of sessions created exceeds %u",
                  MAX_NUM_SESSIONS);
        return -VIRTIO_ACCEL_ERR;
    }

	/* TODO:
    sess_data = exec_call_blabla
    if (!sess_data) {
        return -VIRTIO_ACCEL_ERR;
    }
	*/
	fprintf(stderr, "Dummy Generic Session Created!\n");

    sess = g_new0(AccelDevBackendGenericSession, 1);
    sess->opaque = sess_data;

    generic->sessions[index] = sess;

    return index;
}

static int acceldev_generic_destroy_session(
           AccelDevBackend *ab,
           uint32_t sess_id,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendGeneric *generic =
                      ACCELDEV_BACKEND_GENERIC(ab);

    if (sess_id >= MAX_NUM_SESSIONS ||
              generic->sessions[sess_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    /* TODO:
	free_session(generic->sessions[sess_id]->opaque);
    */
	g_free(generic->sessions[sess_id]);
    generic->sessions[sess_id] = NULL;

	fprintf(stderr, "Dummy Generic Session Destroyed!\n");

    return VIRTIO_ACCEL_OK;
}

static int acceldev_generic_operation(
                 AccelDevBackend *ab,
                 AccelDevBackendOpInfo *info,
                 uint32_t queue_index, Error **errp)
{
    AccelDevBackendGeneric *generic =
                      ACCELDEV_BACKEND_GENERIC(ab);
    AccelDevBackendGenericSession *sess;
    int ret;

    if (info->session_id >= MAX_NUM_SESSIONS ||
              generic->sessions[info->session_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   info->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    sess = generic->sessions[info->session_id];

	/* TODO:
    ret = exec_call_blabla
    if (ret < 0) {
        return -VIRTIO_ACCEL_ERR;
    }
	*/
	fprintf(stderr, "Dummy Generic Operation Done!\n");

	return VIRTIO_ACCEL_OK;
}

static void acceldev_generic_cleanup(
             AccelDevBackend *ab,
             Error **errp)
{
    AccelDevBackendGeneric *generic =
                      ACCELDEV_BACKEND_GENERIC(ab);
    size_t i;
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    for (i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (generic->sessions[i] != NULL) {
            acceldev_generic_destroy_session(
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
acceldev_generic_class_init(ObjectClass *oc, void *data)
{
    AccelDevBackendClass *abc = ACCELDEV_BACKEND_CLASS(oc);

    abc->init = acceldev_generic_init;
    abc->cleanup = acceldev_generic_cleanup;
    abc->create_session = acceldev_generic_create_session;
    abc->destroy_session = acceldev_generic_destroy_session;
    abc->do_op = acceldev_generic_operation;
}

static const TypeInfo acceldev_generic_info = {
    .name = TYPE_ACCELDEV_BACKEND_GENERIC,
    .parent = TYPE_ACCELDEV_BACKEND,
    .class_init = acceldev_generic_class_init,
    .instance_size = sizeof(AccelDevBackendGeneric),
};

static void
acceldev_generic_register_types(void)
{
    type_register_static(&acceldev_generic_info);
}

type_init(acceldev_generic_register_types);
