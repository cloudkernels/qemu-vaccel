#include "qemu/osdep.h"
#include "sysemu/acceldev.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "standard-headers/linux/virtio_accel.h"
#include <vaccel_runtime.h>


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
    unsigned int type;
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
    int ret, i, index = -VIRTIO_ACCEL_ERR;
	unsigned int sess_type;
	struct vaccelrt_arg *req_inargs, *req_outargs;
    AccelDevBackendGenericSession *sess;

    index = acceldev_generic_get_unused_session_index(generic);
    if (index < 0) {
        error_setg(errp, "Total number of sessions created exceeds %u",
                  MAX_NUM_SESSIONS);
        return -VIRTIO_ACCEL_ERR;
    }

    if (info->u.gen.out_nr < 1) {
		error_setg(errp, "Generic op requires at least 1 out argument (got %u)",
				info->u.gen.out_nr);
		return -VIRTIO_ACCEL_ERR;
	}

    sess_data = g_new0(struct vaccelrt_session, 1);
	req_outargs = NULL;
	if (info->u.gen.out_nr > 0) {
		req_outargs = g_new0(struct vaccelrt_arg, info->u.gen.out_nr);
		for (i = 0; i < info->u.gen.out_nr; i++) {
			req_outargs[i].buf = info->u.gen.out[i].buf;
			req_outargs[i].len = info->u.gen.out[i].len;
		}
	}
	req_inargs = NULL;
	if (info->u.gen.in_nr > 0) {
		req_inargs = g_new0(struct vaccelrt_arg, info->u.gen.in_nr);
		for (i = 0; i < info->u.gen.in_nr; i++) {
			req_inargs[i].buf = info->u.gen.in[i].buf;
			req_inargs[i].len = info->u.gen.in[i].len;
		}
	}

	ret = vaccelrt_sess_init(sess_data, req_outargs, req_inargs,
			info->u.gen.out_nr, info->u.gen.in_nr, &sess_type);
    if (ret != VACCELRT_OK) {
		g_free(sess_data);
        ret = -VIRTIO_ACCEL_ERR;
		goto free;
    }

	sess = g_new0(AccelDevBackendGenericSession, 1);
    sess->opaque = sess_data;
	sess->type = sess_type;

    generic->sessions[index] = sess;

    ret = index;

free:
	if (req_outargs)
		g_free(req_outargs);
	if (req_inargs)
		g_free(req_inargs);

	return ret;
}

static int acceldev_generic_destroy_session(
           AccelDevBackend *ab,
           uint32_t sess_id,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendGeneric *generic =
                      ACCELDEV_BACKEND_GENERIC(ab);
	AccelDevBackendGenericSession *sess;

    if (sess_id >= MAX_NUM_SESSIONS ||
              generic->sessions[sess_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }
	sess = generic->sessions[sess_id];

 	vaccelrt_sess_free((struct vaccelrt_session *)sess->opaque);
	
	g_free(sess->opaque);
	g_free(sess);
    generic->sessions[sess_id] = NULL;

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
	struct vaccelrt_arg *req_inargs, *req_outargs;
    int ret, i;

    if (info->session_id >= MAX_NUM_SESSIONS ||
              generic->sessions[info->session_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   info->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (info->u.gen.out_nr < 1) {
		error_setg(errp, "Generic op requires at least 1 out argument (got %u)",
				info->u.gen.out_nr);
		return -VIRTIO_ACCEL_ERR;
	}
    sess = generic->sessions[info->session_id];

	req_outargs = NULL;
	if (info->u.gen.out_nr > 0) {
		req_outargs = g_new0(struct vaccelrt_arg, info->u.gen.out_nr);
		for (i = 0; i < info->u.gen.out_nr; i++) {
			req_outargs[i].buf = info->u.gen.out[i].buf;
			req_outargs[i].len = info->u.gen.out[i].len;
		}
	}
	req_inargs = NULL;
	if (info->u.gen.in_nr > 0) {
		req_inargs = g_new0(struct vaccelrt_arg, info->u.gen.in_nr);
		for (i = 0; i < info->u.gen.in_nr; i++) {
			req_inargs[i].buf = info->u.gen.in[i].buf;
			req_inargs[i].len = info->u.gen.in[i].len;
		}
	}

	ret = vaccelrt_do_op((struct vaccelrt_session *)sess->opaque,
			req_outargs, req_inargs, info->u.gen.out_nr, info->u.gen.in_nr);
    if (ret != VACCELRT_OK) {
        ret = -VIRTIO_ACCEL_ERR;
		goto free;
    }

	ret = VIRTIO_ACCEL_OK;

free:
	if (req_outargs)
		g_free(req_outargs);
	if (req_inargs)
		g_free(req_inargs);

	return ret;
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
