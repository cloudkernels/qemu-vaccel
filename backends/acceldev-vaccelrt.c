#include "qemu/osdep.h"
#include "sysemu/acceldev.h"
#include "hw/boards.h"
#include "qapi/error.h"
#include "standard-headers/linux/virtio_accel.h"
#include <vaccel.h>


/**
 * @TYPE_ACCELDEV_BACKEND_VACCELRT:
 */
#define TYPE_ACCELDEV_BACKEND_VACCELRT "acceldev-backend-vaccelrt"

#define ACCELDEV_BACKEND_VACCELRT(obj) \
    OBJECT_CHECK(AccelDevBackendVaccelRT, \
                 (obj), TYPE_ACCELDEV_BACKEND_VACCELRT)

typedef struct AccelDevBackendVaccelRT
                         AccelDevBackendVaccelRT;

typedef struct AccelDevBackendVaccelRTSession {
    void *opaque;
    unsigned int type;
    QTAILQ_ENTRY(AccelDevBackendVaccelRTSession) next;
} AccelDevBackendVaccelRTSession;

/* Max number of symmetric sessions */
#define MAX_NUM_SESSIONS 1024

struct AccelDevBackendVaccelRT {
    AccelDevBackend parent_obj;

    AccelDevBackendVaccelRTSession *sessions[MAX_NUM_SESSIONS];
};

static void acceldev_vaccelrt_init(
             AccelDevBackend *ab, Error **errp)
{
    /* Only support one queue */
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    if (queues != 1) {
        error_setg(errp,
                  "Only support one queue in acceldev-vaccelrt backend");
        return;
    }

    c = acceldev_backend_new_client(
              "acceldev-vaccelrt", NULL);
    c->info_str = g_strdup_printf("acceldev-vaccelrt0");
    c->queue_index = 0;
    ab->conf.peers.ccs[0] = c;

    // TODO
    //ab->conf.services = 1u << VIRTIO_ACCEL_SERVICE_VACCELRT;
    //
    ab->conf.max_size = LONG_MAX - sizeof(AccelDevBackendOpInfo);

    acceldev_backend_set_ready(ab, true);
}

static int
acceldev_vaccelrt_get_unused_session_index(
                 AccelDevBackendVaccelRT *vaccelrt)
{
    for (int i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (vaccelrt->sessions[i] == NULL) {
            return i;
        }
    }

    return -1;
}

static int64_t acceldev_vaccelrt_create_session(
           AccelDevBackend *ab,
           AccelDevBackendSessionInfo *info,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt =
                      ACCELDEV_BACKEND_VACCELRT(ab);
    struct vaccel_session *sess_data = NULL;
    int index;
    //unsigned int sess_type;
    AccelDevBackendVaccelRTSession *sess;

    index = acceldev_vaccelrt_get_unused_session_index(vaccelrt);
    if (index < 0) {
        error_setg(errp, "Total number of sessions created exceeds %u",
                  MAX_NUM_SESSIONS);
        return -VIRTIO_ACCEL_ERR;
    }

    sess_data = g_new0(struct vaccel_session, 1);
    sess_data->session_id = index;

    sess = g_new0(AccelDevBackendVaccelRTSession, 1);
    sess->opaque = sess_data;
    //sess->type = sess_type;

    vaccelrt->sessions[index] = sess;

    return index;
}

static int acceldev_vaccelrt_destroy_session(
           AccelDevBackend *ab,
           uint32_t sess_id,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt =
                      ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;

    if (sess_id >= MAX_NUM_SESSIONS ||
              vaccelrt->sessions[sess_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }
    sess = vaccelrt->sessions[sess_id];

    vaccel_sess_free((struct vaccel_session *)sess->opaque);
    
    g_free(sess->opaque);
    g_free(sess);
    vaccelrt->sessions[sess_id] = NULL;

    return VIRTIO_ACCEL_OK;
}

static int _acceldev_vaccelrt_operation(struct vaccel_session *sess,
                AccelDevBackendOpInfo *info)
{
    AccelDevBackendArg *in_args = info->op.in;
    AccelDevBackendArg *out_args = info->op.out;
    struct vaccel_arg *req_inargs = NULL, *req_outargs = NULL;
    int ret;

    if (info->op.out_nr > 0) {
        req_outargs = g_new0(struct vaccel_arg, info->op.out_nr);
        for (int i = 0; i < info->op.out_nr; i++) {
            req_outargs[i].buf = out_args[i].buf;
            req_outargs[i].size = out_args[i].len;
        }
    }

    if (info->op.in_nr > 0) {
        req_inargs = g_new0(struct vaccel_arg, info->op.in_nr);
        for (int i = 0; i < info->op.in_nr; i++) {
            req_inargs[i].buf = in_args[i].buf;
            req_inargs[i].size = in_args[i].len;
        }
    }

    ret = vaccel_genop(sess, req_outargs, info->op.out_nr,
                       req_inargs, info->op.in_nr);

    if (ret != VACCEL_OK)
        ret = -VIRTIO_ACCEL_ERR;
    else
        ret = VIRTIO_ACCEL_OK;

    if (req_outargs)
        g_free(req_outargs);
    if (req_inargs)
        g_free(req_inargs);

    return ret;
}

static int acceldev_vaccelrt_operation(
                 AccelDevBackend *ab,
                 AccelDevBackendOpInfo *info,
                 uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt =
                      ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    if (info->sess_id >= MAX_NUM_SESSIONS ||
              vaccelrt->sessions[info->sess_id] == NULL) {
        error_setg(errp, "Cannot find a valid session id: %" PRIu32 "",
                   info->sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (info->op.out_nr < 1) {
        error_setg(errp, "VaccelRT op requires at least 1 out argument (got %u)",
                info->op.out_nr);
        return -VIRTIO_ACCEL_ERR;
    }
    sess = vaccelrt->sessions[info->sess_id];

    ret = _acceldev_vaccelrt_operation(sess->opaque, info);

    if (ret != VACCEL_OK)
        return -VIRTIO_ACCEL_ERR;

    return VIRTIO_ACCEL_OK;
}

static void acceldev_vaccelrt_cleanup(
             AccelDevBackend *ab,
             Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt =
                      ACCELDEV_BACKEND_VACCELRT(ab);
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    for (int i = 0; i < MAX_NUM_SESSIONS; i++) {
        if (vaccelrt->sessions[i] != NULL) {
            acceldev_vaccelrt_destroy_session(
                    ab, i, 0, errp);
        }
    }

    for (int i = 0; i < queues; i++) {
        c = ab->conf.peers.ccs[i];
        if (c) {
            acceldev_backend_free_client(c);
            ab->conf.peers.ccs[i] = NULL;
        }
    }

    acceldev_backend_set_ready(ab, false);
}

static void
acceldev_vaccelrt_class_init(ObjectClass *oc, void *data)
{
    AccelDevBackendClass *abc = ACCELDEV_BACKEND_CLASS(oc);

    abc->init = acceldev_vaccelrt_init;
    abc->cleanup = acceldev_vaccelrt_cleanup;
    abc->create_session = acceldev_vaccelrt_create_session;
    abc->destroy_session = acceldev_vaccelrt_destroy_session;
    abc->do_op = acceldev_vaccelrt_operation;
}

static const TypeInfo acceldev_vaccelrt_info = {
    .name = TYPE_ACCELDEV_BACKEND_VACCELRT,
    .parent = TYPE_ACCELDEV_BACKEND,
    .class_init = acceldev_vaccelrt_class_init,
    .instance_size = sizeof(AccelDevBackendVaccelRT),
};

static void
acceldev_vaccelrt_register_types(void)
{
    type_register_static(&acceldev_vaccelrt_info);
}

type_init(acceldev_vaccelrt_register_types);
