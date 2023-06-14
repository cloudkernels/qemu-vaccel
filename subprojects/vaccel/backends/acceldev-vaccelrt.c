#include "qemu/osdep.h"
#include "../include/sysemu/acceldev.h"
#include "qapi/error.h"
#include "../include/standard-headers/linux/virtio_accel.h"
#include "../include/standard-headers/linux/accel.h"
#include "qom/object.h"
#include <vaccel.h>


/**
 * @TYPE_ACCELDEV_BACKEND_VACCELRT:
 */
#define TYPE_ACCELDEV_BACKEND_VACCELRT "acceldev-backend-vaccelrt"

OBJECT_DECLARE_SIMPLE_TYPE(AccelDevBackendVaccelRT, ACCELDEV_BACKEND_VACCELRT)

typedef struct AccelDevBackendVaccelRTTimer {
    struct vaccel_prof_region vaccel_tmr;
    const char *name;
    QTAILQ_ENTRY(AccelDevBackendVaccelRTTimer) next;
} AccelDevBackendVaccelRTTimer;

typedef struct AccelDevBackendVaccelRTSession {
    void *opaque;
    uint32_t id;
    QTAILQ_HEAD(, AccelDevBackendVaccelRTTimer) timers;
    uint32_t nr_timers;
    QTAILQ_ENTRY(AccelDevBackendVaccelRTSession) next;
} AccelDevBackendVaccelRTSession;

/* Max number of sessions */
#define MAX_NUM_SESSIONS 1024

struct AccelDevBackendVaccelRT {
    AccelDevBackend parent_obj;
    QTAILQ_HEAD(, AccelDevBackendVaccelRTSession) sessions;
};

static AccelDevBackendVaccelRTTimer *timer_get(
                AccelDevBackendVaccelRTSession *sess,
                const char *name)
{
    if (!vaccel_prof_enabled())
        return NULL;

    AccelDevBackendVaccelRTTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp) {
        if (strcmp(timer->name, name) == 0) {
            return timer;
        }
    }
    return NULL;
}

static void timers_del(AccelDevBackendVaccelRTSession *sess)
{
    if (!vaccel_prof_enabled())
        return;

    AccelDevBackendVaccelRTTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp) {
        QTAILQ_REMOVE(&sess->timers, timer, next);
        vaccel_prof_region_destroy(&timer->vaccel_tmr);
        g_free(timer);
    }
}

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

    c = acceldev_backend_new_client("acceldev-vaccelrt", NULL);
    c->info_str = g_strdup_printf("acceldev-vaccelrt0");
    c->queue_index = 0;
    ab->conf.peers.ccs[0] = c;

    // TODO
    //ab->conf.services = 1u << VIRTIO_ACCEL_SERVICE_VACCELRT;
    //
    ab->conf.max_size = LONG_MAX - sizeof(AccelDevBackendOpInfo);

    acceldev_backend_set_ready(ab, true);

    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    QTAILQ_INIT(&vaccelrt->sessions);
}

static AccelDevBackendVaccelRTSession *session_get(
                 AccelDevBackendVaccelRT *vaccelrt,
                 uint32_t session_id)
{
    AccelDevBackendVaccelRTSession *sess, *tmp;
    QTAILQ_FOREACH_SAFE(sess, &vaccelrt->sessions, next, tmp) {
        if (sess->id == session_id) {
            return sess;
        }
    }
    return NULL;
}

static AccelDevBackendVaccelRTSession *session_create_and_add(
                AccelDevBackendVaccelRT *vaccelrt,
                void *sess_data,
                uint32_t sess_id)
{
    AccelDevBackendVaccelRTSession *sess =
        g_new0(AccelDevBackendVaccelRTSession, 1);
    sess->opaque = sess_data;
    sess->id = sess_id;
    QTAILQ_INIT(&sess->timers);
    sess->nr_timers = 0;
    QTAILQ_INSERT_TAIL(&vaccelrt->sessions, sess, next);

    return sess;
}

static void session_del(
                AccelDevBackendVaccelRT *vaccelrt,
                AccelDevBackendVaccelRTSession *sess)
{
    QTAILQ_REMOVE(&vaccelrt->sessions, sess, next);
    g_free(sess->opaque);
    g_free(sess);
}

static int64_t acceldev_vaccelrt_create_session(
           AccelDevBackend *ab,
           AccelDevBackendSessionInfo *info,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    struct vaccel_session *sess_data = NULL;
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess_data = g_new0(struct vaccel_session, 1);

    ret = vaccel_sess_init(sess_data, 0);
    if (ret != VACCEL_OK)
        return -VIRTIO_ACCEL_ERR;

    sess = session_create_and_add(vaccelrt, (void *)sess_data,
                                  sess_data->session_id);

    return sess->id;
}

static int acceldev_vaccelrt_destroy_session(
           AccelDevBackend *ab,
           uint32_t sess_id,
           uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccelrt, sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRIu32 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    ret = vaccel_sess_free((struct vaccel_session *)sess->opaque);
    if (ret != VACCEL_OK)
        return -VIRTIO_ACCEL_ERR;

    timers_del(sess);
    session_del(vaccelrt, sess);

    return VIRTIO_ACCEL_OK;
}

static int do_operation(
                struct vaccel_session *sess,
                AccelDevBackendOpInfo *info,
                AccelDevBackend *ab,
                uint32_t queue_index, Error **errp)
{
    AccelDevBackendArg *in_args = info->op.in;
    AccelDevBackendArg *out_args = info->op.out;
    struct vaccel_arg *req_inargs = NULL, *req_outargs = NULL;
    int ret;

    acceldev_backend_timer_start(ab, sess->session_id, "do op > prepare",
                                 queue_index, errp);

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

    acceldev_backend_timer_stop(ab, sess->session_id, "do op > prepare",
                                queue_index, errp);

    acceldev_backend_timer_start(ab, sess->session_id, "do op > genop",
                                 queue_index, errp);

    ret = vaccel_genop(sess, req_outargs, info->op.out_nr,
                       req_inargs, info->op.in_nr);

    if (ret != VACCEL_OK)
        ret = -VIRTIO_ACCEL_ERR;
    else
        ret = VIRTIO_ACCEL_OK;

    acceldev_backend_timer_stop(ab, sess->session_id, "do op > genop",
                                queue_index, errp);

    acceldev_backend_timer_start(ab, sess->session_id, "do op > free prep",
                                 queue_index, errp);

    if (req_outargs)
        g_free(req_outargs);
    if (req_inargs)
        g_free(req_inargs);

    acceldev_backend_timer_stop(ab, sess->session_id, "do op > free prep",
                                queue_index, errp);

    return ret;
}

static int acceldev_vaccelrt_operation(
                 AccelDevBackend *ab,
                 AccelDevBackendOpInfo *info,
                 uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccelrt, info->sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRIu32 "",
                   info->sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (info->op.out_nr < 1) {
        error_setg(errp, "VaccelRT op requires at least 1 out argument (got %u)",
                info->op.out_nr);
        return -VIRTIO_ACCEL_ERR;
    }

    ret = do_operation(sess->opaque, info, ab, queue_index, errp);

    if (ret != VACCEL_OK)
        return -VIRTIO_ACCEL_ERR;

    return VIRTIO_ACCEL_OK;
}

static int acceldev_vaccelrt_timer_start(
           AccelDevBackend *ab,
           uint32_t sess_id,
           const char *name,
           uint32_t queue_index, Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccelrt, sess_id);
    if (!sess) {
        return -VIRTIO_ACCEL_INVSESS;
    }

    AccelDevBackendVaccelRTTimer *timer = timer_get(sess, name);
    if (!timer) {
        timer = g_new0(AccelDevBackendVaccelRTTimer, 1);
        ret = vaccel_prof_region_init(&timer->vaccel_tmr, name);
        if (ret != VACCEL_OK) {
            g_free(timer);
            return -VIRTIO_ACCEL_ERR;
        }
        timer->name = timer->vaccel_tmr.name;

        QTAILQ_INSERT_TAIL(&sess->timers, timer, next);
        sess->nr_timers++;
    }
    vaccel_prof_region_start(&timer->vaccel_tmr);

    return VIRTIO_ACCEL_OK;
}

static int acceldev_vaccelrt_timer_stop(
           AccelDevBackend *ab,
           uint32_t sess_id,
           const char *name,
           uint32_t queue_index, Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;

    sess = session_get(vaccelrt, sess_id);
    if (!sess) {
        return -VIRTIO_ACCEL_INVSESS;
    }

    AccelDevBackendVaccelRTTimer *timer = timer_get(sess, name);
    if (!timer) {
        return VIRTIO_ACCEL_OK;
    }

    vaccel_prof_region_stop(&timer->vaccel_tmr);

    return VIRTIO_ACCEL_OK;
}

static int timer_sample_acceldev_to_accel(
                struct accel_prof_sample *accel_samples,
                uint32_t nr_accel_samples,
                AccelDevBackendVaccelRTTimer *timer)
{
    int i = 0;

    for (i = 0; i < timer->vaccel_tmr.nr_entries; i++) {
        if (i == nr_accel_samples) {
            fprintf(stderr,
                    "not all acceldev samples for %s can be returned (allocated: %d vs total: %ld)",
                    timer->name, nr_accel_samples,
                    timer->vaccel_tmr.nr_entries);
            break;
        }
        accel_samples[i].start = timer->vaccel_tmr.samples[i].start;
        accel_samples[i].time = timer->vaccel_tmr.samples[i].time;
    }

    return i;
}

#define TIMERS_NAME_PREFIX "[qemu-vaccel]"
static int timers_acceldev_to_accel(
                struct accel_prof_region *accel_timers,
                uint32_t nr_accel_timers,
                AccelDevBackendVaccelRTSession *sess)
{
    if (nr_accel_timers < 1)
        return -VIRTIO_ACCEL_ERR;

    int i = 0;
    AccelDevBackendVaccelRTTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp) {
        if (i == nr_accel_timers) {
            fprintf(stderr,
                    "not all acceldev timers can be returned (allocated: %d vs total: %d)",
                    nr_accel_timers, sess->nr_timers);
            break;
        }
        g_snprintf(accel_timers[i].name, TIMERS_NAME_MAX, "%s %s",
                TIMERS_NAME_PREFIX, timer->name);
        accel_timers[i].nr_entries =
            timer_sample_acceldev_to_accel(accel_timers[i].samples,
                accel_timers[i].size, timer);
        i++;
    }

    return i;
}

static int acceldev_vaccelrt_get_timers(
                 AccelDevBackend *ab,
                 AccelDevBackendOpInfo *info,
                 uint32_t queue_index, Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccelrt, info->sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRIu32 "",
                   info->sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (info->op.in_nr < 1) {
        error_setg(errp,
                "vaccelrt get_timers requires at least 1 in argument (got %u)",
                info->op.out_nr);
        return -VIRTIO_ACCEL_ERR;
    }

    uint32_t *nt = (uint32_t *)info->op.in[0].buf;
    uint32_t *qnt = (uint32_t *)info->op.in[1].buf;
    if (*qnt == 0) {
        *qnt = sess->nr_timers;
        ret = VIRTIO_ACCEL_OK;
    } else {
        uint64_t nr_timers = *nt + *qnt;

        if (info->op.in_nr < 3 + nr_timers) {
            error_setg(errp,
                    "vaccelrt get_timers: not enough in arguments (got %u)",
                    info->op.in_nr);
            return -VIRTIO_ACCEL_ERR;
        }

        struct accel_prof_region *accel_timers =
            (struct accel_prof_region *)info->op.in[2].buf;
        if (info->op.in[2].len < nr_timers * sizeof(*accel_timers)) {
            error_setg(errp,
                    "vaccelrt get_timers: wrong preallocated size (got %d)",
                    info->op.in[2].len);
            return -VIRTIO_ACCEL_ERR;
        }

        struct accel_prof_sample **tmp_samples =
            g_new0(struct accel_prof_sample *, *qnt);
        if (!tmp_samples) {
            return -VIRTIO_ACCEL_ERR;
        }

        for (int i = *nt; i < nr_timers; i++) {
            tmp_samples[i - *nt] = accel_timers[i].samples;
            accel_timers[i].samples =
                (struct accel_prof_sample *)info->op.in[3 + i].buf;
        }

        ret = timers_acceldev_to_accel(&accel_timers[*nt], *qnt, sess);
        if (ret < 0) {
            ret = -VIRTIO_ACCEL_ERR;
            goto free;
        } else {
            ret = VIRTIO_ACCEL_OK;
        }

        for (int i = *nt; i < nr_timers; i++) {
            accel_timers[i].samples = tmp_samples[i - *nt];
        }

free:
        g_free(tmp_samples);
    }

    return ret;
}

static void sessions_del(
                AccelDevBackendVaccelRT *vaccelrt,
                AccelDevBackend *ab,
                Error **errp)
{
    AccelDevBackendVaccelRTSession *sess, *tmp;
    QTAILQ_FOREACH_SAFE(sess, &vaccelrt->sessions, next, tmp) {
        acceldev_vaccelrt_destroy_session(ab, sess->id, 0, errp);
    }
}

static void acceldev_vaccelrt_cleanup(
             AccelDevBackend *ab,
             Error **errp)
{
    AccelDevBackendVaccelRT *vaccelrt = ACCELDEV_BACKEND_VACCELRT(ab);
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    sessions_del(vaccelrt, ab, errp);

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
    abc->timer_start = acceldev_vaccelrt_timer_start;
    abc->timer_stop = acceldev_vaccelrt_timer_stop;
    abc->timers_get = acceldev_vaccelrt_get_timers;
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
