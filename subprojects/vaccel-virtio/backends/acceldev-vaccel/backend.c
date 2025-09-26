// SPDX-License-Identifier: Apache-2.0

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qom/object.h"

#include "standard-headers/linux/accel.h"
#include "standard-headers/linux/virtio_accel.h"
#include "system/acceldev.h"
#include "ops.h"

/* Work around a -Wstrict-prototypes warning in slog headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <vaccel.h>
#pragma GCC diagnostic pop

/**
 * @TYPE_ACCELDEV_BACKEND_VACCELRT:
 */
#define TYPE_ACCELDEV_BACKEND_VACCELRT "acceldev-backend-vaccel"

OBJECT_DECLARE_SIMPLE_TYPE(AccelDevBackendVaccelRT, ACCELDEV_BACKEND_VACCELRT)

typedef struct AccelDevBackendVaccelRTTimer {
    struct vaccel_prof_region vaccel_tmr;
    const char *name;
    QTAILQ_ENTRY(AccelDevBackendVaccelRTTimer) next;
} AccelDevBackendVaccelRTTimer;

typedef struct AccelDevBackendVaccelRTSession {
    void *opaque;
    int64_t id;
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

static AccelDevBackendVaccelRTTimer *
timer_get(AccelDevBackendVaccelRTSession *sess, const char *name)
{
    if (!vaccel_prof_enabled())
        return NULL;

    AccelDevBackendVaccelRTTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
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
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        QTAILQ_REMOVE(&sess->timers, timer, next);
        vaccel_prof_region_release(&timer->vaccel_tmr);
        g_free(timer);
    }
}

static int parse_vaccel_args(AccelDevBackendArg *out_args,
                             AccelDevBackendArg *in_args, size_t nr_out_args,
                             size_t nr_in_args,
                             struct vaccel_arg_array *read_args,
                             struct vaccel_arg_array *write_args)
{
    struct vaccel_arg *read = NULL;
    struct vaccel_arg *write = NULL;
    int ret;

    if (nr_out_args > 0) {
        read = g_new0(struct vaccel_arg, nr_out_args);
        for (size_t i = 0; i < nr_out_args; i++) {
            ret = vaccel_arg_init_from_buf(&read[i], out_args[i].buf,
                                           out_args[i].len,
                                           (vaccel_arg_type_t)out_args[i].type,
                                           out_args[i].custom_type_id);
            if (ret)
                goto free;
        }

        ret = vaccel_arg_array_wrap(read_args, read, nr_out_args);
        if (ret)
            goto free;
    } else {
        read_args->args = NULL;
        read_args->count = 0;
    }

    if (nr_in_args > 0) {
        write = g_new0(struct vaccel_arg, nr_in_args);
        for (size_t i = 0; i < nr_in_args; i++) {
            ret = vaccel_arg_init_from_buf(&write[i], in_args[i].buf,
                                           in_args[i].len,
                                           (vaccel_arg_type_t)in_args[i].type,
                                           in_args[i].custom_type_id);
            if (ret)
                goto free;
        }

        ret = vaccel_arg_array_wrap(write_args, write, nr_in_args);
        if (ret)
            goto free;
    } else {
        write_args->args = NULL;
        write_args->count = 0;
    }

    return VIRTIO_ACCEL_OK;

free:
    g_free(read);
    g_free(write);

    return VIRTIO_ACCEL_ERR;
}

static void cleanup_vaccel_args(struct vaccel_arg_array *read_args,
                                struct vaccel_arg_array *write_args)
{
    if (!read_args || !write_args)
        return;

    g_free(read_args->args);
    g_free(write_args->args);
}

static void acceldev_vaccel_init(AccelDevBackend *ab, Error **errp)
{
    /* Only support one queue */
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    if (queues != 1) {
        error_setg(errp, "Only support one queue in acceldev-vaccel backend");
        return;
    }

    c = acceldev_backend_new_client("acceldev-vaccel", NULL);
    c->info_str = g_strdup_printf("acceldev-vaccel0");
    c->queue_index = 0;
    ab->conf.peers.ccs[0] = c;

    // TODO
    //ab->conf.services = 1u << VIRTIO_ACCEL_SERVICE_VACCELRT;
    //
    ab->conf.max_size = LONG_MAX - sizeof(AccelDevBackendOpInfo);

    acceldev_backend_set_ready(ab, true);

    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    QTAILQ_INIT(&vaccel->sessions);
}

static AccelDevBackendVaccelRTSession *
session_get(AccelDevBackendVaccelRT *vaccel, int64_t sess_id)
{
    AccelDevBackendVaccelRTSession *sess, *tmp;
    QTAILQ_FOREACH_SAFE(sess, &vaccel->sessions, next, tmp)
    {
        if (sess->id == sess_id) {
            return sess;
        }
    }
    return NULL;
}

static AccelDevBackendVaccelRTSession *
session_create_and_add(AccelDevBackendVaccelRT *vaccel, void *sess_data,
                       int64_t sess_id)
{
    AccelDevBackendVaccelRTSession *sess =
        g_new0(AccelDevBackendVaccelRTSession, 1);
    sess->opaque = sess_data;
    sess->id = sess_id;
    QTAILQ_INIT(&sess->timers);
    sess->nr_timers = 0;
    QTAILQ_INSERT_TAIL(&vaccel->sessions, sess, next);

    return sess;
}

static void session_del(AccelDevBackendVaccelRT *vaccel,
                        AccelDevBackendVaccelRTSession *sess)
{
    QTAILQ_REMOVE(&vaccel->sessions, sess, next);
    g_free(sess->opaque);
    g_free(sess);
}

static int64_t acceldev_vaccel_create_session(AccelDevBackend *ab,
                                              AccelDevBackendOpInfo *info,
                                              uint32_t queue_index,
                                              Error **errp)
{
    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    struct vaccel_session *sess_data = NULL;
    AccelDevBackendVaccelRTSession *sess;
    struct vaccel_arg_array read_args;
    struct vaccel_arg_array write_args;
    uint32_t flags;
    int ret = VIRTIO_ACCEL_OK;

    if (info->out_nr < 1) {
        error_setg(errp,
                   "Invalid number of arguments; expected at least 1 out arg");
        return -VIRTIO_ACCEL_ERR;
    }

    ret = parse_vaccel_args(info->out, info->in, info->out_nr, info->in_nr,
                            &read_args, &write_args);
    if (ret) {
        error_setg(errp, "Failed to parse vaccel args");
        return -ret;
    }

    ret = vaccel_arg_array_get_uint32(&read_args, &flags);
    if (ret) {
        error_setg(errp, "Failed to unpack flags arg");
        ret = -VIRTIO_ACCEL_ERR;
        goto cleanup;
    }

    sess_data = g_new0(struct vaccel_session, 1);
    ret = vaccel_session_init(sess_data, flags);
    if (ret) {
        info->op_ret = ret;
        ret = -VIRTIO_ACCEL_ERR;
        goto cleanup;
    }

    sess = session_create_and_add(vaccel, (void *)sess_data, sess_data->id);

cleanup:
    cleanup_vaccel_args(&read_args, &write_args);
    return (ret < 0) ? ret : sess->id;
}

static int acceldev_vaccel_destroy_session(AccelDevBackend *ab, int64_t sess_id,
                                           uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccel, sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    ret = vaccel_session_release((struct vaccel_session *)sess->opaque);
    if (ret != VACCEL_OK)
        return -VIRTIO_ACCEL_ERR;

    timers_del(sess);
    session_del(vaccel, sess);

    return VIRTIO_ACCEL_OK;
}

static int do_operation(struct vaccel_session *sess,
                        AccelDevBackendOpInfo *info, AccelDevBackend *ab,
                        uint32_t queue_index, Error **errp)
{
    struct vaccel_arg_array read_args;
    struct vaccel_arg_array write_args;
    int ret = VIRTIO_ACCEL_OK;

    if (info->op_code >= VACCEL_VIRTIO_MAX)
        return -VIRTIO_ACCEL_ERR;
    if (!ops[info->op_code])
        return -VIRTIO_ACCEL_NOTSUPP;

    acceldev_backend_timer_start(ab, sess->id, "do op > prepare", queue_index,
                                 errp);

    ret = parse_vaccel_args(info->out, info->in, info->out_nr, info->in_nr,
                            &read_args, &write_args);
    if (ret) {
        error_setg(errp, "Failed to parse vaccel args");
        return -ret;
    }

    acceldev_backend_timer_stop(ab, sess->id, "do op > prepare", queue_index,
                                errp);

    acceldev_backend_timer_start(ab, sess->id, "do op > genop", queue_index,
                                 errp);

    ret = ops[info->op_code](sess, &read_args, &write_args, errp);
    if (ret != VACCEL_OK) {
        info->op_ret = ret;
        ret = -VIRTIO_ACCEL_ERR;
    } else {
        ret = VIRTIO_ACCEL_OK;
    }

    acceldev_backend_timer_stop(ab, sess->id, "do op > genop", queue_index,
                                errp);

    acceldev_backend_timer_start(ab, sess->id, "do op > free prep", queue_index,
                                 errp);

    cleanup_vaccel_args(&read_args, &write_args);

    acceldev_backend_timer_stop(ab, sess->id, "do op > free prep", queue_index,
                                errp);

    return ret;
}

static int acceldev_vaccel_operation(AccelDevBackend *ab,
                                     AccelDevBackendOpInfo *info,
                                     uint32_t queue_index, Error **errp)
{
    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccel, info->session_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   info->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (info->out_nr < 1) {
        error_setg(errp, "vAccel op requires at least 1 out argument (got %u)",
                   info->out_nr);
        return -VIRTIO_ACCEL_ERR;
    }

    ret = do_operation(sess->opaque, info, ab, queue_index, errp);
    if (ret != VACCEL_OK)
        return -VIRTIO_ACCEL_ERR;

    return VIRTIO_ACCEL_OK;
}

static int acceldev_vaccel_timer_start(AccelDevBackend *ab, int64_t sess_id,
                                       const char *name, uint32_t queue_index,
                                       Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccel, sess_id);
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

static int acceldev_vaccel_timer_stop(AccelDevBackend *ab, int64_t sess_id,
                                      const char *name, uint32_t queue_index,
                                      Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;

    sess = session_get(vaccel, sess_id);
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

static int
timer_sample_acceldev_to_accel(struct accel_prof_sample *accel_samples,
                               uint32_t nr_accel_samples,
                               AccelDevBackendVaccelRTTimer *timer)
{
    int i = 0;

    for (i = 0; i < timer->vaccel_tmr.nr_entries; i++) {
        if (i == nr_accel_samples) {
            warn_report(
                "Not all acceldev samples for %s can be returned (allocated: %d vs total: %ld)",
                timer->name, nr_accel_samples, timer->vaccel_tmr.nr_entries);
            break;
        }
        accel_samples[i].start = timer->vaccel_tmr.samples[i].start;
        accel_samples[i].time = timer->vaccel_tmr.samples[i].time;
    }

    return i;
}

#define TIMERS_NAME_PREFIX "[qemu-vaccel]"
static int timers_acceldev_to_accel(struct accel_prof_region *accel_timers,
                                    uint32_t nr_accel_timers,
                                    AccelDevBackendVaccelRTSession *sess)
{
    if (nr_accel_timers < 1)
        return -VIRTIO_ACCEL_ERR;

    int i = 0;
    AccelDevBackendVaccelRTTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        if (i == nr_accel_timers) {
            warn_report(
                "Not all acceldev timers can be returned (allocated: %d vs total: %d)",
                nr_accel_timers, sess->nr_timers);
            break;
        }
        g_snprintf(accel_timers[i].name, TIMERS_NAME_MAX, "%s %s",
                   TIMERS_NAME_PREFIX, timer->name);
        accel_timers[i].nr_entries = timer_sample_acceldev_to_accel(
            accel_timers[i].samples, accel_timers[i].size, timer);
        i++;
    }

    return i;
}

static int acceldev_vaccel_get_timers(AccelDevBackend *ab,
                                      AccelDevBackendOpInfo *info,
                                      uint32_t queue_index, Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    AccelDevBackendVaccelRTSession *sess;
    int ret;

    sess = session_get(vaccel, info->session_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   info->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (info->in_nr < 1) {
        error_setg(errp,
                   "vaccel get_timers requires at least 1 in argument (got %u)",
                   info->out_nr);
        return -VIRTIO_ACCEL_ERR;
    }

    uint32_t *nt = (uint32_t *)info->in[0].buf;
    uint32_t *qnt = (uint32_t *)info->in[1].buf;
    if (*qnt == 0) {
        *qnt = sess->nr_timers;
        ret = VIRTIO_ACCEL_OK;
    } else {
        uint64_t nr_timers = *nt + *qnt;

        if (info->in_nr < 3 + nr_timers) {
            error_setg(errp,
                       "vaccel get_timers: not enough in arguments (got %u)",
                       info->in_nr);
            return -VIRTIO_ACCEL_ERR;
        }

        struct accel_prof_region *accel_timers =
            (struct accel_prof_region *)info->in[2].buf;
        if (info->in[2].len < nr_timers * sizeof(*accel_timers)) {
            error_setg(errp,
                       "vaccel get_timers: wrong preallocated size (got %d)",
                       info->in[2].len);
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
                (struct accel_prof_sample *)info->in[3 + i].buf;
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

static void sessions_del(AccelDevBackendVaccelRT *vaccel, AccelDevBackend *ab,
                         Error **errp)
{
    AccelDevBackendVaccelRTSession *sess, *tmp;
    QTAILQ_FOREACH_SAFE(sess, &vaccel->sessions, next, tmp)
    {
        acceldev_vaccel_destroy_session(ab, sess->id, 0, errp);
    }
}

static void acceldev_vaccel_cleanup(AccelDevBackend *ab, Error **errp)
{
    AccelDevBackendVaccelRT *vaccel = ACCELDEV_BACKEND_VACCELRT(ab);
    int queues = ab->conf.peers.queues;
    AccelDevBackendClient *c;

    sessions_del(vaccel, ab, errp);

    for (int i = 0; i < queues; i++) {
        c = ab->conf.peers.ccs[i];
        if (c) {
            acceldev_backend_free_client(c);
            ab->conf.peers.ccs[i] = NULL;
        }
    }

    acceldev_backend_set_ready(ab, false);
}

static void acceldev_vaccel_class_init(ObjectClass *oc, const void *data)
{
    AccelDevBackendClass *abc = ACCELDEV_BACKEND_CLASS(oc);

    abc->init = acceldev_vaccel_init;
    abc->cleanup = acceldev_vaccel_cleanup;
    abc->create_session = acceldev_vaccel_create_session;
    abc->destroy_session = acceldev_vaccel_destroy_session;
    abc->do_op = acceldev_vaccel_operation;
    abc->timer_start = acceldev_vaccel_timer_start;
    abc->timer_stop = acceldev_vaccel_timer_stop;
    abc->timers_get = acceldev_vaccel_get_timers;
}

static const TypeInfo acceldev_vaccel_info = {
    .name = TYPE_ACCELDEV_BACKEND_VACCELRT,
    .parent = TYPE_ACCELDEV_BACKEND,
    .class_init = acceldev_vaccel_class_init,
    .instance_size = sizeof(AccelDevBackendVaccelRT),
};

static void acceldev_vaccel_register_types(void)
{
    type_register_static(&acceldev_vaccel_info);
}

type_init(acceldev_vaccel_register_types);
