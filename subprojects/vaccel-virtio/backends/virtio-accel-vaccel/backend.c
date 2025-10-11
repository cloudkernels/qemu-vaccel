// SPDX-License-Identifier: Apache-2.0

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/error-report.h"
#include "qemu/queue.h"
#include "qom/object.h"

#include "standard-headers/linux/virtio_accel.h"
#include "system/virtio-accel-backend.h"
#include "ops.h"

/* Work around a -Wstrict-prototypes warning in slog headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <vaccel.h>
#pragma GCC diagnostic pop

/**
 * @TYPE_VIRTIO_ACCEL_BACKEND_VACCEL:
 */
#define TYPE_VIRTIO_ACCEL_BACKEND_VACCEL "virtio-accel-backend-vaccel"

OBJECT_DECLARE_SIMPLE_TYPE(VirtIOAccelBackendVaccel,
                           VIRTIO_ACCEL_BACKEND_VACCEL)

// TODO: Move to virtio-accel.c
typedef struct VirtIOAccelBackendVaccelTimer {
    struct vaccel_prof_region vaccel_tmr;
    const char *name;
    QTAILQ_ENTRY(VirtIOAccelBackendVaccelTimer) next;
} VirtIOAccelBackendVaccelTimer;

// TODO: Move to virtio-accel.c
typedef struct VirtIOAccelBackendVaccelSession {
    void *opaque;
    int64_t id;
    QTAILQ_HEAD(, VirtIOAccelBackendVaccelTimer) timers;
    uint32_t nr_timers;
    QTAILQ_ENTRY(VirtIOAccelBackendVaccelSession) next;
} VirtIOAccelBackendVaccelSession;

/* Max number of sessions */
#define MAX_NUM_SESSIONS 1024

struct VirtIOAccelBackendVaccel {
    VirtIOAccelBackend parent_obj;
    QTAILQ_HEAD(, VirtIOAccelBackendVaccelSession) sessions;
};

static VirtIOAccelBackendVaccelTimer *
timer_get(VirtIOAccelBackendVaccelSession *sess, const char *name)
{
    if (!vaccel_prof_enabled())
        return NULL;

    VirtIOAccelBackendVaccelTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        if (strcmp(timer->name, name) == 0) {
            return timer;
        }
    }
    return NULL;
}

static void timers_del(VirtIOAccelBackendVaccelSession *sess)
{
    if (!vaccel_prof_enabled())
        return;

    VirtIOAccelBackendVaccelTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        QTAILQ_REMOVE(&sess->timers, timer, next);
        vaccel_prof_region_release(&timer->vaccel_tmr);
        g_free(timer);
    }
}

static VirtIOAccelBackendVaccelSession *
session_get(VirtIOAccelBackendVaccel *vaccel, int64_t sess_id)
{
    VirtIOAccelBackendVaccelSession *sess, *tmp;
    QTAILQ_FOREACH_SAFE(sess, &vaccel->sessions, next, tmp)
    {
        if (sess->id == sess_id)
            return sess;
    }
    return NULL;
}

static VirtIOAccelBackendVaccelSession *
session_create_and_add(VirtIOAccelBackendVaccel *vaccel, void *sess_data,
                       int64_t sess_id)
{
    VirtIOAccelBackendVaccelSession *sess =
        g_new0(VirtIOAccelBackendVaccelSession, 1);
    sess->opaque = sess_data;
    sess->id = sess_id;
    QTAILQ_INIT(&sess->timers);
    sess->nr_timers = 0;
    QTAILQ_INSERT_TAIL(&vaccel->sessions, sess, next);

    return sess;
}

static void session_del(VirtIOAccelBackendVaccel *vaccel,
                        VirtIOAccelBackendVaccelSession *sess)
{
    QTAILQ_REMOVE(&vaccel->sessions, sess, next);
    g_free(sess->opaque);
    g_free(sess);
}

static int parse_vaccel_args(VirtIOAccelBackendArg *out_args,
                             VirtIOAccelBackendArg *in_args, size_t nr_out_args,
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
                                           (size_t)out_args[i].len,
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
                                           (size_t)in_args[i].len,
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

static int update_backend_args(VirtIOAccelBackendArg *in_args,
                               size_t nr_in_args,
                               struct vaccel_arg_array *write_args,
                               Error **errp)
{
    if (nr_in_args && (!in_args || !write_args))
        return VIRTIO_ACCEL_ERR;

    if (nr_in_args != write_args->count) {
        error_setg(errp, "Invalid number of updated args");
        return VIRTIO_ACCEL_ERR;
    }

    for (size_t i = 0; i < nr_in_args; i++) {
        if ((uint32_t)write_args->args[i].size > in_args[i].len) {
            error_setg(errp, "Updated arg %zu too large; %zu > %u", i,
                       write_args->args[i].size, in_args[i].len);
            return VIRTIO_ACCEL_ERR;
        }

        if (write_args->args[i].buf != in_args[i].buf)
            memcpy(in_args[i].buf, write_args->args[i].buf,
                   write_args->args[i].size);

        in_args[i].data_len = (uint32_t)write_args->args[i].size;
        in_args[i].type = (uint32_t)write_args->args[i].type;
        in_args[i].custom_type_id =
            (uint32_t)write_args->args[i].custom_type_id;
    }

    return VIRTIO_ACCEL_OK;
}

static void cleanup_vaccel_args(struct vaccel_arg_array *read_args,
                                struct vaccel_arg_array *write_args)
{
    if (!read_args || !write_args)
        return;

    g_free(read_args->args);
    g_free(write_args->args);
}

static int64_t virtio_accel_vaccel_create_session(VirtIOAccelBackend *b,
                                                  VirtIOAccelBackendOp *op,
                                                  Error **errp)
{
    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    struct vaccel_session *sess_data = NULL;
    VirtIOAccelBackendVaccelSession *sess;
    struct vaccel_arg_array read_args;
    struct vaccel_arg_array write_args;
    uint32_t flags;
    int ret = VIRTIO_ACCEL_OK;

    if (op->nr_out < 1) {
        error_setg(errp,
                   "Invalid number of arguments; expected at least 1 out arg");
        return -VIRTIO_ACCEL_ERR;
    }

    ret = parse_vaccel_args(op->out, op->in, op->nr_out, op->nr_in, &read_args,
                            &write_args);
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

    ret = vaccel_session_new(&sess_data, flags);
    if (ret) {
        op->op_ret = ret;
        ret = -VIRTIO_ACCEL_ERR;
        goto cleanup;
    }

    sess = session_create_and_add(vaccel, (void *)sess_data, sess_data->id);

cleanup:
    cleanup_vaccel_args(&read_args, &write_args);
    return (ret < 0) ? ret : sess->id;
}

static int virtio_accel_vaccel_destroy_session(VirtIOAccelBackend *b,
                                               int64_t sess_id, Error **errp)
{
    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    VirtIOAccelBackendVaccelSession *sess;
    int ret;

    sess = session_get(vaccel, sess_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   sess_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    ret = vaccel_session_delete((struct vaccel_session *)sess->opaque);
    if (ret)
        return -VIRTIO_ACCEL_ERR;

    timers_del(sess);
    session_del(vaccel, sess);

    return VIRTIO_ACCEL_OK;
}

static int do_operation(struct vaccel_session *sess, VirtIOAccelBackendOp *op,
                        VirtIOAccelBackend *b, Error **errp)
{
    struct vaccel_arg_array read_args;
    struct vaccel_arg_array write_args;
    int ret = VIRTIO_ACCEL_OK;

    if (op->op_code >= VACCEL_VIRTIO_MAX)
        return -VIRTIO_ACCEL_ERR;
    if (!ops[op->op_code])
        return -VIRTIO_ACCEL_NOTSUPP;

    virtio_accel_backend_timer_start(b, sess->id, "do op > prepare", errp);

    ret = parse_vaccel_args(op->out, op->in, op->nr_out, op->nr_in, &read_args,
                            &write_args);
    if (ret) {
        error_setg(errp, "Failed to parse vaccel args");
        return -ret;
    }

    virtio_accel_backend_timer_stop(b, sess->id, "do op > prepare", errp);

    virtio_accel_backend_timer_start(b, sess->id, "do op > genop", errp);

    ret = ops[op->op_code](sess, &read_args, &write_args, errp);
    if (ret != VACCEL_OK) {
        op->op_ret = ret;
        ret = -VIRTIO_ACCEL_ERR;
    } else {
        ret = VIRTIO_ACCEL_OK;
    }

    virtio_accel_backend_timer_stop(b, sess->id, "do op > genop", errp);

    virtio_accel_backend_timer_start(b, sess->id, "do op > update args", errp);

    ret = -update_backend_args(op->in, op->nr_in, &write_args, errp);
    if (ret && errp && *errp == NULL)
        error_setg(errp, "Failed to update backend args");

    virtio_accel_backend_timer_stop(b, sess->id, "do op > update args", errp);

    cleanup_vaccel_args(&read_args, &write_args);
    return ret;
}

static int virtio_accel_vaccel_operation(VirtIOAccelBackend *b,
                                         VirtIOAccelBackendOp *op, Error **errp)
{
    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    VirtIOAccelBackendVaccelSession *sess;
    int ret;

    sess = session_get(vaccel, op->session_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   op->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (op->nr_out < 1) {
        error_setg(errp, "vAccel op requires at least 1 out argument (got %u)",
                   op->nr_out);
        return -VIRTIO_ACCEL_ERR;
    }

    ret = do_operation(sess->opaque, op, b, errp);
    if (ret)
        return ret;

    return VIRTIO_ACCEL_OK;
}

static int virtio_accel_vaccel_timer_start(VirtIOAccelBackend *b,
                                           int64_t sess_id, const char *name,
                                           Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    VirtIOAccelBackendVaccelSession *sess;
    int ret;

    sess = session_get(vaccel, sess_id);
    if (!sess)
        return -VIRTIO_ACCEL_INVSESS;

    VirtIOAccelBackendVaccelTimer *timer = timer_get(sess, name);
    if (!timer) {
        timer = g_new0(VirtIOAccelBackendVaccelTimer, 1);
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

static int virtio_accel_vaccel_timer_stop(VirtIOAccelBackend *b,
                                          int64_t sess_id, const char *name,
                                          Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    VirtIOAccelBackendVaccelSession *sess;

    sess = session_get(vaccel, sess_id);
    if (!sess)
        return -VIRTIO_ACCEL_INVSESS;

    VirtIOAccelBackendVaccelTimer *timer = timer_get(sess, name);
    if (!timer)
        return VIRTIO_ACCEL_OK;

    vaccel_prof_region_stop(&timer->vaccel_tmr);

    return VIRTIO_ACCEL_OK;
}

static int
get_profiler_region_samples(struct virtio_accel_profiler_sample *reg_samples,
                            uint32_t nr_reg_samples,
                            VirtIOAccelBackendVaccelTimer *timer)
{
    int i = 0;

    for (i = 0; i < timer->vaccel_tmr.nr_entries; i++) {
        if (i == nr_reg_samples) {
            warn_report(
                "Not all virtio-accel samples for %s can be returned (allocated: %d vs total: %ld)",
                timer->name, nr_reg_samples, timer->vaccel_tmr.nr_entries);
            break;
        }
        reg_samples[i].start = timer->vaccel_tmr.samples[i].start;
        reg_samples[i].time = timer->vaccel_tmr.samples[i].time;
    }

    return i;
}

#define TIMERS_NAME_PREFIX "[qemu-vaccel]"
static int get_profiler_regions(struct virtio_accel_profiler_region *regions,
                                uint32_t nr_regions,
                                VirtIOAccelBackendVaccelSession *sess)
{
    if (nr_regions < 1)
        return -VIRTIO_ACCEL_ERR;

    int i = 0;
    VirtIOAccelBackendVaccelTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        if (i == nr_regions) {
            warn_report(
                "Not all virtio-accel timers can be returned (allocated: %d vs total: %d)",
                nr_regions, sess->nr_timers);
            break;
        }
        g_snprintf(regions[i].name, VIRTIO_ACCEL_TIMERS_NAME_MAX, "%s %s",
                   TIMERS_NAME_PREFIX, timer->name);
        regions[i].nr_entries = get_profiler_region_samples(
            regions[i].samples, regions[i].size, timer);
        i++;
    }

    return i;
}

static int virtio_accel_vaccel_get_timers(VirtIOAccelBackend *b,
                                          VirtIOAccelBackendOp *op,
                                          Error **errp)
{
    if (!vaccel_prof_enabled())
        return VIRTIO_ACCEL_OK;

    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    VirtIOAccelBackendVaccelSession *sess;
    int ret;

    sess = session_get(vaccel, op->session_id);
    if (!sess) {
        error_setg(errp, "Cannot find a valid session with id: %" PRId64 "",
                   op->session_id);
        return -VIRTIO_ACCEL_INVSESS;
    }

    if (op->nr_in < 1) {
        error_setg(errp,
                   "vaccel get_timers requires at least 1 in argument (got %u)",
                   op->nr_out);
        return -VIRTIO_ACCEL_ERR;
    }

    uint32_t *nt = (uint32_t *)op->in[0].buf;
    uint32_t *qnt = (uint32_t *)op->in[1].buf;
    if (*qnt == 0) {
        *qnt = sess->nr_timers;
        ret = VIRTIO_ACCEL_OK;
    } else {
        uint64_t nr_timers = *nt + *qnt;

        if (op->nr_in < 3 + nr_timers) {
            error_setg(errp,
                       "vaccel get_timers: not enough in arguments (got %u)",
                       op->nr_in);
            return -VIRTIO_ACCEL_ERR;
        }

        struct virtio_accel_profiler_region *regions =
            (struct virtio_accel_profiler_region *)op->in[2].buf;
        if (op->in[2].len < nr_timers * sizeof(*regions)) {
            error_setg(errp,
                       "vaccel get_timers: wrong preallocated size (got %d)",
                       op->in[2].len);
            return -VIRTIO_ACCEL_ERR;
        }

        struct virtio_accel_profiler_sample **tmp_samples =
            g_new0(struct virtio_accel_profiler_sample *, *qnt);
        if (!tmp_samples) {
            return -VIRTIO_ACCEL_ERR;
        }

        for (int i = *nt; i < nr_timers; i++) {
            tmp_samples[i - *nt] = regions[i].samples;
            regions[i].samples =
                (struct virtio_accel_profiler_sample *)op->in[3 + i].buf;
        }

        ret = get_profiler_regions(&regions[*nt], *qnt, sess);
        if (ret < 0) {
            ret = -VIRTIO_ACCEL_ERR;
            goto free;
        } else {
            ret = VIRTIO_ACCEL_OK;
        }

        for (int i = *nt; i < nr_timers; i++) {
            regions[i].samples = tmp_samples[i - *nt];
        }

free:
        g_free(tmp_samples);
    }

    return ret;
}

static void virtio_accel_vaccel_init(VirtIOAccelBackend *b, Error **errp)
{
    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    QTAILQ_INIT(&vaccel->sessions);
}

static void virtio_accel_vaccel_cleanup(VirtIOAccelBackend *b, Error **errp)
{
    VirtIOAccelBackendVaccel *vaccel = VIRTIO_ACCEL_BACKEND_VACCEL(b);
    VirtIOAccelBackendVaccelSession *sess, *tmp;

    QTAILQ_FOREACH_SAFE(sess, &vaccel->sessions, next, tmp)
    {
        virtio_accel_vaccel_destroy_session(b, sess->id, errp);
    }
}

static void virtio_accel_vaccel_class_init(ObjectClass *oc, const void *data)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_CLASS(oc);

    bc->init = virtio_accel_vaccel_init;
    bc->cleanup = virtio_accel_vaccel_cleanup;
    bc->create_session = virtio_accel_vaccel_create_session;
    bc->destroy_session = virtio_accel_vaccel_destroy_session;
    bc->do_op = virtio_accel_vaccel_operation;
    bc->timer_start = virtio_accel_vaccel_timer_start;
    bc->timer_stop = virtio_accel_vaccel_timer_stop;
    bc->timers_get = virtio_accel_vaccel_get_timers;
}

static const TypeInfo virtio_accel_vaccel_info = {
    .name = TYPE_VIRTIO_ACCEL_BACKEND_VACCEL,
    .parent = TYPE_VIRTIO_ACCEL_BACKEND,
    .class_init = virtio_accel_vaccel_class_init,
    .instance_size = sizeof(VirtIOAccelBackendVaccel),
};

static void virtio_accel_vaccel_register_types(void)
{
    type_register_static(&virtio_accel_vaccel_info);
}

type_init(virtio_accel_vaccel_register_types);
