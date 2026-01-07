// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <inttypes.h>

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

struct VirtIOAccelBackendVaccel {
    VirtIOAccelBackend parent_obj;
};

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
                                                  void **handle, Error **errp)
{
    struct vaccel_session *sess_data = NULL;
    struct vaccel_arg_array read_args;
    struct vaccel_arg_array write_args;
    uint32_t flags;
    int ret = VIRTIO_ACCEL_OK;

    (void)b;

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

    *handle = sess_data;

cleanup:
    cleanup_vaccel_args(&read_args, &write_args);
    return (ret < 0) ? ret : sess_data->id;
}

static int virtio_accel_vaccel_destroy_session(VirtIOAccelBackend *b,
                                               VirtIOAccelBackendSession *sess,
                                               Error **errp)
{
    int ret;

    (void)b;

    ret = vaccel_session_delete((struct vaccel_session *)sess->opaque);
    if (ret)
        return -VIRTIO_ACCEL_ERR;

    return VIRTIO_ACCEL_OK;
}

static int do_operation(VirtIOAccelBackend *b, struct vaccel_session *sess,
                        VirtIOAccelBackendOp *op, Error **errp)
{
    struct vaccel_arg_array read_args;
    struct vaccel_arg_array write_args;
    int ret = VIRTIO_ACCEL_OK;

    (void)b;

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
                                         VirtIOAccelBackendSession *sess,
                                         VirtIOAccelBackendOp *op, Error **errp)
{
    int ret;

    (void)b;

    if (op->nr_out < 1) {
        error_setg(errp, "vAccel op requires at least 1 out argument (got %u)",
                   op->nr_out);
        return -VIRTIO_ACCEL_ERR;
    }

    ret = do_operation(b, (struct vaccel_session *)sess->opaque, op, errp);
    if (ret)
        return ret;

    return VIRTIO_ACCEL_OK;
}

static bool virtio_accel_vaccel_timers_enabled(VirtIOAccelBackend *b)
{
    (void)b;
    return vaccel_prof_enabled();
}

static int virtio_accel_vaccel_timer_create(VirtIOAccelBackend *b,
                                            const char *name, void **handle,
                                            Error **errp)
{
    struct vaccel_prof_region *region = g_new0(struct vaccel_prof_region, 1);

    (void)b;

    if (vaccel_prof_region_init(region, name)) {
        g_free(region);
        return -VIRTIO_ACCEL_ERR;
    }

    *handle = region;
    return VIRTIO_ACCEL_OK;
}

static void virtio_accel_vaccel_timer_destroy(VirtIOAccelBackend *b,
                                              VirtIOAccelBackendTimer *timer)
{
    struct vaccel_prof_region *region =
        (struct vaccel_prof_region *)timer->opaque;

    (void)b;

    vaccel_prof_region_release(region);
    g_free(region);
}

static int virtio_accel_vaccel_timer_start(VirtIOAccelBackend *b,
                                           VirtIOAccelBackendTimer *timer,
                                           Error **errp)
{
    (void)b;
    (void)errp;

    if (vaccel_prof_region_start((struct vaccel_prof_region *)timer->opaque))
        return -VIRTIO_ACCEL_ERR;

    return VIRTIO_ACCEL_OK;
}

static int virtio_accel_vaccel_timer_stop(VirtIOAccelBackend *b,
                                          VirtIOAccelBackendTimer *timer,
                                          Error **errp)
{
    (void)b;
    (void)errp;

    if (vaccel_prof_region_stop((struct vaccel_prof_region *)timer->opaque))
        return -VIRTIO_ACCEL_ERR;

    return VIRTIO_ACCEL_OK;
}

static uint32_t get_profiler_samples(VirtIOAccelBackendTimer *timer,
                                     VirtIOAccelBackendProfilerSample *samples,
                                     uint32_t nr_samples)
{
    struct vaccel_prof_region *region =
        (struct vaccel_prof_region *)timer->opaque;
    size_t i = 0;

    for (i = 0; i < region->nr_entries; i++) {
        if (i == (size_t)nr_samples) {
            warn_report(
                "Not all samples for %s can be returned (allocated: %" PRIu32
                " vs total: %zu)",
                timer->name, nr_samples, region->nr_entries);
            break;
        }
        samples[i].start = region->samples[i].start;
        samples[i].time = region->samples[i].time;
    }

    return (uint32_t)i;
}

#define TIMERS_NAME_PREFIX "[qemu-vaccel]"
static uint32_t get_profiler_regions(VirtIOAccelBackendSession *sess,
                                     VirtIOAccelBackendProfilerRegion *regions,
                                     uint32_t nr_regions)
{
    uint32_t i = 0;
    VirtIOAccelBackendTimer *timer, *tmp;
    QTAILQ_FOREACH_SAFE(timer, &sess->timers, next, tmp)
    {
        if (i == nr_regions) {
            warn_report("Not all timers can be returned (allocated: %" PRIu32
                        " vs total: %" PRIu32 ")",
                        nr_regions, sess->nr_timers);
            break;
        }

        g_snprintf(regions[i].name, VIRTIO_ACCEL_BACKEND_TIMERS_NAME_MAX,
                   "%s %s", TIMERS_NAME_PREFIX, timer->name);
        regions[i].nr_samples = get_profiler_samples(timer, regions[i].samples,
                                                     regions[i].max_samples);
        i++;
    }

    return i;
}

static int virtio_accel_vaccel_get_timers(VirtIOAccelBackend *b,
                                          VirtIOAccelBackendSession *sess,
                                          VirtIOAccelBackendProfilerOp *op,
                                          Error **errp)
{
    (void)b;

    op->nr_regions = get_profiler_regions(sess, op->regions, op->max_regions);
    return VIRTIO_ACCEL_OK;
}

static void virtio_accel_vaccel_init(VirtIOAccelBackend *b, Error **errp)
{
    (void)b;
    (void)errp;
}

static void virtio_accel_vaccel_cleanup(VirtIOAccelBackend *b, Error **errp)
{
    (void)b;
    (void)errp;
}

static void virtio_accel_vaccel_class_init(ObjectClass *oc, const void *data)
{
    VirtIOAccelBackendClass *bc = VIRTIO_ACCEL_BACKEND_CLASS(oc);

    bc->init = virtio_accel_vaccel_init;
    bc->cleanup = virtio_accel_vaccel_cleanup;
    bc->create_session = virtio_accel_vaccel_create_session;
    bc->destroy_session = virtio_accel_vaccel_destroy_session;
    bc->do_op = virtio_accel_vaccel_operation;
    bc->timers_enabled = virtio_accel_vaccel_timers_enabled;
    bc->timer_create = virtio_accel_vaccel_timer_create;
    bc->timer_destroy = virtio_accel_vaccel_timer_destroy;
    bc->timer_start = virtio_accel_vaccel_timer_start;
    bc->timer_stop = virtio_accel_vaccel_timer_stop;
    bc->get_timers = virtio_accel_vaccel_get_timers;
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
