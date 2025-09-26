// SPDX-License-Identifier: Apache-2.0

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "resource.h"
#include "vaccel-virtio-common/core.h"
#include "vaccel-virtio-common/pack/resource.h"
#include <vaccel.h>

int vaccel_virtio_resource_register(struct vaccel_session *sess,
                                    struct vaccel_arg_array *read_args,
                                    struct vaccel_arg_array *write_args,
                                    Error **errp)
{
    if (!sess || !read_args || read_args->count < 1 || !errp)
        return VACCEL_EINVAL;

    vaccel_id_t res_id;
    int ret = vaccel_arg_array_get_int64(read_args, &res_id);
    if (ret) {
        error_setg(errp, "Failed to unpack resource.id arg");
        return ret;
    }

    struct vaccel_resource *res;
    if (res_id < 0) {
        error_setg(errp, "Invalid resource.id");
        return VACCEL_EINVAL;
    } else if (res_id < 1) {
        // Resource does not exist. Create it.
        if (!write_args || write_args->count < 1) {
            error_setg(errp,
                       "Expected write args for new resource, but got none");
            return VACCEL_EINVAL;
        }

        ret = vaccel_virtio_unpack_resource(read_args, &res);
        if (ret) {
            error_setg(errp, "Failed to unpack resource");
            return ret;
        }
    } else {
        ret = vaccel_resource_get_by_id(&res, res_id);
        if (ret) {
            error_setg(errp, "Unknown resource %" PRId64, res_id);
            return ret;
        }
    }

    ret = vaccel_resource_register(res, sess);
    if (ret)
        goto delete_resource;

    if (res_id < 1) {
        ret = vaccel_arg_array_set_int64(write_args, &res->id);
        if (ret) {
            error_setg(errp, "Failed to pack resource.id arg");
            goto delete_resource;
        }
    }

    return VACCEL_OK;

delete_resource:
    if (res_id < 1)
        vaccel_resource_delete(res);

    return ret;
}

int vaccel_virtio_resource_unregister(struct vaccel_session *sess,
                                      struct vaccel_arg_array *read_args,
                                      struct vaccel_arg_array *write_args,
                                      Error **errp)
{
    if (!sess || !read_args || read_args->count < 1 || !errp)
        return VACCEL_EINVAL;

    vaccel_id_t res_id;
    int ret = vaccel_arg_array_get_int64(read_args, &res_id);
    if (ret) {
        error_setg(errp, "Failed to unpack resource.id arg");
        return ret;
    }

    struct vaccel_resource *res;
    ret = vaccel_resource_get_by_id(&res, res_id);
    if (ret) {
        error_setg(errp, "Unknown resource %" PRId64, res_id);
        return ret;
    }

    ret = vaccel_resource_unregister(res, sess);
    if (ret)
        return ret;

    // If resource is registered to other sessions do not delete
    if (vaccel_resource_refcount(res) > 0)
        return VACCEL_OK;

    return vaccel_resource_delete(res);
}
