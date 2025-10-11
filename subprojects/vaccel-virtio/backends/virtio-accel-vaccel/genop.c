// SPDX-License-Identifier: Apache-2.0

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "genop.h"
#include <vaccel.h>

int vaccel_virtio_genop(struct vaccel_session *sess,
                        struct vaccel_arg_array *read_args,
                        struct vaccel_arg_array *write_args, Error **errp)
{
    uint8_t u_op_type;
    int ret = vaccel_arg_array_get_uint8(read_args, &u_op_type);
    if (ret) {
        error_setg(errp, "Failed to unpack operation type for genop");
        return ret;
    }

    return vaccel_genop(sess, read_args->args, read_args->count,
                        write_args->args, write_args->count);
}
