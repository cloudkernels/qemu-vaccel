// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "vaccel-virtio-common/core.h"

/* Work around a -Wstrict-prototypes warning in slog headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <vaccel.h>
#pragma GCC diagnostic pop

typedef int (*vaccel_virtio_func_t)(struct vaccel_session *sess,
                                    struct vaccel_arg_array *read_args,
                                    struct vaccel_arg_array *write_args,
                                    Error **errp);

extern vaccel_virtio_func_t ops[VACCEL_VIRTIO_MAX];
