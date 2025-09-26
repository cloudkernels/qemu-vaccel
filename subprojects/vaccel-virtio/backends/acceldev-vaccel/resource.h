// SPDX-License-Identifier: Apache-2.0

#pragma once

#include "qemu/osdep.h"
#include "qapi/error.h"

#include <stddef.h>

/* Work around a -Wstrict-prototypes warning in slog headers */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wstrict-prototypes"
#include <vaccel.h>
#pragma GCC diagnostic pop

int vaccel_virtio_resource_register(struct vaccel_session *sess,
                                    struct vaccel_arg_array *read_args,
                                    struct vaccel_arg_array *write_args,
                                    Error **errp);
int vaccel_virtio_resource_unregister(struct vaccel_session *sess,
                                      struct vaccel_arg_array *read_args,
                                      struct vaccel_arg_array *write_args,
                                      Error **errp);
