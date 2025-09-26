// SPDX-License-Identifier: Apache-2.0

#include "qemu/osdep.h"
#include "qapi/error.h"

#include "ops.h"
#include "genop.h"
#include "resource.h"
#include "vaccel-virtio-common/core.h"

vaccel_virtio_func_t ops[VACCEL_VIRTIO_MAX] = {
    [VACCEL_VIRTIO_RESOURCE_REGISTER] = vaccel_virtio_resource_register,
    [VACCEL_VIRTIO_RESOURCE_UNREGISTER] = vaccel_virtio_resource_unregister,
    [VACCEL_VIRTIO_GENOP] = vaccel_virtio_genop,
};
