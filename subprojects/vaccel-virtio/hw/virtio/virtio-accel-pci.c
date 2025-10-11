// SPDX-License-Identifier: GPL-2.0-or-later

#include "qemu/osdep.h"
#include "qapi/error.h"
#include "qemu/module.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"

#include "hw/virtio/virtio-accel.h"

#define PCI_DEVICE_ID_VIRTIO_ACCEL 0x1013

typedef struct VirtIOAccelPCI VirtIOAccelPCI;

/*
 * virtio-accel-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_ACCEL_PCI "virtio-accel-pci-base"
DECLARE_INSTANCE_CHECKER(VirtIOAccelPCI, VIRTIO_ACCEL_PCI,
                         TYPE_VIRTIO_ACCEL_PCI)

struct VirtIOAccelPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOAccel vdev;
};

static const Property virtio_accel_pci_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors,
                       DEV_NVECTORS_UNSPECIFIED),
};

static void virtio_accel_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOAccelPCI *dev = VIRTIO_ACCEL_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&dev->vdev);
    VirtIOAccelConfig *config = &dev->vdev.config;

    if (config->backend == NULL) {
        error_setg(errp, "'backend' parameter expects a valid object");
        return;
    }

    if (vpci_dev->nvectors == DEV_NVECTORS_UNSPECIFIED)
        vpci_dev->nvectors = config->num_queues + 1;

    qdev_realize(vdev, BUS(&vpci_dev->bus), errp);
}

static void virtio_accel_pci_class_init(ObjectClass *klass, const void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_accel_pci_properties);
    k->realize = virtio_accel_pci_realize;

    pcidev_k->device_id = PCI_DEVICE_ID_VIRTIO_ACCEL;
    pcidev_k->revision = VIRTIO_PCI_ABI_VERSION;
    pcidev_k->class_id = PCI_CLASS_OTHERS;
}

static void virtio_accel_initfn(Object *obj)
{
    VirtIOAccelPCI *dev = VIRTIO_ACCEL_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_ACCEL);
}

static const VirtioPCIDeviceTypeInfo virtio_accel_pci_info = {
    .base_name = TYPE_VIRTIO_ACCEL_PCI,
    .generic_name = "virtio-accel-pci",
    .transitional_name = "virtio-accel-pci-transitional",
    .non_transitional_name = "virtio-accel-pci-non-transitional",
    .instance_size = sizeof(VirtIOAccelPCI),
    .instance_init = virtio_accel_initfn,
    .class_init = virtio_accel_pci_class_init,
};

static void virtio_accel_pci_register_types(void)
{
    virtio_pci_types_register(&virtio_accel_pci_info);
}
type_init(virtio_accel_pci_register_types)
