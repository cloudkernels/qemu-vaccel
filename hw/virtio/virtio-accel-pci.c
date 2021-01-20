#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/qdev-properties.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-accel.h"
#include "qapi/error.h"
#include "qemu/module.h"

typedef struct VirtIOAccelPCI VirtIOAccelPCI;

/*
 * virtio-accel-pci: This extends VirtioPCIProxy.
 */
#define TYPE_VIRTIO_ACCEL_PCI "virtio-accel-pci"
#define VIRTIO_ACCEL_PCI(obj) \
        OBJECT_CHECK(VirtIOAccelPCI, (obj), TYPE_VIRTIO_ACCEL_PCI)

struct VirtIOAccelPCI {
    VirtIOPCIProxy parent_obj;
    VirtIOAccel vdev;
};

static Property virtio_accel_pci_properties[] = {
    DEFINE_PROP_BIT("ioeventfd", VirtIOPCIProxy, flags,
                    VIRTIO_PCI_FLAG_USE_IOEVENTFD_BIT, true),
    DEFINE_PROP_UINT32("vectors", VirtIOPCIProxy, nvectors, 2),
    DEFINE_PROP_END_OF_LIST(),
};

static void virtio_accel_pci_realize(VirtIOPCIProxy *vpci_dev, Error **errp)
{
    VirtIOAccelPCI *vaccel = VIRTIO_ACCEL_PCI(vpci_dev);
    DeviceState *vdev = DEVICE(&vaccel->vdev);

    if (vaccel->vdev.conf.runtime == NULL) {
        error_setg(errp, "'runtime' parameter expects a valid object");
        return;
    }

    qdev_set_parent_bus(vdev, BUS(&vpci_dev->bus));
    virtio_pci_force_virtio_1(vpci_dev);
    object_property_set_bool(OBJECT(vdev), true, "realized", errp);
    object_property_set_link(OBJECT(vaccel),
                 OBJECT(vaccel->vdev.conf.runtime), "runtime",
                 NULL);
}

static void virtio_accel_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    k->realize = virtio_accel_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    device_class_set_props(dc, virtio_accel_pci_properties);
    pcidev_k->class_id = PCI_CLASS_OTHERS;
}

static void virtio_accel_initfn(Object *obj)
{
    VirtIOAccelPCI *dev = VIRTIO_ACCEL_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_ACCEL);
}

static const VirtioPCIDeviceTypeInfo virtio_accel_pci_info = {
    .generic_name  = TYPE_VIRTIO_ACCEL_PCI,
    .instance_size = sizeof(VirtIOAccelPCI),
    .instance_init = virtio_accel_initfn,
    .class_init    = virtio_accel_pci_class_init,
};

static void virtio_accel_pci_register_types(void)
{
    virtio_pci_types_register(&virtio_accel_pci_info);
}
type_init(virtio_accel_pci_register_types)
