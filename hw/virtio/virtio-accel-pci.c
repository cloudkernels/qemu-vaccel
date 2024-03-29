#include "qemu/osdep.h"
#include "hw/pci/pci.h"
#include "hw/virtio/virtio.h"
#include "hw/virtio/virtio-bus.h"
#include "hw/virtio/virtio-pci.h"
#include "hw/virtio/virtio-accel.h"
#include "qapi/error.h"

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

    if (vaccel->vdev.conf.crypto == NULL) {
        error_setg(errp, "'crypto' parameter expects a valid object");
        return;
    }
    if (vaccel->vdev.conf.generic == NULL) {
        error_setg(errp, "'generic' parameter expects a valid object");
        return;
    }

    qdev_set_parent_bus(vdev, BUS(&vpci_dev->bus));
    virtio_pci_force_virtio_1(vpci_dev);
    object_property_set_bool(OBJECT(vdev), true, "realized", errp);
    object_property_set_link(OBJECT(vaccel),
                 OBJECT(vaccel->vdev.conf.crypto), "crypto",
                 NULL);
    object_property_set_link(OBJECT(vaccel),
                 OBJECT(vaccel->vdev.conf.generic), "generic",
                 NULL);
}

static void virtio_accel_pci_class_init(ObjectClass *klass, void *data)
{
    DeviceClass *dc = DEVICE_CLASS(klass);
    VirtioPCIClass *k = VIRTIO_PCI_CLASS(klass);
    PCIDeviceClass *pcidev_k = PCI_DEVICE_CLASS(klass);

    k->realize = virtio_accel_pci_realize;
    set_bit(DEVICE_CATEGORY_MISC, dc->categories);
    dc->props = virtio_accel_pci_properties;
    pcidev_k->class_id = PCI_CLASS_OTHERS;
}

static void virtio_accel_initfn(Object *obj)
{
    VirtIOAccelPCI *dev = VIRTIO_ACCEL_PCI(obj);

    virtio_instance_init_common(obj, &dev->vdev, sizeof(dev->vdev),
                                TYPE_VIRTIO_ACCEL);
    object_property_add_alias(obj, "crypto", OBJECT(&dev->vdev),
                              "crypto", &error_abort);
    object_property_add_alias(obj, "generic", OBJECT(&dev->vdev),
                              "generic", &error_abort);
}

static const TypeInfo virtio_accel_pci_info = {
    .name          = TYPE_VIRTIO_ACCEL_PCI,
    .parent        = TYPE_VIRTIO_PCI,
    .instance_size = sizeof(VirtIOAccelPCI),
    .instance_init = virtio_accel_initfn,
    .class_init    = virtio_accel_pci_class_init,
};

static void virtio_accel_pci_register_types(void)
{
    type_register_static(&virtio_accel_pci_info);
}
type_init(virtio_accel_pci_register_types)
