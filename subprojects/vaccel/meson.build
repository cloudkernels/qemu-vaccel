project('vaccel', 'c',
        license: 'GPL-2.0-or-later',
        default_options: ['c_std=gnu99'])

cc = meson.get_compiler('c')
ss = import('sourceset')

vaccel_lib = cc.find_library('vaccel', has_headers: ['vaccel.h'],
                             required: get_option('vaccel'))

vaccel_virtio_ss = ss.source_set()
vaccel_ss = ss.source_set()

if vaccel_lib.found()
  vaccel_virtio_ss.add([files('hw/virtio/virtio-accel.c'), files('hw/virtio/virtio-accel-pci.c')])
  vaccel_ss.add([vaccel_lib, files('backends/acceldev.c'), files('backends/acceldev-vaccelrt.c')])
endif
