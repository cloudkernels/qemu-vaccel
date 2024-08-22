project('vaccel', 'c',
        license: 'GPL-2.0-or-later',
        default_options: ['c_std=gnu99'])

cc = meson.get_compiler('c')
ss = import('sourceset')

keyval = import('keyval')
config_host = keyval.load(meson.build_root() / 'config-host.mak')
enable_static = 'CONFIG_STATIC' in config_host
if enable_static
  vaccel_lib = dependency('vaccel', static: true)
else
  vaccel_lib = dependency('vaccel')
endif

vaccel_virtio_ss = ss.source_set()
vaccel_ss = ss.source_set()

if vaccel_lib.found()
  vaccel_virtio_ss.add([
    files('hw/virtio/virtio-accel.c'),
    files('hw/virtio/virtio-accel-pci.c')
  ])
  vaccel_ss.add([
    vaccel_lib,
    files('backends/acceldev.c'),
    files('backends/acceldev-vaccel.c')
  ])
endif
