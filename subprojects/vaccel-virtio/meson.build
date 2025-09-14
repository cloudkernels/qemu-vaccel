project('vaccel-virtio', 'c',
        license: 'GPL-2.0-or-later',
        default_options: ['c_std=gnu99'])

add_project_arguments('-Wno-strict-prototypes', language: 'c')

cc = meson.get_compiler('c')
ss = import('sourceset')

keyval = import('keyval')
config_host = keyval.load(meson.global_build_root() / 'config-host.mak')
enable_static = 'CONFIG_STATIC' in config_host
if enable_static
  libvaccel_dep = dependency('vaccel', static: true)
else
  libvaccel_dep = dependency('vaccel')
endif

virtio_accel_ss = ss.source_set()
vaccel_ss = ss.source_set()

if libvaccel_dep.found()
  virtio_accel_ss.add([
    files('hw/virtio/virtio-accel.c'),
    files('hw/virtio/virtio-accel-pci.c')
  ])
  vaccel_ss.add([
    libvaccel_dep,
    files('backends/acceldev.c'),
    files('backends/acceldev-vaccel.c')
  ])
endif
