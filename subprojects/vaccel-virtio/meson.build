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

vaccel_virtio_common_subp = subproject('vaccel-virtio-common')
libvaccel_virtio_common_dep = dependency('vaccel-virtio-common')

vaccel_virtio_dep = declare_dependency(
  include_directories : include_directories('include'))

virtio_accel_ss = ss.source_set()
virtio_accel_backend_ss = ss.source_set()

virtio_accel_ss.add(vaccel_virtio_dep)
virtio_accel_backend_ss.add(vaccel_virtio_dep)

subdir('backends')
subdir('hw')
