#!/bin/bash

set -e

export LD_LIBRARY_PATH=/usr/local/lib:${LD_LIBRARY_PATH}
export QEMU_AUDIO_DRV=none
export VACCEL_BACKENDS=${VACCEL_BACKENDS:=libvaccel-noop.so}
export VACCEL_DEBUG_LEVEL=${VACCEL_DEBUG_LEVEL:=4}

SCRIPT_NAME=$(basename "$0")
RUN_PATH=./run
SSH_HOST=localhost
SSH_PORT_LOCAL=60022
SSH_PORT_VM=22

smp=1
cpu=host
ram=512

machine=pc,accel=kvm
device=pci
kernel=bzImage
rootfs=rootfs.img
cmdline='rw root=/dev/vda console=ttyS0 '
dcache=none
stderr=${RUN_PATH}/stderr.log

log_error() {
    local error=${1:-'Unknown error'}
    local code=${2:-1}
    echo "${SCRIPT_NAME}: ${error} [error ${code}]" >&2
}

error() {
    local code=${2:-1}
    log_error "$1" "${code}"
    exit "${code}"
}

cleanup_log_file() {
    [[ -n "$1" ]] && [[ -z "$(cat "$1")" ]] && rm -f "$1" || true
}

print_log_file() {
    [[ -f "$1" ]] && echo "${1}:" && cat "$1" || true
}

parse_args() {
    short_opts=M:m:r:k:s:n::v::c:
    read -r -d '' long_opts <<-EOF || true
	machine:,cpu:,dtb:,
	vcpus:,ram:,rootfs:,kernel:,cmdline-append:,output-socket:,
	net-tap::,vsock::,cmd:,no-pci,no-kvm,drive-cache,skip-fsck
	EOF

    if ! getopt=$(getopt -o "${short_opts}" --long "${long_opts}" \
        -n "${SCRIPT_NAME}" -- "$@"); then
        echo 'Failed to parse args' >&2
        exit 1
    fi

    eval set -- "$getopt"
    unset "$getopt"

    while true; do
        case "$1" in
        '-M' | '--machine')
            # QEMU Machine
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            machine="$2"
            shift 2
            ;;
        '--cpu')
            # QEMU CPU
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            cpu="$2"
            shift 2
            ;;
        '--dtb')
            # QEMU CPU
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            dtb="$2"
            extra_args+="-dtb ${dtb} "
            shift 2
            ;;
        '--vcpus')
            # VM vCPUs
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            smp="$2"
            shift 2
            ;;
        '-m' | '--memory')
            # VM RAM
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            ram="$2"
            shift 2
            ;;
        '-r' | '--rootfs')
            # VM rootfs
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            rootfs="$2"
            shift 2
            ;;
        '-k' | '--kernel')
            # VM kernel
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            kernel="$2"
            shift 2
            ;;
        '--cmdline-append')
            # VM kernel command line append
            cmdline+="$2 "
            shift 2
            ;;
        '-s' | '--output-socket')
            # QEMU output to socket
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            qemu_socket="$2"
            shift 2
            ;;
        '-n' | '--net-tap')
            # VM w/ network
            [[ -z "$2" ]] && mac='52:54:00:12:34:01' || mac="$2"
            shift 2
            ;;
        '-v' | '--vsock')
            # VM w/ vsock
            [[ "$2" =~ ^[0-9]+$ ]] || error "'$1' requires a number"
            cid="$2"
            shift 2
            ;;
        '-c' | '--cmd')
            # Command to run in the VM
            [[ -z "$2" ]] && error "'$1' requires a non-empty string"
            cmd="$2"
            shift 2
            ;;
        '--no-pci')
            # Switch to MMIO devices
            device='device'
            shift
            ;;
        '--no-kvm')
            # Do not enable KVM
            no_kvm=1
            shift
            ;;
        '--drive-cache')
            # Use drive cache (writeback)
            dcache=writeback
            shift
            ;;
        '--skip-fsck')
            # Skip rootfs image check
            skip_fsck=1
            shift
            ;;
        --)
            shift
            break
            ;;
        *)
            echo 'Internal error parsing args' >&2
            exit 1
            ;;
        esac
    done
    cmdline+="mem=${ram}M"
    [[ -z "${no_kvm}" ]] && extra_args+='-enable-kvm ' || true
}

setup_qemu_network() {
    if [[ -n "${mac}" ]]; then
        extra_args+="-nic tap,model=virtio-net-${device},mac=${mac} "
    else
        extra_args+="-netdev user,id=net0,hostfwd=tcp::${SSH_PORT_LOCAL}-:${SSH_PORT_VM} "
        extra_args+="-device virtio-net-${device},netdev=net0 "
    fi

    if [[ -n "${cid}" ]]; then
        extra_args+="-device vhost-vsock-${device},id=vsock0,guest-cid=${cid} "
    fi
}

setup_qemu_socket() {
    [[ -z "$1" ]] && error "'setup_qemu_socket()' requires a non-empty string"
    stderr="${RUN_PATH}/${1}-stderr.log"
    extra_args+="-serial pipe:${RUN_PATH}/${1}.serial "
    extra_args+="-chardev socket,id=monitor,path=${RUN_PATH}/${1}.monitor,server=on,wait=off "
    extra_args+='-monitor chardev:monitor '
    mkfifo "${RUN_PATH}/${1}.serial.in" "${RUN_PATH}/${1}.serial.out"
}

cleanup_qemu_socket() {
    [[ -n "$1" ]] &&
        rm -f "${RUN_PATH}/${1}.serial.in" "${RUN_PATH}/${1}.serial.out" \
            "${RUN_PATH}/${1}.monitor" ||
        true
}

print_qemu_output() {
    [[ -n "$1" ]] && print_log_file "${RUN_PATH}/${1}.serial.out" || true
}

check_rootfs_img() {
    [[ -z "$1" ]] && error "'check_rootfs_img()' requires a non-empty string"
    fsck.ext4 -fy "$1" 1>/dev/null 2>"${stderr}" || res=$?
    if [[ "${res}" -gt 2 ]]; then
        log_error "'fsck.ext4' error" "${res}"
        print_log_file "${stderr}"
        cleanup_log_file "${stderr}"
    fi
}

run_qemu() {
    TERM=linux qemu-system-"$(uname -m)" \
        -cpu "${cpu}" -m "${ram}" -smp "${smp}" -M "${machine}" -nographic \
        -kernel "${kernel}" -append "${cmdline}" \
        -drive if=none,id=rootfs,file="${rootfs}",format=raw,cache="${dcache}" \
        -device "virtio-blk-${device}",drive=rootfs \
        -fsdev local,id=fsdev0,path=/data/data,security_model=none \
        -device "virtio-9p-${device}",fsdev=fsdev0,mount_tag=data \
        -device "virtio-rng-${device}" \
        -object acceldev-backend-vaccel,id=rt0 \
        -device "virtio-accel-${device}",id=accel0,runtime=rt0 \
        ${extra_args} 2>"${stderr}"
}

run_cmd() {
    [[ -z "$1" ]] && error "'run_cmd()' requires a non-empty string"
    sleep 1
    ssh -o StrictHostKeyChecking=accept-new -o BatchMode=yes -o LogLevel=ERROR \
        "${SSH_HOST}" -p "${SSH_PORT_LOCAL}" \
        "${1}"' || res=$?; poweroff 2>/dev/null; exit "${res:-0}"'
}

main() {
    parse_args "$@"

    cd /data
    mkdir -p "${RUN_PATH}" data
    chown "$(stat -c %u .)":"$(stat -c %g .)" "${RUN_PATH}" data
    setup_qemu_network
    [[ -n "${qemu_socket}" ]] && setup_qemu_socket "${qemu_socket}"
    [[ -z "${skip_fsck}" ]] && check_rootfs_img "${rootfs}"

    res=0

    if [[ -z "${cmd}" ]]; then
        run_qemu || res=$?
        if [[ "${res}" -ne 0 ]]; then
            log_error "'run_qemu()' error" "${res}"
            print_qemu_output "${qemu_socket}"
            print_log_file "${stderr}"
        fi

        cleanup_qemu_socket "${qemu_socket}"
        cleanup_log_file "${stderr}"
        exit "${res}"
    fi

    if [[ -z "${qemu_socket}" ]]; then
        qemu_socket=qemu-$(date +"%Y%m%d-%H%M%S")
        setup_qemu_socket "${qemu_socket}"
    fi

    run_qemu &
    pid_qemu=$!

    run_cmd "${cmd}" || res=$?
    [[ "${res}" -ne 0 ]] && log_error "'run_cmd()' error" "${res}"
    wait "${pid_qemu}" || res=$?
    if [[ "${res}" -ne 0 ]]; then
        log_error "'run_qemu()' error" "${res}"
        print_qemu_output "${qemu_socket}"
        print_log_file "${stderr}"
    fi

    cleanup_qemu_socket "${qemu_socket}"
    cleanup_log_file "${stderr}"
    exit "${res}"
}

main "$@"
