#!/bin/sh

KERNEL=$1

qemu-system-x86_64 \
    -enable-kvm \
    -smp 2 \
    -m 1024 \
    -kernel "$KERNEL" \
    -append "console=ttyS0 root=/dev/sda nokaslr" \
    -nographic \
    -no-reboot \
    -drive file=wheezy.img,format=raw \
    -net nic -net user,hostfwd=tcp::10022-:22
