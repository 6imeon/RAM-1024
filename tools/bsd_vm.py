"""Boot a BSD VM image in QEMU (serial console), copy this source tree in
over HTTP, build with the system compiler and run the conformance test.
Runs inside a Debian container (tools/crossplatform.sh job freebsd-*).

    python3 bsd_vm.py IMAGE.qcow2 USER 'COMMANDS'
"""

import os
import re
import subprocess
import sys
import time

img, user, cmds = sys.argv[1], sys.argv[2], sys.argv[3]
qemu = subprocess.Popen(
    ["qemu-system-aarch64", "-M", "virt", "-cpu", "max", "-smp", "4", "-m", "3072",
     "-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd", "-snapshot",
     "-drive", "if=virtio,file=%s" % img, "-nic", "user,model=virtio-net-pci",
     "-nographic"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
os.set_blocking(qemu.stdout.fileno(), False)
buf = b""


def expect(pattern, timeout):
    global buf
    end = time.time() + timeout
    rx = re.compile(pattern.encode())
    while time.time() < end:
        chunk = qemu.stdout.read()
        if chunk:
            sys.stdout.write(chunk.decode("utf-8", "replace"))
            sys.stdout.flush()
            buf += chunk
            m = rx.search(buf)
            if m:
                buf = buf[m.end():]
                return m
        else:
            time.sleep(0.2)
    raise SystemExit("\ntimeout waiting for %r" % pattern)


def send(s):
    qemu.stdin.write(s.encode() + b"\n")
    qemu.stdin.flush()


try:
    expect(r"login: ", 1800)
    send(user)
    expect(r"[#$] $", 120)
    send("sh")
    expect(r"[#$] $", 60)
    # printf builds the marker, so the echoed command line never matches it
    send("PS1='VM> '; " + cmds + "; printf 'RAM_%s=%d\\n' EXIT $?")
    code = int(expect(r"RAM_EXIT=(\d+)", 3600).group(1))
finally:
    qemu.kill()
print("\nVM exit status", code)
sys.exit(code)
