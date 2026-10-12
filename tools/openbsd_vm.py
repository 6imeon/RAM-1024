"""Install OpenBSD with autoinstall(8) in QEMU, boot it, and run the
conformance test over SSH (see tools/openbsd_check.sh)."""

import os
import re
import subprocess
import sys
import time

miniroot = sys.argv[1]
disk = "/tmp/openbsd.qcow2"
subprocess.check_call(["qemu-img", "create", "-q", "-f", "qcow2", disk, "12G"])
qemu = subprocess.Popen(
    ["qemu-system-aarch64", "-M", "virt", "-cpu", "cortex-a72", "-smp", "4", "-m", "3072",
     "-bios", "/usr/share/qemu-efi-aarch64/QEMU_EFI.fd",
     "-drive", "if=virtio,file=%s" % disk,
     "-drive", "if=virtio,format=raw,snapshot=on,file=%s" % miniroot,
     "-nic", "user,model=virtio-net-pci,hostfwd=tcp::2222-:22", "-nographic"],
    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
os.set_blocking(qemu.stdout.fileno(), False)
buf = b""


def pump():
    global buf
    chunk = qemu.stdout.read()
    if chunk:
        sys.stdout.write(chunk.decode("utf-8", "replace"))
        sys.stdout.flush()
        buf += chunk
    else:
        time.sleep(0.2)


def send(s):
    qemu.stdin.write(s.encode() + b"\n")
    qemu.stdin.flush()


ANSWERS = [  # installer prompts before the response file takes over
    (rb"\(I\)nstall, \(U\)pgrade, \(A\)utoinstall or \(S\)hell\? $", "a"),
    (rb"Response file location\? \[[^\]]*\] $", "http://10.0.2.2:8000/install.conf"),
    (rb"initial DHCP request\? \[[^\]]*\] $", "vio0"),
]
try:
    end = time.time() + 7200
    installed = False
    while time.time() < end:
        pump()
        for rx, ans in ANSWERS:
            m = re.search(rx, buf)
            if m:
                buf = buf[m.end():]
                send(ans)
        if re.search(rb"CONGRATULATIONS", buf):
            installed = True
        if installed and re.search(rb"login: ", buf):
            break
        if re.search(rb"(failed|ERROR|Please answer)", buf) and not installed:
            m = re.search(rb".*(failed|ERROR|Please answer).*", buf)
            print("\ninstaller problem:", m.group(0)[:200])
            buf = b""
    else:
        raise SystemExit("timeout installing/booting OpenBSD")
    ssh = ["ssh", "-p", "2222", "-o", "StrictHostKeyChecking=no",
           "-o", "UserKnownHostsFile=/dev/null", "root@127.0.0.1"]
    cmd = ("uname -srm; cd /tmp && ftp -V -o src.tar http://10.0.2.2:8000/src.tar && "
           "mkdir w && cd w && tar -xf ../src.tar && "
           "for d in '' -DRAM_NO_SIMD -DRAM_RESEARCH; do echo \"== cc -O2 $d\"; "
           "cc -std=c99 -O2 -Wall -Wextra -Werror $d -o t csrc/ram_test.c csrc/ram1024.c "
           "-lpthread && ./t tests/kat.txt tests/kat_pwhash.txt || exit 1; done")
    for _ in range(30):
        r = subprocess.run(ssh + [cmd])
        if r.returncode != 255:  # 255 = ssh could not connect yet
            break
        time.sleep(10)
    code = r.returncode
finally:
    qemu.kill()
print("VM exit status", code)
sys.exit(code)
