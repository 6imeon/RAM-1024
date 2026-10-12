#!/bin/sh
# OpenBSD conformance run (inside a linux/arm64 Debian container; the
# ram-bsd volume caches the release files). OpenBSD ships no VM disk
# images, so the VM is installed unattended with autoinstall(8) from a
# response file; root login is by a throwaway SSH key (no password).
set -eu
V=7.9; S=79
MIRROR=https://cdn.openbsd.org/pub/OpenBSD/$V/arm64
SETS=/bsd/openbsd/pub/OpenBSD/$V/arm64
mkdir -p $SETS
for f in SHA256 SHA256.sig BUILDINFO miniroot$S.img bsd bsd.mp bsd.rd base$S.tgz comp$S.tgz; do
    [ -f $SETS/$f ] || curl -sSfL -o $SETS/$f $MIRROR/$f
done
(cd $SETS && for f in BUILDINFO miniroot$S.img bsd bsd.mp bsd.rd base$S.tgz comp$S.tgz; do
    grep "($f)" SHA256; done > want.sha && sha256sum -c want.sha) || exit 1
(cd $SETS && ls > index.txt)  # the installer lists sets from index.txt

rm -f /root/.ssh/id_ed25519*; mkdir -p /root/.ssh
ssh-keygen -q -t ed25519 -N '' -f /root/.ssh/id_ed25519
cat > /bsd/openbsd/install.conf <<CONF
System hostname = openbsd
Which network interface do you wish to configure = vio0
IPv4 address for vio0 = autoconf
IPv6 address for vio0 = none
Password for root account = *************
Public ssh key for root account = $(cat /root/.ssh/id_ed25519.pub)
Start sshd(8) by default = yes
Do you expect to run the X Window System = no
Setup a user = no
Allow root ssh login = prohibit-password
What timezone are you in = UTC
Which disk is the root disk = sd0
Use (A)uto layout, (E)dit auto layout, or create (C)ustom layout = a
Location of sets = http
HTTP proxy URL = none
HTTP Server = 10.0.2.2:8000
Server directory = pub/OpenBSD/$V/arm64
Set name(s) = -all bsd bsd.mp bsd.rd base$S.tgz comp$S.tgz
Continue without verification = yes
Exit to (S)hell, (H)alt or (R)eboot = R
CONF
mkdir -p /bsd/openbsd && tar -cf /bsd/openbsd/src.tar --exclude=./build --exclude=./results .
(cd /bsd/openbsd && python3 -m http.server 8000 >/dev/null 2>&1 &)
python3 tools/openbsd_vm.py $SETS/miniroot$S.img
