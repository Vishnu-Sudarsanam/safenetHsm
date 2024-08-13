#!/bin/bash
export MOK_PRIV="${MOK_PRIV:-/root/MOK/MOK.priv}"
export MOK_PUB="${MOK_PUB:-/root/MOK/MOK.der}"
#Ubuntu also creates a MOK key in /var/lib/shim-signed/mok
if [ ! -f "$MOK_PRIV" ] || [ ! -f "$MOK_PUB" ]; then
  echo "WARN: Module signing disabled - MOK files not found" > /dev/stderr
  exit 0
fi

export MODULE_NAME=k7.ko
export PACKAGE_VERSION=7.2.1
export MODULE_DIR="/var/lib/dkms/k7/$PACKAGE_VERSION/$kernelver/$arch/module"
export MODULE_FILE=$MODULE_DIR/$MODULE_NAME

echo "Signing module k7 $PACKAGE_VERSION using $MOK_PRIV" > /dev/tty
#Different distros expect/work with a compressed kernel module.
#e.g. CentOS uses a compressed file while Ubuntu does not.
#Since we need a decompressed module to sign, try decompressing first
if [ -f "$MODULE_FILE.xz" ]; then
  unxz -qq "$MODULE_FILE.xz"
fi
/lib/modules/$kernelver/build/scripts/sign-file sha512 "$MOK_PRIV" "$MOK_PUB" "$MODULE_FILE"
#For those distributions that expect a compressed file with the signed
#kernel module, create it here. Keep the decompressed file as well.
xz -fk "$MODULE_FILE"
