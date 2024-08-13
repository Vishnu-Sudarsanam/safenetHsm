#!/bin/bash
# install script for PTK K7 driver for PSI-E3

PACKAGE_VERSION=7.2.1

dkms install -m k7/$PACKAGE_VERSION > /dev/null

if [ $? -eq 0 ]
then
  modprobe k7
  echo ""
  echo "Installation of the k7-$PACKAGE_VERSION driver completed."
  echo ""
else
  echo ""
  echo "Installation of the k7-$PACKAGE_VERSION driver returned an error ($?)."
  echo ""
fi
