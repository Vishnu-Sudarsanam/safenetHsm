#!/bin/bash
# uninstall script for PTK K7 driver for PSI-E3

PACKAGE_VERSION=7.2.1

dkms remove k7/$PACKAGE_VERSION --all

rmmod k7

echo ""
echo "Uninstallation of the k7-$PACKAGE_VERSION driver completed."
echo ""

