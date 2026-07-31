#!/bin/sh
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root."
    exit 1
fi

rm -f /usr/lib64/libjal-*.so
rm -f /usr/sbin/jald
rm -f /usr/sbin/jaldb_inline_filter
rm -f /usr/sbin/jaldb_tail
rm -f /usr/sbin/jaldb_tool
rm -f /usr/sbin/jald_rs
rm -f /usr/sbin/jal_dump
rm -f /usr/sbin/jal-local-store
rm -f /usr/sbin/jalp_test
rm -f /usr/sbin/jal_purge
rm -f /usr/sbin/jal_sub_cpp
rm -f /usr/sbin/jal_subscribe

rm -rf /usr/share/jalop/schemas/
echo "Successfully uninstalled JALoP."
