#!/bin/sh
scons install --prefix=/usr --libdir=/usr/lib64 -j4

#Install Rust binaries
cp -f release/bin/jaldb_inline_filter /usr/sbin/jaldb_inline_filter
cp -f release/bin/jald_rs /usr/sbin/jald_rs

#Install JALoP schemas
echo "Installing JALoP schemas to /usr/share/jalop/schemas..."
rm -rf /usr/share/jalop/schemas/
mkdir -p /usr/share/jalop/schemas/
cp -rf ./schemas/* /usr/share/jalop/schemas/  || echo "Error: failed to copy JALoP schemas"
echo "Successfully installed JALoP schemas."
