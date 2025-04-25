#!/bin/sh
scons install --bdb --prefix=/usr --libdir=/usr/lib64 -j4

#Install JALoP schemas
echo "Installing JALoP schemas to /usr/share/jalop/schemas..."
rm -rf /usr/share/jalop/schemas/
mkdir -p /usr/share/jalop/schemas/
cp -rf ./schemas/* /usr/share/jalop/schemas/  || echo "Error: failed to copy JALoP schemas"
echo "Successfully installed JALoP schemas."
