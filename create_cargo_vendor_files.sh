#!/bin/bash
#Determine the installed operating system version, this script only supports RHEL9 or RHEL10
if grep -q -i "release 10" /etc/redhat-release
then
    OS_VER=10;
elif grep -q -i "release 9" /etc/redhat-release
then
    OS_VER=9;
else
    echo "This script is only supported on RHEL 9 or 10."
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root."
    exit 1
fi

function package_cargo_vendor_files() {
    target_rhel_version=$1
    vendor_tar=vendor-cargo-$target_rhel_version.tar.gz
    dnf remove -y rust-*-devel
    rm -rf /usr/share/cargo/registry/
    mkdir -p /usr/share/cargo/registry
    sh src/jalop-rust/packages.sh $target_rhel_version
    vendor_dest=vendor-cargo/vendor
    rm -rf ${vendor_dest}
    mkdir -p ${vendor_dest}
    cp -r /usr/share/cargo/registry/* ${vendor_dest}
    vendor_root=$(dirname ${vendor_dest})
    tar czf ${vendor_tar} -C ${vendor_root} .
    du -sh ${vendor_tar}
}

echo "Begin generating JALoP cargo vendor files...."

package_cargo_vendor_files 7
package_cargo_vendor_files 8
package_cargo_vendor_files 9
package_cargo_vendor_files 10

#clears out vendor-cargo dir
rm -rf ./vendor-cargo

echo "Finished generating RHEL 7/8/9/10 JALoP cargo vendor files."