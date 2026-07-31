#!/bin/bash

#Determine the installed operating system version
if grep -q -i "release 10" /etc/redhat-release
then
    OS_VER=10;
elif grep -q -i "release 9" /etc/redhat-release
then
    OS_VER=9;
elif grep -q -i "release 8" /etc/redhat-release
then
    OS_VER=8;
else
    echo "This script is only supported on RHEL 8, 9 or 10."
    exit 1
fi

function build_jalop_rust_deps_rpm() {
    vendor_tarball="vendor-cargo-${OS_VER}.tar.gz"

    if [ ! -f "$vendor_tarball" ]; then
        echo "Missing $vendor_tarball file required to build rpm."
        exit 1
    fi
    rpm_folder=".tmp-rust-rpm"
    rm -rf $rpm_folder
    mkdir -p $rpm_folder/{BUILD,RPMS,SOURCES,SPECS}
    spec_file="$rpm_folder/SPECS/jalop-rust-deps.spec"
    cp RPM/jalop-rust-deps.spec $spec_file
    cp $vendor_tarball $rpm_folder/SOURCES/vendor-cargo.tar.gz
    rpmbuild -ba $spec_file --define "_topdir $(pwd)/$rpm_folder"
    cp $rpm_folder/RPMS/x86_64/*.rpm ./RPM/
}

build_jalop_rust_deps_rpm