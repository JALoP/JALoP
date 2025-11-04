#!/bin/bash
#Determine the installed operating system version, this script only supports RHEL9
if ! grep -q -i "release 9" /etc/redhat-release
then
    echo "This script is only supported on RHEL 9."
    exit 1
fi

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root."
    exit 1
fi

echo "Begin generating JALoP cargo vendor files...."
source .gitlab/ci/utils.sh

package_cargo_vendor_files 7
package_cargo_vendor_files 8
package_cargo_vendor_files 9

#clears out vendor-cargo dir
rm -rf ./vendor-cargo

echo "Finished generating RHEL 7/8/9 JALoP cargo vendor files."