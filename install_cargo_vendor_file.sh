#!/bin/bash
logError()
{
    currErrMsg="$1"
    echo "$currErrMsg"
    exit 1
}

if [ "$(id -u)" != "0" ]; then
    logError "This script must be run as root."
fi

#Installs the JALoP vendor cargo tar file for the current OS
#The file vendor-cargo-<rhel version>.tar.gz (ex: vendor-cargo-9.tar.gz) must exist in the same
#directory as this script.
if grep -q -i "release 8" /etc/redhat-release
then
   OS_VER="8"
elif grep -q -i "release 9" /etc/redhat-release
then
   OS_VER="9"
elif grep -q -i "release 10" /etc/redhat-release
then
   OS_VER="10"
else
   logError "Unsupported OS version detected."
fi

#Checks to ensure vendor file is present
vendorFile="vendor-cargo-${OS_VER}.tar.gz"
if [ ! -f "$vendorFile" ]; then
    logError "The following JALoP cargo dependency vendor file: $vendorFile must be present in the same directory as this script."
fi

echo "Begin installing JALoP cargo vendor files for RHEL ${OS_VER}...."
sudo yum install -y rust cargo || logError "Failed to install rust and cargo."

rm -rf /usr/share/cargo/registry
mkdir -p /usr/share/cargo/registry || logError "Failed to create /usr/share/cargo/registry"

#extracts and installs vendor file
sudo tar xvzf "$vendorFile" --strip-components=2 -C "/usr/share/cargo/registry" || logError "Failed to extract $vendorFile to /usr/share/cargo/registry"

echo "Finished install JALop cargo vendor files."