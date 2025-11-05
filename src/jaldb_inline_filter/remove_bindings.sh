#!/usr/bin/env bash
RHEL_VERSION=$(source /etc/os-release && echo ${VERSION_ID%%.*})
destPath="$1"
if [[ "$RHEL_VERSION" == "9" ]]; then
	rm -f "$destPath/sys/src/bindings.rs"
fi