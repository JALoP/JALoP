#!/bin/sh
if [[ $(scons doc 2>&1 | grep ": warning" | wc -l) != 0 ]]; then
	echo -e "ERROR: Doxygen warnings detected, failing CI build.\n"
	exit 1
else
	exit 0
fi