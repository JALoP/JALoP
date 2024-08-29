#!/bin/bash

# This is a script which automates checksec on jalop artifacts.
#   Eventually we would like to increase the scope of what this script
#   assesses to include validating the other 'columns'.
#   Right now, only the RPATH value is validated assessed for pass/fail.

echo "Checking local release builds."
# These are the local target directories for built artifacts
#   by developers.
local_dirs=("release/bin" "release/lib" "debug/bin" "debug/lib")
for dir in "${local_dirs[@]}"
do
    for lib in ../../../"$dir"/*
    do
        result="$(checksec --file="$lib")"
        # if "No RPATH" exists in the output of checksec, then that is a
        #   whitelist for not having the rpath vulnerability
        if [[ $result != *"No RPATH"* ]]; then
            echo "$result"
        else
            echo "$lib has no rpath problems."
        fi
    done
done
echo "Done checking local release builds."

echo "Checking system builds..."
# These are the directories where jalop
#   artifacts are located for general system use.
system_dirs=("/usr/sbin/jal" "/usr/lib64/libjal")
for dir in "${system_dirs[@]}"
do
    for lib in "$dir"*
    do
        result="$(checksec --file="$lib")"
        if [[ $result != *"No RPATH"* ]]; then
            echo "$result"
        else
            echo "$lib has no rpath problems"
        fi
    done
done
echo "Done checking system builds."
