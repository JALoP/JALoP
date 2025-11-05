#!/bin/bash
rm -f src/jaldb_inline_filter/sys/src/bindings.rs
sudo bash src/jaldb_inline_filter/packages.sh
scons
cp release/src/jaldb_inline_filter/sys/src/bindings.rs src/jaldb_inline_filter/sys/src/bindings.rs
