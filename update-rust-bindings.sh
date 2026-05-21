#!/bin/bash
rm -f src/jalop-rust/crates/jalop-sys/src/bindings.rs
sudo bash src/jalop-rust/packages.sh
scons
cp release/src/jalop-rust/crates/jalop-sys/src/bindings.rs src/jalop-rust/crates/jalop-sys/src/bindings.rs
