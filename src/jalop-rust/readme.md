JALoP Inline Filter
===

# setup

The required Rust crates are listed in the packages.sh script.

`sudo ./packages.sh`

There are many transient dependencies that are not linked to their
respective crates, so if a crate is not found on build it may be
that a crate was added and not linked. That requires the developer
to `dnf search` for the crate that cargo is reporting as missing.
So far they have all been available, so select the right version and
add it to the packages.sh script.

It works out well to purge all crates when doing this process to
ensure everything is good, `dnf remove rust-*-devel`, the run your
updated packages.sh.

Sometimes cargo may continue to complain about locked dependencies and
it may require a regeneration of the Cargo.lock: `cargo generate-lockfile`.

# build

`cargo build` for a debug build

`cargo build --release` for an optimized release build

# run

`cargo run -- --help` to see the cli options available
