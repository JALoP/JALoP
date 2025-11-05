#!/usr/bin/env bash

HOST_RHEL_VERSION=$(source /etc/os-release && echo ${VERSION_ID%%.*})
RHEL_VERSION=${1:-$HOST_RHEL_VERSION}

common_pkgs="
rust
cargo
clippy
rustfmt
clang
rust-anstream-devel
rust-anstyle-query-devel
rust-anyhow-devel
rust-assert_matches-devel
rust-async-trait-devel
rust-bindgen0.69-devel
rust-chrono-devel
rust-env_logger-devel
rust-futures-devel
rust-futures-util-devel
rust-humantime-devel
rust-iana-time-zone-devel
rust-jiff-devel
rust-libc-devel
rust-libloading-devel
rust-nix0.29-devel
rust-log-devel
rust-memoffset-devel
rust-prettyplease-devel
rust-serde-devel
rust-slab-devel
rust-signal-hook-devel
rust-thiserror-devel
rust-tokio+full-devel
rust-tokio-util-devel
rust-which4-devel
"
echo "installing dependencies for RHEL$RHEL_VERSION ..."

if [[ "$RHEL_VERSION" == "9" ]]; then

    dnf install -y $common_pkgs \
                   rust-clap-devel rust-clap_derive-devel rust-clap_builder-devel rust-strsim-devel \
                   rust-nom-devel

elif [[ "$RHEL_VERSION" == "8" ]]; then

    dnf install -y $common_pkgs \
                   rust-clap-devel rust-clap_derive-devel rust-clap_builder-devel rust-strsim-devel \
                   rust-nom7-devel rust-regex-devel rust-aho-corasick-devel

elif [[ "$RHEL_VERSION" == "7" ]]; then

    yum install -y $common_pkgs \
                   rust-clap-devel-4.4.7 rust-clap_derive-devel-4.4.7 rust-clap_builder-devel-4.4.7 rust-strsim-devel-0.10.0 \
                   rust-nom7-devel rust-regex-devel rust-aho-corasick-devel

else
    echo "**Unsupported RHEL Version: $RHEL_VERSION"
    exit 1
fi
