#!/usr/bin/env bash

# Copyright (C) 2026 Concurrent Technologies Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
rust-clap_builder-devel
rust-clap-devel
rust-clap_derive-devel
rust-digest0.10-devel
rust-env_logger-devel
rust-futures-devel
rust-futures-util-devel
rust-getrandom-devel
rust-humantime-devel
rust-hyper-tls-devel
rust-iana-time-zone-devel
rust-jiff-devel
rust-libc-devel
rust-libloading-devel
rust-libseccomp-devel
rust-log-devel
rust-memoffset-devel
rust-mime_guess-devel
rust-nix0.29-devel
rust-nom-devel
rust-rustls-pki-types-devel
rust-prettyplease-devel
rust-reqwest-devel
rust-serde-devel
rust-serde_bytes-devel
rust-sha2_0.10-devel
rust-sha2-devel
rust-slab-devel
rust-signal-hook-devel
rust-strsim-devel
rust-thiserror-devel
rust-tokio+full-devel
rust-tokio-util-devel
rust-toml-devel
rust-toml_parser-devel
rust-which4-devel
rust-winnow-devel
rust-uuid-devel
rust-zeroize-devel
"
echo "installing dependencies for RHEL$RHEL_VERSION ..."

if [[ "$RHEL_VERSION" == "10" ]]; then

    dnf install -y $common_pkgs

elif [[ "$RHEL_VERSION" == "9" ]]; then

    dnf install -y $common_pkgs
elif [[ "$RHEL_VERSION" == "8" ]]; then

    dnf install -y $common_pkgs
else
    echo "**Unsupported RHEL Version: $RHEL_VERSION"
    exit 1
fi
