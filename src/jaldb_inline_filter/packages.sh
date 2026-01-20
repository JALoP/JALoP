#!/usr/bin/env bash

# Copyright (C) 2025 Concurrent Technologies Corporation.
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
rust-toml-devel
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
rust-libseccomp-devel
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

    dnf install --nobest -y $common_pkgs \
                   rust-clap-devel rust-clap_derive-devel rust-clap_builder-devel rust-strsim-devel \
                   rust-nom-devel rust-toml_parser-devel

elif [[ "$RHEL_VERSION" == "8" ]]; then

    dnf install --nobest -y $common_pkgs \
                   rust-clap-devel rust-clap_derive-devel rust-clap_builder-devel rust-strsim-devel \
                   rust-nom7-devel rust-regex-devel rust-aho-corasick-devel rust-toml_parser-devel

elif [[ "$RHEL_VERSION" == "7" ]]; then
    yum remove -y rust-toml-devel rust-toml_parser-devel
    yum install --nobest -y $common_pkgs \
                   rust-clap-devel-4.4.7 rust-clap_derive-devel-4.4.7 rust-clap_builder-devel-4.4.7 rust-strsim-devel-0.10.0 \
                   rust-nom7-devel rust-regex-devel rust-aho-corasick-devel rust-toml-devel-0.9.5 rust-toml_parser-devel-1.0.2 \
                   rust-serde_spanned-devel-1.0.0 rust-toml_datetime-devel-0.7.0

else
    echo "**Unsupported RHEL Version: $RHEL_VERSION"
    exit 1
fi
