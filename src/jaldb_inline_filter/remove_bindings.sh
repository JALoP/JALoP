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

RHEL_VERSION=$(source /etc/os-release && echo ${VERSION_ID%%.*})
destPath="$1"
if [[ "$RHEL_VERSION" == "9" ]]; then
	rm -f "$destPath/sys/src/bindings.rs"
fi