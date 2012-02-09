/**
 * @section LICENSE
 *
 * Source code in 3rd-party is licensed and owned by their respective
 * copyright holders.
 *
 * All other source code is copyright Tresys Technology and licensed as below.
 *
 * Copyright (c) 2012 Tresys Technology LLC, Columbia, Maryland, USA
 *
 * This software was developed by Tresys Technology LLC
 * with U.S. Government sponsorship.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/** \mainpage JALoP Reference Implmentation
 *
 * \section intro_sec Introduction
 *
 * The JALoP Reference Implementation is divided into a number of components:
 *  - \subpage page_jnl
 *  - \subpage page_jpl
 *  - Reference Implementation of a JALoP Local Store
 *  - Reference Implementations of JALoP Network Stores
 *  - Variety of tools for accessing the records in the database used by the
 *  JALoP Network and Local Stores.
 *
 * \subsection jnl JALoP Network Library (JNL)
 * The JNL provides a callback driven library that can used to connect to
 * other JALoP peers using the JALoP/BEEP network protocol. More details can be
 * found at \ref page_jnl
 *
 * \subsection jpl JALoP Producer Library (JPL)
 * The JPL is a library that applications may use to generate application
 * metadata and send records to a JALoP Local Store. More details can be found
 * at \ref page_jpl.
 *
 * \subsection local_store JALoP Local Store
 * A reference implementation of a JALoP Local Store is included in this
 * package. The JALoP Local Store accepts JALoP records from applications
 * running on the same machine, generate the system metadata, and stores
 * the records in a database. Typically, a JALoP Local Store shares its
 * database with one or more JALoP Network Stores so that these records may be
 * transfered of the local machine, to another machine, using the JALoP Network
 * Protocol.
 *
 * \subsection net_stores JALoP Network Stores
 * The JALoP Network Stores provide the ability to listen for incoming
 * JALoP/BEEP connections, or initiate a JALoP/BEEP connections.
 * connections. The \p jald program is a daemon that listens for connections.
 * The \p jal_subscribe program is a process that will connect to a remote
 * JALoP Network Store (like \p jald) and subscribe (fetch) JALoP records from
 * the remote. The \p jal_publish program is a process that will connect to a
 * remote JALoP Network Store (like \p jald) and publish (send) JALoP records.
 *
 * \subsection utils Utilities
 * The reference implementation comes with a number of utilities for inspecting
 * the database and sending records to the JALoP Local Store.
 *  - \p jalp_test: This is a development tool that can send journal, audit, or
 *  log data to a local store. It is primarily used to test the JPL.
 *  - \p jal_dump: This utility can be used to retrieve records from the database
 *  using the serial ID
 *
 *  With the exception of \p jalp_test (since this is really a development tool),
 *  *NIX man pages are provided for the various utilities and configuration files.
 *  They can be accessed in the source under doc/man/, or post-installation under
 *  <prefix>/share/man/.
 *
 * \section install_sec Installation
 *
 * \subsection step1 Step 1: Requirements
 *
 * The libraries that this reference implementation relies on must already be
 * installed, either from the included RPMs, source, or your platforms package
 * management tools.
 *
 * The JALoP Reference Implementation requires the following packages to be
 * installed:
 *  - OpenSSL to generate SHA256 digests and handle TLS negotiation
 *  - Vortex/AXL for BEEP over TCP.
 *  - Xerces-C++ to generate the application  metadata and perform schema
 *    validation of audit records, application metadata, and system metadat.
 *  - Santaurio to add a RSA+SHA256 signature to the application and system metadata.
 *  - Libuuid to generate a UUID that is added to the application and system metadata.
 *  - libconfig for configuration file parsing.
 *  - Berkeley DB XML & Berkeley DB for storing JALoP records.
 *  - XQuilla for XQuery 1.0 and XPath 2.0 support within Berkeley DB XML.
 *  - test_dept (for running unit tests)
 *
 * RPMs are provided for some of the packages under the 3rd-party directory:
 *  - Xerces-C
 *  - Santurio - included in the repository
 *  - Vortex/AXL
 *  - XQuilla
 *  - Berkeley DB XML
 *  - libconfig
 *
 *  \subsection step2 Step 2: Building
 *
 *  The library uses the scons build system. All of the libraries
 *  can be built from the top level of the repository by typing 'scons' at
 *  the command prompt.
 *
 *  Unit tests should be run to ensure the library works as expected
 *  on the desired platform. This can be done by typing 'scons tests' from the top
 *  level command prompt.
 *
 *  \subsection step3 Step 3: installing
 *
 *  After building the library and verifying it works as expected
 *  it can be installed by typing 'scons install' at the command prompt. By
 *  default, the library and utilities are installed to under the /usr/local/
 *  prefix, you may wish to customize this to match your system.
 *
 *  A prefix path can be specified by passing --prefix=\<path\> to scons install.
 *  The prefix path must be absolute. Executing 'scons --help' will give a full
 *  list of options that can be used to customize the installation.
 *
 */
