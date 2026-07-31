Name:    JALoP
Version: 2.4.1.0
Release: 1%{?dist}
ExclusiveArch: x86_64
Summary: JALoP binary installation
License: Apache License, Version 2.0
Requires: boost-filesystem
Requires: boost-serialization
Requires: boost-system
Requires: axl
Requires: openssl
Requires: xmlsec1-openssl
Requires: libcurl
Requires: libuuid
Requires: libxml2
Requires: libconfig
Requires: glib2
Requires: apr
Requires: apr-util
Requires: lmdb
Requires: lmdb-libs

%description
JALoP binary installation

%prep
cd ../BUILD
tar -xf ../SOURCES/jalop.tar

%build
# Do nothing here

%install
mkdir -p %{buildroot}/usr/sbin
cp ./release/bin/jal-local-store	%{buildroot}/usr/sbin
cp ./release/bin/jald			%{buildroot}/usr/sbin
cp ./release/bin/jaldb_inline_filter			%{buildroot}/usr/sbin
cp ./release/bin/jald_rs			%{buildroot}/usr/sbin
cp ./release/bin/jal_subscribe		%{buildroot}/usr/sbin
cp ./release/bin/jaldb_tail		%{buildroot}/usr/sbin
cp ./release/bin/jaldb_tool		%{buildroot}/usr/sbin
cp ./release/bin/jal_dump		%{buildroot}/usr/sbin
cp ./release/bin/jalp_test		%{buildroot}/usr/sbin
cp ./release/bin/jal_purge		%{buildroot}/usr/sbin

mkdir -p %{buildroot}/usr/lib64
cp ./release/lib/libjal-common.so	%{buildroot}/usr/lib64
cp ./release/lib/libjal-db.so		%{buildroot}/usr/lib64
cp ./release/lib/libjal-network.so	%{buildroot}/usr/lib64
cp ./release/lib/libjal-producer.so	%{buildroot}/usr/lib64
cp ./release/lib/libjal-utils.so	%{buildroot}/usr/lib64

mkdir -p %{buildroot}/etc/systemd/system
cp ./test-input/SYSTEMD/jalls.service		%{buildroot}/etc/systemd/system
cp ./test-input/SYSTEMD/jalls.socket		%{buildroot}/etc/systemd/system
cp ./test-input/SYSTEMD/jald.service		%{buildroot}/etc/systemd/system
cp ./test-input/SYSTEMD/jald_rs.service		%{buildroot}/etc/systemd/system
cp ./test-input/SYSTEMD/jaldb_inline_filter.service		%{buildroot}/etc/systemd/system
cp ./test-input/SYSTEMD/jal_subscribe.service	%{buildroot}/etc/systemd/system

mkdir -p %{buildroot}/etc/jalop/test-input
cp ./test-input/TLS_Unit_Test_Files/cert		%{buildroot}/etc/jalop
cp ./test-input/TLS_Unit_Test_Files/cert_and_key	%{buildroot}/etc/jalop
cp ./test-input/TLS_Unit_Test_Files/rsa_key		%{buildroot}/etc/jalop
cp ./test-input/jald.cfg				%{buildroot}/etc/jalop
cp ./test-input/jald.toml				%{buildroot}/etc/jalop
cp ./test-input/SYSTEMD/jalls_service.cfg		%{buildroot}/etc/jalop
cp ./test-input/SYSTEMD/jald_service.cfg		%{buildroot}/etc/jalop
cp ./test-input/SYSTEMD/jald_rs_service.cfg		%{buildroot}/etc/jalop
cp ./test-input/SYSTEMD/jaldb_inline_filter_service.cfg		%{buildroot}/etc/jalop
cp ./test-input/SYSTEMD/jal_subscribe_service.cfg	%{buildroot}/etc/jalop
cp ./test-input/sample2.cfg %{buildroot}/etc/jalop/test-input
cp ./test-input/big_payload.txt %{buildroot}/etc/jalop/test-input
cp ./test-input/good_audit_input.xml %{buildroot}/etc/jalop/test-input

mkdir -p %{buildroot}/etc/jalop/schemas
cp ./schemas/*.xsd			%{buildroot}/etc/jalop/schemas
cp ./schemas/externalSchemas/*.xsd	%{buildroot}/etc/jalop/schemas
cp ./schemas/externalSchemas/*.dtd	%{buildroot}/etc/jalop/schemas

mkdir -p %{buildroot}/etc/jalop/TLS_CA_Signed/server/trust_store_dir
cp -R ./test-input/TLS_CA_Signed/server/*		%{buildroot}/etc/jalop/TLS_CA_Signed/server

mkdir -p %{buildroot}/etc/jalop/TLS_CA_Signed/client/trust_store_dir
cp -R ./test-input/TLS_CA_Signed/client/*		%{buildroot}/etc/jalop/TLS_CA_Signed/client

mkdir -p %{buildroot}/etc/jalop/TLS_CA_Signed/local-store
cp -R ./test-input/TLS_CA_Signed/local-store/*		%{buildroot}/etc/jalop/TLS_CA_Signed/local-store

mkdir -p %{buildroot}/var/run/jalop/jalls
mkdir -p %{buildroot}/var/run/jalop/jald/socket

mkdir -p %{buildroot}/var/log/jalop
mkdir -p %{buildroot}/var/log/jalop/db-data
mkdir -p %{buildroot}/var/log/jalop/db-logs


mkdir -p %{buildroot}/var/log/jalop_sub
mkdir -p %{buildroot}/var/log/jalop_sub/db-data
mkdir -p %{buildroot}/var/log/jalop_sub/db-logs


%files
/usr/sbin/jal-local-store
/usr/sbin/jald
/usr/sbin/jald_rs
/usr/sbin/jaldb_inline_filter
/usr/sbin/jal_subscribe
/usr/sbin/jaldb_tail
/usr/sbin/jaldb_tool
/usr/sbin/jal_dump
/usr/sbin/jalp_test
/usr/sbin/jal_purge

/usr/lib64/libjal-common.so
/usr/lib64/libjal-db.so
/usr/lib64/libjal-network.so
/usr/lib64/libjal-producer.so
/usr/lib64/libjal-utils.so

/etc/systemd/system/jalls.service
/etc/systemd/system/jalls.socket
/etc/systemd/system/jald.service
/etc/systemd/system/jald_rs.service
/etc/systemd/system/jaldb_inline_filter.service
/etc/systemd/system/jal_subscribe.service

%dir /etc/jalop
/etc/jalop/TLS_CA_Signed/server/*
/etc/jalop/TLS_CA_Signed/client/*
/etc/jalop/TLS_CA_Signed/local-store/*
/etc/jalop/cert
/etc/jalop/cert_and_key
/etc/jalop/rsa_key
/etc/jalop/jald.cfg
/etc/jalop/jald.toml
/etc/jalop/jalls_service.cfg
/etc/jalop/jald_service.cfg
/etc/jalop/jald_rs_service.cfg
/etc/jalop/jaldb_inline_filter_service.cfg
/etc/jalop/jal_subscribe_service.cfg
/etc/jalop/schemas/*
/etc/jalop/test-input/*

%dir /var/run/jalop/jalls
%dir /var/run/jalop/jald/socket
%dir /var/log/jalop
%dir /var/log/jalop_sub
%dir /var/log/jalop_sub/db-data
%dir /var/log/jalop_sub/db-logs
%dir /var/log/jalop/db-data
%dir /var/log/jalop/db-logs

%pre
%post
ldconfig
systemctl daemon-reload
setcap cap_chown,cap_dac_override+p /usr/sbin/jal-local-store

useradd -M -N -s /sbin/nologin jalls
useradd -M -N -s /sbin/nologin jald
useradd -M -N -s /sbin/nologin jaldb_inline_filter
useradd -M -N -s /sbin/nologin jal_subscribe
useradd -M -N -s /bin/bash -p $(echo jalpro1 | openssl passwd -1 -stdin) jalpro1
useradd -M -N -s /bin/bash -p $(echo jalpro2 | openssl passwd -1 -stdin) jalpro2
useradd -M -N -s /bin/bash -p $(echo jaltester | openssl passwd -1 -stdin) jaltester

groupadd jalproducer
groupadd jalop

groupmems -g jalproducer	-a jalpro1
groupmems -g jalproducer	-a jalpro2
groupmems -g jalop		-a jalls
groupmems -g jalop		-a jald
groupmems -g jalop		-a jaldb_inline_filter
groupmems -g jalop		-a jal_subscribe
groupmems -g jalop		-a jaltester

chgrp -R jalop /var/run/jalop
chmod -R 771 /var/run/jalop

chgrp jalop /var/log/jalop
chmod 770   /var/log/jalop
chgrp jalop /var/log/jalop_sub
chmod 770   /var/log/jalop_sub

chown jalls:jalop /var/log/jalop/db-data
chmod 750   /var/log/jalop/db-data
chown jal_subscribe:jalop /var/log/jalop_sub/db-data
chmod 750   /var/log/jalop_sub/db-data

chown jalls:jalop /var/log/jalop/db-logs
chmod 700   /var/log/jalop/db-logs
chown jal_subscribe:jalop /var/log/jalop_sub/db-logs
chmod 700   /var/log/jalop_sub/db-logs

chmod 755 /usr/sbin/jal*
chmod 755 /usr/lib64/libjal-*

#systemctl enable jalls.service
#systemctl enable jald.service
#systemctl enable jal_subscribe.service

#systemctl start jalls.service
#systemctl start jald.service
#systemctl start jal_subscribe.service

%preun
systemctl stop jalls.service
systemctl stop jaldb_inline_filter.service
systemctl stop jald.service
systemctl stop jal_subscribe.service
%postun
userdel jalls
userdel jald
userdel jaldb_inline_filter
userdel jal_subscribe
userdel jalpro1
userdel jalpro2
userdel jaltester

groupdel jalproducer
groupdel jalop

rm -fr /var/run/jalop
rm -fr /var/log/jalop
rm -fr /var/log/jalop_sub
