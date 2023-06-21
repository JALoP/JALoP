Name:JALoP
Version:1
Release:1
BuildArch:x86_64
Summary:JALoP binary installation
License:Apache License, Version 2.0
Source:jalop.tar
#Requires:

%description
JALoP binary installation

%prep
#%setup -q
cd ../BUILD
tar -xf ../SOURCES/jalop.tar

%install
mkdir -p %{buildroot}/usr/bin
cp ./release/bin/jal-local-store 	%{buildroot}/usr/bin
cp ./release/bin/jald 			%{buildroot}/usr/bin
cp ./release/bin/jaldb_tail 		%{buildroot}/usr/bin
cp ./release/bin/jaldb_tool 		%{buildroot}/usr/bin
cp ./release/bin/jal_dump 		%{buildroot}/usr/bin
cp ./release/bin/jalp_test 		%{buildroot}/usr/bin
cp ./release/bin/jal_purge 		%{buildroot}/usr/bin

mkdir -p %{buildroot}/usr/lib64
cp ./release/lib/libjal-common.so 	%{buildroot}/usr/lib64
cp ./release/lib/libjal-db.so 		%{buildroot}/usr/lib64
cp ./release/lib/libjal-network.so 	%{buildroot}/usr/lib64
cp ./release/lib/libjal-producer.so 	%{buildroot}/usr/lib64
cp ./release/lib/libjal-utils.so 	%{buildroot}/usr/lib64

mkdir -p %{buildroot}/etc/systemd/system
cp ./test-input/jalls.service		%{buildroot}/etc/systemd/system
cp ./test-input/jalls.socket		%{buildroot}/etc/systemd/system
cp ./test-input/jald.service		%{buildroot}/etc/systemd/system

mkdir -p %{buildroot}/etc/jalop
cp ./test-input/TLS_Unit_Test_Files/cert                        %{buildroot}/etc/jalop
cp ./test-input/TLS_Unit_Test_Files/cert_and_key                %{buildroot}/etc/jalop
cp ./test-input/TLS_Unit_Test_Files/rsa_key                     %{buildroot}/etc/jalop
cp ./test-input/jald.cfg                    %{buildroot}/etc/jalop
cp ./test-input/jalls_service.cfg           %{buildroot}/etc/jalop
cp ./test-input/jald_service.cfg            %{buildroot}/etc/jalop
cp ./test-input/local_store.cfg             %{buildroot}/etc/jalop

mkdir -p %{buildroot}/etc/jalop/schemas
cp ./schemas/*.xsd 			%{buildroot}/etc/jalop/schemas
#cp ./schemas/*.dtd 			%{buildroot}/etc/jalop/schemas
cp ./schemas/externalSchemas/*.xsd 	%{buildroot}/etc/jalop/schemas
cp ./schemas/externalSchemas/*.dtd 	%{buildroot}/etc/jalop/schemas

mkdir -p %{buildroot}/etc/jalop/TLS_CA_Signed/server/trust_store_dir
cp -R ./test-input/TLS_CA_Signed/server/*                 %{buildroot}/etc/jalop/TLS_CA_Signed/server

mkdir -p %{buildroot}/etc/jalop/TLS_CA_Signed/client/trust_store_dir
cp -R ./test-input/TLS_CA_Signed/client/*                 %{buildroot}/etc/jalop/TLS_CA_Signed/client

mkdir -p %{buildroot}/etc/jalop/TLS_CA_Signed/local-store
cp -R ./test-input/TLS_CA_Signed/local-store/*                 %{buildroot}/etc/jalop/TLS_CA_Signed/local-store

mkdir -p %{buildroot}/var/run/jalop/jalls
mkdir -p %{buildroot}/var/log/jalop

%files
/usr/bin/jal-local-store
/usr/bin/jald
/usr/bin/jaldb_tail
/usr/bin/jaldb_tool
/usr/bin/jal_dump
/usr/bin/jalp_test
/usr/bin/jal_purge

/usr/lib64/libjal-common.so
/usr/lib64/libjal-db.so
/usr/lib64/libjal-network.so
/usr/lib64/libjal-producer.so
/usr/lib64/libjal-utils.so

/etc/systemd/system/jalls.service
/etc/systemd/system/jalls.socket
/etc/systemd/system/jald.service

%dir /etc/jalop
/etc/jalop/TLS_CA_Signed/server/*
/etc/jalop/TLS_CA_Signed/client/*
/etc/jalop/TLS_CA_Signed/local-store/*
/etc/jalop/cert
/etc/jalop/cert_and_key
/etc/jalop/rsa_key
/etc/jalop/jald.cfg
/etc/jalop/jalls_service.cfg
/etc/jalop/jald_service.cfg
/etc/jalop/local_store.cfg
/etc/jalop/schemas/*

%dir /var/run/jalop/jalls
%dir /var/log/jalop

%pre
%post
ldconfig
systemctl daemon-reload
setcap cap_chown,cap_dac_override+p /usr/bin/jal-local-store

useradd -M -N -s /sbin/nologin jalls
useradd -M -N -s /sbin/nologin jald
useradd -M -N -s /bin/bash -p $(echo jalpro1 | openssl passwd -1 -stdin) jalpro1
useradd -M -N -s /bin/bash -p $(echo jalpro2 | openssl passwd -1 -stdin) jalpro2
useradd -M -N -s /bin/bash -p $(echo jaltester | openssl passwd -1 -stdin) jaltester

groupadd jalproducer
groupadd jalop

groupmems -g jalproducer -a jalpro1
groupmems -g jalproducer -a jalpro2
groupmems -g jalop 	 -a jalls
groupmems -g jalop 	 -a jald
groupmems -g jalop 	 -a jaltester

chgrp jalop /var/log/jalop
chmod 770   /var/log/jalop

%preun
systemctl stop jalls.service
systemctl stop jald.service
%postun
userdel jalls
userdel jald
userdel jalpro1
userdel jalpro2
userdel jaltester

groupdel jalproducer
groupdel jalop

rm -fr /var/run/jalop
rm -fr /var/log/jalop

