Name:JALoP-devel
Version:1
Release:1.0.2
ExclusiveArch:x86_64
Summary:JALoP binary installation
License:Apache License, Version 2.0
Requires: JALoP

%description
JALoP development installation

%prep
cd ../BUILD
tar -xf ../SOURCES/jalop-devel.tar

%build
# Do nothing here

%install
mkdir -p %{buildroot}/usr/include/jalop
cp ./src/lmdb_layer/src/*.h		%{buildroot}/usr/include/jalop
cp ./src/lib_common/include/jalop/*.h	%{buildroot}/usr/include/jalop
cp ./src/lib_common/src/*.h		%{buildroot}/usr/include/jalop
cp ./src/network_lib/include/jalop/*.h	%{buildroot}/usr/include/jalop
cp ./src/network_lib/src/*.h		%{buildroot}/usr/include/jalop
cp ./src/producer_lib/include/jalop/*.h	%{buildroot}/usr/include/jalop
cp ./src/producer_lib/src/*.h		%{buildroot}/usr/include/jalop

%files
%dir /usr/include/jalop
/usr/include/jalop/*

%pre

%post

%preun

%postun
