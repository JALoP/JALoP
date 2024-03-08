Name:JALoP-devel
Version:2
Release:1.0.1
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
# Nothing to do here

%install
mkdir -p %{buildroot}/usr/include/jalop
cp ./src/db_layer/src/*.h		%{buildroot}/usr/include/jalop
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
