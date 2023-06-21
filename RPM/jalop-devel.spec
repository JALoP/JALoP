Name:JALoP-devel
Version:1
Release:1
BuildArch:x86_64
Summary:JALoP binary installation
License:Apache License, Version 2.0
Source:jalop-devel.tar
Requires: JALoP

%description
JALoP development installation

%prep
#%setup -q
cd ../BUILD
tar -xf ../SOURCES/jalop-devel.tar

%install
mkdir -p %{buildroot}/usr/include/jalop
cp ./src/db_layer/src/*.h               %{buildroot}/usr/include/jalop
cp ./src/lib_common/include/jalop/*.h 	%{buildroot}/usr/include/jalop
cp ./src/lib_common/src/*.h 		%{buildroot}/usr/include/jalop
cp ./src/network_lib/include/jalop/*.h	%{buildroot}/usr/include/jalop
cp ./src/network_lib/src/*.h 		%{buildroot}/usr/include/jalop
cp ./src/producer_lib/include/jalop/*.h %{buildroot}/usr/include/jalop
cp ./src/producer_lib/src/*.h 		%{buildroot}/usr/include/jalop

%files
%dir /usr/include/jalop
/usr/include/jalop/*

%pre

%post

%preun

%postun
