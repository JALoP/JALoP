Name:      JALoP-rust-deps
Version:   2.4.1.0
Release:   1%{?dist}
Summary:   JALoP Rust Dependencies

License:   Apache License, Version 2.0
BuildArch: x86_64
Source0:   vendor-cargo.tar.gz

Requires:  rust, cargo, clang-devel

%description
This RPM installs all of the Rust crates under /usr/share/cargo/registry

%global debug_package %{nil}

%prep
%setup -q -n vendor

%build
# Nothing to do here

%install
mkdir -p %{buildroot}/usr/share/cargo/registry
cp -a * %{buildroot}/usr/share/cargo/registry/

%files
%defattr(-,root,root,-)
/usr/share/cargo/registry

%changelog
* Tue Jul 21 2026 Matt Cafasso <cafassom@ctc.com> - 2.4.1.0-1
- Added the Rust Publisher
* Wed Apr 22 2026 Matt Cafasso <cafassom@ctc.com> - 2.4.0.0-1
- Updated for 2.4.0.0-1 for RHEL 10 support
* Wed Mar 18 2026 Matt Cafasso <cafassom@ctc.com> - 2.3.1.0-3
- Updated for 2.3.1.0-3 for RHEL 10 support
* Mon Dec 22 2025 Matt Cafasso <cafassom@ctc.com> - 2.3.1.0-2
- Updated for 2.3.1.0-2 production release for inline filter
* Tue Oct 21 2025 Matt Cafasso <cafassom@ctc.com> - 2.3.1.0
- Updated for 2.3.1.0 beta release for inline filter
* Tue Jul 22 2025 Jeremy Snyder <snyderj@ctc.com> - 0.0.1
- Initial package
