Name:           fstec-client
Version:        0.1.0
Release:        1%{?dist}
Summary:        FSTEC service desktop client
License:        Proprietary
BuildArch:      x86_64

%description
Local TLS proxy launcher for the FSTEC service web interface.

%install
install -Dm755 %{_sourcedir}/fstec-client %{buildroot}/opt/fstec-client/fstec-client
install -Dm644 %{_sourcedir}/fstec-client.conf %{buildroot}/opt/fstec-client/fstec-client.conf
install -Dm644 %{_sourcedir}/fstec-client.desktop %{buildroot}/usr/share/applications/fstec-client.desktop

%files
/opt/fstec-client/fstec-client
/opt/fstec-client/fstec-client.conf
/usr/share/applications/fstec-client.desktop

%changelog
* Tue Nov 10 2026 FSTEC <noreply@example.invalid> - 0.1.0-1
- Initial package
