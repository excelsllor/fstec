# -*- spec -*-
# Универсальный rpm-пакет ФСТЭК Сервис (web-режим).
# Бэкенд собирается PyInstaller под glibc >= 2.17 (manylinux2014),
# поэтому пакет ставится на RED OS 7/8, RHEL 7/8/9, Rocky/Alma, Fedora.
#
# Сборка:
#   rpmbuild -bb fstec-service.spec --define "_sourcedir <SRC>"
# где <SRC> содержит:
#   backend/     - dist/fstec-backend от PyInstaller (ELF + _internal)
#   frontend/    - собранный Vite dist
#   fstec-backend.service
#   fstec-service.desktop
#   fstec-service.png

Name:           fstec-service
Version:        0.1.0
Release:        1%{?dist}
Summary:        FSTEC Service - offline web mode
License:        Proprietary
Group:          Applications/Productivity
BuildArch:      x86_64
Requires:       glibc >= 2.17
AutoReqProv:    yes

%description
Сервис обработки писем по результатам мониторинга ИСПДн.
Работает офлайн: бэкенд запускается скрытым системным сервисом,
интерфейс открывается в браузере по адресу http://127.0.0.1:8765.

%build
# nothing to build, binaries are prebuilt

%install
rm -rf %{buildroot}
install -d %{buildroot}/opt/fstec-service/backend
install -d %{buildroot}/opt/fstec-service/frontend
install -d %{buildroot}/var/lib/fstec-service
install -d %{buildroot}/usr/lib/systemd/system
install -d %{buildroot}/usr/share/applications
install -d %{buildroot}/usr/share/icons/hicolor/128x128/apps

cp -a %{_sourcedir}/backend/. %{buildroot}/opt/fstec-service/backend/
chmod 0755 %{buildroot}/opt/fstec-service/backend/fstec-backend
find %{buildroot}/opt/fstec-service -type f -exec chmod a+r {} +
find %{buildroot}/opt/fstec-service -type d -exec chmod a+rx {} +
cp -a %{_sourcedir}/frontend/. %{buildroot}/opt/fstec-service/frontend/
install -m 0644 %{_sourcedir}/fstec-backend.service %{buildroot}/usr/lib/systemd/system/fstec-backend.service
install -m 0644 %{_sourcedir}/fstec-service.desktop %{buildroot}/usr/share/applications/fstec-service.desktop
install -m 0644 %{_sourcedir}/fstec-service.png %{buildroot}/usr/share/icons/hicolor/128x128/apps/fstec-service.png

%post
systemctl daemon-reload || :
systemctl enable fstec-backend.service || :
systemctl start fstec-backend.service || :

%preun
if [ "$1" = "0" ]; then
    systemctl stop fstec-backend.service || :
    systemctl disable fstec-backend.service || :
fi

%postun
systemctl daemon-reload || :

%files
/opt/fstec-service/backend
/opt/fstec-service/frontend
/var/lib/fstec-service
/usr/lib/systemd/system/fstec-backend.service
/usr/share/applications/fstec-service.desktop
/usr/share/icons/hicolor/128x128/apps/fstec-service.png
