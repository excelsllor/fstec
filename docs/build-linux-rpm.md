# Linux rpm: универсальный web-режим (РЕД ОС / ROSA / RHEL)

Приложение работает в браузере: бэкенд запускается **скрытым системным
сервисом**, ярлык на рабочем столе открывает `http://127.0.0.1:8765`.
Не требует WebKitGTK/Tauri, поэтому один пакет ставится на любой rpm-дистрибутив
с glibc >= 2.17: РЕД ОС 7/8, RHEL 7/8/9, Rocky/Alma, Fedora.

## Сборка

Сборка автоматизирована в GitHub Actions (`.github/workflows/build-linux-rpm.yml`):

| Job       | Где                   | Что делает                                            |
|-----------|-----------------------|-------------------------------------------------------|
| frontend  | ubuntu-latest         | `npm ci && npm run build` (Vite dist)                 |
| backend   | manylinux2014 (glibc 2.17) | PyInstaller: ELF-бинарник, работает на любом rpm с glibc >= 2.17 |
| rpm       | rockylinux:9          | `rpmbuild -bb packaging/linux/fstec-service.spec`     |
| verify    | rockylinux:9          | установка rpm, запуск бэкенда, API+статик смоук       |

Артефакт: `fstec-service-rpm` → `fstec-service-0.1.0-1.el9.x86_64.rpm`.

Ручная сборка на Linux-машине:

```bash
# 1. Бэкенд (важно: среда должна быть с glibc как у целевых машин,
#    для максимальной универсальности — manylinux2014 / РЕД ОС 7)
cd backend
python3 -m pip install -r requirements.txt pyinstaller
python3 -m PyInstaller backend.spec --noconfirm

# 2. Фронтенд
cd ../frontend
npm ci
npm run build

# 3. rpm
mkdir -p ~/rpmbuild/SOURCES
cp -a backend/dist/fstec-backend ~/rpmbuild/SOURCES/backend
cp -a frontend/dist ~/rpmbuild/SOURCES/frontend
cp packaging/linux/fstec-backend.service packaging/linux/fstec-service.desktop \
   packaging/linux/fstec-service.png ~/rpmbuild/SOURCES/
rpmbuild -bb --define "_sourcedir $HOME/rpmbuild/SOURCES" \
  --define "_topdir $HOME/rpmbuild" packaging/linux/fstec-service.spec
# результат: ~/rpmbuild/RPMS/x86_64/fstec-service-*.rpm
```

## Установка на офлайн-машине

Пакет самодостаточен (бэкенд и фронтенд внутри), системные зависимости —
только `glibc` и браузер (уже есть на рабочем столе).

```bash
# с правами root:
rpm -ivh fstec-service-0.1.0-1.el9.x86_64.rpm
# или
dnf install ./fstec-service-0.1.0-1.el9.x86_64.rpm
```

После установки:
- сервис `fstec-backend` включён и запущен (скрытый, без окон);
- в меню приложений появился «ФСТЭК Сервис» (ярлык открывает
  `http://127.0.0.1:8765` в системном браузере);
- данные: `/var/lib/fstec-service` (БД `fstec.db`, uploads, `secret.key`, логи);
- логи сервиса: `journalctl -u fstec-backend`.

Проверка: `curl http://127.0.0.1:8765/api/health` → `{"status":"ok"}`.

Первый вход: сервис сам создаёт администратора и показывает одноразовый пароль
на экране инициализации (логин `admin`). После входа пароль удаляется.

## Управление сервисом

```bash
systemctl status fstec-backend
systemctl restart fstec-backend
systemctl stop fstec-backend
```

## Удаление

```bash
rpm -e fstec-service
# сервис остановится и отключится; данные в /var/lib/fstec-service сохраняются
```

## Настройка

- Порт/адрес: `127.0.0.1:8765` (только localhost).
- Каталог данных: env `FSTEC_DATA_DIR` в `/usr/lib/systemd/system/fstec-backend.service`.
- Каталог фронта: env `FSTEC_FRONTEND_DIR` (должен указывать на собранный dist).

## Ограничения

- Интерфейс — в браузере (нет отдельного окна).
- Проверка GUI на реальной РЕД ОС (7 и 8) — вручную: установить rpm, открыть ярлык,
  пройти инициализацию и полный цикл (загрузка письма → генерация → скачивание DOCX).
- CI-верификация гоняет API-смоук на rocky:9; на РЕД ОС 7 рекомендую повторить
  установку (ABI-совместимость гарантирована glibc 2.17, но проверить лишним не будет).
