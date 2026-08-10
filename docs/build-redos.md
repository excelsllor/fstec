# Сборка под РЕД ОС (Linux)

> **Рекомендуется:** универсальный web-режим (один rpm для РЕД ОС 7/8, без
> WebKitGTK/Tauri) — см. `docs/build-linux-rpm.md`. Ниже — dev-режим и
> Tauri-сборка (только для дистрибутивов с `webkit2gtk4.1`, РЕД ОС 7 не
> подходит).

Релиз для РЕД ОС собирается на машине с РЕД ОС (x86_64). Скрипт `dev.sh` и
инструкция ниже покрывают dev-режим; сборка инсталлера (.rpm/.deb) описана
в конце.

## Предварительные требования

```bash
sudo dnf install -y \
  python3 python3-pip python3-devel \
  nodejs npm \
  cargo rustc \
  gcc-c++ \
  libwebkit2gtk4.1-devel openssl-devel \
  librsvg2-devel \
  rpm-build
```

## Backend

```bash
cd backend
pip install -r requirements.txt
pyinstaller backend.spec
# результат: dist/fstec-backend/fstec-backend
```

## Frontend

```bash
cd frontend
npm install
npm run build
```

## Desktop (Tauri)

```bash
cd src-tauri
npx tauri build --bundles rpm,deb
# результат: target/release/bundle/rpm/*.rpm, target/release/bundle/deb/*.deb
```

Для запуска без установки: `npx tauri dev` или собранный бинарь
`target/release/fstec-service`.

## Особенности

- Sidecar-путь в `src-tauri/src/lib.rs` ищет бэкенд сначала как
  `<resource_dir>/fstec-backend/fstec-backend`, затем fallback
  `backend/dist/fstec-backend/...` — обе раскладки покрыты.
- Данные: по умолчанию `~/.local/share/fstec-service`
  (env `FSTEC_DATA_DIR` переопределяет).
- Бэкенд слушает только `127.0.0.1:8765` — наружу не публикуется.
- Проверка после установки: запустить приложение, `curl http://127.0.0.1:8765/api/health`
  → `{"status":"ok"}`.

## Ограничения

- Парсеры и генерация не зависят от Windows; но сборка .msi/.nsis возможна
  только на Windows (WebView2 + WiX/NSIS).
- Тесты `tools/smoke_12_letters.py` кроссплатформенны и гоняются через
  `python3 tools/smoke_12_letters.py`.
