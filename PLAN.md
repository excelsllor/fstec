# План разработки: Сервис обработки писем ФСТЭК

## Архитектура
- **Backend**: Python 3.11+ / FastAPI / SQLAlchemy / SQLite (порт 8765)
- **Frontend**: React + TypeScript + Vite + MUI
- **Desktop**: Tauri v2 (запускает Python backend как sidecar)
- **Сборка**: PyInstaller (backend) + Tauri (.msi для Windows, .rpm для РЕД ОС)
- **Офлайн**: все зависимости встроены, интернет не нужен

## Бизнес-процесс (из файла «как обрабатывать письма»)
### Путь А: Хакерская группировка
1. Извлечь IOC: emails, IP, домены, IoC → 4 файла
2. Сгенерировать DOCX-ответ

### Путь Б: Уязвимости
1. Для каждой уязвимости: анализ применимости → обновление/компенсирующие меры
2. Сгенерировать DOCX-ответ

### Путь В: Прочее
1. Ручной анализ + ответ

## Этапы

### Этап 0 — Каркас ✅ ГОТОВО
- Tauri v2 + React + FastAPI + SQLite + JWT auth
- 9 ORM-моделей, API endpoints, Login + Dashboard

### Этап 1 — Парсеры ✅ ГОТОВО
- [x] PDF (pdfplumber) — текст + таблицы
- [x] DOCX (python-docx) — текст + таблицы + колонтитулы
- [x] DOC (olefile) — CLX из 1Table + UTF-16 fallback
- [x] ODT (zipfile + XML)
- [x] XLSX (openpyxl)
- [x] Извлечение данных: IP, домены, хэши, email, BDU, CVE, группировки
- [x] Анализ письма: тип, номер, дата, угрозы
- [x] Проверка на всех 12 письмах: 45/45 файлов, 0 ошибок

### Этап 2 — Генерация ответа + Экспорт IOC ✅ ГОТОВО
- [x] DOCX-шаблонизатор: заголовок, интро, нумерованные угрозы с мерами
- [x] Шаблоны мер: антифишинговый (8), компрометация (4), минимальный (2), одиночный (1)
- [x] POST `/api/letters/{id}/generate` — генерация ответа
- [x] GET `/api/letters/{id}/download` — скачивание DOCX
- [x] PUT `/api/letters/{id}/response` — редактирование ответа
- [x] GET `/api/letters/{id}/export/{type}` — экспорт IOC (emails, ip_addresses, domains, ioc_indicators)
- [x] Проверка на 12 письмах: все генерируются (37-38 KB DOCX)

### Этап 3 — Web-интерфейс ✅ ГОТОВО
- [x] Layout: навигация (панель, загрузка, письма, пользователи), logout
- [x] Login: авторизация + автосоздание admin со случайным паролем (одноразовый показ через /api/auth/bootstrap)
- [x] Dashboard: 4 карточки статистики + последние письма
- [x] Upload: drag-and-drop PDF + вложения
- [x] LetterList: таблица с фильтрацией по типу и поиску
- [x] LetterDetail: 6 табов (инфо, угрозы, IOC, уязвимости, ответ, экспорт)
- [x] Редактор ответа: загрузка текста, редактирование, сохранение, регенерация DOCX
- [x] VulnWorkflow: интерактивный анализ (применимость, действие, детали)
- [x] Админка: CRUD пользователей (создание, редактирование, удаление)
- [x] Сборка frontend: 617 KB bundle
- [x] dev.bat / dev.sh: скрипты запуска dev-режима
- [x] README.md: инструкция по установке и запуску
- [x] Интеграционный тест: 17/17 проверок прошли

### Этап 4 — Сборка ✅ ГОТОВО
- [x] PyInstaller: backend → onedir `fstec-backend` (hiddenimports uvicorn/pdfminer/pydantic, console=False)
- [x] `run_server.py` — энтрипоинт: данные в `%LOCALAPPDATA%\fstec-service` (БД, uploads, secret.key, логи)
- [x] Tauri: `.msi` (per-machine) + `.nsis` (per-user, без админа) для Windows
- [x] Sidecar: `<resource_dir>/fstec-backend/fstec-backend(.exe)` с fallback на старую раскладку
- [x] CSP задан; фронтенд встроен в `app.exe` (офлайн, без CDN)
- [x] Инсталлеры: `installer/fstec-service_0.1.0_x64-setup.exe` (40,2 МБ), `installer/fstec-service_0.1.0_x64_en-US.msi` (55,5 МБ)
- [x] Офлайн-установка NSIS проверена: exit 0 без прав администратора, бэкенд автостартует
- [x] Полный цикл через установленное приложение: 10/10 PASS (bootstrap, login, upload, generate, download DOCX, экспорты)
- [x] Сохранение данных после рестарта: логин + 1 письмо на месте
- [ ] .rpm для РЕД ОС — см. `docs/build-redos.md` (нужна машина с РЕД ОС)

### Этап 5 — Тестирование ✅ ГОТОВО (Windows)
- [x] API-смоук на всех 12 письмах: `tools/smoke_12_letters.py` — 110/110 PASS
- [x] Проверка офлайн-установки на Windows (NSIS-инсталлер, полный цикл + рестарт)
- [x] Орфографический аудит: 12 писем, 0 ошибок
- [ ] Проверка офлайн-установки на РЕД ОС
- [ ] `docs/checklist.md` — чек-лист перед каждым выпуском
