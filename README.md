# ФСТЭК Сервис

Сервис автоматического формирования ответов на предписания ФСТЭК.

## Требования

- Python 3.11+
- Node.js 18+
- Rust + Cargo (для Tauri)

## Установка зависимостей

### Backend
```bash
cd backend
pip install -r requirements.txt
```

### Frontend
```bash
cd frontend
npm install
```

## Запуск (dev режим)

### Windows
```bash
dev.bat
```

### Linux (РЕД ОС)
```bash
chmod +x dev.sh
./dev.sh
```

### Ручной запуск

**Терминал 1 — Backend:**
```bash
cd backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8765 --reload
```

**Терминал 2 — Frontend:**
```bash
cd frontend
npm run dev
```

Открыть: http://localhost:5173

## Первый запуск

При первом входе система автоматически создаёт учётную запись администратора
(`admin`) со случайным паролем:

1. На экране входа появится карточка «Первичная инициализация» с логином и паролем
2. **Пароль показывается один раз** — запишите его (или нажмите «Скопировать»)
3. После первого входа пароль восстановить нельзя
4. Сразу после входа создайте дополнительные учётные записи в разделе «Пользователи»

## Использование

1. **Загрузить письмо** — выбрать PDF + вложения (DOC/DOCX/ODT/XLSX)
2. Система автоматически:
   - Извлечёт текст из всех файлов
   - Определит тип письма (хакерская группировка / компрометация / уязвимости)
   - Найдёт угрозы и группировки
   - Извлечёт IOC (IP, домены, хэши, email, BDU, CVE)
3. **Карточка письма** — 6 вкладок:
   - Информация — номер, дата, тип, вложения
   - Угрозы — список с группировками и мерами
   - IOC — IP, домены, хэши, email (с копированием)
   - Уязвимости — анализ применимости, действия
   - Ответ — генерация, редактирование, скачивание DOCX
   - Экспорт — 4 IOC-файла (emails.txt, ip_addresses.txt, domains.txt, ioc_indicators.txt)

## Tauri (desktop)

```bash
cd src-tauri
cargo tauri dev
```

Tauri автоматически запускает frontend dev server и Python backend.

## Готовый дистрибутив (Windows)

Инсталлеры лежат в `installer/` (офлайн, всё внутри):

| Файл | Назначение |
|------|-----------|
| `fstec-service_0.1.0_x64-setup.exe` | NSIS, per-user, без прав администратора |
| `fstec-service_0.1.0_x64_en-US.msi` | MSI, per-machine, требует администратора |

- Приложение само поднимает бэкенд (встроенный `fstec-backend`), интернет не нужен.
- Данные: `%LOCALAPPDATA%\fstec-service` (БД, uploads, secret.key, логи).
- Сборка и пред-релизная проверка: `docs/build-redos.md`, `docs/checklist.md`.

## Структура проекта

```
fstec-service/
├── backend/           # Python FastAPI
│   ├── app/
│   │   ├── api/       # endpoints (auth, users, letters, generate)
│   │   ├── parsers/   # PDF, DOCX, DOC, ODT, XLSX
│   │   ├── extractor/ # IOC, letter analyzer, vuln extractor
│   │   ├── generator/ # DOCX response generator, IOC exporter
│   │   ├── auth.py    # JWT auth
│   │   ├── models.py  # ORM models
│   │   └── main.py    # FastAPI app
│   ├── data/          # SQLite DB + uploads
│   └── requirements.txt
├── frontend/          # React + TypeScript + MUI
│   ├── src/
│   │   ├── api/       # API client
│   │   ├── store/     # Zustand (auth)
│   │   ├── components/ # Layout
│   │   └── pages/     # Login, Dashboard, Upload, LetterList, LetterDetail, Admin/Users
│   └── package.json
├── src-tauri/         # Tauri v2 (desktop shell)
│   ├── src/           # Rust (sidecar launch)
│   └── tauri.conf.json
├── dev.bat            # Запуск (Windows)
├── dev.sh             # Запуск (Linux)
└── PLAN.md
```

## Поддерживаемые форматы

| Формат | Библиотека |
|--------|-----------|
| PDF | pdfplumber |
| DOCX | python-docx |
| DOC | olefile + CLX + UTF-16 scan |
| ODT | zipfile + XML |
| XLSX | openpyxl |

## Бизнес-процесс

### Хакерская группировка
1. Загрузить письмо → система извлекает IOC и угрозы
2. Сгенерировать ответ (DOCX)
3. Экспортировать 4 IOC-файла
4. Оператор отправляет файлы по назначению

### Уязвимости
1. Загрузить письмо → система извлекает BDU/CVE
2. Для каждой уязвимости: отметить применимость
3. Выбрать действие: обновить ПО / компенсирующие меры / пропустить
4. Сгенерировать ответ (DOCX)
