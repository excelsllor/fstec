# Чек-лист перед выпуском

Все пункты должны быть зелёными перед поставкой новой версии.

## Сборка

- [ ] `python backend/run_server.py` стартует без ошибок
- [ ] `npm run build` во `frontend/` — без ошибок
- [ ] `pyinstaller backend.spec` (в `backend/`) — без ошибок
- [ ] `npx tauri build --bundles msi,nsis` — оба инсталлера собраны
- [ ] В инсталлерах присутствуют `app.exe` и `fstec-backend\fstec-backend.exe`
  (проверка: `msiexec /a <msi> /qn TARGETDIR=<папка>` и разбор NSIS-установки)

## Функциональность (API-смоук)

- [ ] `python tools/smoke_12_letters.py` — 110/110 PASS (12 писем, upload →
      generate → download DOCX → 4 экспорта IOC)
- [ ] Офлайн-проверка установленного приложения:
  - установка без интернета (NSIS — без прав администратора, MSI — с правами)
  - запуск `app.exe` сам поднимает бэкенд (`GET /api/health` → ok)
  - bootstrap → login → upload → generate → download работают
  - рестарт приложения — данные на месте (письма, пользователи)

## Безопасность

- [ ] На чистой БД: `GET /api/auth/status` → `needs_setup: true`
- [ ] `GET /api/auth/bootstrap` отдаёт `admin` + сгенерированный пароль (длина ≥ 6)
- [ ] После первого успешного входа: `needs_setup: false`, `/api/auth/bootstrap` → 404
- [ ] В `DATA_DIR` нет файла с паролем (одноразовый пароль хранится в БД
      и удаляется после входа)
- [ ] Если пользователей нет (напр., все удалены) — админ создаётся заново
- [ ] Подделанный JWT (старый/чужой ключ) → 401
- [ ] Rate-limit логина: 5 неудач за 5 минут → 429
- [ ] Загрузка недопустимого расширения → 415, превышение лимитов → 413
- [ ] `/docs`, `/redoc`, `/openapi.json` скрыты при `FSTEC_DISABLE_DOCS=1`
- [ ] CSP задан в `tauri.conf.json`, скачивание DOCX работает при включённом CSP
- [ ] В репозитории нет секретов; `secret.key` генерируется при первом старте

## Данные

- [ ] Продакшн-данные в `%LOCALAPPDATA%\fstec-service`
      (БД `fstec.db`, `uploads`, `secret.key`, логи в `logs/backend.log`)
- [ ] Резервная копия БД: скопировать папку данных до обновления

## Код

- [ ] `npm run lint` — 0 ошибок
- [ ] Орфографический аудит 12 писем: `python tools/audit_quality.py` — 0 ошибок
- [ ] `requirements.txt` синхронизирован с установленными версиями
