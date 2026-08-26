"""API-смоук: полный цикл на всех 12 эталонных письмах на временной БД.

Запускает бэкенд (run_server.py) с FSTEC_DATA_DIR=<временная папка>,
ждёт /api/health, выполняет: login (пароль из backend.log) -> upload
-> generate -> download DOCX -> 4 экспорта IOC для каждого письма,
затем проверяет список писем и корректно завершает процесс. Временные
данные удаляются.

Запуск:
    python tools/smoke_12_letters.py

Возвращает код 0 при успехе, 1 при любом провале.
"""
import io
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

import httpx

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BASE = os.path.dirname(REPO)
RUN_SERVER = os.path.join(REPO, "backend", "run_server.py")

LETTERS = [
    "9-70", "9-77", "9-78", "9-81", "9-85", "9-89", "9-93",
    "9-99", "9-104", "9-107", "9-113", "9-118",
]

BASE_URL = "http://127.0.0.1:8765"

ok, fail = [], []


def check(name, cond, extra=""):
    (ok if cond else fail).append(name)
    print(("PASS" if cond else "FAIL"), name, extra)


def wait_health(proc, timeout=60):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if proc.poll() is not None:
            return False
        try:
            r = httpx.get(f"{BASE_URL}/api/health", timeout=2)
            if r.status_code == 200 and r.json().get("status") == "ok":
                return True
        except httpx.HTTPError:
            pass
        time.sleep(1)
    return False


def main():
    data_dir = tempfile.mkdtemp(prefix="fstec_smoke_")
    env = dict(os.environ)
    env["FSTEC_DATA_DIR"] = data_dir

    proc = None
    try:
        proc = subprocess.Popen(
            [sys.executable, RUN_SERVER],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if not wait_health(proc):
            print("FAIL health: бэкенд не поднялся за 60с")
            return 1

        c = httpx.Client(base_url=BASE_URL, timeout=120)
        r = c.get("/api/auth/status")
        check("status needs_setup", r.status_code == 200 and r.json().get("needs_setup"),
              str(r.status_code))
        # Read bootstrap password from backend.log
        password = None
        log_path = os.path.join(data_dir, "logs", "backend.log")
        try:
            with open(log_path) as f:
                for line in f:
                    m = re.search(r"Bootstrap password for user .admin.: (\S+)", line)
                    if m:
                        password = m.group(1)
                        break
        except Exception:
            pass
        check("bootstrap_password_in_log", password is not None and len(password) >= 6,
              str(password))
        r = c.post("/api/auth/login", json={"username": "admin", "password": password})
        check("login", r.status_code == 200, str(r.status_code))
        token = r.json().get("access_token", "")
        H = {"Authorization": f"Bearer {token}"}
        r = c.get("/api/auth/status")
        check("status после входа", r.status_code == 200 and not r.json().get("needs_setup"),
              str(r.status_code))

        for num in LETTERS:
            pdf = os.path.join(BASE, num, num + ".pdf")
            if not os.path.exists(pdf):
                check(f"{num} upload", False, "нет PDF")
                continue
            with open(pdf, "rb") as f:
                r = c.post("/api/letters/upload",
                           files={"pdf_file": (num + ".pdf", f, "application/pdf")},
                           headers=H)
            check(f"{num} upload", r.status_code == 201, str(r.status_code))
            if r.status_code != 201:
                continue
            letter_id = r.json().get("id")
            check(f"{num} id", bool(letter_id), str(letter_id))

            r = c.post(f"/api/letters/{letter_id}/generate", headers=H)
            check(f"{num} generate", r.status_code == 201, str(r.status_code))

            r = c.get(f"/api/letters/{letter_id}/download", headers=H)
            size = len(r.content) if r.status_code == 200 else 0
            check(f"{num} download", r.status_code == 200 and size > 30000,
                  f"bytes={size}")

            paras = 0
            if r.status_code == 200:
                from docx import Document
                doc = Document(io.BytesIO(r.content))
                paras = len([p.text.strip() for p in doc.paragraphs if p.text.strip()])
            check(f"{num} docx-абзацы", paras > 5, f"абзацев={paras}")

            for t in ["emails", "ip_addresses", "domains", "ioc_indicators"]:
                r = c.get(f"/api/letters/{letter_id}/export/{t}", headers=H)
                check(f"{num} export {t}", r.status_code == 200, str(r.status_code))

        r = c.get("/api/letters", headers=H)
        count = len(r.json()) if r.status_code == 200 else -1
        check("letters list", r.status_code == 200 and count == len(LETTERS),
              f"count={count}")

    except Exception as e:
        check("смоук-цикл", False, f"{type(e).__name__}: {e}")
    finally:
        if proc is not None:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
        shutil.rmtree(data_dir, ignore_errors=True)

    print(f"\nИТОГО: {len(ok)} PASS, {len(fail)} FAIL")
    return 1 if fail else 0


if __name__ == "__main__":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
    sys.exit(main())
