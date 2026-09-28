"""API Gateway (ТЗ 2.6, 3.1). Внешний контур микросервисной архитектуры.

Эндпоинты ТЗ 2.6: POST /upload, GET /documents, GET /documents/{id},
GET /reports/{id}/download, GET /reports/{id}/download_raw, POST /reply/generate.
Плюс обратная совместимость: /api/letters/... и /api/auth/*.
"""
import base64
import logging
import os
import shutil
import threading
import time
from collections import deque
from contextlib import asynccontextmanager
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, Response
from sqlalchemy.orm import Session

from shared import bus as eventbus
from shared.auth import (
    create_access_token, ensure_bootstrap, get_current_user,
    hash_password, mark_bootstrap_used, needs_setup, require_admin, verify_password,
)
from shared.config import (
    ALLOWED_EXTENSIONS, BOOTSTRAP_USERNAME, CORS_ORIGINS, DISABLE_DOCS,
    MAX_FILE_SIZE, MAX_FILES_PER_BATCH, ORG_NAME, UPLOAD_DIR,
)
from shared.db import SessionLocal, get_db, init_db
from shared.events import DocumentsUploaded
from shared.models import (
    Attachment, AuditLog, BootstrapSecret, Document, Entity, GeneratedResponse,
    IoC, Measure, MeasureCandidate, MeasureTemplate, Report, Summary,
    Threat, ThreatType, User, VulnActionTemplate, Vulnerability,
)

logger = logging.getLogger("fstec.gateway")

# IP клиента текущего запроса (заполняется middleware) — используется аудитом,
# чтобы не передавать Request в каждую ручку.
_client_ip: ContextVar[str] = ContextVar("fstec_client_ip", default="")

# --- Rate limit на /api/auth/login (анти-брутфорс; off для автотестов) ---

_LOGIN_LIMIT = int(os.environ.get("FSTEC_LOGIN_RATE_LIMIT", "10"))
_LOGIN_WINDOW_S = int(os.environ.get("FSTEC_LOGIN_RATE_WINDOW_S", "60"))
_LOGIN_LIMIT_DISABLED = os.environ.get("FSTEC_DISABLE_LOGIN_RATE_LIMIT", "0") == "1"

_login_attempts: dict[str, deque] = {}
_login_lock = threading.Lock()


def _login_allowed(client_ip: str) -> bool:
    if _LOGIN_LIMIT_DISABLED:
        return True
    now = time.monotonic()
    with _login_lock:
        q = _login_attempts.setdefault(client_ip, deque())
        while q and now - q[0] > _LOGIN_WINDOW_S:
            q.popleft()
        if len(q) >= _LOGIN_LIMIT:
            return False
        q.append(now)
        return True

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as sess:
        ensure_bootstrap(sess)
    yield


app = FastAPI(
    title="FSTEC API Gateway", version="1.0.0",
    docs_url=None if DISABLE_DOCS else "/api/docs",
    redoc_url=None,
    openapi_url=None if DISABLE_DOCS else "/api/openapi.json",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

_SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


@app.middleware("http")
async def _add_security_headers(request: Request, call_next):
    # request.client.host учитывает X-Forwarded-For при uvicorn --proxy-headers.
    _client_ip.set(request.client.host if request.client else "")
    response = await call_next(request)
    for name, value in _SECURITY_HEADERS.items():
        response.headers.setdefault(name, value)
    return response


@app.exception_handler(OverflowError)
async def _overflow_exception_handler(request: Request, exc: OverflowError):
    # Числовые параметры (id в пути, offset) вне диапазона SQLite INTEGER.
    return JSONResponse(status_code=422, content={"detail": "Некорректное числовое значение параметра"})


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception):
    logger.exception("Unhandled error on %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Внутренняя ошибка сервера"})


def _utcnow():
    return datetime.now(timezone.utc)


def _content_disposition(filename: str) -> str:
    """Content-Disposition с ASCII-fallback и RFC 5987 (*=UTF-8'') для кириллицы."""
    from urllib.parse import quote
    try:
        filename.encode("latin-1")
        return f"attachment; filename={filename}"
    except UnicodeEncodeError:
        safe = filename.encode("ascii", "replace").decode("ascii") or "download"
        return f"attachment; filename={safe}; filename*=UTF-8''{quote(filename)}"


def _audit(db: Session, user: User | None, action: str, object_type: str = "",
           object_id: int | None = None, filename: str = "", document_id: int | None = None,
           request: Request | None = None):
    rec = AuditLog(
        user_id=user.id if user else None,
        username=user.username if user else "",
        action=action,
        object_type=object_type,
        object_id=object_id,
        filename=filename,
        document_id=document_id,
        ip_address=(request.client.host if request and request.client else _client_ip.get()),
    )
    db.add(rec)
    # Аудит должен сохраняться всегда: часть ручек вызывает _audit уже после
    # db.commit(), поэтому коммитим запись здесь (иначе она теряется при закрытии сессии).
    db.commit()


def _owned_document(db: Session, user: User, doc_id: int,
                    detail: str = "Документ не найден") -> Document:
    """Возвращает документ, только если он принадлежит пользователю (или он admin).

    Для чужих документов отдаём 404, чтобы не раскрывать их существование.
    """
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if doc is None or (user.role != "admin" and doc.created_by != user.id):
        raise HTTPException(status_code=404, detail=detail)
    return doc


def _scoped_documents(db: Session, user: User):
    """Базовый запрос документов с учётом объектной авторизации."""
    query = db.query(Document)
    if user.role != "admin":
        query = query.filter(Document.created_by == user.id)
    return query


# ---------------- Auth ----------------

@app.post("/api/auth/login")
def login(body: dict, request: Request, db: Session = Depends(get_db)):
    client_ip = request.client.host if request.client else "unknown"
    if not _login_allowed(client_ip):
        raise HTTPException(status_code=429, detail="Слишком много попыток входа, повторите позже")
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""
    user = db.query(User).filter(User.username == username).first()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Неверный логин или пароль")
    if user.username == BOOTSTRAP_USERNAME:
        mark_bootstrap_used(db)
    _audit(db, user, "login", "user", user.id, request=request)
    db.commit()
    token = create_access_token({"sub": user.username, "role": user.role})
    return {"access_token": token, "token_type": "bearer", "role": user.role, "username": user.username}


@app.get("/api/auth/status")
def auth_status(db: Session = Depends(get_db)):
    setup = needs_setup(db)
    return {"needs_setup": setup}


@app.get("/api/auth/me")
def auth_me(user: User = Depends(get_current_user)):
    return {"id": user.id, "username": user.username, "role": user.role,
            "full_name": user.full_name, "is_active": user.is_active}


@app.get("/api/health")
def health():
    return {"status": "ok"}


# ---------------- Upload (ТЗ 2.6 POST /upload) ----------------

_MAGIC = {
    ".pdf": (b"%PDF", 4),
    ".docx": (b"PK\x03\x04", 4),
    ".xlsx": (b"PK\x03\x04", 4),
    ".odt": (b"PK\x03\x04", 4),
    ".doc": (b"\xd0\xcf\x11\xe0", 4),
    ".rtf": (b"{\\rtf", 5),
}


def _validate_file(uf: UploadFile):
    ext = Path(uf.filename or "").suffix.lower()
    if ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Недопустимый формат: {ext or '(нет расширения)'}")
    uf.file.seek(0, os.SEEK_END)
    size = uf.file.tell()
    uf.file.seek(0)
    if size > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"Файл {uf.filename} больше 20 МБ")
    magic, n = _MAGIC.get(ext, (None, 0))
    if magic:
        head = uf.file.read(n)
        uf.file.seek(0)
        if ext == ".rtf":
            head = head.lstrip(b"\x00\x09\x0a\x0d\x20")
        if not head.startswith(magic):
            raise HTTPException(status_code=415, detail=f"Файл {uf.filename} не соответствует формату {ext}")
    uf.file.seek(0)
    return size


@app.post("/upload", status_code=201)
async def upload(
    request: Request,
    files: Optional[list[UploadFile]] = File(default=None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    if not files:
        raise HTTPException(status_code=400, detail="Нет файлов")
    if len(files) > MAX_FILES_PER_BATCH:
        raise HTTPException(status_code=413, detail=f"Допускается до {MAX_FILES_PER_BATCH} файлов одновременно")

    sizes = []
    for uf in files:
        sizes.append(_validate_file(uf))

    main_name = Path(files[0].filename).name
    doc = Document(
        letter_type="other", status="uploaded", processing_stage="uploaded",
        source_filename=main_name,
        size=sum(sizes), mime=Path(main_name).suffix,
        created_by=user.id,
    )
    db.add(doc)
    db.flush()

    doc_dir = UPLOAD_DIR / f"doc_{doc.id}"
    doc_dir.mkdir(parents=True, exist_ok=True)
    doc.file_path = str(doc_dir)

    att_metas = []
    for idx, uf in enumerate(files):
        name = Path(uf.filename).name
        dest = doc_dir / name
        with open(dest, "wb") as f:
            shutil.copyfileobj(uf.file, f)
        db.add(Attachment(
            document_id=doc.id, filename=name, file_path=str(dest),
            file_type=Path(name).suffix.lower(), parse_status="pending", is_main=(idx == 0),
        ))
        att_metas.append({"filename": name, "path": str(dest), "size": sizes[idx]})

    _audit(db, user, "upload", "document", doc.id, files[0].filename, doc.id, request=request)
    db.commit()

    await eventbus.publish("documents.uploaded", str(doc.id), DocumentsUploaded(
        document_id=doc.id,
        user_id=user.id,
        main_file=att_metas[0],
        attachments=att_metas[1:],
    ).model_dump(mode="json"))

    return {"id": doc.id, "status": "uploaded", "filename": files[0].filename}


# ---------------- Documents (ТЗ 2.6) ----------------

@app.get("/documents")
def list_documents(
    skip: int = Query(0, ge=0, le=1_000_000), limit: int = Query(50, ge=1, le=200),
    letter_type: str | None = None,
    status: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
):
    query = _scoped_documents(db, user)
    if letter_type:
        query = query.filter(Document.letter_type == letter_type)
    if status:
        query = query.filter(Document.status == status)
    docs = query.order_by(Document.created_at.desc()).offset(skip).limit(limit).all()
    return [{
        "id": d.id, "letter_number": d.letter_number, "letter_date": d.letter_date,
        "letter_type": d.letter_type, "status": d.status, "sla": d.sla, "routing": d.routing,
        "source_filename": d.source_filename, "processing_stage": d.processing_stage,
        "created_at": d.created_at,
    } for d in docs]


def _document_brief(doc: Document):
    return {
        "id": doc.id,
        "letter_number": doc.letter_number,
        "letter_date": doc.letter_date,
        "letter_type": doc.letter_type,
        "status": doc.status,
        "sla": doc.sla,
        "routing": doc.routing,
        "source_filename": doc.source_filename,
        "processing_stage": doc.processing_stage,
        "created_at": doc.created_at,
    }


def _serialize_document(db: Session, doc: Document) -> dict:
    attachments = [{
        "id": a.id, "filename": a.filename, "file_type": a.file_type,
        "parse_status": a.parse_status, "parse_errors": a.parse_errors,
        "parsed_text": a.parsed_text, "is_main": a.is_main,
    } for a in doc.attachments]

    threats = [{
        "id": t.id, "number": t.number, "group_name": t.group_name,
        "threat_type": t.threat_type, "theme": t.theme,
        "archive_name": t.archive_name, "exe_name": t.exe_name,
        "malware_type": t.malware_type, "description": t.description,
        "measures": t.measures,
    } for t in doc.threats]

    iocs = [{
        "id": i.id, "ioc_type": i.ioc_type, "value": i.value,
        "context": i.context, "llm_validated": i.llm_validated, "source": i.source,
    } for i in doc.iocs]

    vulnerabilities = [{
        "id": v.id, "bdu_id": v.bdu_id, "cve_id": v.cve_id,
        "description": v.description, "software": v.software, "severity": v.severity,
        "cvss_score": v.cvss_score, "cpe": v.cpe, "affected_range": v.affected_range,
        "fixed_version": v.fixed_version, "patch_url": v.patch_url,
        "cmdb_match": v.cmdb_match, "current_version": v.current_version,
        "target_version": v.target_version, "source": v.source,
        "recommendation": v.recommendation,
        "is_applicable": v.is_applicable, "applicability_notes": v.applicability_notes,
        "action_type": v.action_type, "action_details": v.action_details,
        "response_point": v.response_point,
    } for v in doc.vulnerabilities]

    entities = [{
        "id": e.id, "entity_type": e.entity_type, "value": e.value, "context": e.context,
    } for e in db.query(Entity).filter(Entity.document_id == doc.id).all()]

    summaries = [{"id": s.id, "summary": s.summary, "confidence": s.confidence}
                 for s in db.query(Summary).filter(Summary.document_id == doc.id).all()]

    resp = (db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc.id)
            .order_by(GeneratedResponse.id.desc()).first())

    data = _document_brief(doc)
    data.update({
        "subject": doc.subject,
        "original_text": doc.original_text,
        "all_text": doc.all_text,
        "parse_errors": doc.parse_errors,
        "ocr_used": doc.ocr_used,
        "updated_at": doc.updated_at,
        "attachments": attachments,
        "threats": threats,
        "iocs": iocs,
        "vulnerabilities": vulnerabilities,
        "entities": entities,
        "summaries": summaries,
        "ioc_count": len(iocs),
        "vuln_count": len(vulnerabilities),
        "threat_count": len(threats),
        "response": {"text": resp.content or "", "exists": resp is not None, "id": resp.id} if resp
        else {"text": "", "exists": False},
    })
    return data


@app.get("/documents/{doc_id}")
def get_document(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, doc_id)
    return _serialize_document(db, doc)


# ---------------- Reports (ТЗ 2.6) ----------------

@app.get("/reports/{doc_id}/download")
def download_report(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, doc_id)
    report = (db.query(Report).filter(Report.document_id == doc_id)
              .order_by(Report.generated_at.desc()).first())
    if not report:
        raise HTTPException(status_code=404, detail="Отчёт ещё не сформирован")
    return FileResponse(report.file_path, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                        filename=report.filename)


@app.get("/reports/{doc_id}/download_raw")
def download_raw(doc_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, doc_id)
    main = (db.query(Attachment).filter(Attachment.document_id == doc_id, Attachment.is_main == True).first())
    path = main.file_path if main else (doc.file_path and os.path.join(doc.file_path, doc.source_filename))
    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail="Исходный файл не найден")
    return FileResponse(path, filename=doc.source_filename)


@app.post("/reply/generate")
def reply_generate(doc_id: int, request: Request, body: dict | None = None,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """Принудительная генерация проекта ответа (ТЗ 2.6 /reply/generate)."""
    from shared.generator.templated_reply import generate_reply, persist_candidates
    doc = _owned_document(db, user, doc_id)
    threat_rows = (db.query(Threat).filter(Threat.document_id == doc_id)
                   .order_by(Threat.number).all())
    blocks = [{
        "id": t.id, "number": t.number, "threat_type": t.threat_type, "theme": t.theme,
        "group_name": t.group_name, "archive_name": t.archive_name, "exe_name": t.exe_name,
        "malware_type": t.malware_type, "description": t.description,
        "explicit_measures": [m.strip() for m in (t.measures or "").split("\n") if m.strip()],
    } for t in threat_rows]
    vulns = [{"cve_id": v.cve_id, "bdu_id": v.bdu_id, "description": v.description or "",
              "software": v.software, "severity": v.severity, "cvss_score": v.cvss_score,
              "cvss_version": v.cvss_version or "", "current_version": v.current_version,
              "target_version": v.target_version, "fixed_version": v.fixed_version,
              "cmdb_match": v.cmdb_match, "recommendation": v.recommendation}
             for v in db.query(Vulnerability).filter(Vulnerability.document_id == doc_id).all()]
    iocs = db.query(IoC).filter(IoC.document_id == doc_id).all()
    addr_count = len({i.value.split(":")[0] for i in iocs if i.ioc_type in ("ip", "domain")})

    rep = generate_reply(db=db, doc_id=doc.id, letter_type=doc.letter_type, blocks=blocks,
                         addr_count=addr_count, active_vulns=vulns)
    if rep["candidates"]:
        for i, c in enumerate(rep["candidates"]):
            rep["candidates"][i]["threat_id"] = (blocks[i]["id"] if i < len(blocks) else None)
        persist_candidates(db, doc.id, rep["candidates"])

    resp = GeneratedResponse(document_id=doc_id, content=rep["text"],
                             edited_content=base64.b64encode(rep["docx"]).decode("ascii"),
                             plan_json=rep["plan_json"], created_by=user.id)
    db.add(resp)
    _audit(db, user, "generate_reply", "document", doc_id, doc.source_filename, doc_id, request=request)
    db.commit()
    return {"id": resp.id, "document_id": doc_id, "status": "generated", "text": rep["text"],
            "llm_used": rep["llm_used"], "new_measures": len(rep["candidates"])}


# ---------------- Admin: библиотека мер и очередь кандидатов (LLM) ----------------

@app.get("/admin/measures")
def admin_measures(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    rows = db.query(Measure).order_by(Measure.id).all()
    return [{"id": m.id, "text": m.text, "threat_type": m.threat_type, "tags": m.tags,
             "addr_inflection": m.addr_inflection, "source": m.source} for m in rows]


@app.post("/admin/measures")
def admin_measures_add(body: dict, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    text = (body.get("text") or "").strip()
    if not text:
        raise HTTPException(status_code=400, detail="text обязателен")
    dup = db.query(Measure).filter(Measure.text == text).first()
    if dup:
        return {"id": dup.id, "status": "exists"}
    m = Measure(text=text, threat_type=body.get("threat_type", ""),
                tags=body.get("tags", ""), addr_inflection=bool(body.get("addr_inflection", False)),
                source="admin")
    db.add(m)
    db.commit()
    _audit(db, user, "measure_add", "measure", m.id)
    return {"id": m.id, "status": "added"}


@app.delete("/admin/measures/{measure_id}")
def admin_measures_delete(measure_id: int, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    m = db.query(Measure).filter(Measure.id == measure_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Мера не найдена")
    db.delete(m)
    db.commit()
    _audit(db, user, "measure_delete", "measure", measure_id)
    return {"status": "deleted"}


@app.get("/admin/measures/candidates")
def admin_candidates(status: str | None = "pending", db: Session = Depends(get_db),
                     user: User = Depends(require_admin)):
    q = db.query(MeasureCandidate)
    if status:
        q = q.filter(MeasureCandidate.status == status)
    rows = q.order_by(MeasureCandidate.id.desc()).all()
    out = []
    for c in rows:
        doc = db.query(Document).filter(Document.id == c.document_id).first()
        threat = (db.query(Threat).filter(Threat.id == c.threat_id).first()
                  if c.threat_id else None)
        out.append({
            "id": c.id, "text": c.text, "note": c.note, "status": c.status,
            "document_id": c.document_id,
            "letter_number": doc.letter_number if doc else "",
            "letter_date": doc.letter_date if doc else "",
            "threat_theme": (threat.theme or threat.description or "") if threat else "",
            "created_at": c.created_at.isoformat() if c.created_at else None,
            "reviewed_at": c.reviewed_at.isoformat() if c.reviewed_at else None,
        })
    return out


@app.post("/admin/measures/candidates/{candidate_id}/accept")
def admin_candidate_accept(candidate_id: int, db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    c = db.query(MeasureCandidate).filter(MeasureCandidate.id == candidate_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Кандидат не найден")
    if c.status == "approved":
        return {"id": c.id, "status": "already_approved"}
    dup = db.query(Measure).filter(Measure.text == c.text).first()
    if not dup:
        dup = Measure(text=c.text, threat_type="", tags="", addr_inflection=False, source="llm")
        db.add(dup)
    c.status = "approved"
    c.reviewed_by = user.id
    c.reviewed_at = _utcnow()
    db.commit()
    _audit(db, user, "candidate_accept", "measure_candidate", candidate_id)
    return {"id": c.id, "status": "approved", "measure_id": dup.id}


@app.post("/admin/measures/candidates/{candidate_id}/reject")
def admin_candidate_reject(candidate_id: int, db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    c = db.query(MeasureCandidate).filter(MeasureCandidate.id == candidate_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Кандидат не найден")
    c.status = "rejected"
    c.reviewed_by = user.id
    c.reviewed_at = _utcnow()
    db.commit()
    _audit(db, user, "candidate_reject", "measure_candidate", candidate_id)
    return {"id": c.id, "status": "rejected"}


# ---------------- Legacy compat: /api/letters ----------------
# (обратная совместимость для существующего фронтенда до его перехода на ТЗ 2.6)

@app.get("/api/letters")
def legacy_list(skip: int = Query(0, ge=0, le=1_000_000), limit: int = Query(50, ge=1, le=200),
                letter_type: str | None = None,
                status: str | None = None, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    query = _scoped_documents(db, user)
    if letter_type:
        query = query.filter(Document.letter_type == letter_type)
    if status:
        query = query.filter(Document.status == status)
    docs = query.order_by(Document.created_at.desc()).offset(skip).limit(limit).all()
    return [{"id": d.id, "letter_number": d.letter_number, "letter_date": d.letter_date,
             "letter_type": d.letter_type, "status": d.status, "created_at": d.created_at,
             "threat_count": db.query(Threat).filter(Threat.document_id == d.id).count(),
             "ioc_count": db.query(IoC).filter(IoC.document_id == d.id).count(),
             "vuln_count": db.query(Vulnerability).filter(Vulnerability.document_id == d.id).count()}
            for d in docs]


@app.get("/api/letters/stats")
def legacy_stats(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    scope = _scoped_documents(db, user)
    doc_ids = [d.id for d in scope.with_entities(Document.id).all()]

    def _count(model) -> int:
        if not doc_ids:
            return 0
        return db.query(model).filter(model.document_id.in_(doc_ids)).count()

    return {
        "total_letters": len(doc_ids),
        "hacker_letters": scope.filter(Document.letter_type == "hacker").count(),
        "vulnerability_letters": scope.filter(Document.letter_type == "vulnerability").count(),
        "other_letters": scope.filter(Document.letter_type == "other").count(),
        "total_threats": _count(Threat),
        "total_iocs": _count(IoC),
        "total_vulns": _count(Vulnerability),
    }


@app.get("/api/letters/{letter_id}")
def legacy_detail(letter_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    return _serialize_document(db, doc)


@app.get("/api/letters/{letter_id}/response/text")
def legacy_response_text(letter_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == letter_id) \
        .order_by(GeneratedResponse.id.desc()).first()
    return {"text": (resp.content or "") if resp else "", "exists": resp is not None}


@app.put("/api/letters/{letter_id}/response")
def legacy_response_update(letter_id: int, body: dict, request: Request,
                           db: Session = Depends(get_db),
                           user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    text = (body.get("content") or "").strip()
    resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == letter_id) \
        .order_by(GeneratedResponse.id.desc()).first()
    if not resp:
        resp = GeneratedResponse(document_id=letter_id, content=text, created_by=user.id)
        db.add(resp)
    else:
        resp.content = text
        resp.updated_at = _utcnow()
    from shared.generator.response_generator import render_reply_docx
    resp.edited_content = base64.b64encode(render_reply_docx(text)).decode("ascii")
    _audit(db, user, "update_response", "document", letter_id, request=request)
    db.commit()
    return {"id": resp.id, "text": text}


@app.get("/api/letters/{letter_id}/response/preview")
def legacy_response_preview(letter_id: int, db: Session = Depends(get_db),
                            user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    from shared.generator.reply_preview import build_preview
    threats = db.query(Threat).filter(Threat.document_id == doc.id).order_by(Threat.number).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.document_id == doc.id).all()
    iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
    preview = build_preview(db=db, document=doc, threats=threats,
                            vulnerabilities=vulns, iocs=iocs)
    return preview


@app.put("/api/letters/{letter_id}/response/measures/{threat_id}")
def legacy_measures_update(letter_id: int, threat_id: int, body: dict, request: Request,
                           db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    measures = body.get("measures") or []
    threat = db.query(Threat).filter(Threat.id == threat_id, Threat.document_id == letter_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Угроза не найдена")
    threat.measures = "\n".join(measures)
    db.commit()
    texts = [m.strip() for m in measures if m.strip()]
    return {"measures": measures, "text": "\n".join(f"  {m}" for m in texts)}


def _update_vulnerability(db: Session, user: User, doc_id: int, vuln_id: int,
                          body: dict, request: Request | None = None) -> dict:
    doc = _owned_document(db, user, doc_id, detail="Уязвимость не найдена")
    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id, Vulnerability.document_id == doc_id).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена")
    if "is_applicable" in body and body["is_applicable"] is not None:
        vuln.is_applicable = bool(body["is_applicable"])
    for f in ("applicability_notes", "action_type", "action_details", "response_point", "software"):
        if f in body and body[f] is not None:
            setattr(vuln, f, body[f])
    db.commit()
    _audit(db, user, "update_vulnerability", "vulnerability", vuln_id,
           document_id=doc_id, request=request)
    return _serialize_document(db, doc)


@app.put("/api/letters/{letter_id}/vulnerabilities/{vuln_id}")
def legacy_vuln_update(letter_id: int, vuln_id: int, body: dict, request: Request,
                       db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _update_vulnerability(db, user, letter_id, vuln_id, body, request=request)


@app.put("/documents/{doc_id}/vulnerabilities/{vuln_id}")
def vuln_update(doc_id: int, vuln_id: int, body: dict, request: Request,
                db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    return _update_vulnerability(db, user, doc_id, vuln_id, body, request=request)


@app.get("/api/letters/{letter_id}/export/{export_type}")
def legacy_export(letter_id: int, export_type: str, db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
    text = _build_export_text(export_type, iocs)
    if text is None:
        raise HTTPException(status_code=400, detail=f"Неизвестный тип экспорта: {export_type}")
    filename = _EXPORT_FILENAMES.get(export_type, f"{export_type}.txt")
    return Response(text.encode("utf-8"), media_type="text/plain; charset=utf-8",
                    headers={"Content-Disposition": _content_disposition(filename)})


@app.get("/api/letters/{letter_id}/export/{export_type}/docx")
def legacy_export_docx(letter_id: int, export_type: str, db: Session = Depends(get_db),
                       user: User = Depends(get_current_user)):
    doc = _owned_document(db, user, letter_id, detail="Письмо не найдено")
    iocs = db.query(IoC).filter(IoC.document_id == doc.id).all()
    content = _build_export_text(export_type, iocs, docx=True)
    if content is None:
        raise HTTPException(status_code=400, detail=f"Неизвестный тип экспорта: {export_type}")
    filename = _EXPORT_DOCX_FILENAMES.get(export_type, f"{export_type}.docx")
    return Response(content, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": _content_disposition(filename)})


def _build_export_text(export_type: str, iocs, docx: bool = False):
    """Возвращает текст или bytes для вида экспорта, либо None для неизвестного типа."""
    if docx:
        from shared.generator.ioc_export_docx import export_ips_docx, export_domains_docx, \
            export_emails_docx, export_all_docx
        builders = {
            "emails": export_emails_docx, "ip_addresses": export_ips_docx,
            "domains": export_domains_docx, "ioc_indicators": export_all_docx,
        }
        fn = builders.get(export_type)
        return fn(iocs) if fn else None

    from shared.generator.ioc_export import export_emails, export_ips, export_domains, export_all
    builders = {
        "emails": export_emails, "ip_addresses": export_ips,
        "domains": export_domains, "ioc_indicators": export_all,
    }
    fn = builders.get(export_type)
    return fn(iocs) if fn else None


_EXPORT_FILENAMES = {
    "emails": "emails.txt",
    "ip_addresses": "ip-адреса на блокировку.txt",
    "domains": "Адреса на блокировку.txt",
    "ioc_indicators": "ioc_indicators.txt",
}

_EXPORT_DOCX_FILENAMES = {
    "emails": "emails.docx",
    "ip_addresses": "ip-адреса на блокировку.docx",
    "domains": "Адреса на блокировку.docx",
    "ioc_indicators": "ioc_indicators.docx",
}


@app.get("/api/letters/{letter_id}/download")
def legacy_download(letter_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    _owned_document(db, user, letter_id, detail="Письмо не найдено")
    resp = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == letter_id) \
        .order_by(GeneratedResponse.id.desc()).first()
    if not resp:
        raise HTTPException(status_code=404, detail="Ответ ещё не сгенерирован")
    import io
    from docx import Document as DocxDocument
    if resp.edited_content:
        content = base64.b64decode(resp.edited_content)
    else:
        buf = io.BytesIO()
        d = DocxDocument()
        d.add_paragraph(resp.content or "")
        d.save(buf)
        content = buf.getvalue()
    return Response(content, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": _content_disposition(f"answer_{letter_id}.docx")})


# ---------------- Templates (шаблоны и библиотека мер) ----------------

def _threat_type_dict(tt):
    return {"id": tt.id, "name": tt.name, "key": tt.key,
            "description": tt.description or "",
            "created_at": tt.created_at.isoformat() if tt.created_at else None}


def _measure_tpl_dict(mt):
    return {"id": mt.id, "name": mt.name, "threat_type_id": mt.threat_type_id,
            "measures": mt.content or "", "is_default": bool(mt.is_default),
            "created_at": mt.created_at.isoformat() if mt.created_at else None}


def _vuln_tpl_dict(vt):
    return {"id": vt.id, "name": vt.name, "vuln_type_id": None,
            "action_type": vt.action_type or "update", "content": vt.content or "",
            "is_default": bool(vt.is_default),
            "created_at": vt.created_at.isoformat() if vt.created_at else None}


@app.get("/api/templates/threat-types")
def list_threat_types(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_threat_type_dict(t) for t in db.query(ThreatType).order_by(ThreatType.id).all()]


@app.post("/api/templates/threat-types", status_code=201)
def create_threat_type(body: dict, db: Session = Depends(get_db), user: User = Depends(require_admin)):
    name = (body.get("name") or "").strip()
    key = (body.get("key") or "").strip()
    if not name or not key:
        raise HTTPException(status_code=422, detail="name и key обязательны")
    if db.query(ThreatType).filter(ThreatType.name == name).first():
        raise HTTPException(status_code=409, detail="Тип угрозы с таким названием уже есть")
    if db.query(ThreatType).filter(ThreatType.key == key).first():
        raise HTTPException(status_code=409, detail="Тип угрозы с таким ключом уже есть")
    tt = ThreatType(name=name, key=key, description=(body.get("description") or "").strip())
    db.add(tt)
    db.commit()
    _audit(db, user, "threat_type_create", "threat_type", tt.id)
    return _threat_type_dict(tt)


@app.put("/api/templates/threat-types/{tt_id}")
def update_threat_type(tt_id: int, body: dict, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    tt = db.query(ThreatType).filter(ThreatType.id == tt_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Тип угрозы не найден")
    if "name" in body and body["name"]:
        tt.name = (body["name"] or "").strip()
    if "description" in body:
        tt.description = (body.get("description") or "")
    db.commit()
    _audit(db, user, "threat_type_update", "threat_type", tt.id)
    return _threat_type_dict(tt)


@app.delete("/api/templates/threat-types/{tt_id}")
def delete_threat_type(tt_id: int, db: Session = Depends(get_db),
                       user: User = Depends(require_admin)):
    tt = db.query(ThreatType).filter(ThreatType.id == tt_id).first()
    if not tt:
        raise HTTPException(status_code=404, detail="Тип угрозы не найден")
    db.query(MeasureTemplate).filter(MeasureTemplate.threat_type_id == tt_id).delete(
        synchronize_session=False)
    db.delete(tt)
    db.commit()
    _audit(db, user, "threat_type_delete", "threat_type", tt_id)
    return {"status": "deleted"}


@app.get("/api/templates/measure-templates")
def list_measure_templates(threat_type_id: int | None = Query(None, ge=1, le=2_147_483_647),
                           db: Session = Depends(get_db),
                           user: User = Depends(require_admin)):
    q = db.query(MeasureTemplate)
    if threat_type_id:
        q = q.filter(MeasureTemplate.threat_type_id == threat_type_id)
    return [_measure_tpl_dict(m) for m in q.order_by(MeasureTemplate.id).all()]


@app.post("/api/templates/measure-templates", status_code=201)
def create_measure_template(body: dict, db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    content = (body.get("measures") if body.get("measures") not in (None, "")
               else body.get("content") or "")
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="name обязателен")
    mt = MeasureTemplate(name=name, threat_type_id=body.get("threat_type_id"),
                         content=str(content or ""), is_default=bool(body.get("is_default")))
    db.add(mt)
    db.commit()
    _audit(db, user, "measure_template_create", "measure_template", mt.id)
    return _measure_tpl_dict(mt)


@app.put("/api/templates/measure-templates/{mt_id}")
def update_measure_template(mt_id: int, body: dict, db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    mt = db.query(MeasureTemplate).filter(MeasureTemplate.id == mt_id).first()
    if not mt:
        raise HTTPException(status_code=404, detail="Шаблон мер не найден")
    if "name" in body and body["name"]:
        mt.name = (body["name"] or "").strip()
    if "threat_type_id" in body:
        mt.threat_type_id = body["threat_type_id"]
    if body.get("measures") not in (None, ""):
        mt.content = str(body["measures"])
    elif "content" in body:
        mt.content = str(body.get("content") or "")
    if "is_default" in body:
        mt.is_default = bool(body.get("is_default"))
    db.commit()
    _audit(db, user, "measure_template_update", "measure_template", mt.id)
    return _measure_tpl_dict(mt)


@app.delete("/api/templates/measure-templates/{mt_id}")
def delete_measure_template(mt_id: int, db: Session = Depends(get_db),
                            user: User = Depends(require_admin)):
    mt = db.query(MeasureTemplate).filter(MeasureTemplate.id == mt_id).first()
    if not mt:
        raise HTTPException(status_code=404, detail="Шаблон мер не найден")
    db.delete(mt)
    db.commit()
    _audit(db, user, "measure_template_delete", "measure_template", mt_id)
    return {"status": "deleted"}


@app.get("/api/templates/vuln-templates")
def list_vuln_templates(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    return [_vuln_tpl_dict(v) for v in db.query(VulnActionTemplate).order_by(VulnActionTemplate.id).all()]


@app.post("/api/templates/vuln-templates", status_code=201)
def create_vuln_template(body: dict, db: Session = Depends(get_db),
                         user: User = Depends(require_admin)):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=422, detail="name обязателен")
    vt = VulnActionTemplate(name=name, action_type=(body.get("action_type") or "update").strip(),
                            content=(body.get("content") or "").strip(),
                            is_default=bool(body.get("is_default")))
    db.add(vt)
    db.commit()
    _audit(db, user, "vuln_template_create", "vuln_action_template", vt.id)
    return _vuln_tpl_dict(vt)


@app.put("/api/templates/vuln-templates/{vt_id}")
def update_vuln_template(vt_id: int, body: dict, db: Session = Depends(get_db),
                         user: User = Depends(require_admin)):
    vt = db.query(VulnActionTemplate).filter(VulnActionTemplate.id == vt_id).first()
    if not vt:
        raise HTTPException(status_code=404, detail="Шаблон уязвимости не найден")
    if "name" in body and body["name"]:
        vt.name = (body["name"] or "").strip()
    if "action_type" in body:
        vt.action_type = (body.get("action_type") or "update").strip()
    if "content" in body:
        vt.content = str(body.get("content") or "")
    if "is_default" in body:
        vt.is_default = bool(body.get("is_default"))
    db.commit()
    _audit(db, user, "vuln_template_update", "vuln_action_template", vt.id)
    return _vuln_tpl_dict(vt)


@app.delete("/api/templates/vuln-templates/{vt_id}")
def delete_vuln_template(vt_id: int, db: Session = Depends(get_db),
                         user: User = Depends(require_admin)):
    vt = db.query(VulnActionTemplate).filter(VulnActionTemplate.id == vt_id).first()
    if not vt:
        raise HTTPException(status_code=404, detail="Шаблон уязвимости не найден")
    db.delete(vt)
    db.commit()
    _audit(db, user, "vuln_template_delete", "vuln_action_template", vt_id)
    return {"status": "deleted"}


# ---------------- Diagnostics ----------------

def _probe_http(url: str, timeout: float = 3.0) -> dict:
    """Проверка доступности хоста. «Доступен» = получен любой HTTP-ответ (включая 4xx/5xx),
    недоступен — только транспортные ошибки (DNS, таймаут, TLS, refused)."""
    import urllib.error
    import urllib.request
    start = time.time()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "fstec-diagnostics"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return {"reachable": True, "http_status": resp.status,
                    "latency_ms": round((time.time() - start) * 1000), "error": ""}
    except urllib.error.HTTPError as e:  # сервер ответил не-2xx — хост доступен
        return {"reachable": True, "http_status": e.code,
                "latency_ms": round((time.time() - start) * 1000),
                "error": f"HTTP {e.code}"}
    except Exception as e:  # noqa: BLE001
        return {"reachable": False, "http_status": None,
                "latency_ms": round((time.time() - start) * 1000),
                "error": str(e)[:160]}


def _db_health(db: Session) -> dict:
    from sqlalchemy import text
    start = time.time()
    try:
        db.execute(text("SELECT 1")).scalar()
        return {"name": "База данных", "reachable": True,
                "latency_ms": round((time.time() - start) * 1000), "error": ""}
    except Exception as e:  # noqa: BLE001
        return {"name": "База данных", "reachable": False,
                "latency_ms": round((time.time() - start) * 1000),
                "error": str(e)[:160]}


def _services_with_heartbeat() -> list[dict]:
    from shared.registry import read_services
    now = time.time()
    out = []
    for s in read_services():
        lt = s.get("last_seen")
        out.append({**s, "pid_exists": bool(s.get("alive")),
                    "heartbeat_age_sec": int(now - lt) if lt else None})
    return out


@app.get("/api/diagnostics")
def diagnostics(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Статус модулей, БД, внешних подключений, LLM и ресурсов (для страницы «Диагностика»)."""
    from shared.config import (BDU_API_BASE, CMDB_ENDPOINT, CMDB_PROVIDER,
                               LLM_PROVIDER, NVD_API_BASE, VLLM_BASE_URL, VLLM_MODEL)
    from shared.registry import touch_service
    import psutil

    touch_service("gateway")
    services = _services_with_heartbeat()

    # Проверки выполняются сервером (gateway), а не браузером.
    external = [{"name": "BDU ФСТЭК", "url": f"{BDU_API_BASE.rstrip('/')}/",
                 **_probe_http(f"{BDU_API_BASE.rstrip('/')}/", timeout=4.0)}]
    # NVD отдаёт большой JSON; проверяем доступность корня API
    external.append({"name": "NVD (NIST)", "url": f"{NVD_API_BASE}/rest/json/cves/2.0?resultsPerPage=1",
                     **_probe_http(f"{NVD_API_BASE}/rest/json/cves/2.0?resultsPerPage=1", timeout=4.0)})
    if CMDB_PROVIDER != "mock":
        external.append({"name": "CMDB (rest)", "url": CMDB_ENDPOINT,
                         **_probe_http(CMDB_ENDPOINT, timeout=4.0)})
    else:
        external.append({"name": "CMDB (rest)", "url": CMDB_ENDPOINT, "reachable": True,
                         "http_status": None, "latency_ms": 0,
                         "error": "провайдер 'mock' (внешний запрос не выполняется)"})

    llm_probe = _probe_http(f"{VLLM_BASE_URL}/models", timeout=2.0)
    llm = {
        "provider": LLM_PROVIDER,
        "base_url": VLLM_BASE_URL,
        "model": VLLM_MODEL,
        "reachable": llm_probe["reachable"],
        "http_status": llm_probe["http_status"],
        "latency_ms": llm_probe["latency_ms"],
        "error": llm_probe["error"],
        "note": ("heuristic-режим: LLM не вызывается (dev). Для реальных вызовов укажите "
                 "FSTEC_LLM_PROVIDER=vllm") if LLM_PROVIDER != "vllm" else "",
    }

    proc = psutil.Process()
    disk = psutil.disk_usage(str(Path(__file__).resolve().parent.parent))
    system = {
        "cpu_percent": psutil.cpu_percent(interval=0.4),
        "memory_mb": round(psutil.virtual_memory().used / 1048576),
        "memory_total_mb": round(psutil.virtual_memory().total / 1048576),
        "disk_free_gb": round(disk.free / 1073741824, 1),
        "gateway_proc_cpu_percent": proc.cpu_percent(interval=0.2),
        "gateway_proc_memory_mb": round(proc.memory_info().rss / 1048576),
        "gateway_uptime_sec": int(time.time() - proc.create_time()),
    }
    from shared.config import GATEWAY_PORT
    gw_probe = _probe_http(f"http://127.0.0.1:{GATEWAY_PORT}/api/health", timeout=2.0)
    return {"services": services, "external": external, "db": _db_health(db),
            "llm": llm, "system": system,
            "gateway": {"name": "gateway", "reachable": gw_probe["reachable"],
                        "http_status": gw_probe["http_status"],
                        "latency_ms": gw_probe["latency_ms"], "error": gw_probe["error"]}}


@app.get("/api/diagnostics/ping")
def diagnostics_ping(name: str | None = Query(default=None, max_length=64),
                     db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Активный «пинг» модулей (или одного), БД и самого gateway."""
    from shared.config import GATEWAY_PORT

    def _ok(service: dict) -> bool:
        return bool(service.get("pid_exists")) and (service.get("heartbeat_age_sec") or 0) <= 60

    now = time.time()
    services = []
    for s in _services_with_heartbeat():
        if name and s["name"] != name:
            continue
        services.append({
            "name": s["name"], "pid": s["pid"], "pid_exists": s["pid_exists"],
            "alive": s["alive"], "heartbeat_age_sec": s["heartbeat_age_sec"],
            "ok": _ok(s), "latency_ms": None,
        })

    gw = _probe_http(f"http://127.0.0.1:{GATEWAY_PORT}/api/health", timeout=2.0)
    for s in services:
        if s["name"] == "gateway":
            s["ok"] = gw["reachable"]
            s["latency_ms"] = gw["latency_ms"]
    return {"pinged_at": round(now), "name_sent": name or None,
            "services": services, "db": _db_health(db),
            "gateway": {"ok": gw["reachable"], "latency_ms": gw["latency_ms"],
                        "error": gw["error"]}}


@app.get("/api/diagnostics/bus")
def diagnostics_bus(db: Session = Depends(get_db), user: User = Depends(require_admin)):
    """Краткий статус очереди сообщений (dev: SQLite-таблица bus_message)."""
    from sqlalchemy import text
    try:
        total = db.execute(text("SELECT COUNT(*) FROM bus_message")).scalar() or 0
        topics = db.execute(text(
            "SELECT topic, COUNT(*) AS c, MAX(id) AS last_id FROM bus_message GROUP BY topic")).fetchall()
        rows = [{"topic": t[0], "count": t[1], "last_id": t[2]} for t in topics]
        return {"total": total, "topics": rows}
    except Exception as e:  # noqa: BLE001
        return {"total": 0, "topics": [], "error": str(e)[:160]}


if __name__ == "__main__":
    import uvicorn
    from shared.config import GATEWAY_PORT
    from shared.registry import register_service
    register_service("gateway")
    uvicorn.run(app, host="0.0.0.0", port=GATEWAY_PORT)