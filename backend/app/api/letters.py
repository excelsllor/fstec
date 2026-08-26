import os
import shutil
from pathlib import Path
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form
from sqlalchemy.orm import Session
from sqlalchemy import func
from app.database import get_db
from app.config import UPLOAD_DIR, ALLOWED_EXTENSIONS, MAX_FILE_SIZE, MAX_TOTAL_SIZE
from app.models import User, Letter, Attachment, Threat, IoC, Vulnerability
from app.auth import get_current_user
from app.schemas import LetterListItem, LetterResponse, StatsResponse, VulnerabilityUpdate
from app.parsers import parse_bytes, ParseResult
from app.extractor.ioc_extractor import extract_iocs
from app.extractor.letter_analyzer import analyze_letter
from app.extractor.vuln_extractor import extract_vulns

router = APIRouter(prefix="/api/letters", tags=["letters"])

_MAGIC_BYTES = {
    ".pdf": [b"%PDF"],
    ".docx": [b"PK"],
    ".doc": [b"\xd0\xcf\x11\xe0"],
    ".xlsx": [b"PK"],
    ".xls": [b"\xd0\xcf\x11\xe0"],
    ".odt": [b"PK"],
}


def _validate_magic_bytes(filename: str, content: bytes):
    ext = Path(filename).suffix.lower()
    expected = _MAGIC_BYTES.get(ext)
    if expected and content:
        if not any(content[:8].startswith(magic) for magic in expected):
            raise HTTPException(
                status_code=415,
                detail=f"Файл «{filename}» не соответствует формату {ext} (проверка содержимого)",
            )


def _require_letter_access(letter: Letter, user: User):
    if letter.created_by != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Нет доступа к этому письму")


@router.post("/upload", response_model=LetterResponse, status_code=201)
def upload_letter(
    pdf_file: UploadFile = File(...),
    attachments: list[UploadFile] = File(default=[]),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if not pdf_file.filename:
        raise HTTPException(status_code=400, detail="Нет основного файла")

    base_name = Path(pdf_file.filename).stem
    letter_dir = UPLOAD_DIR / f"letter_{base_name}_{os.urandom(4).hex()}"

    def _cleanup():
        shutil.rmtree(letter_dir, ignore_errors=True)

    main_ext = Path(pdf_file.filename).suffix.lower()
    if main_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(status_code=415, detail=f"Недопустимый формат файла: {main_ext or '(нет расширения)'}. Разрешены: {', '.join(sorted(ALLOWED_EXTENSIONS))}")

    all_text_parts = []
    parse_errors = []

    pdf_content = pdf_file.file.read()
    if len(pdf_content) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"Файл больше {MAX_FILE_SIZE // (1024 * 1024)} МБ")

    _validate_magic_bytes(pdf_file.filename, pdf_content)

    total_size = len(pdf_content)

    letter_dir.mkdir(parents=True, exist_ok=True)
    pdf_path = letter_dir / Path(pdf_file.filename).name
    with open(pdf_path, "wb") as f:
        f.write(pdf_content)

    try:
        pdf_result = parse_bytes(pdf_file.filename, pdf_content)
    except Exception as e:
        pdf_result = ParseResult(errors=[f"{type(e).__name__}: {e}"])
    all_text_parts.append(pdf_result.text)
    parse_errors.extend(pdf_result.errors)

    if not pdf_result.text.strip():
        _cleanup()
        raise HTTPException(status_code=422, detail="Не удалось извлечь текст из основного файла")

    letter_info = analyze_letter(pdf_result.text)
    iocs = extract_iocs(pdf_result.text, pdf_result.tables)
    vulns = extract_vulns(pdf_result.text, pdf_result.tables)

    letter = Letter(
        letter_number=letter_info.letter_number,
        letter_date=letter_info.letter_date,
        letter_type=letter_info.letter_type,
        status="processed",
        original_text=pdf_result.text,
        all_text=pdf_result.text,
        parse_errors="\n".join(parse_errors),
        created_by=current_user.id,
    )
    db.add(letter)
    db.flush()

    pdf_attachment = Attachment(
        letter_id=letter.id,
        filename=pdf_file.filename,
        file_path=str(pdf_path),
        file_type=main_ext,
        parsed_text=pdf_result.text,
        parse_status="ok" if not pdf_result.errors else "partial",
        parse_errors="\n".join(pdf_result.errors),
    )
    db.add(pdf_attachment)

    for att in attachments:
        if not att.filename or att.filename.startswith("~$"):
            continue

        att_name = Path(att.filename).name
        att_ext = Path(att_name).suffix.lower()
        if att_ext not in ALLOWED_EXTENSIONS:
            _cleanup()
            raise HTTPException(status_code=415, detail=f"Недопустимый формат вложения: {att_ext or '(нет расширения)'}")

        att_content = att.file.read()
        if len(att_content) > MAX_FILE_SIZE:
            _cleanup()
            raise HTTPException(status_code=413, detail=f"Вложение «{att_name}» больше {MAX_FILE_SIZE // (1024 * 1024)} МБ")
        _validate_magic_bytes(att_name, att_content)
        total_size += len(att_content)
        if total_size > MAX_TOTAL_SIZE:
            _cleanup()
            raise HTTPException(status_code=413, detail=f"Суммарный размер файлов больше {MAX_TOTAL_SIZE // (1024 * 1024)} МБ")

        att_path = letter_dir / att_name
        with open(att_path, "wb") as f:
            f.write(att_content)

        try:
            att_result = parse_bytes(att_name, att_content)
        except Exception as e:
            att_result = ParseResult(errors=[f"{type(e).__name__}: {e}"])
        all_text_parts.append(att_result.text)

        attachment = Attachment(
            letter_id=letter.id,
            filename=att_name,
            file_path=str(att_path),
            file_type=att_ext,
            parsed_text=att_result.text,
            parse_status="ok" if not att_result.errors else "partial",
            parse_errors="\n".join(att_result.errors),
        )
        db.add(attachment)

        if att_result.errors:
            parse_errors.extend(att_result.errors)

        att_iocs = extract_iocs(att_result.text, att_result.tables)
        _merge_iocs(db, letter.id, att_iocs)
        att_vulns = extract_vulns(att_result.text, att_result.tables)
        _merge_vulns(db, letter.id, att_vulns)

    letter.all_text = "\n\n".join(all_text_parts)
    letter.parse_errors = "\n".join(parse_errors)

    for threat in letter_info.threats:
        db.add(Threat(
            letter_id=letter.id,
            number=threat.number,
            group_name=threat.group_name,
            threat_type=threat.threat_type,
            theme=threat.theme,
            archive_name=threat.archive_name,
            exe_name=threat.exe_name,
            malware_type=threat.malware_type,
            description=threat.description,
            measures="",
        ))

    _merge_iocs(db, letter.id, iocs)
    _merge_vulns(db, letter.id, vulns)

    db.commit()
    db.refresh(letter)
    return letter


@router.get("", response_model=list[LetterListItem])
def list_letters(
    skip: int = 0,
    limit: int = 50,
    letter_type: str | None = None,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    query = db.query(Letter)
    if letter_type:
        query = query.filter(Letter.letter_type == letter_type)
    letters = query.order_by(Letter.created_at.desc()).offset(skip).limit(limit).all()

    result = []
    for letter in letters:
        threat_count = db.query(func.count(Threat.id)).filter(Threat.letter_id == letter.id).scalar() or 0
        ioc_count = db.query(func.count(IoC.id)).filter(IoC.letter_id == letter.id).scalar() or 0
        vuln_count = db.query(func.count(Vulnerability.id)).filter(Vulnerability.letter_id == letter.id).scalar() or 0
        result.append(LetterListItem(
            id=letter.id,
            letter_number=letter.letter_number,
            letter_date=letter.letter_date,
            letter_type=letter.letter_type,
            status=letter.status,
            created_at=letter.created_at,
            threat_count=threat_count,
            ioc_count=ioc_count,
            vuln_count=vuln_count,
        ))
    return result


@router.get("/stats", response_model=StatsResponse)
def get_stats(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    total = db.query(func.count(Letter.id)).scalar() or 0
    return StatsResponse(
        total_letters=total,
        hacker_letters=db.query(func.count(Letter.id)).filter(Letter.letter_type == "hacker").scalar() or 0,
        compromise_letters=db.query(func.count(Letter.id)).filter(Letter.letter_type == "compromise").scalar() or 0,
        vulnerability_letters=db.query(func.count(Letter.id)).filter(Letter.letter_type == "vulnerability").scalar() or 0,
        other_letters=db.query(func.count(Letter.id)).filter(Letter.letter_type == "other").scalar() or 0,
        total_threats=db.query(func.count(Threat.id)).scalar() or 0,
        total_iocs=db.query(func.count(IoC.id)).scalar() or 0,
        total_vulns=db.query(func.count(Vulnerability.id)).scalar() or 0,
    )


@router.get("/{letter_id}", response_model=LetterResponse)
def get_letter(
    letter_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")
    return letter


@router.put("/{letter_id}/vulnerabilities/{vuln_id}", response_model=LetterResponse)
def update_vulnerability(
    letter_id: int,
    vuln_id: int,
    data: VulnerabilityUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")
    _require_letter_access(letter, current_user)

    vuln = db.query(Vulnerability).filter(
        Vulnerability.id == vuln_id,
        Vulnerability.letter_id == letter_id,
    ).first()
    if not vuln:
        raise HTTPException(status_code=404, detail="Уязвимость не найдена")

    if data.is_applicable is not None:
        vuln.is_applicable = data.is_applicable
    if data.applicability_notes is not None:
        vuln.applicability_notes = data.applicability_notes
    if data.action_type is not None:
        vuln.action_type = data.action_type
    if data.action_details is not None:
        vuln.action_details = data.action_details
    if data.response_point is not None:
        vuln.response_point = data.response_point
    if data.software is not None:
        vuln.software = data.software

    db.commit()
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    return letter


@router.delete("/{letter_id}", status_code=204)
def delete_letter(
    letter_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")
    _require_letter_access(letter, current_user)
    db.delete(letter)
    db.commit()


def _merge_iocs(db: Session, letter_id: int, iocs):
    existing = {(i.ioc_type, i.value) for i in db.query(IoC).filter(IoC.letter_id == letter_id).all()}
    type_map = {
        "ips": "ip", "domains": "domain", "hashes": "hash",
        "emails": "email", "vuln_ids": "bdu", "cve_ids": "cve",
    }
    for attr, ioc_type in type_map.items():
        for val in getattr(iocs, attr):
            if (ioc_type, val) not in existing:
                db.add(IoC(letter_id=letter_id, ioc_type=ioc_type, value=val))
                existing.add((ioc_type, val))


def _merge_vulns(db: Session, letter_id: int, vulns):
    existing_bdu = {v.bdu_id for v in db.query(Vulnerability).filter(
        Vulnerability.letter_id == letter_id,
        Vulnerability.bdu_id != "",
    ).all()}
    existing_cve = {v.cve_id for v in db.query(Vulnerability).filter(
        Vulnerability.letter_id == letter_id,
        Vulnerability.cve_id != "",
    ).all()}

    for v in vulns:
        if v.bdu_id and v.bdu_id in existing_bdu:
            continue
        if v.cve_id and v.cve_id in existing_cve:
            continue
        if v.bdu_id:
            existing_bdu.add(v.bdu_id)
        if v.cve_id:
            existing_cve.add(v.cve_id)
        db.add(Vulnerability(
            letter_id=letter_id,
            bdu_id=v.bdu_id,
            cve_id=v.cve_id,
            description=v.description,
            software=v.software,
            severity=v.severity,
        ))
