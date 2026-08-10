import io
import urllib.parse
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import Response
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, Letter, Threat, IoC, Vulnerability, GeneratedResponse
from app.auth import get_current_user
from app.generator.response_generator import generate_response, generate_response_from_text
from app.generator.ioc_exporter import EXPORT_TYPES, EXPORT_FILENAMES
from app.generator.ioc_docx_exporter import EXPORT_DOCX_TYPES, EXPORT_DOCX_FILENAMES

router = APIRouter(prefix="/api/letters", tags=["generate"])


@router.post("/{letter_id}/generate", status_code=201)
def generate_letter_response(
    letter_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")

    threats = db.query(Threat).filter(Threat.letter_id == letter_id).order_by(Threat.number).all()
    vulns = db.query(Vulnerability).filter(Vulnerability.letter_id == letter_id).all()

    docx_bytes = generate_response(letter, threats, vulns, db=db)
    text_content = _extract_text_from_docx(docx_bytes)

    existing = db.query(GeneratedResponse).filter(
        GeneratedResponse.letter_id == letter_id
    ).order_by(GeneratedResponse.id.desc()).first()

    if existing:
        existing.content = text_content
        existing.edited_content = docx_bytes.decode("latin-1", errors="replace")
        response = existing
    else:
        response = GeneratedResponse(
            letter_id=letter_id,
            content=text_content,
            edited_content=docx_bytes.decode("latin-1", errors="replace"),
            created_by=current_user.id,
        )
        db.add(response)

    letter.status = "response_generated"
    db.commit()
    db.refresh(response)

    return {"id": response.id, "letter_id": letter_id, "status": "generated", "text": text_content}


@router.get("/{letter_id}/response/text")
def get_response_text(
    letter_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    resp = db.query(GeneratedResponse).filter(
        GeneratedResponse.letter_id == letter_id
    ).order_by(GeneratedResponse.id.desc()).first()

    if not resp:
        return {"text": "", "exists": False}

    return {"text": resp.content or "", "exists": True}


@router.get("/{letter_id}/response/preview")
def get_response_preview(
    letter_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    from app.generator.response_generator import (
        _build_threat_description, _get_measures_for_threat,
    )
    from app.models import MeasureTemplate, ThreatType

    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")

    threats = db.query(Threat).filter(Threat.letter_id == letter_id).order_by(Threat.number).all()
    num = letter.letter_number or ""
    dt = letter.letter_date or ""
    if dt:
        try:
            parts = dt.split("-")
            if len(parts) == 3:
                dt = f"{parts[2]}.{parts[1]}.{parts[0]}"
        except Exception:
            pass

    title = f"Ответ на письмо {num} от {dt}"
    intro = "Сообщаем о принятых мерах по повышению защищенности инфраструктуры Правительства Липецкой области."

    all_measure_options = {}
    for tt in db.query(ThreatType).all():
        opts = []
        for mt in db.query(MeasureTemplate).filter(MeasureTemplate.threat_type_id == tt.id).all():
            short_lines = [m.strip() for m in mt.measures.split("\n") if m.strip()]
            for m in short_lines:
                if m and m not in opts:
                    opts.append(m)
        all_measure_options[tt.key] = opts

    sections = []
    has_multiple = len(threats) > 1
    for threat in threats:
        prefix = f"{threat.number}. " if has_multiple else ""
        desc = _build_threat_description(threat)

        tt_key = threat.threat_type or ""
        if not tt_key:
            from app.extractor.letter_analyzer import _detect_threat_type
            tt_key = _detect_threat_type(threat.description or "")
            threat.threat_type = tt_key
            db.commit()

        measures = _get_measures_for_threat(threat, db)

        if threat.measures and threat.measures.strip():
            saved = [m.strip() for m in threat.measures.split("\n") if m.strip()]
            if saved:
                measures = saved

        # предпросмотр показывает те же короткие меры, что попадают в финальный
        # DOCX-ответ (без списков IoC), чтобы предпросмотр и ответ совпадали
        measures_preview = list(measures)

        measure_options = all_measure_options.get(tt_key, [])

        intro_text = f"{prefix}В целях предотвращения возможности реализации угроз безопасности информации, связанных с {desc}, приняты следующие меры защиты:"
        measures_text = "\n".join(f"  {m}" for m in measures_preview)
        section_text = f"{intro_text}\n{measures_text}" if measures_preview else intro_text

        sections.append({
            "threat_id": threat.id,
            "number": threat.number,
            "prefix": prefix,
            "description": desc,
            "measures": measures,
            "measures_preview": measures_preview,
            "threat_type": tt_key,
            "measure_options": measure_options,
            "intro_text": intro_text,
            "section_text": section_text,
        })

    return {
        "title": title,
        "intro": intro,
        "sections": sections,
    }


@router.put("/{letter_id}/response/measures/{threat_id}")
def update_threat_measures(
    letter_id: int,
    threat_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    threat = db.query(Threat).filter(Threat.id == threat_id, Threat.letter_id == letter_id).first()
    if not threat:
        raise HTTPException(status_code=404, detail="Угроза не найдена")

    measures = data.get("measures")
    if measures is None:
        raise HTTPException(status_code=400, detail="Нет поля measures")

    threat.measures = "\n".join(measures)
    db.commit()

    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    all_threats = db.query(Threat).filter(Threat.letter_id == letter_id).order_by(Threat.number).all()
    all_vulns = db.query(Vulnerability).filter(Vulnerability.letter_id == letter_id).all()

    docx_bytes = generate_response(letter, all_threats, all_vulns, db=db)
    text_content = _extract_text_from_docx(docx_bytes)

    resp = db.query(GeneratedResponse).filter(
        GeneratedResponse.letter_id == letter_id
    ).order_by(GeneratedResponse.id.desc()).first()

    if resp:
        resp.content = text_content
        resp.edited_content = docx_bytes.decode("latin-1", errors="replace")
    else:
        resp = GeneratedResponse(
            letter_id=letter_id,
            content=text_content,
            edited_content=docx_bytes.decode("latin-1", errors="replace"),
            created_by=current_user.id,
        )
        db.add(resp)
    db.commit()

    return {"measures": measures, "text": text_content}


@router.get("/{letter_id}/download")
def download_response(
    letter_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")

    resp = db.query(GeneratedResponse).filter(
        GeneratedResponse.letter_id == letter_id
    ).order_by(GeneratedResponse.id.desc()).first()

    if not resp:
        threats = db.query(Threat).filter(Threat.letter_id == letter_id).order_by(Threat.number).all()
        vulns = db.query(Vulnerability).filter(Vulnerability.letter_id == letter_id).all()
        docx_bytes = generate_response(letter, threats, vulns, db=db)
    elif resp.edited_content:
        docx_bytes = resp.edited_content.encode("latin-1", errors="replace")
    else:
        docx_bytes = generate_response_from_text(resp.content or "")

    num = letter.letter_number or str(letter.id)
    filename = f"Ответ на письмо {num}.docx"
    encoded_filename = urllib.parse.quote(filename)

    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"},
    )


@router.put("/{letter_id}/response")
def update_response_content(
    letter_id: int,
    data: dict,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")

    text = data.get("content")
    if text is None:
        raise HTTPException(status_code=400, detail="Нет поля content")

    docx_bytes = generate_response_from_text(text)

    resp = db.query(GeneratedResponse).filter(
        GeneratedResponse.letter_id == letter_id
    ).order_by(GeneratedResponse.id.desc()).first()

    if not resp:
        resp = GeneratedResponse(
            letter_id=letter_id,
            content=text,
            edited_content=docx_bytes.decode("latin-1", errors="replace"),
            created_by=current_user.id,
        )
        db.add(resp)
    else:
        resp.content = text
        resp.edited_content = docx_bytes.decode("latin-1", errors="replace")

    db.commit()

    return {"status": "updated"}


@router.get("/{letter_id}/export/{export_type}")
def export_iocs(
    letter_id: int,
    export_type: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if export_type not in EXPORT_TYPES:
        raise HTTPException(status_code=400, detail=f"Неизвестный тип экспорта: {export_type}")

    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")

    iocs = db.query(IoC).filter(IoC.letter_id == letter_id).all()

    content = EXPORT_TYPES[export_type](letter, iocs)
    filename = EXPORT_FILENAMES[export_type]
    encoded_filename = urllib.parse.quote(filename)

    return Response(
        content=content.encode("utf-8"),
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"},
    )


@router.get("/{letter_id}/export/{export_type}/docx")
def export_iocs_docx(
    letter_id: int,
    export_type: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    if export_type not in EXPORT_DOCX_TYPES:
        raise HTTPException(status_code=400, detail=f"Неизвестный тип экспорта: {export_type}")

    letter = db.query(Letter).filter(Letter.id == letter_id).first()
    if not letter:
        raise HTTPException(status_code=404, detail="Письмо не найдено")

    iocs = db.query(IoC).filter(IoC.letter_id == letter_id).all()

    docx_bytes = EXPORT_DOCX_TYPES[export_type](letter, iocs)
    filename = EXPORT_DOCX_FILENAMES[export_type]
    encoded_filename = urllib.parse.quote(filename)

    return Response(
        content=docx_bytes,
        media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        headers={"Content-Disposition": f"attachment; filename*=UTF-8''{encoded_filename}"},
    )


def _extract_text_from_docx(docx_bytes: bytes) -> str:
    try:
        from docx import Document
        doc = Document(io.BytesIO(docx_bytes))
        lines = []
        for p in doc.paragraphs:
            if p.text.strip():
                lines.append(p.text)
        return "\n\n".join(lines)
    except Exception:
        return ""
