"""Сборка блоков письма для генератора ответа.

Общая логика для API и reporting-воркера. Для загруженного файла-ответа
(«Ответ на письмо …») метаданные и меры берутся из исходного письма с тем же
номером, а не из пустого ответа.
"""
from sqlalchemy.orm import Session

from shared.models import Document, Threat, User


def _is_derived_reply(doc: Document) -> bool:
    name = (doc.source_filename or "").strip().casefold()
    return name.startswith(("ответ", "response", "answer"))


def reply_source_document(db: Session, doc: Document,
                          user: User | None = None) -> Document | None:
    if not doc.letter_number or not _is_derived_reply(doc):
        return None
    query = (db.query(Document)
             .filter(Document.letter_number == doc.letter_number, Document.id != doc.id)
             .order_by(Document.id))
    if user is not None and user.role != "admin":
        query = query.filter(Document.created_by == doc.created_by)
    for candidate in query.all():
        if not _is_derived_reply(candidate):
            return candidate
    return None


def build_reply_blocks(db: Session, doc: Document,
                       user: User | None = None) -> list[dict]:
    threat_rows = (db.query(Threat).filter(Threat.document_id == doc.id)
                   .order_by(Threat.number).all())
    source_doc = reply_source_document(db, doc, user)
    source_by_number = {}
    if source_doc is not None:
        source_by_number = {
            t.number: t for t in (db.query(Threat)
                                  .filter(Threat.document_id == source_doc.id)
                                  .order_by(Threat.number).all())
        }

    blocks = []
    phishing_rank = 0
    for threat in threat_rows:
        source = source_by_number.get(threat.number)
        measure_text = (source.measures if source else "") or threat.measures
        if (threat.threat_type or "").strip().lower() == "phishing":
            phishing_rank += 1
        blocks.append({
            "id": threat.id,
            "number": threat.number,
            "threat_type": threat.threat_type or (source.threat_type if source else ""),
            "theme": threat.theme or (source.theme if source else ""),
            "group_name": threat.group_name or (source.group_name if source else ""),
            "archive_name": threat.archive_name or (source.archive_name if source else ""),
            "exe_name": threat.exe_name or (source.exe_name if source else ""),
            "malware_type": threat.malware_type or (source.malware_type if source else ""),
            "description": source.description if source else threat.description,
            "explicit_measures": [m.strip() for m in (measure_text or "").split("\n")
                                  if m.strip()],
            "phishing_rank": phishing_rank,
        })
    return blocks
