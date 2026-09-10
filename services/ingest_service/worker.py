"""Ingest Service (ТЗ 2.2): парсинг + OCR → document.parsed."""
import asyncio
import logging
from pathlib import Path

from shared.bus import get_event_bus
from shared.config import OCR_ENABLED, OCR_MIN_TEXT, OCR_LANG
from shared.db import SessionLocal
from shared.events import DocumentParsed
from shared.models import Attachment, Document
from shared.parsers import parse_file
from shared.parsers.ocr import ocr_pdf_bytes
from shared.worker import configure_logging, register_handlers

logger = logging.getLogger("fstec.ingest")


async def handle_uploaded(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip ingest", doc_id)
            return
        attachments = (db.query(Attachment)
                       .filter(Attachment.document_id == doc_id)
                       .order_by(Attachment.is_main.desc())
                       .order_by(Attachment.id).all())
        if not attachments:
            logger.warning("No attachments for doc %s", doc_id)
            return

        main_text = ""
        all_texts: list[str] = []
        ocr_used = False
        parse_errors: list[str] = []
        att_meta = []

        for att in attachments:
            path = Path(att.file_path)
            try:
                result = parse_file(path)
            except Exception as exc:
                att.parse_status = "error"
                att.parse_errors = str(exc)
                parse_errors.append(f"{att.filename}: {exc}")
                continue

            text = result.text or ""
            if text and len(text.strip()) < OCR_MIN_TEXT and OCR_ENABLED and att.file_type == ".pdf":
                try:
                    content = path.read_bytes()
                    text, ocr_errors = ocr_pdf_bytes(content, lang=OCR_LANG)
                    ocr_used = True
                    parse_errors.extend(f"OCR {att.filename}: {e}" for e in ocr_errors)
                    logger.info("OCR applied to %s (chars=%d)", att.filename, len(text))
                except Exception as exc:
                    parse_errors.append(f"OCR {att.filename}: {exc}")

            att.parsed_text = text
            att.parse_status = "done" if text.strip() else "empty"
            all_texts.append(text)
            if att.is_main:
                main_text = text
            att_meta.append({"filename": att.filename, "text_len": len(text), "status": att.parse_status})

        doc.original_text = main_text or (all_texts[0] if all_texts else "")
        doc.all_text = "\n\n".join(t for t in all_texts if t.strip())
        doc.ocr_used = ocr_used
        doc.processing_stage = "parsed"
        doc.status = "parsed"
        doc.parse_errors = "; ".join(parse_errors)
        db.commit()

    event = DocumentParsed(
        document_id=doc_id,
        text=main_text or (all_texts[0] if all_texts else ""),
        all_text="\n\n".join(t for t in all_texts if t.strip()),
        ocr_used=ocr_used,
        parse_errors=parse_errors,
        attachments=att_meta,
    )
    await get_event_bus().publish("document.parsed", str(doc_id), event.model_dump(mode="json"))
    logger.info("Parsed doc %s: %d attachments, %d chars", doc_id, len(att_meta),
                len(event.all_text))


def main():
    configure_logging()
    asyncio.run(run_service())


async def run_service():
    bus = get_event_bus()
    register_handlers(bus, {"documents.uploaded": handle_uploaded})
    from shared.worker import serve_forever
    await serve_forever(bus)


if __name__ == "__main__":
    main()