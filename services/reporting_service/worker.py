"""Reporting Service (ТЗ 2.5): security.assessed → карточка индикаторов (2.5.1)
и проект ответа (2.5.2) → report.ready + reply.generated."""
import asyncio
import base64
import logging
from datetime import date, datetime, timezone
from pathlib import Path

from shared.bus import get_event_bus
from shared.config import ORG_NAME, REPORT_DIR
from shared.db import SessionLocal, init_db
from shared.events import ReportReady, ReplyGenerated
from shared.generator.indicator_card import build_indicator_card, report_filename
from shared.generator.response_generator import render_reply_docx
from shared.models import (
    Document, GeneratedResponse, IoC, Report, Threat, Vulnerability,
)
from shared.worker import configure_logging, register_handlers, serve_forever

logger = logging.getLogger("fstec.reporting")


def _now():
    return datetime.now(timezone.utc)


async def handle_assessed(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    assessed_vulns = payload.get("vulnerabilities", [])

    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip report", doc_id)
            return

        ioc = db.query(IoC).filter(IoC.document_id == doc_id).all()
        ips = [i.value for i in ioc if i.ioc_type == "ip"]
        ipv6 = [i.value for i in ioc if i.ioc_type == "ipv6"]
        domains = [i.value for i in ioc if i.ioc_type == "domain"]
        emails = [i.value for i in ioc if i.ioc_type == "email"]

        vulns = [{
            "cve_id": v.get("cve_id", ""),
            "bdu_id": v.get("bdu_id", ""),
            "description": v.get("description", ""),
            "software": v.get("software", ""),
            "severity": v.get("severity", "unknown"),
            "cvss_score": v.get("cvss_score"),
            "affected_range": v.get("affected_range", ""),
            "fixed_version": v.get("fixed_version", ""),
            "patch_url": v.get("patch_url", ""),
            "current_version": v.get("current_version", ""),
            "target_version": v.get("target_version", ""),
            "recommendation": v.get("recommendation", ""),
            "cmdb_match": v.get("cmdb_match", False),
            "source": v.get("source", "manual"),
        } for v in assessed_vulns]

        # 2.5.1 Карточка индикаторов
        card_bytes = build_indicator_card(
            org_name=ORG_NAME,
            source_filename=doc.source_filename,
            document_id=doc.id,
            ips=ips,
            ipv6=ipv6,
            domains=domains,
            emails=emails,
            vulnerabilities=vulns,
            sla=doc.sla,
        )
        fname = report_filename(doc.source_filename)
        report_dir = REPORT_DIR / f"doc_{doc.id}"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / fname
        report_path.write_bytes(card_bytes)

        db.add(Report(document_id=doc.id, report_type="indicator_card",
                      filename=fname, file_path=str(report_path)))

        # 2.5.2 Проект ответа (шаблон + библиотека мер + LLM-подбор; fallback — детерминированный)
        threat_rows = (db.query(Threat).filter(Threat.document_id == doc_id)
                       .order_by(Threat.number).all())
        blocks = [{
            "id": t.id, "number": t.number, "threat_type": t.threat_type, "theme": t.theme,
            "group_name": t.group_name, "archive_name": t.archive_name, "exe_name": t.exe_name,
            "malware_type": t.malware_type, "description": t.description,
        } for t in threat_rows]
        from shared.generator.templated_reply import generate_reply, persist_candidates
        rep = generate_reply(
            db=db, doc_id=doc.id, letter_type=doc.letter_type, blocks=blocks,
            addr_count=len(domains) + len(ips), active_vulns=[v for v in vulns],
            addresses=sorted({*domains, *ips}),
        )
        if rep["candidates"]:
            for i, c in enumerate(rep["candidates"]):
                rep["candidates"][i]["threat_id"] = (blocks[i]["id"] if i < len(blocks) else None)
            persist_candidates(db, doc.id, rep["candidates"])

        reply_text = rep["text"]
        reply_docx = render_reply_docx(reply_text)
        ans_fname = f"answer_{doc.id}.docx"
        reply_path = report_dir / ans_fname
        reply_path.write_bytes(reply_docx)

        db.add(GeneratedResponse(document_id=doc.id, content=reply_text,
                                 edited_content=base64.b64encode(reply_docx).decode("ascii"),
                                 plan_json=rep["plan_json"]))

        doc.processing_stage = "done"
        doc.status = "completed"
        db.commit()

        card_rel, reply_rel = str(report_path), str(reply_path)

    await get_event_bus().publish("report.ready", str(doc_id), ReportReady(
        document_id=doc_id, report_type="indicator_card", filename=fname,
        file_path=card_rel).model_dump(mode="json"))
    await get_event_bus().publish("reply.generated", str(doc_id), ReplyGenerated(
        document_id=doc_id, filename=ans_fname,
        file_path=reply_rel, text=reply_text).model_dump(mode="json"))
    logger.info("Report + reply generated for doc %s", doc_id)


def main():
    configure_logging()
    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"security.assessed": handle_assessed})
        await serve_forever(bus)
    asyncio.run(_run())


if __name__ == "__main__":
    main()