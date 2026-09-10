"""LLM Service (ТЗ 2.3): document.parsed → анализ → document.analyzed."""
import asyncio
import logging

from shared.bus import get_event_bus
from shared.db import SessionLocal, init_db
from shared.models import Document
from shared.worker import configure_logging, register_handlers, serve_forever
from llm_service.analyze import analyze, compute_sla, persist_analysis
from llm_service.provider import get_provider

logger = logging.getLogger("fstec.llm")


async def handle_parsed(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    text = (payload.get("all_text") or payload.get("text") or "")
    if not text.strip():
        logger.warning("Empty text for doc %s, skip analysis", doc_id)
        return
    provider = get_provider()
    event_data, _ = analyze(provider, text)
    event_data.document_id = doc_id

    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip analysis", doc_id)
            return
        persist_analysis(db, doc, event_data)
        sla, routing = compute_sla(
            classification=event_data.classification,
            threat_count=len(event_data.threats),
            vuln_severities=[v.get("severity", "unknown") for v in event_data.vulns_raw],
            domain_count=len(event_data.iocs.domains),
        )
        doc.sla, doc.routing = sla, routing
        db.commit()
        event_data.sla = sla
        event_data.routing = routing

    await get_event_bus().publish("document.analyzed", str(doc_id), event_data.model_dump(mode="json"))
    logger.info("Analyzed doc %s: %s, %d threats, %d iocs", doc_id,
                event_data.classification, len(event_data.threats),
                len(event_data.iocs.ip_addresses) + len(event_data.iocs.domains))


def main():
    configure_logging()
    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"document.parsed": handle_parsed})
        await serve_forever(bus)
    asyncio.run(_run())


if __name__ == "__main__":
    main()