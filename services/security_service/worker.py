"""Security Posture Analyzer (ТЗ 2.4): document.analyzed → обогащение NVD/BDU + CMDB +
версионный matching → security.assessed (keep-all; match — флаг). Недоступность внешних
БД → graceful (raw в письме), внешние ошибки в external_errors + audit + DLQ (ТЗ 4.2)."""
import asyncio
import logging

from sqlalchemy.orm import Session

from shared.bus import get_event_bus
from shared.config import SECURITY_MODE
from shared.db import SessionLocal, init_db
from shared.events import AuditEvent, SecurityAssessed, VulnerabilityAssessed
from shared.models import Document, SLABase, Vulnerability, VulnActionTemplate
from shared.worker import configure_logging, register_handlers, serve_forever
from security_service.assessment import assess_document
from security_service.bdu_client import BDUClient
from security_service.cache import get_cache
from security_service.cmdb import get_cmdb
from security_service.nvd_client import NVDClient

logger = logging.getLogger("fstec.security")

# Инъекция клиентов для тестов (CI/offline): set_test_clients(nvd=..., bdu=..., cmdb=...)
_OVERRIDES: dict[str, object] = {}
_enrich: bool | None = None
_nvd: NVDClient | None = None
_bdu: BDUClient | None = None


def set_test_clients(nvd=None, bdu=None, cmdb=None) -> None:
    global _enrich
    _OVERRIDES.clear()
    _enrich = None
    if nvd is not None:
        _OVERRIDES["nvd"] = nvd
    if bdu is not None:
        _OVERRIDES["bdu"] = bdu
    if cmdb is not None:
        _OVERRIDES["cmdb"] = cmdb
    if nvd is not None or bdu is not None:
        _enrich = True


def set_enrich(enabled: bool) -> None:
    global _enrich
    _enrich = enabled


def _get_nvd() -> NVDClient | None:
    global _nvd
    if SECURITY_MODE != "live":
        return None
    if _nvd is None:
        _nvd = NVDClient(cache=get_cache())
    return _nvd


def _get_bdu() -> BDUClient | None:
    global _bdu
    if SECURITY_MODE != "live":
        return None
    if _bdu is None:
        _bdu = BDUClient(cache=get_cache())
    return _bdu


def _store_assessments(db: Session, doc: Document, assessed: list[dict]) -> None:
    db.query(Vulnerability).filter(Vulnerability.document_id == doc.id).delete()
    templates = {t.action_type: t.content for t in db.query(VulnActionTemplate).all()}
    for a in assessed:
        rec = Vulnerability(
            document_id=doc.id,
            cve_id=a.get("cve_id", ""),
            bdu_id=a.get("bdu_id", ""),
            description=a.get("description", ""),
            software=a.get("software", ""),
            severity=a.get("severity", "unknown"),
            cvss_score=a.get("cvss_score"),
            cpe=a.get("cpe", ""),
            affected_range=a.get("affected_range", ""),
            fixed_version=a.get("fixed_version", ""),
            patch_url=a.get("patch_url", ""),
            cmdb_match=a.get("cmdb_match", False),
            current_version=a.get("current_version", ""),
            target_version=a.get("target_version", ""),
            source=a.get("source", "manual"),
            recommendation=a.get("recommendation", templates.get("update", "")),
        )
        db.add(rec)


async def handle_analyzed(topic: str, key: str, payload: dict) -> None:
    doc_id = int(payload["document_id"])
    vulns_raw = payload.get("vulns_raw", [])

    nvd = _OVERRIDES.get("nvd", _get_nvd())
    bdu = _OVERRIDES.get("bdu", _get_bdu())
    cmdb = _OVERRIDES.get("cmdb") or get_cmdb() or None

    enrich = _enrich if _enrich is not None else (SECURITY_MODE == "live")
    assessment = await assess_document(vulns_raw, cmdb=cmdb, enrich=enrich, nvd=nvd, bdu=bdu)
    sla, routing = assessment.sla, assessment.routing

    with SessionLocal() as db:
        doc = db.query(Document).filter(Document.id == doc_id).first()
        if not doc:
            logger.warning("Document %s not found, skip security", doc_id)
            return
        _store_assessments(db, doc, assessment.assessed)
        doc.sla, doc.routing = sla, routing
        doc.processing_stage = "assessed"
        doc.status = "assessed"
        db.add(SLABase(document_id=doc_id, sla=sla, routing=routing,
                       reason=f"cmdb_matches={sum(1 for a in assessment.assessed if a['cmdb_match'])}"))
        db.commit()

    bus = get_event_bus()
    if assessment.external_errors:
        reason = "; ".join(assessment.external_errors)[:2000]
        await bus.publish("audit.events", str(doc_id), _audit(doc_id, reason))
        await bus.publish("documents.failed", str(doc_id), {
            "event": "documents.failed",
            "document_id": doc_id,
            "stage": "security.assessed",
            "reason": reason,
        })
        logger.warning("External security sources unavailable for doc %s: %s", doc_id, reason)

    event = SecurityAssessed(
        document_id=doc_id,
        vulnerabilities=[VulnerabilityAssessed(**a) for a in assessment.assessed],
        sla=sla,
        routing=routing,
        external_errors=assessment.external_errors,
    )
    await bus.publish("security.assessed", str(doc_id), event.model_dump(mode="json"))
    logger.info("Assessed doc %s: %d vulns, sla=%s routing=%s",
                doc_id, len(assessment.assessed), sla, routing)


def _audit(doc_id: int, reason: str) -> dict:
    return AuditEvent(
        action="external_security_error", object_type="document",
        object_id=doc_id, document_id=doc_id, ip_address="",
    ).model_dump(mode="json")


def main():
    configure_logging()
    async def _run():
        init_db()
        bus = get_event_bus()
        register_handlers(bus, {"document.analyzed": handle_analyzed})
        await serve_forever(bus)
    asyncio.run(_run())


if __name__ == "__main__":
    main()