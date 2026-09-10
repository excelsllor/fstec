"""Пайплайн анализа документа (llm-service): regex-first + LLM-валидация.

Сохраняет: entities, iocs, threats, vulns_raw, summary, классификацию.
Возвращает DocumentAnalyzed для публикации в document.analyzed.
"""
import logging

from sqlalchemy.orm import Session

from shared.events import AnalysisIocs, DocumentAnalyzed
from shared.extractor.ioc_extractor import extract_iocs
from shared.extractor.letter_analyzer import analyze_letter
from shared.extractor.ner import extract_standard_ner
from shared.extractor.summary import summarize_heuristic
from shared.extractor.vuln_extractor import extract_vulns
from shared.models import Document, Entity, IoC, Summary, Threat
from llm_service.provider import LLMProvider
from llm_service.rubert import rubert_available, get_rubert

logger = logging.getLogger("fstec.llm")

# Веса SLA: критичность (ТЗ 2.4 / Национальный стандарт правил категорирования)
THREAT_WEIGHTS = {
    "malware_attack": 1.4,
    "compromise": 1.3,
    "phishing": 1.1,
    "clickfix": 1.5,
    "vulnerability": 1.2,
}
VULN_WEIGHTS = {"critical": 1.8, "high": 1.6, "medium": 1.3, "low": 1.0, "unknown": 1.2}


def analyze(provider: LLMProvider, text: str) -> tuple[DocumentAnalyzed, dict]:
    """Анализ текста: результат события + ddl-промежуточные данные для БД."""
    letter = analyze_letter(text)
    iocs = extract_iocs(text)
    vulns = extract_vulns(text)
    ner = extract_standard_ner(text)
    summary = summarize_heuristic(text)

    # Классификация: regex-first (ТЗ 2.3) → RuBERT — только если regex не определил
    # тип (вернул "other"); LLM-валидация — финальный слой.
    classification = letter.letter_type
    if classification == "other" and rubert_available():
        rl, conf = get_rubert().classify(text)
        if rl and conf:
            classification = rl
    llm_result = provider.analyze(text, hint=letter.letter_type)
    if llm_result.llm_used and llm_result.classification in ("hacker", "compromise", "vulnerability", "other"):
        classification = llm_result.classification
    if llm_result.summary:
        summary = llm_result.summary
    if llm_result.entities:
        ner.organizations = [e["value"] for e in llm_result.entities if e.get("type") == "organization"] or ner.organizations
        ner.deadlines = [e["value"] for e in llm_result.entities if e.get("type") == "deadline"] or ner.deadlines
        ner.contacts = [e["value"] for e in llm_result.entities if e.get("type") == "contact"] or ner.contacts

    threats = [{"number": t.number, "threat_type": t.threat_type, "group_name": t.group_name,
                "theme": t.theme, "archive_name": t.archive_name, "exe_name": t.exe_name,
                "malware_type": t.malware_type, "description": t.description,
                "measures": t.measures} for t in letter.threats]
    vuln_items = [{"bdu_id": v.bdu_id, "cve_id": v.cve_id, "description": v.description,
                   "software": v.software, "severity": v.severity} for v in vulns]

    entities_out = [
        {"type": "organization", "value": o} for o in ner.organizations
    ] + [
        {"type": "deadline", "value": d} for d in ner.deadlines
    ] + [
        {"type": "contact", "value": c} for c in ner.contacts
    ]

    event = DocumentAnalyzed(
        document_id=0,
        classification=classification,
        letter_number=letter.letter_number,
        letter_date=letter.letter_date,
        summary=summary,
        entities=entities_out,
        iocs=AnalysisIocs(
            ip_addresses=iocs.ips,
            ipv4_cidr=iocs.ipv4_cidr,
            ipv6=iocs.ipv6,
            domains=iocs.domains,
            emails=iocs.emails,
            cve=iocs.cve_ids,
            bdu=iocs.vuln_ids,
        ),
        threats=threats,
        vulns_raw=vuln_items,
        llm_used=llm_result.llm_used,
    )
    return event, {
        "letter_number": letter.letter_number,
        "letter_date": letter.letter_date,
        "classification": classification,
        "domains": iocs.domains,
    }


def persist_analysis(db: Session, doc: Document, event: DocumentAnalyzed) -> None:
    doc.letter_number = event.letter_number
    doc.letter_date = event.letter_date
    doc.letter_type = event.classification
    doc.processing_stage = "analyzed"
    doc.status = "analyzed"
    db.query(IoC).filter(IoC.document_id == doc.id).delete()
    db.query(Threat).filter(Threat.document_id == doc.id).delete()
    db.query(Entity).filter(Entity.document_id == doc.id).delete()
    db.query(Summary).filter(Summary.document_id == doc.id).delete()

    for ioc_type, values in [
        ("ip", event.iocs.ip_addresses),
        ("ipv6", event.iocs.ipv6),
        ("domain", event.iocs.domains),
        ("email", event.iocs.emails),
        ("cve", event.iocs.cve),
        ("bdu", event.iocs.bdu),
    ]:
        for v in values:
            db.add(IoC(document_id=doc.id, ioc_type=ioc_type, value=v, source="regex" if not event.llm_used else "llm"))

    for t in event.threats:
        db.add(Threat(document_id=doc.id, number=t.get("number", 0), threat_type=t.get("threat_type", ""),
                      group_name=t.get("group_name", ""),
                      theme=t.get("theme", ""), archive_name=t.get("archive_name", ""),
                      exe_name=t.get("exe_name", ""), malware_type=t.get("malware_type", ""),
                      description=t.get("description", ""),
                      measures="\n".join(t.get("measures", []))))

    for e in event.entities:
        etype = e.get("type") if isinstance(e, dict) else e.type
        evalue = e.get("value") if isinstance(e, dict) else e.value
        db.add(Entity(document_id=doc.id, entity_type=etype, value=evalue))

    conf = 0.9 if event.llm_used else 0.6
    db.add(Summary(document_id=doc.id, summary=event.summary, confidence=conf))
    db.commit()


def compute_sla(classification: str, threat_count: int, vuln_severities: list[str], domain_count: int) -> tuple[str, str]:
    """SLA normal|critical и routing default|infosec (категорирование, ТЗ 2.4)."""
    score = 1.0
    if threat_count:
        score *= min(2.0, THREAT_WEIGHTS.get(classification, 1.0) * (1 + threat_count * 0.1))
    for sev in vuln_severities:
        score *= VULN_WEIGHTS.get(sev, 1.2)
    score *= 1.0 if domain_count == 0 else min(1.5, 1.0 + 0.1 * domain_count)
    sla = "critical" if score >= 1.6 else "normal"
    routing = "infosec" if classification in ("compromise", "clickfix") or "critical" in vuln_severities else "default"
    return sla, routing