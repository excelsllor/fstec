"""Security Posture Analyzer (ТЗ 2.4): обогащение NVD/BDU → сопоставление с CMDB →
версионный matching → recommendation/SLA. Keep-all: ВСЕ уязвимости письма возвращаются
(cmatch_match — флаг), рекомендация по формуле «Обновить {P} с {a} до {b}»."""
import logging
import re
from dataclasses import dataclass, field

from security_service.cmdb import InventoryClient, InventoryItem
from security_service.enriched import EnrichedVuln
from security_service.versioning import (match_cpe, match_product, normalize_version,
                                         vuln_range_hit)
from shared.config import SECURITY_MODE

logger = logging.getLogger("fstec.security.assessment")

UPDATE_TEMPLATE = "Обновить ПО до указанной версии, закрывающей уязвимость"

_FIXED_RE = re.compile(
    r"(?:до\s+версии|устраня(?:ется|емой|емых)\s+.*?версии?|fixed\s+in|patched\s+in)"
    r"[:]?\s*([A-Za-z0-9][\w.\-]*)",
    re.IGNORECASE,
)


def derive_fixed_version(enriched: EnrichedVuln | None, raw_description: str = "") -> str:
    """fixed_version: структурированное поле BDU/NVD, иначе regex по описанию («до версии X»)."""
    if enriched and enriched.fixed_version:
        return enriched.fixed_version
    text = raw_description or (enriched.description if enriched else "")
    m = _FIXED_RE.search(text)
    if m:
        candidate = m.group(1).rstrip(".,;:")
        if re.match(r"^[\w.]", candidate):
            return candidate
    return ""


async def _enrich(vuln: dict, nvd, bdu) -> tuple[EnrichedVuln | None, str]:
    """Обогащает raw-уязвимость клиентами внешних БД. Возвращает (enriched, error_hint)."""
    cve_id = (vuln.get("cve_id") or "").strip()
    bdu_id = (vuln.get("bdu_id") or "").strip()
    errors: list[str] = []
    for client, vid, kind in ((nvd, cve_id, "NVD"), (bdu, bdu_id, "BDU")):
        if not client or not vid:
            continue
        try:
            if kind == "NVD":
                result = await client.get_cve(vid)
            else:
                result = await client.get_bdu(vid)
        except Exception as exc:  # noqa: BLE001 — недоступность внешней БД не роняет документ
            logger.warning("%s lookups failed for %s: %s", kind, vid, exc)
            errors.append(f"{kind}:{vid}:{exc}")
            continue
        if result is not None:
            return result, "; ".join(errors)
    return None, "; ".join(errors)


def _cpe_ok(matcher, item_cpe: str) -> bool:
    """True если CPE-запись уязвимости похожа на CPE инвентаря (по vendor/product)."""
    from security_service.versioning import _cpe_parts
    v = _cpe_parts(matcher.criteria)
    i = _cpe_parts(item_cpe)
    if not v or not i:
        return False
    return (not v[0] or not i[0] or v[0] == i[0]) and (not v[1] or not i[1] or v[1] == i[1])


def _match_cmdb(enriched: EnrichedVuln | None, candidates: list[InventoryItem],
                software: str) -> tuple[InventoryItem | None, bool]:
    """Выбирает лучшего кандидата CMDB и определяет версионный match (ТЗ 2.4).

    Match = (CPE-совпадение ∥ product-совпадение) ∧ (нет диапазона ∨ версия в диапазоне).
    """
    if not candidates:
        return None, False
    range_info = bool(enriched and any(
        r.is_specified for m in enriched.cpe_matches for r in m.ranges))
    for item in candidates:
        cpe_hit = bool(enriched and enriched.cpes and item.cpe
                       and match_cpe(enriched.cpes, item.cpe))
        name_hit = match_product(item.name, software)
        if not (cpe_hit or name_hit):
            continue
        version_hit = True
        if range_info and item.version and enriched:
            if cpe_hit and item.cpe:
                targets = [m for m in enriched.cpe_matches if _cpe_ok(m, item.cpe)]
                if not targets:
                    targets = enriched.cpe_matches
            else:
                targets = enriched.cpe_matches
            version_hit = bool(targets) and vuln_range_hit(item.version, targets)
        if not version_hit:
            continue
        return item, True
    return None, False


def _severity(enriched: EnrichedVuln | None, raw: dict) -> str:
    if enriched and enriched.severity != "unknown":
        return enriched.severity
    return raw.get("severity") or "unknown"


@dataclass
class Assessment:
    assessed: list[dict] = field(default_factory=list)
    external_errors: list[str] = field(default_factory=list)
    sla: str = "normal"
    routing: str = "default"


async def assess_document(vulns_raw: list[dict], *, cmdb: InventoryClient,
                          enrich: bool | None = None, nvd=None, bdu=None) -> Assessment:
    """Полный цикл ТЗ 2.4. enrich=False → без внешних вызовов (mock/dev-режим)."""
    enrich = SECURITY_MODE == "live" if enrich is None else enrich
    out: list[dict] = []
    external_errors: list[str] = []

    for v in vulns_raw or []:
        raw = dict(v or {})
        software = raw.get("software") or ""
        enriched: EnrichedVuln | None = None
        if enrich and (raw.get("cve_id") or raw.get("bdu_id")) and nvd and bdu:
            enriched, errs = await _enrich(raw, nvd, bdu)
            if errs:
                external_errors.append(errs)

        item, matched = None, False
        try:
            candidates = await cmdb.find_many(software)
            item, matched = _match_cmdb(enriched, candidates, software)
        except Exception as exc:  # noqa: BLE001 — CMDB недоступна (ТЗ 4.2)
            logger.warning("cmdb lookup failed for %r: %s", software, exc)
            external_errors.append(f"cmdb:{software}:{exc}")

        fixed = derive_fixed_version(enriched, raw.get("description", ""))
        current_version = item.version if item else ""
        rec = (f"Обновить {item.name if item else software} с {current_version} до {fixed}"
               if matched and fixed else UPDATE_TEMPLATE)
        out.append({
            "cve_id": enriched.cve_id if enriched and enriched.cve_id else raw.get("cve_id", ""),
            "bdu_id": enriched.bdu_id if enriched and enriched.bdu_id else raw.get("bdu_id", ""),
            "description": enriched.description if enriched and enriched.description else raw.get("description", ""),
            "software": software,
            "severity": _severity(enriched, raw),
            "cvss_score": enriched.cvss_score if enriched else raw.get("cvss_score"),
            "cpe": enriched.cpes[0] if enriched and enriched.cpes else (raw.get("cpe") or ""),
            "affected_range": enriched.affected_range if enriched else (raw.get("affected_range") or ""),
            "fixed_version": fixed,
            "patch_url": enriched.patch_url if enriched else (raw.get("patch_url") or ""),
            "cmdb_match": matched,
            "current_version": current_version,
            "target_version": fixed,
            "recommendation": rec,
            "source": enriched.source if enriched else "manual",
        })

    sla_score = "critical" if any(a["cmdb_match"] for a in out) else "normal"
    routing = "infosec" if sla_score == "critical" else "default"
    return Assessment(assessed=out, external_errors=external_errors, sla=sla_score, routing=routing)