"""Security Posture Analyzer (ТЗ 2.4): обогащение NVD/BDU → сопоставление с CMDB →
версионный matching → recommendation/SLA. Keep-all: ВСЕ уязвимости письма возвращаются
(cmatch_match — флаг), рекомендация по формуле «Обновить {P} с {a} до {b}»."""
import asyncio
import logging
import re
from difflib import SequenceMatcher
from dataclasses import dataclass, field

from security_service.cmdb import InventoryClient, InventoryItem
from security_service.enriched import EnrichedVuln
from security_service.versioning import (compare_versions, match_cpe, match_product,
                                         match_product_strict, vuln_range_hit)
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
    """Обогащает raw-уязвимость клиентами внешних БД.

    Для BDU-записей источником истины является BDU: именно BDU задаёт
    версию CVSS (3.1) и severity для ответа ФСТЭК. NVD используется как
    дополнительный источник CPE/диапазонов версий, если BDU их не дал.
    """
    cve_id = (vuln.get("cve_id") or "").strip()
    bdu_id = (vuln.get("bdu_id") or "").strip()
    errors: list[str] = []
    found: dict[str, EnrichedVuln] = {}
    requests = []
    if nvd and cve_id:
        requests.append(("NVD", cve_id, nvd.get_cve(cve_id)))
    if bdu and bdu_id:
        requests.append(("BDU", bdu_id, bdu.get_bdu(bdu_id)))
    if requests:
        results = await asyncio.gather(*(task for _, _, task in requests), return_exceptions=True)
        for (kind, vid, _), result in zip(requests, results):
            if isinstance(result, Exception):
                logger.warning("%s lookups failed for %s: %s", kind, vid, result)
                errors.append(f"{kind}:{vid}:{result}")
            elif isinstance(result, EnrichedVuln):
                found[kind] = result

    bdu_result = found.get("BDU")
    nvd_result = found.get("NVD")
    if bdu_result is not None:
        if nvd_result is not None:
            if not bdu_result.cpe_matches:
                bdu_result.cpe_matches = nvd_result.cpe_matches
            if not bdu_result.fixed_version:
                bdu_result.fixed_version = nvd_result.fixed_version
            if not bdu_result.patch_url:
                bdu_result.patch_url = nvd_result.patch_url
            if not bdu_result.cve_id:
                bdu_result.cve_id = nvd_result.cve_id
            if not bdu_result.cvss_version:
                bdu_result.cvss_version = nvd_result.cvss_version
        return bdu_result, "; ".join(errors)
    if nvd_result is not None:
        return nvd_result, "; ".join(errors)
    return None, "; ".join(errors)


def _cpe_ok(matcher, item_cpe: str) -> bool:
    """True если CPE-запись уязвимости похожа на CPE инвентаря (по vendor/product)."""
    from security_service.versioning import _cpe_parts
    v = _cpe_parts(matcher.criteria)
    i = _cpe_parts(item_cpe)
    if not v or not i:
        return False
    return (not v[0] or not i[0] or v[0] == i[0]) and (not v[1] or not i[1] or v[1] == i[1])


_NON_PRODUCT_TOKENS = {
    "bdu", "cve", "cvss", "api", "http", "https", "raw", "xml", "gnu", "os",
    "and", "the", "for", "with",
}


def _description_product_candidates(description: str) -> list[str]:
    """Извлекает названия продуктов из текста уязвимости без списка соответствий."""
    text = " ".join((description or "").split())
    match = re.search(
        r"уязвимость\s+(.+?)(?:\s+связан|,\s*связан|\.(?:\s|$))",
        text, re.IGNORECASE)
    clause = match.group(1) if match else text
    candidates = re.findall(
        r"[A-Za-z][A-Za-z0-9]*(?:[ ._+&/-]+[A-Za-z][A-Za-z0-9]*)*",
        clause)
    result: list[str] = []
    seen: set[str] = set()
    for candidate in reversed(candidates):
        candidate = candidate.strip(" .,;:-")
        key = candidate.casefold()
        if len(candidate) < 2 or key in seen or key in _NON_PRODUCT_TOKENS:
            continue
        seen.add(key)
        result.append(candidate)
    return result


def _product_kind(description: str, product: str = "") -> str:
    low = " ".join((description or "").lower().replace("ё", "е").split())
    needle = (product or "").casefold()
    position = low.rfind(needle) if needle else -1
    context = low[max(0, position - 180):position] if position >= 0 else low
    library_markers = (
        "библиотек", "пакет", "модул", "фреймворк", "интерпретатор",
        "языка программирования", "компонент",
    )
    application_markers = (
        "платформ", "систем", "сервер", "приложен", "устройств", "процессор",
        "операционн", "редактор", "средств",
    )
    library_pos = max((context.rfind(marker) for marker in library_markers), default=-1)
    application_pos = max(
        (context.rfind(marker) for marker in application_markers), default=-1)
    return "library" if library_pos > application_pos else "application"


def _product_for_cmdb(description: str, software: str) -> tuple[str, list[str]]:
    """Возвращает отображаемый продукт и все разумные термины для GLPI."""
    primary = " ".join((software or "").split()).strip(" ,;:-")
    candidates = _description_product_candidates(description)
    primary_key = primary.casefold().strip(" -")
    valid_primary = (
        bool(primary)
        and any(ch.isalpha() and ch.isascii() for ch in primary)
        and not primary.endswith("-")
        and primary_key not in _NON_PRODUCT_TOKENS
    )
    product = primary if valid_primary else (candidates[0] if candidates else primary)
    return product, ([product] if product else [])


def _affected_product_hit(enriched: EnrichedVuln | None, software: str,
                          current_version: str) -> bool:
    if not enriched or not current_version:
        return False
    current = current_version.casefold().replace("ё", "е")
    for product in enriched.affected_products:
        name = str(product.get("name") or "")
        version = str(product.get("version") or "")
        if not match_product(name, software):
            continue
        values = f"{name} {version}".casefold().replace("ё", "е")
        if current and current in values:
            return True
    return False


def _candidate_matches(candidate: InventoryItem, term: str, kind: str) -> bool:
    if match_product_strict(candidate.name, term, kind):
        return True
    if not match_product(candidate.vendor, term):
        return False
    low_name = candidate.name.casefold()
    blocked = ("runner", "agent", "update", "viewer", "util", "library",
               "module", "plugin", "sdk", "driver", "firmware", "common")
    return not any(marker in low_name for marker in blocked)


def _related_glpi_names(candidates: list[InventoryItem], software: str) -> list[str]:
    tokens = [token for token in re.split(r"[^0-9A-Za-zА-Яа-яЁё]+",
                                          software.casefold()) if len(token) >= 3]
    if not tokens:
        return []
    return [
        candidate.name for candidate in candidates
        if all(token in candidate.name.casefold() for token in tokens)
    ]


def _match_cmdb(enriched: EnrichedVuln | None, candidates: list[InventoryItem],
                software: str, fixed_hint: str = "") -> tuple[InventoryItem | None, bool]:
    """Выбирает лучшего кандидата CMDB и определяет версионный match (ТЗ 2.4).

    Match = (CPE-совпадение ∥ product-совпадение) ∧ (нет диапазона ∨ версия в диапазоне).
    """
    if not candidates:
        return None, False
    range_info = bool(enriched and any(
        r.is_specified for m in enriched.cpe_matches for r in m.ranges))
    for item in candidates:
        if not item.installed:
            continue
        cpe_hit = bool(enriched and enriched.cpes and item.cpe
                       and match_cpe(enriched.cpes, item.cpe))
        name_hit = (match_product(item.name, software)
                    or match_product(item.vendor, software))
        if not (cpe_hit or name_hit):
            continue
        version_hit = False
        fixed_for_check = (enriched.fixed_version if enriched else fixed_hint)
        if item.version:
            if range_info and enriched:
                if cpe_hit and item.cpe:
                    targets = [m for m in enriched.cpe_matches if _cpe_ok(m, item.cpe)]
                    if not targets:
                        targets = enriched.cpe_matches
                else:
                    targets = enriched.cpe_matches
                version_hit = bool(targets) and vuln_range_hit(item.version, targets)
            elif fixed_for_check:
                version_hit = compare_versions(item.version, fixed_for_check) < 0
        if not version_hit:
            continue
        return item, True
    return None, False


def _severity(enriched: EnrichedVuln | None, raw: dict) -> str:
    if enriched and enriched.severity != "unknown":
        return enriched.severity
    return raw.get("severity") or "unknown"


def _mentions_software(description: str, software: str) -> bool:
    def norm(value: str) -> str:
        text = (value or "").lower().replace("ё", "е")
        return " ".join("".join(ch if ch.isalnum() else " " for ch in text).split())
    desc = norm(description)
    tokens = [token for token in norm(software).split() if len(token) >= 4]
    return not tokens or any(token in desc for token in tokens)


def _bdu_description_mismatch(enriched: EnrichedVuln | None, raw: dict,
                              software: str) -> bool:
    raw_desc = (raw.get("description") or "").strip()
    enriched_desc = (enriched.description if enriched else "").strip()
    return bool(enriched_desc and raw_desc
                and not _mentions_software(enriched_desc, software)
                and _mentions_software(raw_desc, software))


def _preferred_description(enriched: EnrichedVuln | None, raw: dict,
                           software: str) -> str:
    if _bdu_description_mismatch(enriched, raw, software):
        return (raw.get("description") or "").strip()
    return (enriched.description if enriched else "").strip() or (raw.get("description") or "").strip()


@dataclass
class Assessment:
    assessed: list[dict] = field(default_factory=list)
    external_errors: list[str] = field(default_factory=list)
    sla: str = "normal"
    routing: str = "default"


async def _assess_one(v: dict, *, cmdb, enrich: bool, nvd, bdu, cmdb_cache: dict | None = None) -> tuple[dict, str]:
    """Обогащение + сопоставление с CMDB для одной уязвимости."""
    raw = dict(v or {})
    raw_software = " ".join((raw.get("software") or "").split())
    enriched: EnrichedVuln | None = None
    if enrich and (raw.get("cve_id") or raw.get("bdu_id")) and (nvd or bdu):
        enriched, errs = await _enrich(raw, nvd, bdu)
        err_text = errs
    else:
        err_text = ""

    bdu_mismatch = _bdu_description_mismatch(enriched, raw, raw_software)
    preferred_description = _preferred_description(enriched, raw, raw_software)
    software, lookup_terms = _product_for_cmdb(preferred_description, raw_software)
    if not (raw.get("bdu_id") or raw.get("cve_id")):
        software, lookup_terms = "", []
    fixed = (derive_fixed_version(
        None if bdu_mismatch else enriched, preferred_description)
        or " ".join(str(raw.get("fixed_version") or "").split()).strip(" ,;"))
    item, matched = None, False
    cmdb_error = ""
    candidates: list[InventoryItem] = []
    seen_candidates: set[tuple[str, str, int]] = set()
    try:
        for term in lookup_terms or ([software] if software else []):
            cache_key = term.casefold()
            if cmdb_cache is not None and cache_key in cmdb_cache:
                found = cmdb_cache[cache_key]
            else:
                found = await cmdb.find_many(term)
                if cmdb_cache is not None:
                    cmdb_cache[cache_key] = found
            for candidate in found:
                key = (candidate.name.casefold(), candidate.version, candidate.assets)
                if key not in seen_candidates:
                    seen_candidates.add(key)
                    candidates.append(candidate)
    except Exception as exc:  # noqa: BLE001 — CMDB недоступна (ТЗ 4.2)
        logger.warning("cmdb lookup failed for %r: %s", software, exc)
        cmdb_error = f"cmdb:{software}:{exc}"
        err_text = "; ".join(x for x in (err_text, f"cmdb:{software}:{exc}") if x)

    lookup_targets = lookup_terms or ([software] if software else [])
    product_kind = _product_kind(preferred_description, software)
    raw_candidates = list(candidates)
    candidates = [
        candidate for candidate in candidates
        if any(_candidate_matches(candidate, term, product_kind)
               for term in lookup_targets)
    ]
    if not candidates and software:
        normalized_software = software.casefold().replace(" ", "")
        fallback_terms = [
            candidate for candidate in _description_product_candidates(preferred_description)
            if len(candidate) >= 4
            and (candidate.casefold().replace(" ", "") in normalized_software
                 or normalized_software in candidate.casefold().replace(" ", ""))
        ]
        for term in fallback_terms:
            cache_key = term.casefold()
            if cmdb_cache is not None and cache_key in cmdb_cache:
                found = cmdb_cache[cache_key]
            else:
                found = await cmdb.find_many(term)
                if cmdb_cache is not None:
                    cmdb_cache[cache_key] = found
            for candidate in found:
                key = (candidate.name.casefold(), candidate.version, candidate.assets)
                if key not in seen_candidates:
                    seen_candidates.add(key)
                    candidates.append(candidate)
        candidates = [
            candidate for candidate in candidates
            if any(_candidate_matches(candidate, term, product_kind)
                   for term in fallback_terms)
        ]
    for term in lookup_targets:
        item, matched = _match_cmdb(
            enriched, candidates, term, fixed_hint=fixed)
        if item:
            break
    installed = [candidate for candidate in candidates if candidate.installed]
    current_version = (item.version if item else
                       (installed[0].version if installed else ""))
    range_info = bool(enriched and any(
        spec.is_specified for cpe_match in enriched.cpe_matches for spec in cpe_match.ranges))
    affected_hit = _affected_product_hit(enriched, software, current_version)
    affected_named = bool(enriched and any(
        match_product(str(p.get("name") or ""), software)
        for p in enriched.affected_products))
    related_names = _related_glpi_names(raw_candidates, software)
    vendor_alias_hit = bool(
        affected_named and any(
            match_product(candidate.vendor, software)
            and not match_product_strict(candidate.name, software, product_kind)
            and candidate.name.isalnum()
            and not any(token in candidate.name.casefold()
                        for token in re.findall(r"[a-zа-яё0-9]{3,}", software.casefold()))
            and SequenceMatcher(None, candidate.name.casefold(),
                                software.casefold()).ratio() >= 0.6
            for candidate in installed
        )
    )
    if cmdb_error:
        applicable = None
    else:
        applicable = bool(installed) or (affected_named and bool(related_names))
    if matched or affected_hit or vendor_alias_hit:
        action_type = "update" if fixed else "compensate"
    elif installed and not fixed and not range_info:
        action_type = "skip" if enriched and enriched.affected_products else "verify"
    elif affected_named and related_names:
        action_type = "verify"
    elif applicable is not None:
        action_type = "skip"
    else:
        action_type = ""
    notes = ""
    if installed and current_version:
        notes = (f"ПО «{installed[0].name}» {current_version} найдено в GLPI (список ПО); "
                 f"{installed[0].assets} запись в списке.")
        if software.casefold() != raw_software.casefold():
            notes += f" Продукт уточнён по описанию: «{software}»."
        if vendor_alias_hit:
            notes += " Продукт сопоставлен с GLPI по вендору."
        if action_type == "verify":
            notes += " Диапазон уязвимых версий и исправленная версия не заданы."
    elif affected_named and related_names:
        notes = (f"Продукт «{software}» используется, но в GLPI найдена только "
                 f"запись компонента «{related_names[0]}»; версия продукта не подтверждена.")
    elif applicable is False:
        notes = f"ПО «{software}» не найдено в установленном ПО GLPI."
    remediation = enriched.remediation if enriched else ""
    rec = (f"Обновить {item.name if item else software} с {current_version} до {fixed}"
           if matched and fixed else (remediation or UPDATE_TEMPLATE))
    return {
        "cve_id": enriched.cve_id if enriched and enriched.cve_id else raw.get("cve_id", ""),
        "bdu_id": enriched.bdu_id if enriched and enriched.bdu_id else raw.get("bdu_id", ""),
        "description": preferred_description,
        "software": software,
        "severity": ((raw.get("severity") or "unknown") if bdu_mismatch
                     else _severity(enriched, raw)),
        "cvss_score": (raw.get("cvss_score") if bdu_mismatch
                       else (enriched.cvss_score if enriched else raw.get("cvss_score"))),
        "cvss_version": (enriched.cvss_version if enriched else raw.get("cvss_version", "")),
        "cpe": ((raw.get("cpe") if bdu_mismatch
                 else (enriched.cpes[0] if enriched and enriched.cpes else raw.get("cpe"))) or ""),
        "affected_range": ((raw.get("affected_range") if bdu_mismatch
                            else (enriched.affected_range if enriched else raw.get("affected_range"))) or ""),
        "fixed_version": fixed,
        "patch_url": enriched.patch_url if enriched else (raw.get("patch_url") or ""),
        "cmdb_match": matched,
        "cmdb_error": cmdb_error,
        "current_version": current_version,
        "target_version": fixed,
        "recommendation": rec,
        "remediation": remediation,
        "action_details": remediation,
        "source": enriched.source if enriched else "manual",
        "is_applicable": applicable,
        "action_type": action_type,
        "applicability_notes": notes,
    }, err_text


async def assess_document(vulns_raw: list[dict], *, cmdb: InventoryClient,
                          enrich: bool | None = None, nvd=None, bdu=None,
                          letter_type: str = "") -> Assessment:
    """Полный цикл ТЗ 2.4. enrich=False → без внешних вызовов (mock/dev-режим).

    Этап 4: уязвимости одного письма обрабатываются параллельно (ранее строго
    последовательно), но не более SECURITY_LOOKUP_CONCURRENCY одновременно —
    это ограничивает давление на NVD/BDU/CMDB. Порядок результата совпадает с
    порядком во входном списке."""
    from shared.concurrency import bounded_gather
    from shared.config import SECURITY_LOOKUP_CONCURRENCY

    enrich = SECURITY_MODE == "live" if enrich is None else enrich
    vulns = list(vulns_raw or [])
    if not vulns:
        return Assessment(assessed=[], external_errors=[], sla="normal", routing="default")

    cmdb_cache: dict = {}

    # Один запрос GLPI на уникальное ПО на документ, а не на каждую уязвимость.
    unique_products = sorted({
        " ".join((v.get("software") or "").split())
        for v in vulns if " ".join((v.get("software") or "").split())
    })

    async def _warm_cmdb(product: str) -> None:
        try:
            cmdb_cache[product] = await cmdb.find_many(product)
        except Exception as exc:  # noqa: BLE001 — ошибки обработает _assess_one
            logger.debug("CMDB prefetch failed for %s: %s", product, exc)

    if cmdb is not None and unique_products:
        await bounded_gather(
            [_warm_cmdb(product) for product in unique_products],
            SECURITY_LOOKUP_CONCURRENCY,
            name="cmdb-prefetch",
        )

    results = await bounded_gather(
        [_assess_one(v, cmdb=cmdb, enrich=enrich, nvd=nvd, bdu=bdu, cmdb_cache=cmdb_cache)
         for v in vulns],
        SECURITY_LOOKUP_CONCURRENCY,
        name="security",
    )
    out: list[dict] = []
    external_errors: list[str] = []
    for rec, err_text in results:
        out.append(rec)
        if err_text:
            external_errors.append(err_text)

    sla_score = "critical" if (
        any(a.get("cmdb_match") for a in out)
        or (letter_type or "").lower() in ("compromise", "clickfix")
    ) else "normal"
    routing = "infosec" if sla_score == "critical" or (letter_type or "").lower() in ("compromise", "clickfix") else "default"
    return Assessment(assessed=out, external_errors=external_errors, sla=sla_score, routing=routing)
