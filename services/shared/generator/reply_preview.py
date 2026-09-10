"""Проект ответа в виде структуры секций (для файла редактирования во фронтенде).

Возвращает структуру, аналогичную legacy /api/letters/{id}/response/preview:
  title, intro, sections[] (prefix, description, measures, measures_preview,
  threat_type, measure_options, base_measures, intro_text, section_text).

Строится на новых моделях (Document/Threat/Vulnerability/IoC + справочники
MeasureTemplate / VulnActionTemplate) и переиспользует логику ответа
из response_generator (ТЗ 2.5.2).
"""
import json
import re

from shared.config import ORG_NAME
from shared.generator.response_generator import NO_RISK_TEXT, _inflect

# Набор мер по умолчанию, доступных оператору при редактировании
DEFAULT_MEASURES = [
    "производится автоматическая проверка вложений с использованием имеющейся «песочницы» («sandbox») для выявления вредоносной активности на этапе приема письма почтовым сервером;",
    "производится проверка почтовых вложений с использованием сертифицированного средства антивирусной защиты с использованием функции «Защита от почтовых угроз»;",
    "осуществляется автоматическая проверка указанных в письмах URL-адресов, содержащихся в электронных письмах, с использованием механизмов анализа ссылок;",
    "в целях идентификации отправителя производится проверка имени домена отправителя электронного письма;",
    "сотрудники проинструктированы о запрете открывать и загружать почтовые вложения писем с тематикой, не относящейся к рабочей деятельности;",
    "работы с электронной почтой производятся только с учетных записей пользователей операционной системы с минимальными возможными привилегиями;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

MONITORING = [
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

COMPROMISE_MEASURES = [
    "регулярно производится контроль журналов DNS-серверов, прокси-серверов, средств межсетевого экранирования, средств обнаружения и реагирования уровня узла;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведено внеплановое сканирование информационной инфраструктуры средствами антивирусной защиты;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]


def _normalize_date(dt: str) -> str:
    if not dt:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):
        return f"{dt[8:10]}.{dt[5:7]}.{dt[0:4]}"
    return dt


def _base_measures_for_threat_type(db, threat_type: str) -> list[str]:
    """Меры по умолчанию для типа угрозы из справочника MeasureTemplate."""
    try:
        from shared.models import MeasureTemplate, ThreatType
        tt = db.query(ThreatType).filter(ThreatType.key == threat_type).first()
        if tt:
            tmpl = (db.query(MeasureTemplate)
                    .filter(MeasureTemplate.threat_type_id == tt.id,
                            MeasureTemplate.is_default == True)
                    .first())
            if tmpl and tmpl.content:
                return [m.strip() for m in tmpl.content.split("\n") if m.strip()]
    except Exception:
        pass
    return []


def build_preview(*, db, document, threats, vulnerabilities, iocs) -> dict:
    """Секции ответа для редактора (ответ на ТЗ 2.5.2)."""
    from shared.models import GeneratedResponse
    resp = (db.query(GeneratedResponse).filter(GeneratedResponse.document_id == document.id)
            .order_by(GeneratedResponse.id.desc()).first())
    if resp and resp.plan_json:
        from shared.generator.templated_reply import build_annotated_preview
        plan = json.loads(resp.plan_json)
        title = (f"Ответ на письмо {document.letter_number} от {_normalize_date(document.letter_date)}"
                 if document.letter_number else "Ответ на письмо")
        intro = f"Сообщаем о принятых мерах по повышению защищенности инфраструктуры {ORG_NAME}."
        sections = build_annotated_preview(db, plan, threats, addr_count=len(iocs))
        return {
            "title": title, "intro": intro, "sections": sections,
            "text": resp.content or "", "llm": bool(plan.get("llm")),
        }

    num = document.letter_number or ""
    dt = _normalize_date(document.letter_date or "")
    title = f"Ответ на письмо {num} от {dt}".strip() if num else "Ответ на письмо"
    intro = "Сообщаем о принятых мерах по повышению защищенности информационной инфраструктуры."

    addr_count = len({i.value.split(":")[0] for i in iocs if i.ioc_type in ("ip", "domain")})

    # Приоритет: уязвимости (тип vulnerability) иначе угрозы
    active_vulns = [v for v in vulnerabilities
                    if v.cmdb_match or v.severity in ("critical", "high")]

    lines = [title, "", intro]

    if active_vulns:
        lines.append("")
        lines.append("Выявлены уязвимости, затрагивающие используемое программное обеспечение. "
                     "Требуется срочно выполнить обновление:")
        sections = []
        for v in vulnerabilities:
            if (v.action_type or "").lower() == "exclude":
                continue
            sw = v.software or "программного обеспечения"
            cur = v.current_version
            tgt = v.target_version or v.fixed_version
            rec = v.recommendation or ""
            if rec:
                text = f"{rec};"
            elif cur and tgt:
                text = f"обновить {sw} c {cur} до {tgt};"
            else:
                text = f"обновить {sw};"
            lines.append(f"  - {text}")
            sections.append({
                "threat_id": 0,
                "number": 0,
                "prefix": "",
                "description": f"{v.cve_id or v.bdu_id or sw}",
                "measures": [text],
                "measures_preview": [text],
                "threat_type": "vulnerability",
                "measure_options": DEFAULT_MEASURES,
                "base_measures": [],
                "intro_text": "",
                "section_text": text,
            })
        sections = sections if sections else _fallback_sections(threats, addr_count, db)
    elif threats:
        sections = []
        multiple = len(threats) > 1
        for t in threats:
            prefix = f"{t.number}. " if multiple else ""
            desc = re.sub(r"\s+", " ", (t.theme or t.description or "")).strip() or "угрозой безопасности информации"
            measures = _base_measures_for_threat_type(db, t.threat_type) or DEFAULT_MEASURES
            measures = _inflect(measures, addr_count)
            if t.measures and t.measures.strip():
                saved = [m.strip() for m in t.measures.split("\n") if m.strip()]
                if saved:
                    measures = saved
            intro_text = (f"{prefix}В целях предотвращения возможности реализации угроз безопасности "
                          f"информации, связанных с {desc}, приняты следующие меры защиты:")
            measure_options = _inflect(DEFAULT_MEASURES, addr_count)
            if t.threat_type == "compromise":
                measure_options = _inflect(COMPROMISE_MEASURES, addr_count)
                base = measure_options
            else:
                base = _inflect(_base_measures_for_threat_type(db, t.threat_type)
                                or DEFAULT_MEASURES, addr_count)
            section_text = intro_text + "\n" + "\n".join(f"  {m}" for m in measures)
            sections.append({
                "threat_id": t.id,
                "number": t.number,
                "prefix": prefix,
                "description": desc,
                "measures": measures,
                "measures_preview": measures,
                "threat_type": t.threat_type or "",
                "measure_options": measure_options,
                "base_measures": base,
                "intro_text": intro_text,
                "section_text": section_text,
            })
            lines.extend([intro_text] + [f"  {m}" for m in measures])
    else:
        sections = []
        lines.append("")
        lines.append(NO_RISK_TEXT)

    return {
        "title": title,
        "intro": intro,
        "sections": sections,
        "text": "\n".join(lines),
    }


def _fallback_sections(threats, addr_count, db):
    sections = []
    for t in threats:
        measures = _inflect(DEFAULT_MEASURES, addr_count)
        intro_text = (f"В целях предотвращения возможности реализации угроз безопасности информации, "
                      f"связанных с {t.theme or 'угрозой безопасности информации'}, приняты следующие меры защиты:")
        sections.append({
            "threat_id": t.id, "number": t.number, "prefix": "",
            "description": t.theme or "", "measures": measures,
            "measures_preview": measures, "threat_type": t.threat_type or "",
            "measure_options": measures, "base_measures": measures,
            "intro_text": intro_text, "section_text": intro_text,
        })
    return sections
