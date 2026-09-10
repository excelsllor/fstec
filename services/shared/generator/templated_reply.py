"""Шаблонный проект ответа (ТЗ 2.5.2) с библиотекой мер и LLM-подбором.

Отличие от response_generator: шапка/intro/outro из шаблонов (reply_templates),
блоки описываются планом {fragment_key, measures[]}, меры выбираются LLM из
библиотеки (measures), придуманные LLM меры помечаются source="new" и пишутся
в measure_candidates (очередь админа). При недоступном LLM — детерминированный
fallback (по образцу response_generator), чтобы ответ всегда собирался.
"""
import json
import logging
import re

from shared.config import ORG_NAME
from shared.generator.response_generator import _clean_theme, render_reply_docx

logger = logging.getLogger("fstec.reply")

# --- fallback-наборы (по образцу response_generator) ---------------------

_FALLBACK_PHISHING = [
    "производится автоматическая проверка вложений с использованием имеющейся «песочницы» («sandbox») для выявления вредоносной активности на этапе приема письма почтовым сервером;",
    "производится проверка почтовых вложений с использованием сертифицированного средства антивирусной защиты с использованием функции «Защита от почтовых угроз»;",
    "осуществляется автоматическая проверка указанных в письмах URL-адресов, содержащихся в электронных письмах, с использованием механизмов анализа ссылок;",
    "в целях идентификации отправителя производится проверка имени домена отправителя электронного письма;",
    "сотрудники проинструктированы о запрете открывать и загружать почтовые вложения писем с тематикой, не относящейся к рабочей деятельности;",
    "работы с электронной почтой производятся только с учетных записей пользователей операционной системы с минимальными возможными привилегиями;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]
_FALLBACK_MINIMAL = [
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]
_SCAN_MEASURE = "произведено внеплановое сканирование информационной инфраструктуры средствами антивирусной защиты;"


def _vary_minimal_measures(idx: int) -> list[str]:
    """Вариативность мер для повторяющихся блоков вредоносного ПО (эталон 9-70)."""
    base = list(_FALLBACK_MINIMAL)
    limit = base[0]
    monitor = base[1]
    scan = _SCAN_MEASURE
    if idx % 4 == 0:
        return [limit, scan, monitor]
    if idx % 4 == 1:
        return [limit, monitor]
    if idx % 4 == 2:
        return [limit, scan]
    return [limit]
_FALLBACK_COMPROMISE = [
    "регулярно производится контроль журналов DNS-серверов, прокси-серверов, средств межсетевого экранирования и средств обнаружения и реагирования уровня узла;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведено внеплановое сканирование информационной инфраструктуры средствами антивирусной защиты;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

_RE_IMPORT = re.compile(r"^from\s+shared\s|^import\s+shared")

_FROM_RE = re.compile(r"от\s+лица\s+«([^»]{3,120})»")
_CKFRAMEWORK_RE = re.compile(r"модифицированного\s+«фреймворка»\s+«([^»]+)»")
_MALWARE_DESC_RE = re.compile(
    r"(?:с\s+)?(?:возможно\s+)?(?:применени(?:ем|е|я)\s+)"
    r"(?:вредоносного\s+программного\s+обеспечения|вредоносного\s+ПО)\s+"
    r"(?:типа\s+|типов\s+|семейства\s+|семейств\s+)?"
    r"(«[^»]+»(?:\s*\((?:[^()]|\([^()]*\))*\))?(?:\s+и\s+«[^»]+»(?:\s*\((?:[^()]|\([^()]*\))*\))?)*)",
    re.IGNORECASE)
_MALWARE_DESC_RE2 = re.compile(
    r"применени(?:ем|е|я)\s+вредоносного\s+программного\s+обеспечения",
    re.IGNORECASE)
_VULN_EXPLOIT_RE = re.compile(
    r"эксплуатаци(?:я|ю|и)\s+уязвимости\s+(.+?)(?=;\s|\.\s*$|\.\s+(?:[А-ЯЁA-Z]|\d)|\.\s*(?:[А-ЯЁA-Z]|$))",
    re.IGNORECASE)


def _patch_tail(desc: str, start: int) -> str:
    """Хвост после фразы про уязвимость вида «…обновление до версии 2.17.0 до 01.06.2025»."""
    seg = desc[start:]
    i = re.search(r"обновл|устраня(?:ется|ются)?|рекоменд", seg, re.I)
    if not i:
        return ""
    j = start + i.start()
    rest = seg[i.start():]
    end_m = re.search(r"\.\s+(?:[А-ЯЁA-Z]|\d)|\.\s*$", rest)
    tail = rest[:end_m.start()] if end_m else rest
    return re.sub(r"\s+", " ", tail).strip(" ,;.")
_SYSADM_RE = re.compile(r"для\s+системного\s+администрирования\s+(.+?)(?:,\s*принят|\.\s*$)", re.IGNORECASE)


# --- утилиты ---------------------------------------------------------------

def _norm_date(dt: str) -> str:
    if not dt:
        return ""
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}", dt):
        return f"{dt[8:10]}.{dt[5:7]}.{dt[0:4]}"
    return dt


def _inflect_measure(text: str, addr_count: int) -> str:
    if addr_count == 1:
        return text.replace("указанным адресам", "указанному адресу")
    return text


def _extract_ctx(block: dict) -> dict:
    """Контекст для заполнения intro-фрагмента из данных угрозы."""
    desc = re.sub(r"\s+", " ", (block.get("description") or "").replace("\xa0", " ")).strip()
    ctx = {
        "group": (block.get("group_name") or "").strip(),
        "theme": _clean_theme(block.get("theme") or "") or "",
        "archive": (block.get("archive_name") or "").strip(),
        "exe": (block.get("exe_name") or "").strip(),
        "from": "",
        "malware": "",
        "obj": "",
    }
    m = _FROM_RE.search(desc)
    if m:
        ctx["from"] = m.group(1)
    m = _CKFRAMEWORK_RE.search(desc)
    if m:
        ctx["obj"] = m.group(1)
    m = _MALWARE_DESC_RE.search(desc)
    if m:
        ctx["malware"] = m.group(1).strip()
    dlow = desc.lower()
    if not ctx["malware"] and _MALWARE_DESC_RE2.search(desc) and "компрометаци" in dlow:
        ctx["malware"] = "типов «троян удаленного доступа»"
    if not ctx["obj"] and "уязвимост" in dlow and "эксплуатаци" in dlow:
        v = _VULN_EXPLOIT_RE.search(desc)
        if v:
            obj = re.sub(r"\s+", " ", v.group(1)).strip()
            ctx["obj"] = obj[:320].rstrip(" ,;")
            tail = _patch_tail(desc, v.end())
            if tail and "обновл" in tail.lower() and len(ctx["obj"]) + len(tail) < 340:
                ctx["obj"] += f", для устранения которой необходимо {tail}"
    m = _SYSADM_RE.search(desc)
    if m and not ctx["obj"]:
        ctx["obj"] = m.group(1).strip().rstrip(", ")
    if not ctx["obj"] and (block.get("threat_type") == "vulnerability"
                           or "уязвимост" in dlow[:200]):
        ctx["obj"] = desc[:320].rstrip(" ,;")
    return ctx


def _render_fragment(template: str, ctx: dict) -> str:
    out = template
    for k, v in ctx.items():
        if v:
            out = out.replace("{{%s}}" % k, v)
    if "{{" in out:
        return ""
    return " ".join(out.split()).strip(" ,")


# --- ресуры из БД ----------------------------------------------------------

def load_reply_resources(db):
    from shared.models import Measure, IntroFragment, ReplyTemplate
    library = db.query(Measure).order_by(Measure.id).all()
    fragments = db.query(IntroFragment).order_by(IntroFragment.id).all()
    templates = {t.key: (t.skeleton or {}) for t in db.query(ReplyTemplate).all()}
    return (
        [{"id": m.id, "text": m.text, "threat_type": m.threat_type,
          "tags": m.tags, "addr_inflection": m.addr_inflection, "source": m.source} for m in library],
        [{"id": fr.id, "key": fr.key, "label": fr.label, "template": fr.template,
          "applies_to": fr.applies_to} for fr in fragments],
        templates,
    )


def _fragments_for_type(fragments: list[dict], threat_type: str, letter_type: str) -> list[dict]:
    wanted = threat_type or letter_type
    out = [f for f in fragments if wanted in (f["applies_to"] or "").split(",")]
    if not out:
        out = [f for f in fragments if "hacker" in (f["applies_to"] or "").split(",")]
    return out or fragments


# --- fallback-план ---------------------------------------------------------

def _fallback_plan(letter_type: str, blocks: list[dict], fragments: list[dict],
                   addr_count: int = 1) -> dict:
    """Детерминированный план по образцу response_generator."""
    if letter_type == "compromise" and not blocks:
        return {"template_key": "compromise", "llm": False, "blocks": [{
            "number": 1, "threat_id": None, "fragment_key": "", "intro": "",
            "threat_type": "compromise", "description": "", "fixed_header": True,
            "measures": [{"text": _inflect_measure(m, addr_count), "source": "library",
                          "measure_id": None} for m in _FALLBACK_COMPROMISE],
            "new_measures": [],
        }]}
    plan_blocks = []
    minimal_idx = 0
    for b in blocks:
        desc_low = (b.get("description") or "").lower()
        ttype = b.get("threat_type") or ""
        if letter_type == "compromise":
            measures = list(_FALLBACK_COMPROMISE)
        elif ttype == "phishing" or "фишинг" in desc_low:
            measures = list(_FALLBACK_PHISHING)
        else:
            minimal_idx += 1
            measures = _vary_minimal_measures(minimal_idx)

        ctx = _extract_ctx(b)
        frags = _fragments_for_type(fragments, ttype if ttype != "phishing" else "phishing",
                                    "phishing" if ttype == "phishing" else "hacker")
        intro = ""
        if ttype == "phishing":
            ordered = ["phishing_group_archive_theme", "phishing_group_archive", "phishing_group_theme",
                       "phishing_group_doc", "phishing_group_from", "phishing_general_archive",
                       "phishing_general_theme", "phishing_general"]
        elif letter_type == "compromise":
            ordered = ["compromise_site", "generic_hacker"]
        elif ttype == "clickfix":
            ordered = ["clickfix_groups", "generic_hacker"]
        elif ctx["malware"]:
            ordered = ["malware_group", "malware_groups"]
        elif "компрометации учетных" in desc_low:
            ordered = ["credential_compromise_group", "generic_hacker"]
        else:
            ordered = ["vuln_exploit", "generic_hacker"]
        frag_map = {f["key"]: f for f in fragments}
        for key in ordered:
            f = frag_map.get(key)
            if not f:
                continue
            intro = _render_fragment(f["template"], ctx)
            if intro:
                plan_blocks.append({
                    "number": b.get("number", 0), "threat_id": b.get("id"),
                    "fragment_key": key, "intro": intro, "threat_type": ttype,
                    "description": b.get("description", ""),
                    "measures": [{"text": _inflect_measure(m, addr_count),
                                  "source": "library", "measure_id": None} for m in measures],
                    "new_measures": [],
                })
                break
        if not intro:
            group = ctx["group"]
            theme = ctx["theme"]
            if theme:
                intro = theme
            elif group:
                intro = f"деятельностью хакерской группировки {group}"
            else:
                intro = "реализуемыми угрозами безопасности информации"
            inflect_measures = [_inflect_measure(m, addr_count) for m in measures]
            plan_blocks.append({
                "number": b.get("number", 0), "threat_id": b.get("id"), "fragment_key": "",
                "intro": intro, "threat_type": ttype, "description": b.get("description", ""),
                "measures": [{"text": m, "source": "library", "measure_id": None} for m in inflect_measures],
                "new_measures": [],
            })
    return {"template_key": letter_type, "blocks": plan_blocks, "llm": False}


# --- LLM-план ----------------------------------------------------------------

def _plugin_provider():
    try:
        from llm_service.provider import get_provider
        return get_provider()
    except Exception:
        return None


def _llm_plan(provider, letter_type: str, blocks: list[dict], library: list[dict],
              fragments: list[dict]) -> dict | None:
    """Один вызов LLM на всё письмо. Возвращает план или None."""
    try:
        raw = provider.plan_reply(
            letter_type=letter_type, blocks=blocks, library=library, fragments=fragments)
        decoded = raw or {}
        if not isinstance(decoded, dict) or not isinstance(decoded.get("blocks"), list):
            return None
        return {"template_key": letter_type, "blocks": decoded["blocks"], "llm": True}
    except Exception as e:  # noqa: BLE001
        logger.warning("LLM plan_reply failed: %s", e)
        return None


def _apply_llm_plan(llm_plan: dict | None, lib_by_id: dict, frag_by_key: dict,
                    blocks: list[dict], addr_count: int) -> dict:
    """Нормализация LLM-плана: валидация id/фрагментов + склонение мер."""
    if not llm_plan:
        return None
    out_blocks = []
    existing = {b.get("n") or b.get("number") for b in blocks}
    by_index = {i: b for i, b in enumerate(blocks)}
    for entry in llm_plan["blocks"] or []:
        if not isinstance(entry, dict):
            continue
        n = entry.get("n")
        if n is None:
            continue
        src = by_index.get(int(n) - 1)
        if src is None:
            continue
        frag = frag_by_key.get(entry.get("fragment_id") or "") if entry.get("fragment_id") else None
        intro = ""
        if frag:
            intro = _render_fragment(frag["template"], _extract_ctx(src))
            if not intro:
                frag = None
        if not frag or not intro:
            ttype = src.get("threat_type") or ""
            ctx = _extract_ctx(src)
            if ctx["theme"]:
                intro = ctx["theme"]
            elif ctx["group"]:
                intro = f"деятельностью хакерской группировки {ctx['group']}"
            else:
                intro = "реализуемыми угрозами безопасности информации"
            frag_key = ""
        else:
            frag_key = frag["key"]
        measures = []
        seen = set()
        for mid in entry.get("measure_ids") or []:
            m = lib_by_id.get(int(mid)) if isinstance(mid, int) else lib_by_id.get(str(mid))
            if not m or m["text"] in seen:
                continue
            seen.add(m["text"])
            measures.append({"text": _inflect_measure(m["text"], addr_count),
                             "source": "library", "measure_id": m["id"]})
        new_measures = []
        for nm in entry.get("new_measures") or []:
            if not isinstance(nm, dict):
                continue
            text = (nm.get("text") or "").strip()
            if not text or text in seen or text.lower() in {x["text"].lower() for x in measures}:
                continue
            if len(text) > 300:
                continue
            seen.add(text)
            new_measures.append({"text": _inflect_measure(text, addr_count),
                                 "source": "new", "note": (nm.get("note") or "")[:300]})
            measures.append({"text": _inflect_measure(text, addr_count),
                             "source": "new", "measure_id": None})
        out_blocks.append({
            "number": src.get("number") or int(n), "threat_id": src.get("id"),
            "fragment_key": frag_key, "intro": intro, "threat_type": src.get("threat_type", ""),
            "description": src.get("description", ""), "measures": measures,
            "new_measures": new_measures,
        })
    if not out_blocks:
        return None
    return {"template_key": llm_plan["template_key"], "blocks": out_blocks, "llm": True}


# --- главный планировщик ------------------------------------------------------

def plan_reply(*, db, letter_type: str, blocks: list[dict], addr_count: int,
               use_llm: bool | None = None) -> dict:
    """План ответа: LLM (один вызов/письмо) или детерминированный fallback."""
    if letter_type not in {"hacker", "compromise", "vulnerability", "other"}:
        letter_type = "hacker" if blocks else "other"
    library, fragments, _ = load_reply_resources(db)
    frag_by_key = {f["key"]: f for f in fragments}
    lib_by_id = {m["id"]: m for m in library}

    explicit = {
        b.get("id"): [_inflect_measure(m.strip(), addr_count)
                      for m in (b.get("explicit_measures") or []) if m.strip()]
        for b in blocks if b.get("explicit_measures")
    }

    llm_plan = None
    provider = _plugin_provider() if use_llm is not False else None
    if provider is not None and getattr(provider, "kind", None) == "vllm":
        llm_plan = _llm_plan(provider, letter_type, blocks, library, fragments)

    plan = None
    if llm_plan:
        plan = _apply_llm_plan(llm_plan, lib_by_id, frag_by_key, blocks, addr_count)
    if plan is None:
        plan = _fallback_plan(letter_type, blocks, fragments, addr_count)

    if explicit:
        for blk in plan.get("blocks") or []:
            chosen = explicit.get(blk.get("threat_id"))
            if chosen is None:
                chosen = explicit.get(blk.get("number"))
            if chosen is not None:
                blk["measures"] = [{"text": t, "source": "library", "measure_id": None}
                                   for t in chosen]
                blk["new_measures"] = []
    return plan


# --- рендер текста ------------------------------------------------------------

_SEV_RU = {"critical": "критический", "high": "высокий", "medium": "средний",
           "low": "низкий", "unknown": "не определён"}


def _vuln_paragraph(v: dict) -> list[str]:
    """Абзац про уязвимость по образцу эталона:
    «Уязвимость <продукт> (BDU:..., уровень опасности по CVSS 3.1 — критический),
    связанная с <описание>. <статус/действие>.»"""
    desc = re.sub(r"\s+", " ", (v.get("description") or "")).strip().rstrip(".")
    bdu = v.get("bdu_id") or ""
    cve = v.get("cve_id") or ""
    sev = _SEV_RU.get((v.get("severity") or "").lower(), v.get("severity") or "")
    fixed = v.get("fixed_version") or v.get("target_version") or ""
    software = (v.get("software") or "").strip()

    product, tail = "", ""
    m = re.search(r"Уязвимость\s+(.+?)\s+связан[аы]?\s+с\s+(.+)", desc, re.I)
    if m:
        product = m.group(1).strip().rstrip(",")
        tail = m.group(2).strip().rstrip(",")
    if not product:
        product = software or "программного обеспечения"
    product = product[:220]

    m_cvss = re.search(r"CVSS\s*(\d(?:\.\d)?)", desc, re.I)
    cvss_ver = m_cvss.group(1) if m_cvss else ""
    cvss = v.get("cvss_score")
    parts = [bdu if str(bdu).upper().startswith("BDU") else f"BDU:{bdu}"] if bdu else []
    if cve:
        parts.append(cve)
    threat_line = ""
    if sev:
        if cvss_ver:
            threat_line = f"уровень опасности по CVSS {cvss_ver} — {sev}"
        else:
            threat_line = f"уровень опасности — {sev}"
    if cvss is not None and sev:
        if cvss_ver:
            threat_line += f", базовая оценка по CVSS {cvss_ver} — {cvss}"
        else:
            threat_line += f" (базовая оценка по CVSS — {cvss})"
    if threat_line:
        parts.append(threat_line)

    info = ", ".join(x for x in parts if x)
    first = f"Уязвимость {product}"
    if info:
        first += f" ({info})"
    if tail:
        first += f", связанная с {tail}."
    else:
        first += "."

    status = ""
    dlow = desc.lower()
    for marker in ("не применяется", "не используется", "не применяется в", "не подвержена"):
        if marker in dlow:
            start = dlow.find(marker)
            chunk = desc[start:start + 240].split(".", 1)[0].strip().rstrip(",")
            status = chunk.capitalize() + "."
            break
    if not status and fixed:
        status = f"Ведутся работы по обновлению {product} до версии {fixed}."
    if not status:
        status = f"Проводится анализ применяемости {product} в информационной инфраструктуре для последующего принятия необходимых мер."

    rec = (v.get("recommendation") or "").strip()
    lines = [first]
    if rec:
        lines.append("Дополнительно приняты следующие меры: " + rec.rstrip(".") + ".")
    else:
        lines.append(status)
    return lines


def render_reply(*, plan: dict, templates: dict | None = None, letter_number: str = "",
                 letter_date: str = "", org_name: str = ORG_NAME, addr_count: int = 1,
                 active_vulns: list[dict] | None = None,
                 addresses: list[str] | None = None) -> tuple[str, dict]:
    """Рендер ответа из плана (+ блок уязвимостей для vulnerability-писем)."""
    key = plan.get("template_key") or "hacker"
    skel = (templates or {}).get(key) or {}
    if not skel and key != "other":
        key = "other"
        skel = (templates or {}).get("other") or {}
    header = (skel.get("header") or "Ответ на письмо {{num}} от {{date}}").replace(
        "{{num}}", letter_number or "").replace("{{date}}", _norm_date(letter_date) or "")
    intro = (skel.get("intro") or "Сообщаем о принятых мерах по повышению защищенности инфраструктуры {{org}}.").replace(
        "{{org}}", org_name)
    outro = (skel.get("outro") or "С уважением,\n{{signer}}").replace(
        "{{signer}}", skel.get("signer") or "Ответственное должностное лицо")
    block_tpl = skel.get("block_template") or "{{n}}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {{intro}}, приняты следующие меры защиты:"

    lines = [header, "", intro]

    if key == "vulnerability":
        vuln_lead = skel.get("vuln_lead") or "С учетом требований законодательства Российской Федерации в области безопасности информации сообщаем, что в информационной инфраструктуре выявлены уязвимости программного обеспечения, используемые при реализации компьютерных атак:"
        active = active_vulns or []
        if active:
            lines.append("")
            lines.append(vuln_lead)
            for v in active:
                lines.append("")
                lines.extend(_vuln_paragraph(v))
        else:
            lines.append(NO_RISK_TEXT_C)
    elif key == "other":
        lines.append("")
        lines.append(skel.get("no_risk_text") or
                     "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации.")
    else:
        numbered = bool(skel.get("number_blocks", key == "hacker"))
        plan_blocks = list(plan.get("blocks") or [])
        for i, blk in enumerate(plan_blocks, 1):
            intro_phrase = blk.get("intro") or "реализуемыми угрозами безопасности информации"
            if blk.get("fixed_header"):
                head = (skel.get("empty_block_text")
                        or "В целях предотвращения реализации угроз, связанных со случаем компрометации "
                           "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                           "приняты следующие меры защиты:")
            elif numbered:
                if "{{n}}" in block_tpl:
                    head = block_tpl.replace("{{n}}", str(i)).replace("{{intro}}", intro_phrase)
                else:
                    head = f"{i}. " + block_tpl.replace("{{intro}}", intro_phrase)
            else:
                head = block_tpl.replace("{{n}}", "").replace("{{n}}. ", "").replace("{{intro}}", intro_phrase).strip()
            if i > 1:
                lines.append("")
            lines.append(head)
            sender = ", ".join(addresses[:8]) if addresses else ""
            for m in blk.get("measures") or []:
                t = m['text'].replace("{{sender}}", sender) if sender else m['text']
                lines.append(f"  {t}")
        if not plan_blocks:
            lines.append("")
            lines.append(NO_RISK_TEXT_C)

    lines.append("")
    lines.extend(outro.split("\n"))
    # Защита от неразрешённых плейсхолдеров (LLM иногда копирует {{...}} из шаблонов)
    lines = [ln for ln in lines if "{{" not in ln]
    text = "\n".join(lines)
    return text, {"template_key": key, "header": header, "intro": intro}


NO_RISK_TEXT_C = "Сообщаем, что используемое программное обеспечение не подвержено риску, указанному в обращении, и предпринятые меры достаточны для обеспечения защиты информации."


# --- интеграция для worker/gateway --------------------------------------------

def generate_reply(db, doc_id: int, *, letter_type: str | None = None, blocks: list[dict] | None = None,
                   active_vulns: list[dict] | None = None, addr_count: int = 1,
                   letter_number: str = "", letter_date: str = "", org_name: str = ORG_NAME,
                   use_llm: bool | None = None, addresses: list[str] | None = None) -> dict:
    """Полная генерация: план (LLM/fallback) → текст + docx + план-json + кандидаты."""
    from shared.models import Document
    doc = db.query(Document).filter(Document.id == doc_id).first()
    if doc:
        letter_type = letter_type or doc.letter_type
        letter_number = letter_number or doc.letter_number
        letter_date = letter_date or doc.letter_date

    plan = plan_reply(db=db, letter_type=letter_type or "hacker", blocks=blocks or [],
                      addr_count=addr_count, use_llm=use_llm)
    templates = load_reply_resources(db)[2]
    text, meta = render_reply(plan=plan, templates=templates, letter_number=letter_number,
                              letter_date=letter_date, org_name=org_name,
                              addr_count=addr_count, active_vulns=active_vulns or [],
                              addresses=addresses)
    plan_blocks = [
        {
            "number": b.get("number"), "threat_id": b.get("threat_id"), "fragment_key": b.get("fragment_key"),
            "intro": b.get("intro"), "threat_type": b.get("threat_type"),
            "description": (b.get("description") or "")[:500],
            "measures": b.get("measures") or [],
        }
        for b in plan.get("blocks") or []
    ]
    plan_json = json.dumps({"template_key": plan.get("template_key"), "llm": plan.get("llm", False),
                            "blocks": plan_blocks}, ensure_ascii=False)
    return {
        "text": text,
        "plan": plan,
        "plan_json": plan_json,
        "docx": render_reply_docx(text),
        "candidates": [m for b in plan.get("blocks") or [] for m in (b.get("new_measures") or [])],
        "llm_used": bool(plan.get("llm")),
    }


def persist_candidates(db, document_id: int, candidates: list[dict]) -> list[int]:
    from shared.models import MeasureCandidate
    ids = []
    for c in candidates:
        snap = MeasureCandidate(document_id=document_id, threat_id=c.get("threat_id"),
                                text=c["text"], note=c.get("note") or "")
        db.add(snap)
        db.flush()
        ids.append(snap.id)
    return ids


def _obj_attr(obj, name, default=""):
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def build_annotated_preview(db, response_plan: dict, threats, addr_count: int = 1) -> list[dict]:
    """Секции предпросмотра с аннотациями мер (source: library|new, candidate_id)."""
    sections = []
    for i, blk in enumerate(response_plan.get("blocks") or [], 1):
        t = threats[i - 1] if i - 1 < len(threats) else None
        measures = [m["text"] for m in blk.get("measures") or []]
        annotations = [{"text": m["text"], "source": m.get("source", "library"),
                        "candidate_id": m.get("candidate_id")} for m in blk.get("measures") or []]
        if blk.get("fixed_header"):
            head = ("В целях предотвращения реализации угроз, связанных со случаем компрометации "
                    "(скомпрометированные интернет-ресурсы, веб-сайты и программное обеспечение), "
                    "приняты следующие меры защиты:")
        elif len(response_plan.get("blocks") or []) == 1 and not (t and _obj_attr(t, "id")):
            head = f"В целях предотвращения возможности реализации угроз безопасности информации, связанных с {blk.get('intro') or 'угрозой безопасности информации'}, приняты следующие меры защиты:"
        else:
            head = f"{i}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {blk.get('intro') or 'угрозой безопасности информации'}, приняты следующие меры защиты:"
        sections.append({
            "threat_id": blk.get("threat_id") or _obj_attr(t, "id", 0),
            "number": blk.get("number") or i,
            "prefix": f"{i}. " if len(response_plan.get("blocks") or []) > 1 else "",
            "description": _obj_attr(t, "theme", "") or blk.get("intro") or "",
            "measures": measures,
            "measures_preview": measures,
            "measure_annotations": annotations,
            "threat_type": blk.get("threat_type") or "",
            "intro_text": head,
            "section_text": head + "\n" + "\n".join(f"  {m}" for m in measures),
        })
    return sections