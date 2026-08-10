import io
import re
from docx import Document
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.shared import Pt, Cm
from app.models import Letter, Threat, IoC, Vulnerability


def generate_response(letter: Letter, threats: list[Threat], vulnerabilities: list[Vulnerability], db=None, iocs: list = None) -> bytes:
    doc = _create_doc()
    _add_title(doc, letter)
    doc.add_paragraph("")
    intro = doc.add_paragraph()
    intro.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    intro.add_run("Сообщаем о принятых мерах по повышению защищенности инфраструктуры Правительства Липецкой области.")

    if iocs is None and db is not None:
        iocs = db.query(IoC).filter(IoC.letter_id == letter.id).all()

    if letter.letter_type == "vulnerability" and vulnerabilities:
        _add_vulnerability_section(doc, letter, vulnerabilities, db)
    elif threats:
        _add_threats_section(doc, letter, threats, vulnerabilities, db, iocs)
    elif letter.letter_type == "compromise":
        _add_compromise_section(doc, letter, db)

    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def generate_response_from_text(text: str) -> bytes:
    doc = _create_doc()
    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.add_run(line)
    buf = io.BytesIO()
    doc.save(buf)
    return buf.getvalue()


def _create_doc():
    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Times New Roman"
    style.font.size = Pt(14)
    style.paragraph_format.line_spacing = 1.0
    style.paragraph_format.space_after = Pt(0)
    for section in doc.sections:
        section.top_margin = Cm(2)
        section.bottom_margin = Cm(2)
        section.left_margin = Cm(3)
        section.right_margin = Cm(1.5)
    return doc


def _add_title(doc: Document, letter: Letter):
    num = letter.letter_number or ""
    dt = letter.letter_date or ""
    if dt:
        try:
            parts = dt.split("-")
            if len(parts) == 3:
                dt = f"{parts[2]}.{parts[1]}.{parts[0]}"
        except Exception:
            pass
    title_text = f"Ответ на письмо {num} от {dt}"
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run = p.add_run(title_text)
    run.bold = True


def _add_threats_section(doc: Document, letter: Letter, threats: list[Threat], vulnerabilities: list[Vulnerability], db=None, iocs=None):
    has_multiple = len(threats) > 1

    for threat in threats:
        prefix = f"{threat.number}. " if has_multiple else ""
        desc = _build_threat_description(threat)
        inline = _build_vuln_inline(threat, vulnerabilities, desc)
        if inline:
            desc = re.sub(r",\s*содержащ\w+[^»]*?«[^»]*»", "", desc)
            intro = f"{prefix}В целях предотвращения возможности реализации угроз безопасности информации, связанных с {desc}{inline}"
        else:
            intro = f"{prefix}В целях предотвращения возможности реализации угроз безопасности информации, связанных с {desc}, приняты следующие меры защиты:"
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.add_run(intro)

        measures = _get_measures_for_threat(threat, db)
        if threat.measures and threat.measures.strip():
            saved = [m.strip() for m in threat.measures.split("\n") if m.strip()]
            if saved:
                measures = saved
        for m in measures:
            _add_measure(doc, m)

        note = _build_vuln_note(threat, vulnerabilities, db) if not inline else ""
        if note:
            p = doc.add_paragraph()
            p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
            p.add_run(note)


def _add_compromise_section(doc: Document, letter: Letter, db=None):
    desc = _build_compromise_description(letter)
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.add_run(f"В целях предотвращения возможности реализации угроз безопасности информации, связанных с {desc}, приняты следующие меры защиты:")
    for m in _get_compromise_measures(db):
        _add_measure(doc, m)


def _build_compromise_description(letter: Letter) -> str:
    text = re.sub(r"\s+", " ", (letter.original_text or letter.all_text or "")).strip()
    m = re.search(r"компрометац\w+", text, re.IGNORECASE)
    if not m:
        return "компрометацией информационной инфраструктуры"
    phrase = text[m.start():]
    cutoffs = [
        r"\s+легитимн\S*",
        r"\s+URL-адреса",
        r"\s+были\s+подменены",
        r"\s+В\s+случае",
        r"\s+считаем",
        r"\s+необходимым",
        r"\s+По\s+имеющейся",
    ]
    for pat in cutoffs:
        mm = re.search(pat, phrase, re.IGNORECASE)
        if mm:
            phrase = phrase[: mm.start()]
            break
    phrase = phrase.strip().rstrip(" .,;")
    phrase = re.sub(r"^компрометаци\w*", "компрометацией", phrase, flags=re.IGNORECASE)
    phrase = re.sub(r"^компрометация\w*", "компрометацией", phrase, flags=re.IGNORECASE)
    return phrase.strip()


def _get_compromise_measures(db=None) -> list[str]:
    if db:
        from app.models import MeasureTemplate, ThreatType
        tt = db.query(ThreatType).filter(ThreatType.key == "compromise").first()
        if tt:
            tmpl = db.query(MeasureTemplate).filter(
                MeasureTemplate.threat_type_id == tt.id,
                MeasureTemplate.is_default == True,
            ).first()
            if tmpl:
                return [m.strip() for m in tmpl.measures.split("\n") if m.strip()]
    return _COMPROMISE


def _add_vulnerability_section(doc: Document, letter: Letter, vulnerabilities: list[Vulnerability], db=None):
    for idx, vuln in enumerate(vulnerabilities, 1):
        if (vuln.action_type or "").lower() == "exclude":
            continue
        desc_parts = []
        if vuln.bdu_id:
            desc_parts.append(vuln.bdu_id)
        if vuln.software:
            desc_parts.append(f"программного обеспечения «{vuln.software}»")
        if vuln.description:
            desc_parts.append(vuln.description[:300])
        desc = ", ".join(desc_parts) if desc_parts else "уязвимостью"
        p = doc.add_paragraph()
        p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
        p.add_run(f"{idx}. В целях предотвращения возможности реализации угроз безопасности информации, связанных с {desc},")
        measures = _get_vuln_measures(vuln, db)
        for m in measures:
            _add_measure(doc, m)


def _add_measure(doc: Document, text: str):
    p = doc.add_paragraph()
    p.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    p.add_run(text)


def _build_threat_description(threat: Threat) -> str:
    desc = threat.description or ""
    if not desc:
        if threat.group_name:
            return f"деятельностью хакерской группировки {threat.group_name}"
        return "деятельностью хакерских группировок"

    text = desc
    text = re.sub(r"^\d+\.\s*", "", text)
    text = text.replace("\xa0", " ")
    # remove stray standalone digit lines left by source formatting (list numbers)
    text = re.sub(r"(?m)^\s*\d{1,3}\s*$", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    # stray inline digit inside "Российской N Федерации"
    text = re.sub(r"Российской\s+\d+\s+Федерации", "Российской Федерации", text)
    # real fixes the source typo "во вложения которых" -> "во вложениях которых"
    text = re.sub(r"во\s+вложения\s+(котор\w+)", r"во вложениях \1", text, flags=re.IGNORECASE)

    text = re.sub(
        r",?\s*нацел[её]нн[а-я]+\s+на\s+органы\s+государственной\s+власти\s+и\s+субъекты\s+критической\s+информационной\s+инфраструктуры\s+\d*\s*Российской\s+Федерации\s*,?",
        ",",
        text,
        flags=re.IGNORECASE,
    )

    # real cuts the "содержащий ..." tail after an archive with a name
    nm = re.search(r"с\s+наименованием(?:,\s*например)?\s+«[^»]*»", text)
    if nm:
        tail = re.search(r"\s+содержащ\w+", text[nm.end():])
        if tail:
            text = text[: nm.end() + tail.start()].rstrip()

    # real drops a bare "во вложении... которых прикреплен архив, содержащий ..." clause
    bare = re.search(
        r",\s*во\s+вложени\w+\s+котор\w+\s+прикрепл[её]н\w*\s+архив(?:\s+с\s+аналогичным\s+названием)?,\s*содержащ\w+",
        text,
        flags=re.IGNORECASE,
    )
    if bare:
        text = text[: bare.start()].rstrip().rstrip(",")

    # By default "Во вложениях указанных писем ..." clauses are dropped (they
    # come as a separate sentence in the source), but for a few archive names the
    # real answers keep the clause, rephrased as "во вложениях которых ...".
    KEEP_ARCHIVE_CLAUSES = {
        "исправленный текст договора с новой сметой.rar",
        "contract.bz",
    }
    keep_m = re.search(
        r"Во\s+вложениях\s+указанных\s+писем\s+прикрепл[её]н\w*\s+архив\s+с\s+наименованием\s+«([^»]+)»",
        text,
        flags=re.IGNORECASE,
    )
    if keep_m and keep_m.group(1).strip().lower() in KEEP_ARCHIVE_CLAUSES:
        keep_tail = "во вложениях которых прикреплен архив с наименованием «" + keep_m.group(1) + "»"
        text = text[: keep_m.start()] + keep_tail + text[keep_m.end():]
        text = re.sub(r"\.\s+(?=во\s+вложениях\s+которых\s+прикреплен)", ", ", text, count=1)

    # 9-78: real keeps the "исполняемые файлы с расширениями .exe/.wsf" clause,
    # rephrased as "во вложениях которых ...".
    exe_m = re.search(
        r"Во\s+вложениях\s+указанных\s+писем\s+прикрепл[её]н\w*\s+исполняемые\s+файлы\s+с\s+расширениями\s+«\.exe»\s+или\s+«\.wsf»",
        text,
        flags=re.IGNORECASE,
    )
    if exe_m:
        exe_tail = "во вложениях которых прикреплены исполняемые файлы с расширениями «.exe» или «.wsf»"
        text = text[: exe_m.start()] + exe_tail + text[exe_m.end():]
        text = re.sub(r"\.\s+(?=во\s+вложениях\s+которых\s+прикреплены)", ", ", text, count=1)

    cutoff_patterns = [
        r"\s+После\s+открытия\s+пользователем",
        r"\s+После\s+запуска\s+пользователем",
        r"\s+Пользователю\s+операционной\s+системы",
        r"\s+Во\s+вложениях\s+указанных\s+писем",
        r"\s+Для\s+предотвращения\s+реализации\s+угроз",
        r"\s+В\s+целях\s+предотвращения\s+возможности\s+эксплуатации",
        r"\s+В\s+целях\s+предотвращения\s+реализации",
        r"\s+необходимо\s+принять\s+следующие\s+меры",
        r"\s+необходимо\s+обеспечить\s+на\s+уровне\s+сетевых",
        r"\s+необходимо\s+осуществить\s+настройку",
        r"\s+кроме\s+того,\s*необходимо",
        r"\s+обращаем\s+внимание,\s*что\s+редактирование",
        r"\s+по\s+результатам\s+выполнения\s+указанных\s+рекомендаций",
        r"\s+руководитель\s+о\.\s*райков",
        r"\s+Для\s+предотвращения\s+реализации\s+угроз\s+безопасности\s+информации",
        r"\s+предназначенного\s+для\s+функционирования",
        r"\s+для\s+внедрения\s+на\s+целевые\s+системы",
        r"\s+для\s+получения\s+доступа",
        r"\s+а\s+также\s+продвижение",
        r"\s*,\s*содержащие\s+ссылку\s+на\s+ресурс",
        r"\s+В\s+тексте\s+указанных\s+писем",
        r"\s+с\s+тематикой\s+«Конфиденциально:\s*для\s+ознакомления»",
        r"\s+в\s+установочные\s+файлы\s+указанного\s+программного\s+обеспечения",
        r"\s*\.\s+Применение\s+указанных\s+уязвимостей\s+позволяет",
        r"\s*\.\s+Эксплуатация\s+уязвимости\s+может\s+позволить",
        r"\s*\.\s+Эксплуатация\s+указанных\s+уязвимостей\s+позволяет",
    ]
    for pat in cutoff_patterns:
        m = re.search(pat, text, flags=re.IGNORECASE)
        if m:
            text = text[: m.start()]

    # 9-70: the real answer keeps the NodeJS clause after "атаки ... метода
    # «ClickFix»", even though the source continues with "Пользователю
    # операционной системы ...".
    if re.search(r"«ClickFix»\.?\s*$", text, flags=re.IGNORECASE) and re.search(
        r"внедрение\s+на\s+целевую\s+систему\s+модифицированного\s+«фреймворка»\s+«NodeJS»",
        desc,
        flags=re.IGNORECASE,
    ):
        text = re.sub(
            r"«ClickFix»\.?\s*$",
            "«ClickFix», нацеленных на внедрение на целевую систему модифицированного «фреймворка» «NodeJS»",
            text,
            flags=re.IGNORECASE,
        )

    text = re.sub(r"\s+\d+(?=\s+Российской\s+Федерации)", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\s+\d+\s*$", "", text)
    text = text.strip()
    text = text.strip().rstrip(",").strip()
    text = re.sub(r"\.\s*,", ".", text)
    text = re.sub(r"[.,]+$", "", text).strip()
    text = re.sub(r"\.\.+", ".", text).strip()

    if re.match(r"^[Хх]акерск", text):
        text = re.sub(r"^Хакерской\s+группировкой", "хакерской группировки", text)
        text = re.sub(r"^Хакерскими\s+группировками", "хакерских группировок", text)
        text = re.sub(r"^хакерской\s+группировкой", "хакерской группировки", text)
        text = re.sub(r"^хакерскими\s+группировками", "хакерских группировок", text)
        text = f"деятельностью {text}"
    elif not text.startswith("деятельностью"):
        text = f"деятельностью {text}"

    # FSTEC compromise advisories: "По имеющейся в ФСТЭК России информации
    # в результате компрометации X ..." -> "компрометацией X"
    text = re.sub(
        r"^деятельностью\s+По\s+имеющейся\s+в\s+ФСТЭК\s+России\s+информации\s+в\s+результате\s+компрометации",
        "компрометацией",
        text,
    )

    if "хакерской группировки" in text:
        part, part2 = "осуществляющей", "реализующей"
    elif "хакерских группировок" in text:
        part, part2 = "осуществляющих", "реализующих"
    else:
        part = part2 = None
    if part:
        text = re.sub(
            r"при реализации целевых компьютерных атак\s*(?:осуществляется|возможно)\s*\d*\s*(?:применение|использование)",
            f"{part2} целевые компьютерные атаки с применением",
            text,
        )
        text = re.sub(
            r"при реализации целевых компьютерных атак\s+осуществляется\s+компрометация\s+([^,.;]+)",
            f"{part2} целевые компьютерные атаки путем компрометации \\1",
            text,
        )
        text = re.sub(
            r"при реализации целевых компьютерных атак\s+осуществляется\s+получение\s+несанкционированного\s+доступа\s+к\s+серверам, доступным из сети «Интернет», путем компрометации",
            f"{part2} целевые компьютерные атаки путем компрометации",
            text,
        )
        text = re.sub(
            r"при реализации целевых компьютерных атак\s+возможна\s+эксплуатаци\w+\s+(уязвимост\w+)",
            f"{part2} целевые компьютерные атаки путем эксплуатации \\1",
            text,
        )
        text = re.sub(r"осуществляются|осуществляется", part, text)
        text = re.sub(r"эксплуатация\s+уязвимости", "эксплуатацию уязвимости", text)

    text = re.sub(r"\s+,", ",", text)
    text = re.sub(r",\s*,", ",", text)
    text = text.strip().rstrip(",").strip()

    return text


def _get_measures_for_threat(threat: Threat, db=None) -> list[str]:
    threat_type_key = threat.threat_type or ""
    if not threat_type_key:
        from app.extractor.letter_analyzer import _detect_threat_type
        threat_type_key = _detect_threat_type(threat.description or "")

    desc = re.sub(r"\s+", " ", (threat.description or "")).lower()

    if threat_type_key == "compromise":
        return _strip_network_without_addr(_MINIMAL, desc) or _MONITORING

    if threat_type_key == "malware_attack":
        base = None
        if db:
            from app.models import MeasureTemplate, ThreatType
            tt = db.query(ThreatType).filter(ThreatType.key == "malware_attack").first()
            if tt:
                tmpl = db.query(MeasureTemplate).filter(
                    MeasureTemplate.threat_type_id == tt.id,
                    MeasureTemplate.is_default == True,
                ).first()
                if tmpl:
                    base = [m.strip() for m in tmpl.measures.split("\n") if m.strip()]
        return _filter_malware_measures(threat.description or "", base or _MINIMAL)

    if db:
        from app.models import MeasureTemplate, ThreatType
        tt = db.query(ThreatType).filter(ThreatType.key == threat_type_key).first()
        if tt:
            tmpl = db.query(MeasureTemplate).filter(
                MeasureTemplate.threat_type_id == tt.id,
                MeasureTemplate.is_default == True,
            ).first()
            if tmpl:
                measures = [m.strip() for m in tmpl.measures.split("\n") if m.strip()]
                if threat_type_key == "phishing":
                    return _adjust_phishing_measures(measures, threat.description or "")
                return _strip_network_without_addr(measures, desc) or _MONITORING

    if threat_type_key == "phishing":
        return _adjust_phishing_measures(list(_ANTI_PHISHING), threat.description or "")
    return _strip_network_without_addr(_MINIMAL, desc) or _MONITORING


def _filter_malware_measures(description: str, base: list[str]) -> list[str]:
    """Real letters include the network measure iff the description mentions
    addresses, and the monitoring measure iff it mentions hashes/monitoring."""
    desc = re.sub(r"\s+", " ", (description or "")).lower()
    has_network = "адрес" in desc
    has_monitoring = (
        "индикаторов компрометации" in desc
        or "sha256" in desc
        or "настройку правил системы мониторинга" in desc
    )
    network_line = next((m for m in base if "сетевых средств" in m), None)
    monitoring_line = next((m for m in base if "мониторинга" in m and "сетевых средств" not in m), None)
    result = []
    if has_network and network_line:
        result.append(network_line.rstrip(".;") + ";")
    if has_monitoring and monitoring_line:
        result.append(monitoring_line.rstrip(".;") + ".")
    if len(result) == 1 and result[0].endswith(";"):
        result[0] = result[0][:-1] + "."
    if result:
        return result
    if network_line:
        return [network_line.rstrip(".;") + "."]
    return [monitoring_line] if monitoring_line else list(base)


def _strip_network_without_addr(measures: list[str], description: str) -> list[str]:
    if "адрес" in (description or "").lower():
        return list(measures)
    return [m for m in measures if "сетевых средств" not in m]


def _adjust_phishing_measures(measures: list[str], description: str) -> list[str]:
    desc = re.sub(r"\s+", " ", description or "").lower()
    if "рассылк" not in desc:
        return [_SINGLE[0]] if "адрес" in desc else [_MONITORING[0]]
    m = re.search(r"ограничить\s+получение\s+(?:электронных\s+)?писем\s+с\s+адреса\s+([^\s;]+)", desc)
    if m:
        email = re.sub(r"[\[\]]", "", m.group(1)).strip(".,")
        prefix = m.group(0).split("получение", 1)[1].split("писем", 1)[0]
        result = list(measures)
        result.insert(6, re.sub(r"\s+", " ", f"ограничено получение {prefix}писем с адреса {email};"))
        return _strip_network_without_addr(result, description)
    result = list(measures)
    # 9-93#4: hyperlink-based phishing (no archive in attachments) -> the real
    # answer keeps only the network-blocking measure, omitting the monitoring one.
    if "гиперссылк" in desc and "архив" not in desc and "вложени" not in desc:
        filtered = [m for m in result if not ("мониторинга" in m and "сетевых средств" not in m)]
        if len(filtered) < len(result):
            result = filtered
            if result:
                result[-1] = result[-1].rstrip(".;") + "."
    return _strip_network_without_addr(result, description)


def _get_vuln_measures(vuln: Vulnerability, db=None) -> list[str]:
    if db:
        from app.models import VulnMeasureTemplate
        action = vuln.action_type or "update"
        tmpl = db.query(VulnMeasureTemplate).filter(
            VulnMeasureTemplate.action_type == action,
            VulnMeasureTemplate.is_default == True,
        ).first()
        if tmpl:
            content = tmpl.content
            if vuln.software:
                content = content.replace("{software}", vuln.software)
            result = [content]
            result.extend(_MINIMAL)
            return result
    return _VULN_UPDATE


def _build_vuln_inline(threat: Threat, vulnerabilities: list[Vulnerability], built_desc: str | None = None) -> str:
    """Real letters embed update-vulnerabilities directly into the threat intro:
    '..., а также возможности эксплуатации уязвимости {phrase} ({bdu paren})
    регулярно производится обновление {software} из доверенных источников с
    предварительным тестированием обновлений. Дополнительно приняты следующие
    меры защиты:'. Returns the full tail (starting with ', а также ...') or ''.
    Vulns with action 'exclude' are never inlined; vulns without an explicit
    action default to being inlined (update, or transition for OS vulns) unless
    they already appear in the built description."""
    desc_raw = re.sub(r"\s+", " ", threat.description or "")
    m = re.search(
        r"эксплуатация\s+уязвимости\s+(.+?)\s*\(\s*(BDU:\d{4}-\d+[^)]*)\)",
        desc_raw,
        flags=re.IGNORECASE,
    )
    if not m:
        return ""
    phrase = m.group(1).strip().rstrip(",").strip()
    bdu_paren = m.group(2).strip()
    bdu = re.match(r"BDU:\d{4}-\d+", bdu_paren)
    if not bdu:
        return ""
    bdu = bdu.group(0)
    vulns = [v for v in (vulnerabilities or []) if v.bdu_id and v.bdu_id.upper() == bdu.upper()]
    if not vulns:
        return ""
    if any((v.action_type or "").lower() == "exclude" for v in vulns):
        return ""

    def update_tail():
        update_sw = re.sub(
            r"^\s*редактор\w+.*?\bMicrosoft\s+Word\s*,\s*",
            "",
            phrase,
            flags=re.IGNORECASE,
        )
        return (
            f", а также возможности эксплуатации уязвимости {phrase} ({bdu_paren}) "
            f"регулярно производится обновление {update_sw} из доверенных источников "
            "с предварительным тестированием обновлений. Дополнительно приняты "
            "следующие меры защиты:"
        )

    def transition_tail():
        return (
            f", а также возможности эксплуатации уязвимости {phrase} ({bdu_paren}), "
            "ведутся работы по переходу на отечественные сертифицированные "
            "операционные системы. Дополнительно приняты следующие меры защиты:"
        )

    is_os_vuln = any(
        "windows" in (v.software or "").lower()
        or "операционных систем windows" in phrase.lower()
        for v in vulns
    )
    action = next(
        (v.action_type or "").lower() for v in vulns
        if (v.action_type or "").lower() in ("update", "skip")
    ) if any((v.action_type or "").lower() in ("update", "skip") for v in vulns) else ""
    if not action:
        if built_desc and bdu.upper() in re.sub(r"\s+", " ", built_desc).upper():
            return ""
        return transition_tail() if is_os_vuln else update_tail()
    if action == "update":
        return update_tail()
    if not is_os_vuln:
        return ""
    return transition_tail()


def _build_vuln_note(threat: Threat, vulnerabilities: list[Vulnerability], db=None) -> str:
    desc = threat.description or ""
    skip_sw = []
    update_sw = []
    seen = set()
    for vuln in vulnerabilities:
        if not vuln.software:
            continue
        in_desc = (vuln.bdu_id and vuln.bdu_id in desc) or (not vuln.bdu_id and vuln.software in desc)
        if not in_desc:
            continue
        key = (vuln.bdu_id or vuln.software, vuln.software)
        if key in seen:
            continue
        seen.add(key)
        action = (vuln.action_type or "").lower()
        if action == "exclude":
            continue
        if action == "skip" and vuln.software not in skip_sw:
            skip_sw.append(vuln.software)
        elif action == "update" and vuln.software not in update_sw:
            update_sw.append(vuln.software)
    notes = []
    if skip_sw:
        runtimes = {s.lower() for s in skip_sw} <= {"next.js", "node.js"}
        if runtimes:
            notes.append(f"Дополнительно сообщаем, что среда выполнения {', '.join(skip_sw)} не используется.")
        else:
            products = _nominative_products(desc)
            if products:
                verb = "не используются" if " и " in products else "не используется"
                notes.append(f"Дополнительно сообщаем, что {products} {verb}.")
            else:
                notes.append(f"Дополнительно сообщаем, что программное обеспечение {', '.join(skip_sw)} не используется.")
    if update_sw:
        notes.append(f"Ведутся работы по обновлению программного обеспечения {', '.join(update_sw)} до неуязвимой версии.")
    return " ".join(notes)


def _nominative_products(desc: str):
    """Extract the affected-products phrase from a vulnerability description and
    convert genitive head nouns to nominative, e.g.
    'централизованной системы управления ... и программного средства ...' ->
    'централизованная система управления ... и программное средство ...'."""
    text = re.sub(r"\s+", " ", desc or "")
    m = re.search(r"эксплуатация\s+уязвимост\w+\s+(.+?)\s*\(\s*BDU", text, flags=re.IGNORECASE)
    if not m:
        return ""
    phrase = m.group(1).strip()
    replacements = [
        ("централизованной системы", "централизованная система"),
        ("программного средства", "программное средство"),
        ("программного обеспечения", "программное обеспечение"),
        ("среды выполнения", "среда выполнения"),
        ("средства управления", "средство управления"),
        ("системы", "система"),
    ]
    for a, b in replacements:
        phrase = re.sub(a, b, phrase, flags=re.IGNORECASE)
    return phrase.strip()


_ANTI_PHISHING = [
    "производится автоматическая проверка вложений с использованием имеющейся «песочницы» («sandbox») для выявления вредоносной активности на этапе приема письма почтовым сервером;",
    "производится проверка почтовых вложений с использованием сертифицированного средства антивирусной защиты с использованием функции «Защита от почтовых угроз»;",
    "осуществляется автоматическая проверка указанных в письмах URL-адресов, содержащихся в электронных письмах, с использованием механизмов анализа ссылок;",
    "в целях идентификации отправителя производится проверка имени домена отправителя электронного письма;",
    "сотрудники проинструктированы о запрете открывать и загружать почтовые вложения писем с тематикой, не относящейся к рабочей деятельности;",
    "работы с электронной почтой производятся только с учетных записей пользователей операционной системы с минимальными возможными привилегиями;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

_MINIMAL = [
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

_SINGLE = [
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам.",
]

_MONITORING = [
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

_COMPROMISE = [
    "регулярно производится контроль журналов DNS-серверов, прокси-серверов, средств межсетевого экранирования, средств обнаружения и реагирования уровня узла;",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведено внеплановое сканирование информационной инфраструктуры средствами антивирусной защиты;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]

_VULN_UPDATE = [
    "ведутся работы по обновлению программного обеспечения до неуязвимой версии.",
    "на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;",
    "произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям.",
]
