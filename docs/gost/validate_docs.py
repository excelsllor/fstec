# -*- coding: utf-8 -*-
"""Read-only checks for the rebuilt documentation package."""
from pathlib import Path
import json
import re
from docx import Document
from docx.oxml.ns import qn

ROOT = Path(__file__).resolve().parent.parent.parent
DOC_DIR = next(p.parent for p in (ROOT / "docs").glob("*/*.docx") if p.name.startswith("00_"))
CFG = json.loads((Path(__file__).parent / "doc_config.json").read_text(encoding="utf-8"))
REQUIRED = [
    CFG["labels"]["contents_title"],
]

out = []
errors = []


def field_text(doc):
    xml = doc.element.xml
    return " ".join(re.findall(r"<w:instrText[^>]*>(.*?)</w:instrText>", xml))


for code in CFG["titles"]:
    files = sorted(p for p in DOC_DIR.glob(f"{code}_*.docx")
                   if not p.name.startswith("~$") and ".pre_security" not in p.name)
    if not files:
        errors.append(f"{code}: missing")
        continue
    p = files[0]
    d = Document(p)
    s = d.sections[0]
    problems = []
    if abs(s.page_width.cm - 21.0) > 0.15 or abs(s.page_height.cm - 29.7) > 0.15:
        problems.append("not A4")
    margins = [round(x.cm, 2) for x in (s.left_margin, s.right_margin, s.top_margin, s.bottom_margin)]
    if margins != [3.0, 1.5, 2.0, 2.0]:
        problems.append(f"margins={margins}")
    text = "\n".join(x.text for x in d.paragraphs)
    for req in REQUIRED:
        if req.lower() not in text.lower():
            problems.append(f"missing section: {req}")
    if CFG["labels"]["approval_title"].lower() in text.lower():
        problems.append("approval sheet remains")
    if CFG["labels"]["annotation_title"].lower() in text.lower():
        problems.append("annotation remains")
    if CFG["labels"]["references_title"].lower() in text.lower():
        problems.append("references section remains")
    if CFG["labels"]["abbrev_title"].lower() in text.lower():
        problems.append("abbreviations section remains")
    if CFG["labels"]["changes_title"].lower() in text.lower():
        problems.append("change sheet remains")
    if "УТВЕРЖДАЮ" in text or "СОГЛАСОВАНО" in text or "Подпись" in text:
        problems.append("signature fields remain")
    if "TOC" not in field_text(d):
        problems.append("no TOC field")
    if not re.search(r"\bPAGE\b", s.footer.paragraphs[0]._p.xml):
        problems.append("no PAGE field")
    if not s.different_first_page_header_footer:
        problems.append("title page shares header/footer")
    if any(x.text.strip() for x in s.header.paragraphs):
        problems.append("document header remains")
    if re.search(r"\b(PASS|FAIL)\b", text):
        problems.append("PASS/FAIL remains")
    prose = "\n".join(x.text for x in d.paragraphs if x.style.name != "Code")
    if "2026-11-15" in prose or "15.11.2026" in prose:
        problems.append("old date remains")
    captions = sum(1 for x in d.paragraphs if x.text.strip().startswith(CFG["labels"]["table_word"]))
    if d.tables and captions < 1:
        problems.append(f"only {captions} table captions")
    normal = d.styles["Normal"]
    if normal.font.name != "Times New Roman" or normal.font.size.pt != 14:
        problems.append(f"normal font {normal.font.name} {normal.font.size.pt}")
    out.append((p.name, len(d.paragraphs), len(d.tables), captions, problems))

report = []
for name, paras, tables, captions, problems in out:
    report.append(f"{name}: paragraphs={paras} tables={tables} table_captions={captions}")
    if problems:
        report.append("  ISSUES: " + "; ".join(problems))
        errors.extend((name, x) for x in problems)
    else:
        report.append("  OK")
Path(__file__).with_name("validation.txt").write_text("\n".join(report) + "\n", encoding="utf-8")
print("\n".join(report))
print("ERROR_COUNT", len(errors))
