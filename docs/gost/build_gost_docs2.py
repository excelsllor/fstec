# -*- coding: utf-8 -*-
"""Rebuild the documentation package with a single GOST-style layout.

All Russian strings live in doc_config.json. This file is intentionally
ASCII-only so it remains stable across Windows code pages.
"""
from pathlib import Path
import json
import re
import shutil

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.style import WD_STYLE_TYPE
from docx.shared import Cm, Pt
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.table import Table
from docx.text.paragraph import Paragraph

ROOT = Path(__file__).resolve().parent.parent.parent
DOC_DIR = next(p.parent for p in (ROOT / "docs").glob("*/*.docx")
               if p.name.startswith("00_"))
CFG = json.loads((Path(__file__).parent / "doc_config.json").read_text(encoding="utf-8"))
FONT = "Times New Roman"
MONO = "Courier New"
PAGE_W = Cm(21.0)
PAGE_H = Cm(29.7)
MARGIN_LEFT = Cm(3.0)
MARGIN_RIGHT = Cm(1.5)
MARGIN_TOP = Cm(2.0)
MARGIN_BOTTOM = Cm(2.0)


def set_run_font(run, size=14, bold=None, italic=None, mono=False):
    run.font.name = MONO if mono else FONT
    run.font.size = Pt(size)
    if bold is not None:
        run.bold = bold
    if italic is not None:
        run.italic = italic
    rpr = run._element.get_or_add_rPr()
    rfonts = rpr.find(qn("w:rFonts"))
    if rfonts is None:
        rfonts = OxmlElement("w:rFonts")
        rpr.insert(0, rfonts)
    for key in ("w:ascii", "w:hAnsi", "w:eastAsia", "w:cs"):
        rfonts.set(qn(key), MONO if mono else FONT)


def set_paragraph(p, first_indent=True, align=WD_ALIGN_PARAGRAPH.JUSTIFY,
                  before=0, after=0, line=1.5, keep=False):
    pf = p.paragraph_format
    pf.left_indent = Cm(0)
    pf.right_indent = Cm(0)
    pf.first_line_indent = Cm(1.25) if first_indent else Cm(0)
    pf.space_before = Pt(before)
    pf.space_after = Pt(after)
    pf.line_spacing = line
    p.alignment = align
    p.paragraph_format.keep_with_next = keep
    p.paragraph_format.widow_control = True


def set_cell_font(cell, size=10, bold=False):
    for p in cell.paragraphs:
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.space_before = Pt(0)
        p.alignment = WD_ALIGN_PARAGRAPH.LEFT
        for r in p.runs:
            set_run_font(r, size, bold=bold)


def add_field(paragraph, instr, placeholder=""):
    run = paragraph.add_run()
    fld_begin = OxmlElement("w:fldChar")
    fld_begin.set(qn("w:fldCharType"), "begin")
    instr_el = OxmlElement("w:instrText")
    instr_el.set(qn("xml:space"), "preserve")
    instr_el.text = f" {instr} "
    fld_sep = OxmlElement("w:fldChar")
    fld_sep.set(qn("w:fldCharType"), "separate")
    txt = OxmlElement("w:t")
    txt.text = placeholder
    fld_end = OxmlElement("w:fldChar")
    fld_end.set(qn("w:fldCharType"), "end")
    for e in (fld_begin, instr_el, fld_sep, txt, fld_end):
        run._r.append(e)


def style_document(doc):
    normal = doc.styles["Normal"]
    normal.font.name = FONT
    normal.font.size = Pt(14)
    normal.paragraph_format.space_after = Pt(0)
    normal.paragraph_format.space_before = Pt(0)
    normal.paragraph_format.line_spacing = 1.5
    normal.paragraph_format.first_line_indent = Cm(1.25)
    normal.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.JUSTIFY
    rpr = normal.element.get_or_add_rPr()
    lang = rpr.find(qn("w:lang"))
    if lang is None:
        lang = OxmlElement("w:lang")
        rpr.append(lang)
    lang.set(qn("w:val"), "ru-RU")
    lang.set(qn("w:eastAsia"), "ru-RU")

    for name, size, align in [
        ("Heading 1", 14, WD_ALIGN_PARAGRAPH.CENTER),
        ("Heading 2", 14, WD_ALIGN_PARAGRAPH.LEFT),
        ("Heading 3", 14, WD_ALIGN_PARAGRAPH.LEFT),
    ]:
        st = doc.styles[name]
        st.font.name = FONT
        st.font.size = Pt(size)
        st.font.bold = True
        st.font.italic = False
        st.paragraph_format.space_before = Pt(12)
        st.paragraph_format.space_after = Pt(6)
        st.paragraph_format.line_spacing = 1.5
        st.paragraph_format.first_line_indent = Cm(0)
        st.paragraph_format.keep_with_next = True
        st.paragraph_format.alignment = align
        st.paragraph_format.page_break_before = (name == "Heading 1")

    code = doc.styles.add_style("Code", WD_STYLE_TYPE.PARAGRAPH)
    code.base_style = doc.styles["Normal"]
    code.font.name = MONO
    code.font.size = Pt(10)
    code.paragraph_format.first_line_indent = Cm(0)
    code.paragraph_format.left_indent = Cm(0.5)
    code.paragraph_format.line_spacing = 1.0
    code.paragraph_format.space_before = Pt(0)
    code.paragraph_format.space_after = Pt(0)
    code.paragraph_format.alignment = WD_ALIGN_PARAGRAPH.LEFT


def page_setup(doc, code):
    sec = doc.sections[0]
    sec.page_width = PAGE_W
    sec.page_height = PAGE_H
    sec.left_margin = MARGIN_LEFT
    sec.right_margin = MARGIN_RIGHT
    sec.top_margin = MARGIN_TOP
    sec.bottom_margin = MARGIN_BOTTOM
    sec.header_distance = Cm(1.0)
    sec.footer_distance = Cm(1.0)
    sec.different_first_page_header_footer = True

    hp = sec.header.paragraphs[0]
    hp.text = ""
    hp.alignment = WD_ALIGN_PARAGRAPH.LEFT

    fp = sec.footer.paragraphs[0]
    fp.text = ""
    fp.alignment = WD_ALIGN_PARAGRAPH.CENTER
    add_field(fp, "PAGE", "2")


def centered_line(doc, text, size=12, bold=False, line=1.0):
    p = doc.add_paragraph()
    set_paragraph(p, first_indent=False, align=WD_ALIGN_PARAGRAPH.CENTER, line=line)
    r = p.add_run(text)
    set_run_font(r, size, bold=bold)
    return p


def add_title_page(doc, code):
    centered_line(doc, CFG["organization"], 12, True)
    centered_line(doc, CFG["system"], 12)
    centered_line(doc, " ", 12)
    centered_line(doc, " ", 12)

    for _ in range(2):
        centered_line(doc, " ", 12)
    centered_line(doc, CFG["titles"][code].upper(), 18, True)
    if CFG["codes"].get(code):
        centered_line(doc, CFG["codes"][code], 14, True)
    centered_line(doc, f"{CFG.get('version_label', '')} {CFG['version']}", 12)
    for _ in range(2):
        centered_line(doc, " ", 12)
    centered_line(doc, CFG["city"], 12)
    centered_line(doc, CFG["year"], 12)


def add_approval_sheet(doc, code):
    h = doc.add_heading(CFG["labels"]["approval_title"], level=1)
    h.alignment = WD_ALIGN_PARAGRAPH.CENTER
    p = doc.add_paragraph()
    set_paragraph(p, first_indent=False, align=WD_ALIGN_PARAGRAPH.CENTER)
    r = p.add_run(f"{CFG['codes'][code]}  {CFG['titles'][code]}")
    set_run_font(r, 12, bold=True)

    rows = [CFG["labels"]["approval_header"]] + CFG["labels"]["approval_rows"]
    table = doc.add_table(rows=len(rows), cols=4)
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    for i, row in enumerate(rows):
        for j, text in enumerate(row):
            cell = table.cell(i, j)
            cell.text = text
            set_cell_font(cell, 10, bold=(i == 0))


def add_annotation(doc, code):
    doc.add_heading(CFG["labels"]["annotation_title"], level=1)
    p = doc.add_paragraph(CFG["annotations"][code])
    set_paragraph(p)
    p = doc.add_paragraph(CFG["labels"]["annotation_note"])
    set_paragraph(p)


def add_contents(doc):
    title = doc.add_paragraph()
    title.paragraph_format.page_break_before = True
    set_paragraph(title, first_indent=False, align=WD_ALIGN_PARAGRAPH.CENTER,
                  keep=True)
    set_run_font(title.add_run(CFG["labels"]["contents_title"].upper()), 14,
                 bold=True)
    p = doc.add_paragraph()
    set_paragraph(p, first_indent=False)
    add_field(p, 'TOC \\o "1-2" \\h \\z \\u', CFG["labels"]["toc_placeholder"])


def clean_text(text, technical=False):
    if technical or text.strip().lower().endswith(".docx"):
        return text
    for old, new in CFG["replacements"]:
        if old in ("PASS", "FAIL"):
            text = re.sub(r"\b" + re.escape(old) + r"\b", new, text)
        else:
            text = text.replace(old, new)
    return text


def looks_technical(text):
    markers = ("{", "}", "GLPI_", "CMDB_", "KAFKA_", "FSTEC_", "POSTGRES_")
    return any(x in text for x in markers) or text.strip().startswith(("http://", "https://"))


def add_table(doc, rows, caption):
    if not rows:
        return
    p = doc.add_paragraph()
    set_paragraph(p, first_indent=False, align=WD_ALIGN_PARAGRAPH.LEFT, before=6, after=3, keep=True)
    r = p.add_run(caption)
    set_run_font(r, 11, italic=True)

    table = doc.add_table(rows=len(rows), cols=len(rows[0]))
    table.style = "Table Grid"
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    table.autofit = True
    for i, row in enumerate(rows):
        for j, text in enumerate(row):
            cell = table.cell(i, j)
            cell.text = clean_text(text, technical=looks_technical(text))
            set_cell_font(cell, 9, bold=(i == 0))
        if i == 0:
            trPr = table.rows[i]._tr.get_or_add_trPr()
            hdr = OxmlElement("w:tblHeader")
            hdr.set(qn("w:val"), "true")
            trPr.append(hdr)
    doc.add_paragraph()


def add_main_content(doc, src, code):
    title = CFG["titles"][code]
    section_name = ""
    table_no = 0
    figure_no = 0
    figure_added = False
    skipped_title = False

    def add_source_paragraph(p):
        nonlocal section_name, figure_no, figure_added, skipped_title
        style = p.style.name
        text = clean_text(p.text.strip(), technical=(style == "No Spacing"))
        if not text:
            return
        if any(text.startswith(x) for x in CFG["labels"].get(
                "metadata_prefixes", [CFG["labels"]["metadata_prefix"]])):
            return
        if not skipped_title and style == "Heading 1":
            skipped_title = True
            return
        if not skipped_title and text.replace("\u0451", "\u0435") == title.replace("\u0451", "\u0435"):
            skipped_title = True
            return

        if style == "Heading 1":
            doc.add_heading(text.upper(), level=1)
            section_name = text
        elif style == "Heading 2":
            doc.add_heading(text, level=1)
            section_name = text
        elif style == "Heading 3":
            doc.add_heading(text, level=2)
            section_name = text
        elif style in ("List Bullet", "List Number"):
            pnew = doc.add_paragraph(style=style)
            set_run_font(pnew.add_run(text), 14)
            set_paragraph(pnew, first_indent=False, align=WD_ALIGN_PARAGRAPH.JUSTIFY)
        elif style == "No Spacing":
            pnew = doc.add_paragraph(style="Code")
            set_run_font(pnew.add_run(text), 10, mono=True)
            if "->" in text and not figure_added:
                figure_no += 1
                cap = doc.add_paragraph()
                set_paragraph(cap, first_indent=False, align=WD_ALIGN_PARAGRAPH.CENTER,
                              before=3, after=6)
                set_run_font(cap.add_run(
                    f"{CFG['labels']['figure_word']} {figure_no} — {CFG['labels']['figure_caption']}"),
                    11, italic=True)
                figure_added = True
        else:
            pnew = doc.add_paragraph()
            set_run_font(pnew.add_run(text), 14)
            set_paragraph(pnew)

    for child in src.element.body.iterchildren():
        if child.tag == qn("w:p"):
            add_source_paragraph(Paragraph(child, src))
        elif child.tag == qn("w:tbl"):
            table_no += 1
            table = Table(child, src)
            rows = [[cell.text.replace("\n", " ") for cell in row.cells]
                    for row in table.rows]
            add_table(doc, rows, f"{CFG['labels']['table_word']} {table_no} — {section_name or title}")


def add_references(doc):
    doc.add_heading(CFG["labels"]["references_title"], level=1)
    for i, ref in enumerate(CFG["references"], 1):
        p = doc.add_paragraph()
        set_paragraph(p, first_indent=False, align=WD_ALIGN_PARAGRAPH.JUSTIFY, line=1.0)
        set_run_font(p.add_run(f"{i}. {ref}"), 12)


def add_abbreviations(doc):
    doc.add_heading(CFG["labels"]["abbrev_title"], level=1)
    p = doc.add_paragraph(CFG["labels"]["abbrev_intro"])
    set_paragraph(p, first_indent=False)
    rows = [CFG["labels"]["abbrev_header"]] + CFG["abbreviations"]
    add_table(doc, rows, f"{CFG['labels']['table_word']} — {CFG['labels']['abbrev_title'].lower()}")


def add_change_sheet(doc, code):
    doc.add_heading(CFG["labels"]["changes_title"], level=1)
    rows = [CFG["labels"]["changes_header"], CFG["labels"]["changes_row"]]
    add_table(doc, rows, f"{CFG['labels']['table_word']} — {CFG['labels']['changes_title'].lower()}")
    p = doc.add_paragraph()
    set_paragraph(p, first_indent=False, align=WD_ALIGN_PARAGRAPH.LEFT)
    set_run_font(p.add_run(CFG["labels"]["change_footer"].format(
        code=code, version=CFG["version"])), 11)


def build(code, src_path):
    doc = Document()
    style_document(doc)
    doc.core_properties.language = "ru-RU"
    doc.core_properties.title = CFG["titles"][code]
    doc.core_properties.subject = CFG["system"]
    page_setup(doc, CFG["codes"][code])
    add_title_page(doc, code)
    add_contents(doc)
    add_main_content(doc, Document(src_path), code)

    update = OxmlElement("w:updateFields")
    update.set(qn("w:val"), "true")
    doc.settings.element.append(update)

    files = [p for p in DOC_DIR.glob(f"{code}_*.docx")
             if not p.name.startswith("~$") and ".pre_security" not in p.name]
    out = files[0] if files else DOC_DIR / f"{code}.docx"
    try:
        doc.save(str(out))
    except PermissionError:
        print("SKIP locked:", out.name)
        return
    print("saved", out.name)


def main():
    backups = DOC_DIR / "_backup_20261116"
    backups.mkdir(exist_ok=True)
    for code in CFG["titles"]:
        current = [p for p in DOC_DIR.glob(f"{code}_*.docx")
                   if not p.name.startswith("~$") and ".pre_security" not in p.name]
        saved = [p for p in backups.glob(f"{code}_*.docx")
                 if not p.name.startswith("~$") and ".pre_security" not in p.name]
        if not current and not saved:
            print("skip", code)
            continue
        if saved:
            src = saved[0]
        else:
            src = current[0]
            backup = backups / src.name
            if not backup.exists():
                shutil.copy2(src, backup)
        build(code, src)


if __name__ == "__main__":
    main()
