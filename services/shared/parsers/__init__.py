from pathlib import Path
from shared.parsers.base import ParseResult
from shared.parsers.pdf_parser import parse_pdf
from shared.parsers.docx_parser import parse_docx
from shared.parsers.doc_parser import parse_doc
from shared.parsers.odt_parser import parse_odt
from shared.parsers.xlsx_parser import parse_xlsx
from shared.parsers.text_parser import parse_text, parse_rtf, parse_html

EXTENSION_MAP = {
    ".pdf": parse_pdf,
    ".docx": parse_docx,
    ".doc": parse_doc,
    ".odt": parse_odt,
    ".xlsx": parse_xlsx,
    ".xls": parse_xlsx,
    ".rtf": parse_rtf,
    ".txt": parse_text,
    ".eml": parse_text,
    ".html": parse_html,
    ".htm": parse_html,
    ".csv": parse_text,
    ".xml": parse_text,
    ".json": parse_text,
    ".log": parse_text,
}


def parse_file(path: str | Path) -> ParseResult:
    path = Path(path)
    if path.name.startswith("~$"):
        return ParseResult(errors=["lock file skipped"])
    suffix = path.suffix.lower()
    content = path.read_bytes()
    if suffix in EXTENSION_MAP:
        result = EXTENSION_MAP[suffix](content)
    else:
        result = parse_text(content)
    result.metadata["filename"] = path.name
    result.metadata["extension"] = suffix
    return result


def parse_bytes(filename: str, content: bytes) -> ParseResult:
    suffix = Path(filename).suffix.lower()
    if suffix in EXTENSION_MAP:
        result = EXTENSION_MAP[suffix](content)
    else:
        result = parse_text(content)
    result.metadata["filename"] = filename
    result.metadata["extension"] = suffix
    return result