"""Защита от XXE/DTD при разборе ZIP-XML (docx/xlsx/odt).

lxml (python-docx) и openpyxl по умолчанию могут резолвить внутренние/внешние
сущности DTD; OOXML-части не должны содержать DOCTYPE/ENTITY вообще.
Любая часть архива с запрещёнными маркерами → кортеж отклонён, содержимое не разбирается.
"""
import io
import zipfile

_XXE_MARKERS = (b"<!DOCTYPE", b"<!ENTITY", b"<!ELEMENT", b"<!ATTLIST", b"<!NOTATION")


def guard_zip_xml(content: bytes, *, what: str, errors: list[str], max_part: int = 2 * 1024 * 1024) -> bool:
    """Проверяет все XML/rels-части zip-архива на DTD/ENTITY.

    True — безопасно (можно парсить). False — в errors добавлено описание, архив отклонён.
    """
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            for name in zf.namelist():
                low = name.lower()
                if not (low.endswith((".xml", ".rels")) or ".xml" in low):
                    continue
                data = zf.read(name)
                if len(data) > max_part:
                    errors.append(f"{what}: XML-часть {name!r} превышает лимит")
                    return False
                if any(marker in data for marker in _XXE_MARKERS):
                    errors.append(f"{what}: отклонён XML-файл с DTD/ENTITY ({name!r})")
                    return False
    except zipfile.BadZipFile:
        errors.append(f"{what}: повреждён ZIP-архив")
        return False
    except Exception as e:  # noqa: BLE001
        errors.append(f"{what}: ошибка проверки архива: {e}")
        return False
    return True