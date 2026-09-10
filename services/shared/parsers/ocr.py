"""OCR-модуль (ТЗ 2.2): PaddleOCR (GPU/CUDA) основной, Tesseract (CPU) fallback.

Провайдер выбирается env FSTEC_OCR_ENGINE=auto|paddle|tesseract,
устройство — FSTEC_OCR_DEVICE=gpu|cpu (по умолчанию cpu — dev и малые GPU).
Общий интерфейс: ocr_pdf_bytes(content, lang) -> (text, errors).
Недоступность любого движка → ошибка, падение не допускается.
"""
import logging

from PIL import Image

from shared.config import OCR_DEVICE, OCR_ENGINE

logger = logging.getLogger(__name__)


def _pdf_to_images(content: bytes, dpi: int):
    """Рендер PDF → PIL-страницы. PyMuPDF (pip, без poppler) → fallback pdf2image."""
    try:
        import io

        import pymupdf as fitz  # type: ignore[attr-defined]
        doc = fitz.open(stream=content, filetype="pdf")
        zoom = dpi / 72.0
        out = []
        for page in doc:
            pix = page.get_pixmap(matrix=fitz.Matrix(zoom, zoom), alpha=False)
            img = Image.open(io.BytesIO(pix.tobytes("png"))).convert("RGB")
            out.append(img)
        if out:
            return out
    except Exception as exc:  # pragma: no cover - fallback
        logger.debug("PyMuPDF render failed (%s), try pdf2image", exc)
    from pdf2image import convert_from_bytes
    return convert_from_bytes(content, dpi=dpi)


def ocr_pdf_bytes(content: bytes, lang: str = "rus", dpi: int = 200) -> tuple[str, list[str]]:
    """Распознаёт сканированный PDF. Возвращает (текст, ошибки)."""
    errors: list[str] = []
    eng = OCR_ENGINE
    candidates = {"auto": ["paddle", "tesseract"], "paddle": ["paddle"], "tesseract": ["tesseract"]}.get(eng, ["paddle", "tesseract"])
    for name in candidates:
        if name == "paddle":
            result = _paddle_engine(content, lang, dpi)
        else:
            result = _tesseract_engine(content, lang, dpi)
        text, errs = result
        if text.strip():
            return text, errs
        errors.extend(errs or [f"OCR {name}: пустой результат"])
    return "", errors


def _tesseract_engine(content: bytes, lang: str, dpi: int) -> tuple[str, list[str]]:
    errors: list[str] = []
    try:
        import pytesseract
        pages = _pdf_to_images(content, dpi=dpi)
    except Exception as e:  # pragma: no cover
        return "", [f"Tesseract OCR недоступен: {e} (установите pytesseract/pdf2image и бинарники tesseract+poppler)"]
    parts = []
    for i, image in enumerate(pages, 1):
        try:
            parts.append(pytesseract.image_to_string(image, lang=lang))
        except Exception as e:
            errors.append(f"Tesseract стр. {i}: {e}")
    return "\n".join(parts), errors


def _paddle_engine(content: bytes, lang: str, dpi: int) -> tuple[str, list[str]]:
    errors: list[str] = []
    try:
        from paddleocr import PaddleOCR
    except Exception as e:  # pragma: no cover
        return "", [f"PaddleOCR недоступен: {e} (установите paddlepaddle + paddleocr)"]

    try:
        if OCR_DEVICE == "gpu":
            try:
                ocr_engine = PaddleOCR(use_angle_cls=True, lang="ru", use_gpu=True, show_log=False)
            except Exception:
                logger.warning("PaddleOCR GPU недоступен, переключаюсь на CPU")
                ocr_engine = PaddleOCR(use_angle_cls=True, lang="ru", use_gpu=False, show_log=False)
        else:
            ocr_engine = PaddleOCR(use_angle_cls=True, lang="ru", use_gpu=False, show_log=False)
    except Exception as e:  # pragma: no cover
        return "", [f"PaddleOCR инициализация: {e}"]

    try:
        pages = _pdf_to_images(content, dpi=dpi)
    except Exception as e:
        return "", [f"PaddleOCR: конвертация PDF: {e}"]

    import numpy as np

    parts = []
    for i, image in enumerate(pages, 1):
        try:
            arr = np.asarray(image)
            result = ocr_engine.ocr(arr, cls=True)
            if not result:
                errors.append(f"PaddleOCR стр. {i}: пустой результат")
                continue
            texts = []
            for line_group in result:
                if not line_group:
                    continue
                for entry in line_group:
                    if isinstance(entry, (list, tuple)) and len(entry) >= 2:
                        texts.append(str(entry[1][0]))
                    elif isinstance(entry, dict):
                        texts.extend(entry.get("rec_texts") or [])
                    elif isinstance(entry, str):
                        texts.append(entry)
            line = "\n".join(t for t in texts if t)
            parts.append(line)
            if not line:
                errors.append(f"PaddleOCR стр. {i}: пустой результат")
        except Exception as e:
            errors.append(f"PaddleOCR стр. {i}: {e}")
    return "\n".join(parts), errors


def ocr_needed(parsed_text: str, min_text: int) -> bool:
    return len((parsed_text or "").strip()) < min_text