from shared.db import SessionLocal
from shared.generator.response_store import replace_response
from shared.models import Document, GeneratedResponse


def test_replace_response_keeps_single_current_row():
    with SessionLocal() as db:
        doc = Document(source_filename="test-response-store.docx", letter_type="other")
        db.add(doc)
        db.commit()
        try:
            first = replace_response(db, doc.id, content="first", edited_content="", plan_json="{}")
            db.commit()
            second = replace_response(db, doc.id, content="second", edited_content="", plan_json="{}")
            db.commit()
            rows = db.query(GeneratedResponse).filter(GeneratedResponse.document_id == doc.id).all()
            assert len(rows) == 1
            assert rows[0].id == second.id
            assert rows[0].content == "second"
        finally:
            db.delete(doc)
            db.commit()
