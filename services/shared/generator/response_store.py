from shared.models import GeneratedResponse


def replace_response(db, document_id: int, *, content: str, edited_content: str,
                     plan_json: str, created_by: int | None = None) -> GeneratedResponse:
    db.query(GeneratedResponse).filter(
        GeneratedResponse.document_id == document_id
    ).delete(synchronize_session=False)
    row = GeneratedResponse(
        document_id=document_id,
        content=content,
        edited_content=edited_content,
        plan_json=plan_json,
        created_by=created_by,
    )
    db.add(row)
    db.flush()
    return row
