from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from app.database import get_db
from app.models import User, ThreatType, MeasureTemplate, VulnMeasureTemplate, VulnType
from app.auth import get_current_user, require_admin
from app.schemas import (
    ThreatTypeResponse, ThreatTypeCreate, ThreatTypeUpdate,
    MeasureTemplateResponse, MeasureTemplateCreate, MeasureTemplateUpdate,
    VulnMeasureTemplateResponse, VulnMeasureTemplateCreate, VulnMeasureTemplateUpdate,
    VulnTypeResponse, VulnTypeCreate, VulnTypeUpdate,
)

router = APIRouter(prefix="/api/templates", tags=["templates"])


@router.get("/threat-types", response_model=list[ThreatTypeResponse])
def list_threat_types(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(ThreatType).order_by(ThreatType.id).all()


@router.post("/threat-types", response_model=ThreatTypeResponse, status_code=201)
def create_threat_type(data: ThreatTypeCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    if db.query(ThreatType).filter(ThreatType.key == data.key).first():
        raise HTTPException(status_code=400, detail="Тип с таким ключом уже существует")
    t = ThreatType(name=data.name, key=data.key, description=data.description)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@router.put("/threat-types/{type_id}", response_model=ThreatTypeResponse)
def update_threat_type(type_id: int, data: ThreatTypeUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    t = db.query(ThreatType).filter(ThreatType.id == type_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Тип угрозы не найден")
    if data.name is not None:
        t.name = data.name
    if data.description is not None:
        t.description = data.description
    db.commit()
    db.refresh(t)
    return t


@router.delete("/threat-types/{type_id}", status_code=204)
def delete_threat_type(type_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    t = db.query(ThreatType).filter(ThreatType.id == type_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Тип угрозы не найден")
    db.delete(t)
    db.commit()


@router.get("/measure-templates", response_model=list[MeasureTemplateResponse])
def list_measure_templates(threat_type_id: int | None = None, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    q = db.query(MeasureTemplate)
    if threat_type_id:
        q = q.filter(MeasureTemplate.threat_type_id == threat_type_id)
    return q.order_by(MeasureTemplate.id).all()


@router.post("/measure-templates", response_model=MeasureTemplateResponse, status_code=201)
def create_measure_template(data: MeasureTemplateCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    m = MeasureTemplate(name=data.name, threat_type_id=data.threat_type_id, measures=data.measures, is_default=data.is_default)
    if data.is_default:
        db.query(MeasureTemplate).filter(MeasureTemplate.threat_type_id == data.threat_type_id).update({"is_default": False})
    db.add(m)
    db.commit()
    db.refresh(m)
    return m


@router.put("/measure-templates/{template_id}", response_model=MeasureTemplateResponse)
def update_measure_template(template_id: int, data: MeasureTemplateUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    m = db.query(MeasureTemplate).filter(MeasureTemplate.id == template_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    if data.name is not None:
        m.name = data.name
    if data.threat_type_id is not None:
        m.threat_type_id = data.threat_type_id
    if data.measures is not None:
        m.measures = data.measures
    if data.is_default is not None:
        if data.is_default:
            db.query(MeasureTemplate).filter(MeasureTemplate.threat_type_id == m.threat_type_id, MeasureTemplate.id != template_id).update({"is_default": False})
        m.is_default = data.is_default
    db.commit()
    db.refresh(m)
    return m


@router.delete("/measure-templates/{template_id}", status_code=204)
def delete_measure_template(template_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    m = db.query(MeasureTemplate).filter(MeasureTemplate.id == template_id).first()
    if not m:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    db.delete(m)
    db.commit()


@router.get("/vuln-templates", response_model=list[VulnMeasureTemplateResponse])
def list_vuln_templates(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(VulnMeasureTemplate).order_by(VulnMeasureTemplate.id).all()


@router.post("/vuln-templates", response_model=VulnMeasureTemplateResponse, status_code=201)
def create_vuln_template(data: VulnMeasureTemplateCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    v = VulnMeasureTemplate(name=data.name, vuln_type_id=data.vuln_type_id, action_type=data.action_type, content=data.content, is_default=data.is_default)
    db.add(v)
    db.commit()
    db.refresh(v)
    return v


@router.put("/vuln-templates/{template_id}", response_model=VulnMeasureTemplateResponse)
def update_vuln_template(template_id: int, data: VulnMeasureTemplateUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    v = db.query(VulnMeasureTemplate).filter(VulnMeasureTemplate.id == template_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    if data.name is not None:
        v.name = data.name
    if data.vuln_type_id is not None:
        v.vuln_type_id = data.vuln_type_id
    if data.action_type is not None:
        v.action_type = data.action_type
    if data.content is not None:
        v.content = data.content
    if data.is_default is not None:
        v.is_default = data.is_default
    db.commit()
    db.refresh(v)
    return v


@router.delete("/vuln-templates/{template_id}", status_code=204)
def delete_vuln_template(template_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    v = db.query(VulnMeasureTemplate).filter(VulnMeasureTemplate.id == template_id).first()
    if not v:
        raise HTTPException(status_code=404, detail="Шаблон не найден")
    db.delete(v)
    db.commit()


@router.get("/vuln-types", response_model=list[VulnTypeResponse])
def list_vuln_types(db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    return db.query(VulnType).order_by(VulnType.id).all()


@router.post("/vuln-types", response_model=VulnTypeResponse, status_code=201)
def create_vuln_type(data: VulnTypeCreate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    if db.query(VulnType).filter(VulnType.key == data.key).first():
        raise HTTPException(status_code=400, detail="Тип с таким ключом уже существует")
    t = VulnType(name=data.name, key=data.key, description=data.description)
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


@router.put("/vuln-types/{type_id}", response_model=VulnTypeResponse)
def update_vuln_type(type_id: int, data: VulnTypeUpdate, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    t = db.query(VulnType).filter(VulnType.id == type_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Тип уязвимости не найден")
    if data.name is not None:
        t.name = data.name
    if data.description is not None:
        t.description = data.description
    db.commit()
    db.refresh(t)
    return t


@router.delete("/vuln-types/{type_id}", status_code=204)
def delete_vuln_type(type_id: int, db: Session = Depends(get_db), current_user: User = Depends(require_admin)):
    t = db.query(VulnType).filter(VulnType.id == type_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Тип уязвимости не найден")
    db.delete(t)
    db.commit()
