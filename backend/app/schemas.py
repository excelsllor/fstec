from datetime import datetime
from typing import Literal
from pydantic import BaseModel, Field
from app.config import MIN_USERNAME_LENGTH, MIN_PASSWORD_LENGTH


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    role: str
    username: str


class TokenData(BaseModel):
    username: str | None = None
    role: str | None = None


class UserBase(BaseModel):
    username: str = Field(min_length=MIN_USERNAME_LENGTH)
    full_name: str = ""


UserRole = Literal["admin", "user"]


class UserCreate(UserBase):
    password: str = Field(min_length=MIN_PASSWORD_LENGTH, max_length=128)
    role: UserRole = "user"


class UserUpdate(BaseModel):
    full_name: str | None = None
    password: str | None = Field(default=None, min_length=MIN_PASSWORD_LENGTH, max_length=128)
    role: UserRole | None = None
    is_active: bool | None = None


class UserResponse(UserBase):
    id: int
    role: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


class AttachmentResponse(BaseModel):
    id: int
    filename: str
    file_type: str
    parse_status: str
    parse_errors: str
    parsed_text: str

    class Config:
        from_attributes = True


class ThreatResponse(BaseModel):
    id: int
    number: int
    group_name: str
    threat_type: str = ""
    theme: str
    archive_name: str
    exe_name: str
    malware_type: str
    description: str
    measures: str

    class Config:
        from_attributes = True


class IoCResponse(BaseModel):
    id: int
    ioc_type: str
    value: str
    context: str

    class Config:
        from_attributes = True


class VulnerabilityResponse(BaseModel):
    id: int
    bdu_id: str
    cve_id: str
    description: str
    software: str
    severity: str
    is_applicable: bool | None
    applicability_notes: str
    action_type: str
    action_details: str
    response_point: str

    class Config:
        from_attributes = True


class LetterResponse(BaseModel):
    id: int
    letter_number: str
    letter_date: str
    letter_type: str
    status: str
    subject: str
    original_text: str
    all_text: str
    parse_errors: str
    created_at: datetime
    updated_at: datetime
    attachments: list[AttachmentResponse] = []
    threats: list[ThreatResponse] = []
    iocs: list[IoCResponse] = []
    vulnerabilities: list[VulnerabilityResponse] = []

    class Config:
        from_attributes = True


class LetterListItem(BaseModel):
    id: int
    letter_number: str
    letter_date: str
    letter_type: str
    status: str
    created_at: datetime
    threat_count: int = 0
    ioc_count: int = 0
    vuln_count: int = 0

    class Config:
        from_attributes = True


class StatsResponse(BaseModel):
    total_letters: int
    hacker_letters: int
    compromise_letters: int
    vulnerability_letters: int
    other_letters: int
    total_threats: int
    total_iocs: int
    total_vulns: int


class ResponseTemplateBase(BaseModel):
    name: str
    threat_type: str = "hacker"
    content: str = ""
    is_default: bool = False


class ResponseTemplateCreate(ResponseTemplateBase):
    pass


class ResponseTemplateUpdate(BaseModel):
    name: str | None = None
    threat_type: str | None = None
    content: str | None = None
    is_default: bool | None = None


class ResponseTemplateResponse(ResponseTemplateBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class MeasureBlockBase(BaseModel):
    name: str
    block_type: str = "anti_phishing"
    content: str = ""


class MeasureBlockCreate(MeasureBlockBase):
    pass


class MeasureBlockUpdate(BaseModel):
    name: str | None = None
    block_type: str | None = None
    content: str | None = None


class MeasureBlockResponse(MeasureBlockBase):
    id: int
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class GeneratedResponseResponse(BaseModel):
    id: int
    letter_id: int
    content: str
    edited_content: str
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityUpdate(BaseModel):
    is_applicable: bool | None = None
    applicability_notes: str | None = None
    action_type: str | None = None
    action_details: str | None = None
    response_point: str | None = None
    software: str | None = None


class ThreatMeasuresUpdate(BaseModel):
    measures: list[str]


class ResponseContentUpdate(BaseModel):
    content: str = Field(max_length=100000)


class GenerateResponseRequest(BaseModel):
    pass


class ThreatTypeCreate(BaseModel):
    name: str
    key: str
    description: str = ""


class ThreatTypeUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class ThreatTypeResponse(BaseModel):
    id: int
    name: str
    key: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True


class MeasureTemplateCreate(BaseModel):
    name: str
    threat_type_id: int | None = None
    measures: str = ""
    is_default: bool = False


class MeasureTemplateUpdate(BaseModel):
    name: str | None = None
    threat_type_id: int | None = None
    measures: str | None = None
    is_default: bool | None = None


class MeasureTemplateResponse(BaseModel):
    id: int
    name: str
    threat_type_id: int | None = None
    measures: str
    is_default: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VulnMeasureTemplateCreate(BaseModel):
    name: str
    vuln_type_id: int | None = None
    action_type: str = "update"
    content: str = ""
    is_default: bool = False


class VulnMeasureTemplateUpdate(BaseModel):
    name: str | None = None
    vuln_type_id: int | None = None
    action_type: str | None = None
    content: str | None = None
    is_default: bool | None = None


class VulnMeasureTemplateResponse(BaseModel):
    id: int
    name: str
    vuln_type_id: int | None = None
    action_type: str
    content: str
    is_default: bool
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class VulnTypeCreate(BaseModel):
    name: str
    key: str
    description: str = ""


class VulnTypeUpdate(BaseModel):
    name: str | None = None
    description: str | None = None


class VulnTypeResponse(BaseModel):
    id: int
    name: str
    key: str
    description: str
    created_at: datetime

    class Config:
        from_attributes = True
