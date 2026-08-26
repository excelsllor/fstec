from datetime import datetime
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Boolean, JSON,
)
from sqlalchemy.orm import relationship
from app.database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), nullable=False, default="user")
    full_name = Column(String(200), default="")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class BootstrapSecret(Base):
    __tablename__ = "bootstrap_secrets"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100), nullable=False, index=True)
    secret = Column(Text, nullable=False)
    used = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)


class LoginAttempt(Base):
    __tablename__ = "login_attempts"

    id = Column(Integer, primary_key=True, index=True)
    ip = Column(String(45), nullable=False, index=True)
    username = Column(String(100), nullable=False)
    attempts = Column(Integer, default=1)
    first_attempt_at = Column(DateTime, nullable=False)


class Letter(Base):
    __tablename__ = "letters"

    id = Column(Integer, primary_key=True, index=True)
    letter_number = Column(String(50), default="")
    letter_date = Column(String(20), default="")
    letter_type = Column(String(30), default="hacker")
    status = Column(String(30), default="new")
    subject = Column(String(500), default="")
    original_text = Column(Text, default="")
    all_text = Column(Text, default="")
    parse_errors = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    attachments = relationship("Attachment", back_populates="letter", cascade="all, delete-orphan")
    threats = relationship("Threat", back_populates="letter", cascade="all, delete-orphan")
    iocs = relationship("IoC", back_populates="letter", cascade="all, delete-orphan")
    vulnerabilities = relationship("Vulnerability", back_populates="letter", cascade="all, delete-orphan")
    responses = relationship("GeneratedResponse", back_populates="letter", cascade="all, delete-orphan")


class Attachment(Base):
    __tablename__ = "attachments"

    id = Column(Integer, primary_key=True, index=True)
    letter_id = Column(Integer, ForeignKey("letters.id", ondelete="CASCADE"), nullable=False)
    filename = Column(String(500), nullable=False)
    file_path = Column(String(1000), nullable=False)
    file_type = Column(String(20), default="")
    parsed_text = Column(Text, default="")
    parse_status = Column(String(20), default="pending")
    parse_errors = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    letter = relationship("Letter", back_populates="attachments")


class Threat(Base):
    __tablename__ = "threats"

    id = Column(Integer, primary_key=True, index=True)
    letter_id = Column(Integer, ForeignKey("letters.id", ondelete="CASCADE"), nullable=False)
    number = Column(Integer, default=0)
    group_name = Column(String(200), default="")
    threat_type = Column(String(50), default="")
    theme = Column(String(500), default="")
    archive_name = Column(String(300), default="")
    exe_name = Column(String(300), default="")
    malware_type = Column(String(200), default="")
    description = Column(Text, default="")
    measures = Column(Text, default="")

    letter = relationship("Letter", back_populates="threats")


class IoC(Base):
    __tablename__ = "iocs"

    id = Column(Integer, primary_key=True, index=True)
    letter_id = Column(Integer, ForeignKey("letters.id", ondelete="CASCADE"), nullable=False)
    ioc_type = Column(String(30), nullable=False, index=True)
    value = Column(String(500), nullable=False)
    context = Column(Text, default="")

    letter = relationship("Letter", back_populates="iocs")


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    letter_id = Column(Integer, ForeignKey("letters.id", ondelete="CASCADE"), nullable=False)
    bdu_id = Column(String(50), default="")
    cve_id = Column(String(50), default="")
    description = Column(Text, default="")
    software = Column(String(500), default="")
    severity = Column(String(30), default="unknown")
    is_applicable = Column(Boolean, nullable=True)
    applicability_notes = Column(Text, default="")
    action_type = Column(String(30), default="")
    action_details = Column(Text, default="")
    response_point = Column(Text, default="")

    letter = relationship("Letter", back_populates="vulnerabilities")


class ThreatType(Base):
    __tablename__ = "threat_types"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False, unique=True)
    key = Column(String(50), nullable=False, unique=True)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    measure_templates = relationship("MeasureTemplate", back_populates="threat_type", cascade="all, delete-orphan")


class MeasureTemplate(Base):
    __tablename__ = "measure_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    threat_type_id = Column(Integer, ForeignKey("threat_types.id"), nullable=True)
    measures = Column(Text, default="")
    full_text = Column(Text, default="")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    threat_type = relationship("ThreatType", back_populates="measure_templates")


class VulnType(Base):
    __tablename__ = "vuln_types"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False, unique=True)
    key = Column(String(50), nullable=False, unique=True)
    description = Column(Text, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

    vuln_templates = relationship("VulnMeasureTemplate", back_populates="vuln_type", cascade="all, delete-orphan")


class VulnMeasureTemplate(Base):
    __tablename__ = "vuln_measure_templates"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(200), nullable=False)
    vuln_type_id = Column(Integer, ForeignKey("vuln_types.id"), nullable=True)
    action_type = Column(String(50), default="update")
    content = Column(Text, default="")
    is_default = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    vuln_type = relationship("VulnType", back_populates="vuln_templates")


class GeneratedResponse(Base):
    __tablename__ = "generated_responses"

    id = Column(Integer, primary_key=True, index=True)
    letter_id = Column(Integer, ForeignKey("letters.id", ondelete="CASCADE"), nullable=False)
    content = Column(Text, default="")
    edited_content = Column(Text, default="")
    created_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    letter = relationship("Letter", back_populates="responses")
