from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base
from app.config import DATABASE_URL

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    Base.metadata.create_all(bind=engine)
    _migrate_threats_table()
    _migrate_user_roles()
    _migrate_bootstrap_hash()
    _populate_defaults()


def _migrate_user_roles():
    try:
        with engine.connect() as conn:
            conn.execute(text("UPDATE users SET role = 'user' WHERE role = 'operator'"))
            conn.commit()
    except Exception:
        pass


def _migrate_threats_table():
    try:
        with engine.connect() as conn:
            cols = conn.execute(text("PRAGMA table_info(threats)")).fetchall()
            col_names = [c[1] for c in cols]
            if "threat_type" not in col_names:
                conn.execute(text("ALTER TABLE threats ADD COLUMN threat_type VARCHAR(50) DEFAULT ''"))
                conn.commit()
            conn.execute(text("UPDATE threats SET measures = '' WHERE measures LIKE '%;%'"))
            conn.commit()

            mt_cols = conn.execute(text("PRAGMA table_info(measure_templates)")).fetchall()
            mt_col_names = [c[1] for c in mt_cols]
            if "full_text" not in mt_col_names:
                conn.execute(text("ALTER TABLE measure_templates ADD COLUMN full_text TEXT DEFAULT ''"))
                conn.commit()
    except Exception:
        pass


def _migrate_bootstrap_hash():
    """Hash any existing plaintext bootstrap secrets (C-2 fix)."""
    try:
        from app.auth import hash_password
        with engine.connect() as conn:
            rows = conn.execute(text("SELECT id, secret FROM bootstrap_secrets")).fetchall()
            for row_id, secret in rows:
                if secret and not secret.startswith("$2"):
                    new_hash = hash_password(secret)
                    conn.execute(text("UPDATE bootstrap_secrets SET secret = :secret WHERE id = :id"),
                                 {"secret": new_hash, "id": row_id})
            conn.commit()
    except Exception:
        pass


def _populate_defaults():
    from app.models import ThreatType, MeasureTemplate, VulnMeasureTemplate, VulnType
    db = SessionLocal()
    try:
        if db.query(ThreatType).count() == 0:
            _create_default_threat_types(db)
            db.commit()
        if db.query(MeasureTemplate).count() == 0:
            _create_default_measure_templates(db)
            db.commit()
        if db.query(VulnType).count() == 0:
            _create_default_vuln_types(db)
            db.commit()
        if db.query(VulnMeasureTemplate).count() == 0:
            _create_default_vuln_templates(db)
            db.commit()
    except Exception as e:
        print(f"Error populating defaults: {e}")
        db.rollback()
    finally:
        db.close()


ANTI_PHISHING = """производится автоматическая проверка вложений с использованием имеющейся «песочницы» («sandbox») для выявления вредоносной активности на этапе приема письма почтовым сервером;
производится проверка почтовых вложений с использованием сертифицированного средства антивирусной защиты с использованием функции «Защита от почтовых угроз»;
осуществляется автоматическая проверка указанных в письмах URL-адресов, содержащихся в электронных письмах, с использованием механизмов анализа ссылок;
в целях идентификации отправителя производится проверка имени домена отправителя электронного письма;
сотрудники проинструктированы о запрете открывать и загружать почтовые вложения писем с тематикой, не относящейся к рабочей деятельности;
работы с электронной почтой производятся только с учетных записей пользователей операционной системы с минимальными возможными привилегиями;
на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;
произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."""

MINIMAL = """на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;
произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."""

SINGLE = """на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам."""

COMPROMISE = """регулярно производится контроль журналов DNS-серверов, прокси-серверов, средств межсетевого экранирования, средств обнаружения и реагирования уровня узла;
на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;
произведено внеплановое сканирование информационной инфраструктуры средствами антивирусной защиты;
произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."""

VULN_UPDATE = """ведутся работы по обновлению программного обеспечения до неуязвимой версии.
на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;
произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."""

VULN_COMPENSATE = """применены компенсирующие меры.
на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;
произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."""

VULN_SKIP = """программное обеспечение не используется.
на уровне сетевых средств защиты информации обеспечено ограничение обращений к указанным адресам;
произведена настройка правил системы мониторинга событий информационной безопасности согласно рекомендациям."""


def _create_default_threat_types(db):
    from app.models import ThreatType
    types = [
        ("Фишинговая рассылка", "phishing", "Фишинговые рассылки электронных писем"),
        ("Целевая компьютерная атака", "malware_attack", "Атаки с применением вредоносного ПО"),
        ("Эксплуатация уязвимости", "vulnerability", "Эксплуатация уязвимостей ПО (BDU/CVE)"),
        ("Компрометация веб-сайта", "compromise", "Компрометация веб-сайта разработчика ПО"),
        ("Атака ClickFix", "clickfix", "Атаки с использованием метода ClickFix"),
    ]
    for name, key, desc in types:
        db.add(ThreatType(name=name, key=key, description=desc))


def _create_default_measure_templates(db):
    from app.models import ThreatType, MeasureTemplate
    types = {t.key: t.id for t in db.query(ThreatType).all()}

    templates = [
        ("Антифишинговый блок (8 мер)", "phishing", ANTI_PHISHING, True),
        ("Минимальный блок (2 меры)", "malware_attack", MINIMAL, True),
        ("Одиночная мера (ограничение)", "malware_attack", SINGLE, False),
        ("Блок компрометации (4 меры)", "compromise", COMPROMISE, True),
        ("Блок ClickFix (2 меры)", "clickfix", MINIMAL, True),
        ("Блок обновления ПО", "vulnerability", VULN_UPDATE, True),
        ("Блок компенсирующих мер", "vulnerability", VULN_COMPENSATE, False),
        ("Блок «ПО не используется»", "vulnerability", VULN_SKIP, False),
    ]
    for name, type_key, content, is_default in templates:
        db.add(MeasureTemplate(
            name=name,
            threat_type_id=types.get(type_key),
            measures=content,
            is_default=is_default,
        ))


def _create_default_vuln_templates(db):
    from app.models import VulnMeasureTemplate
    templates = [
        ("Обновление ПО", "update", "Ведутся работы по обновлению программного обеспечения «{software}» до неуязвимой версии.", True),
        ("Компенсирующие меры", "compensate", "Применены компенсирующие меры для программного обеспечения «{software}».", False),
        ("ПО не используется", "skip", "Программное обеспечение «{software}» не используется.", False),
    ]
    for name, action, content, is_default in templates:
        db.add(VulnMeasureTemplate(name=name, action_type=action, content=content, is_default=is_default))


def _create_default_vuln_types(db):
    from app.models import VulnType
    types = [
        ("Уязвимость удалённого выполнения кода", "rce", "Уязвимости, позволяющие удалённо выполнить произвольный код"),
        ("Уязвимость повышения привилегий", "privilege_escalation", "Уязвимости, позволяющие повысить привилегии в системе"),
        ("Уязвимость отказа в обслуживании", "dos", "Уязвимости, приводящие к отказу в обслуживании"),
        ("Уязвимость обхода аутентификации", "auth_bypass", "Уязвимости, позволяющие обойти аутентификацию"),
        ("Уязвимость раскрытия информации", "info_disclosure", "Уязвимости, приводящие к раскрытию конфиденциальной информации"),
        ("Уязвимость межсайтового скриптинга", "xss", "XSS-уязвимости"),
        ("Уязвимость SQL-инъекции", "sqli", "SQL-инъекции"),
        ("Прочая уязвимость", "other", "Уязвимости, не попадающие в другие категории"),
    ]
    for name, key, desc in types:
        db.add(VulnType(name=name, key=key, description=desc))
