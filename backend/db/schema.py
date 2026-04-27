"""
db/schema.py
SecurityScanKit — 전체 DB 스키마 정의
SQLAlchemy ORM + SQLite (운영 시 PostgreSQL로 교체 가능)
"""

from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Text,
    DateTime, Boolean, ForeignKey, JSON, Index
)
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from sqlalchemy.sql import func
from datetime import datetime
import os
from pathlib import Path

BASE_DIR = Path(__file__).parent.parent.parent  # SecurityScanKit_v1.0/
DB_PATH  = BASE_DIR / "data" / "ssk.db"
DB_PATH.parent.mkdir(parents=True, exist_ok=True)

DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
    echo=False
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# ─────────────────────────────────────────────────────────────────
# 1. 자산 (Assets)
# ─────────────────────────────────────────────────────────────────
class Asset(Base):
    __tablename__ = "assets"

    id          = Column(String(36), primary_key=True)       # UUID
    name        = Column(String(200), nullable=False)        # 시스템 명칭
    ip          = Column(String(45),  nullable=False)        # IPv4/IPv6
    asset_type  = Column(String(50))                         # 웹서버/DB서버 등
    environment = Column(String(50))                         # Production/Dev 등
    os_type     = Column(String(100))                        # Windows/Linux 등
    department  = Column(String(100))                        # 담당부서
    manager     = Column(String(100))                        # 담당자
    priority    = Column(String(20), default="medium")       # critical/high/medium/low
    scan_types  = Column(String(200), default="port,web,ssl")# 점검유형 (콤마구분)
    http_port   = Column(Integer, default=80)
    https_port  = Column(Integer, default=443)
    db_type     = Column(String(50))                         # mysql/oracle 등
    db_port     = Column(Integer)
    is_active   = Column(Boolean, default=True)
    note        = Column(Text, default="")
    risk_score  = Column(Float, default=0.0)                 # 0-100
    last_scan   = Column(DateTime)
    created_at  = Column(DateTime, default=func.now())
    updated_at  = Column(DateTime, default=func.now(), onupdate=func.now())

    # Relations
    scan_jobs   = relationship("ScanJob",       back_populates="asset", cascade="all, delete-orphan")
    findings    = relationship("Finding",       back_populates="asset", cascade="all, delete-orphan")
    cve_impacts = relationship("CVEImpact",     back_populates="asset", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_assets_ip", "ip"),
        Index("ix_assets_priority", "priority"),
    )


# ─────────────────────────────────────────────────────────────────
# 2. 점검 작업 (ScanJobs)
# ─────────────────────────────────────────────────────────────────
class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id           = Column(String(36), primary_key=True)
    asset_id     = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"))
    scan_types   = Column(String(200))                        # 점검유형
    status       = Column(String(20), default="queued")       # queued/running/completed/failed
    progress     = Column(Integer, default=0)                 # 0-100
    current_step = Column(String(100), default="")
    started_at   = Column(DateTime)
    completed_at = Column(DateTime)
    duration_sec = Column(Float)
    error_msg    = Column(Text, default="")
    triggered_by = Column(String(100), default="manual")      # manual/schedule/api
    created_at   = Column(DateTime, default=func.now())

    # 결과 요약
    crit_count   = Column(Integer, default=0)
    high_count   = Column(Integer, default=0)
    med_count    = Column(Integer, default=0)
    low_count    = Column(Integer, default=0)
    info_count   = Column(Integer, default=0)

    asset    = relationship("Asset",    back_populates="scan_jobs")
    findings = relationship("Finding",  back_populates="scan_job", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_scan_jobs_status",     "status"),
        Index("ix_scan_jobs_asset_id",   "asset_id"),
        Index("ix_scan_jobs_created_at", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────
# 3. 취약점 (Findings)
# ─────────────────────────────────────────────────────────────────
class Finding(Base):
    __tablename__ = "findings"

    id              = Column(String(36), primary_key=True)
    asset_id        = Column(String(36), ForeignKey("assets.id", ondelete="CASCADE"))
    scan_job_id     = Column(String(36), ForeignKey("scan_jobs.id", ondelete="CASCADE"))

    vuln_id         = Column(String(100))                    # PORT-00023, SSL-CERT-EXP 등
    title           = Column(String(500))
    description     = Column(Text)
    recommendation  = Column(Text)
    severity        = Column(String(20))                     # critical/high/medium/low/info
    cvss_score      = Column(Float)
    scan_type       = Column(String(50))                     # port/web/ssl/db/network
    port            = Column(Integer)
    protocol        = Column(String(10))
    service         = Column(String(100))

    status          = Column(String(20), default="open")     # open/in_progress/resolved/accepted
    resolution_note = Column(Text, default="")
    resolved_at     = Column(DateTime)
    resolved_by     = Column(String(100))

    # 반복 추적
    repeat_count    = Column(Integer, default=0)             # 같은 취약점 반복 발견 횟수
    first_seen      = Column(DateTime, default=func.now())
    last_seen       = Column(DateTime, default=func.now())

    # 규정 연관
    regulation      = Column(String(500))
    reference       = Column(String(500))

    # AI 분석
    ai_analysis     = Column(Text)
    ai_priority     = Column(Integer)

    raw_output      = Column(Text)
    created_at      = Column(DateTime, default=func.now())

    asset    = relationship("Asset",   back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings")

    __table_args__ = (
        Index("ix_findings_asset_id",  "asset_id"),
        Index("ix_findings_severity",  "severity"),
        Index("ix_findings_status",    "status"),
        Index("ix_findings_vuln_id",   "vuln_id"),
        Index("ix_findings_scan_type", "scan_type"),
    )


# ─────────────────────────────────────────────────────────────────
# 4. 알람 (Alerts)
# ─────────────────────────────────────────────────────────────────
class Alert(Base):
    __tablename__ = "alerts"

    id          = Column(String(36), primary_key=True)
    alert_type  = Column(String(50))           # repeat_vuln/ssl_expiry/cve_match/scan_fail
    severity    = Column(String(20))
    title       = Column(String(500))
    message     = Column(Text)
    asset_id    = Column(String(36), ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    finding_id  = Column(String(36), nullable=True)
    cve_id      = Column(String(50),  nullable=True)
    is_read     = Column(Boolean, default=False)
    is_sent     = Column(Boolean, default=False)   # 이메일 발송 여부
    created_at  = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_alerts_is_read",   "is_read"),
        Index("ix_alerts_severity",  "severity"),
        Index("ix_alerts_created_at","created_at"),
    )


# ─────────────────────────────────────────────────────────────────
# 5. CVE (CVERecords)
# ─────────────────────────────────────────────────────────────────
class CVERecord(Base):
    __tablename__ = "cve_records"

    id             = Column(String(50), primary_key=True)   # CVE-2026-1337
    cvss_score     = Column(Float)
    cvss_vector    = Column(String(200))
    severity       = Column(String(20))
    description    = Column(Text)
    description_ko = Column(Text)
    affected_products = Column(Text)                         # JSON 직렬화
    patch_info     = Column(Text)
    references     = Column(Text)
    published_date = Column(DateTime)
    modified_date  = Column(DateTime)
    is_kev         = Column(Boolean, default=False)          # CISA KEV 등재 여부
    kev_added_date = Column(DateTime)
    created_at     = Column(DateTime, default=func.now())
    updated_at     = Column(DateTime, default=func.now(), onupdate=func.now())

    impacts = relationship("CVEImpact", back_populates="cve", cascade="all, delete-orphan")

    __table_args__ = (
        Index("ix_cve_severity",   "severity"),
        Index("ix_cve_published",  "published_date"),
        Index("ix_cve_is_kev",     "is_kev"),
    )


# ─────────────────────────────────────────────────────────────────
# 6. CVE 영향 자산 매핑 (CVEImpact)
# ─────────────────────────────────────────────────────────────────
class CVEImpact(Base):
    __tablename__ = "cve_impacts"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    cve_id     = Column(String(50), ForeignKey("cve_records.id", ondelete="CASCADE"))
    asset_id   = Column(String(36), ForeignKey("assets.id",      ondelete="CASCADE"))
    status     = Column(String(20), default="open")   # open/patched/accepted
    patched_at = Column(DateTime)
    created_at = Column(DateTime, default=func.now())

    cve   = relationship("CVERecord", back_populates="impacts")
    asset = relationship("Asset",     back_populates="cve_impacts")

    __table_args__ = (
        Index("ix_cve_impacts_cve_id",   "cve_id"),
        Index("ix_cve_impacts_asset_id", "asset_id"),
    )


# ─────────────────────────────────────────────────────────────────
# 7. 보안 뉴스 (NewsItems)
# ─────────────────────────────────────────────────────────────────
class NewsItem(Base):
    __tablename__ = "news_items"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    source       = Column(String(50))                # KrCERT/KISA/CISA/NVD 등
    source_tag   = Column(String(50))                # CRITICAL/ADVISORY 등
    title        = Column(String(1000))
    title_ko     = Column(String(1000))
    summary      = Column(Text)
    url          = Column(String(2000))
    severity     = Column(String(20), default="info")
    published_at = Column(DateTime)
    is_read      = Column(Boolean, default=False)
    affects_assets = Column(Boolean, default=False)
    created_at   = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_news_source",       "source"),
        Index("ix_news_published_at", "published_at"),
        Index("ix_news_severity",     "severity"),
    )


# ─────────────────────────────────────────────────────────────────
# 8. 업로드 이력 (UploadHistory)
# ─────────────────────────────────────────────────────────────────
class UploadHistory(Base):
    __tablename__ = "upload_history"

    id           = Column(Integer, primary_key=True, autoincrement=True)
    filename     = Column(String(500))
    uploaded_by  = Column(String(100))
    asset_count  = Column(Integer, default=0)
    version      = Column(Integer, default=1)
    status       = Column(String(20), default="active")   # active/archive
    file_hash    = Column(String(64))
    notes        = Column(Text, default="")
    created_at   = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_upload_history_created_at", "created_at"),
    )


# ─────────────────────────────────────────────────────────────────
# 9. 알람 설정 (AlertConfig)
# ─────────────────────────────────────────────────────────────────
class AlertConfig(Base):
    __tablename__ = "alert_configs"

    id               = Column(Integer, primary_key=True, autoincrement=True)
    alert_type       = Column(String(50), unique=True)
    label            = Column(String(200))
    condition        = Column(String(500))
    channels         = Column(String(200))         # email,sms,dashboard
    is_active        = Column(Boolean, default=True)
    threshold_value  = Column(Integer, default=1)  # 반복 임계값 등
    updated_at       = Column(DateTime, default=func.now(), onupdate=func.now())


# ─────────────────────────────────────────────────────────────────
# 10. 보고서 (Reports)
# ─────────────────────────────────────────────────────────────────
class Report(Base):
    __tablename__ = "reports"

    id           = Column(String(36), primary_key=True)
    report_type  = Column(String(50))              # executive/technical/excel/compliance
    title        = Column(String(500))
    file_path    = Column(String(1000))
    file_size    = Column(Integer)
    scan_job_ids = Column(Text)                    # JSON 배열
    generated_by = Column(String(100), default="system")
    created_at   = Column(DateTime, default=func.now())



# ── 조직 구조 (본부/부서) ─────────────────────────────────────
class Division(Base):
    """본부"""
    __tablename__ = "divisions"
    id   = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), unique=True, nullable=False)
    sort_order = Column(Integer, default=0)

class Department(Base):
    """부서"""
    __tablename__ = "departments"
    id            = Column(Integer, primary_key=True, autoincrement=True)
    name          = Column(String(100), unique=True, nullable=False)
    division_name = Column(String(100), default="")
    sort_order    = Column(Integer, default=0)


# ─────────────────────────────────────────────────────────────────

class SystemUser(Base):
    """시스템 사용자 — 로그인/출입 관리"""
    __tablename__ = "system_users"

    id         = Column(Integer, primary_key=True, autoincrement=True)
    name       = Column(String(100), nullable=False, unique=True)
    division   = Column(String(100), default="")   # 본부
    dept       = Column(String(100), default="")   # 부서
    role       = Column(String(50),  default="user")
    email      = Column(String(200), default="")
    phone      = Column(String(50),  default="")
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())

    __table_args__ = (
        Index("ix_sysuser_name", "name"),
    )

# DB 초기화 함수
# ─────────────────────────────────────────────────────────────────
def init_db():
    """테이블 생성 + 기본 데이터 삽입"""
    Base.metadata.create_all(bind=engine)
    _seed_default_data()
    print(f"[DB] 초기화 완료: {DB_PATH}")


def get_db():
    """FastAPI Dependency Injection용"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _seed_default_data():
    """기본 알람 설정 삽입 (없을 경우)"""
    db = SessionLocal()
    try:
        if db.query(AlertConfig).count() == 0:
            defaults = [
                AlertConfig(alert_type="critical_found",   label="긴급 취약점 발견",    condition="severity=critical",      channels="email,dashboard", is_active=True,  threshold_value=1),
                AlertConfig(alert_type="repeat_vuln",      label="반복 취약점 경고",    condition="repeat_count>=2",        channels="email,dashboard", is_active=True,  threshold_value=2),
                AlertConfig(alert_type="ssl_expiry",       label="SSL 인증서 만료 임박", condition="days_remaining<=30",     channels="email,dashboard", is_active=True,  threshold_value=30),
                AlertConfig(alert_type="cve_match",        label="CVE 영향 자산 탐지",  condition="cvss>=7.0 AND matched",  channels="dashboard",       is_active=True,  threshold_value=1),
                AlertConfig(alert_type="unscanned_asset",  label="미점검 자산",         condition="last_scan_days>=30",     channels="email",           is_active=False, threshold_value=30),
            ]
            db.add_all(defaults)
            db.commit()

        # ── 본부 초기 데이터
        if db.query(Division).count() == 0:
            divs = [
                "AI Biz TF", "Auto본부", "ContactCenter", "Corporate본부",
                "Global사업", "IT본부", "Lease본부", "Medical리스",
                "RM본부", "Retail본부", "Risk관리", "경영전략본부",
                "경영지원본부", "신용관리본부",
            ]
            db.add_all([Division(name=d, sort_order=i) for i, d in enumerate(divs)])
            db.commit()

        # ── 부서 초기 데이터
        if db.query(Department).count() == 0:
            dept_data = [
                ("AI Biz TF팀","AI Biz TF"), ("Auto대구센타","Auto본부"), ("Auto본부","Auto본부"),
                ("Auto부산센타","Auto본부"), ("ContactCenter","ContactCenter"),
                ("Corporate기획팀","Corporate본부"), ("Corporate본부","Corporate본부"),
                ("Corporate영업1팀","Corporate본부"), ("Corporate영업2팀","Corporate본부"),
                ("Corporate영업3팀","Corporate본부"), ("Corporate영업4팀","Corporate본부"),
                ("Global사업팀","Global사업"), ("IR전략TF팀","경영전략본부"),
                ("IT감리팀","IT본부"), ("IT개발1팀","IT본부"), ("IT개발2팀","IT본부"),
                ("IT개발3팀","IT본부"), ("IT개발4팀","IT본부"), ("IT본부","IT본부"),
                ("IT시스템기획팀","IT본부"), ("IT채널개발팀","IT본부"),
                ("Lease본부","Lease본부"), ("Medical리스팀","Medical리스"),
                ("RM본부","RM본부"), ("Retail Direct영업팀","Retail본부"),
                ("Retail기획팀","Retail본부"), ("Retail본부","Retail본부"),
                ("Retail상품개발팀","Retail본부"), ("Retail심사팀","Retail본부"),
                ("Retail영업지원팀","Retail본부"), ("Retail영업팀","Retail본부"),
                ("Risk관리팀","Risk관리"), ("Vendor리스팀","Lease본부"),
                ("가치창조팀","경영전략본부"), ("경영전략본부","경영전략본부"),
                ("경영지원본부","경영지원본부"), ("경영혁신팀","경영전략본부"),
                ("고객관리팀","ContactCenter"), ("공공리스팀","Lease본부"),
                ("금융소비자보호 담당임원","경영지원본부"), ("대구컬렉션센타","신용관리본부"),
                ("대전컬렉션센타","신용관리본부"), ("동대문론센타","Retail본부"),
                ("디지털채널팀","IT본부"), ("리스운영팀","Lease본부"),
                ("리스크관리팀","Risk관리"), ("부산론센타","Retail본부"),
                ("부산영업팀","Retail본부"), ("부산컬렉션센타","신용관리본부"),
                ("산업리스팀","Lease본부"), ("상계론센타","Retail본부"),
                ("서울컬렉션센타","신용관리본부"), ("소비자보호팀","경영지원본부"),
                ("수원론센타","Retail본부"), ("신용관리본부","신용관리본부"),
                ("신용분석1팀","신용관리본부"), ("신용분석2팀","신용관리본부"),
                ("심사팀","신용관리본부"), ("안전관리팀","경영지원본부"),
                ("오토기획팀","Auto본부"), ("오토심사팀","Auto본부"),
                ("오토영업1팀","Auto본부"), ("오토영업2팀","Auto본부"),
                ("오토지원팀","Auto본부"), ("윤리경영팀","경영지원본부"),
                ("인사팀","경영지원본부"), ("임원실(관리)","경영지원본부"),
                ("임원실(사외이사)","경영지원본부"), ("자금팀","경영지원본부"),
                ("자산관리팀","경영전략본부"), ("자산운영팀","경영전략본부"),
                ("전략기획팀","경영전략본부"), ("정보보호팀","IT본부"),
                ("준법감시인","경영지원본부"), ("준법경영팀","경영지원본부"),
                ("채널영업팀","Corporate본부"), ("총무팀","경영지원본부"),
                ("컬렉션관리팀","신용관리본부"), ("컬렉션기획팀","신용관리본부"),
                ("컬렉션분석TF팀","신용관리본부"), ("컬렉션운영1팀","신용관리본부"),
                ("컬렉션운영2팀","신용관리본부"), ("회계팀","경영지원본부"),
            ]
            db.add_all([Department(name=d, division_name=div, sort_order=i)
                        for i, (d, div) in enumerate(dept_data)])
            db.commit()
    finally:
        db.close()


if __name__ == "__main__":
    init_db()
    print("테이블 목록:")
    for t in Base.metadata.tables:
        print(f"  - {t}")


# ─────────────────────────────────────────────────────────────────
# 보안 조치 통보 (Notifications)
# ─────────────────────────────────────────────────────────────────
class Notification(Base):
    __tablename__ = "notifications"

    id              = Column(String(36), primary_key=True)
    # 발송 정보
    manager         = Column(String(100), nullable=False)    # 담당자 이름
    manager_email   = Column(String(200), nullable=False)    # 수신 이메일
    department      = Column(String(100))                    # 담당 부서
    subject         = Column(String(500))                    # 메일 제목
    report_path     = Column(String(500))                    # 첨부 PDF 경로
    asset_ids       = Column(Text)                           # 대상 자산 ID (JSON)
    finding_ids     = Column(Text)                           # 대상 취약점 ID (JSON)
    finding_count   = Column(Integer, default=0)             # 취약점 건수
    critical_count  = Column(Integer, default=0)             # 긴급 건수
    # 발송 상태
    status          = Column(String(20), default="pending")  # pending/sent/failed
    sent_at         = Column(DateTime)
    error_msg       = Column(Text)
    sent_by         = Column(String(100))                    # 발송자
    # 조치 추적
    action_status   = Column(String(20), default="notified") # notified/in_progress/completed/overdue
    action_due_date = Column(DateTime)                       # 조치 기한
    action_note     = Column(Text, default="")               # 조치 내용 메모
    action_completed_at = Column(DateTime)
    action_completed_by = Column(String(100))

    created_at      = Column(DateTime, default=func.now())

    __table_args__ = (
        Index("ix_notif_manager",      "manager"),
        Index("ix_notif_status",       "status"),
        Index("ix_notif_action_status","action_status"),
    )

