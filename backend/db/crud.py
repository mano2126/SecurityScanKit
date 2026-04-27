"""
db/crud.py
SecurityScanKit — 데이터 접근 계층 (Create/Read/Update/Delete)
모든 DB 조작은 이 파일을 통해서만 수행
"""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc, func, and_, or_

from .schema import (
    Asset, ScanJob, Finding, Alert, CVERecord,
    CVEImpact, NewsItem, UploadHistory, AlertConfig, Report
)


# ═══════════════════════════════════════════════════════════════
# 자산 (Assets)
# ═══════════════════════════════════════════════════════════════

def create_asset(db: Session, data: dict) -> Asset:
    asset = Asset(id=str(uuid.uuid4()), **data)
    db.add(asset)
    db.commit()
    db.refresh(asset)
    return asset


def get_asset(db: Session, asset_id: str) -> Optional[Asset]:
    return db.query(Asset).filter(Asset.id == asset_id).first()


def get_asset_by_ip(db: Session, ip: str) -> Optional[Asset]:
    return db.query(Asset).filter(Asset.ip == ip, Asset.is_active == True).first()


def get_all_assets(db: Session, active_only: bool = True) -> List[Asset]:
    q = db.query(Asset)
    if active_only:
        q = q.filter(Asset.is_active == True)
    return q.order_by(desc(Asset.risk_score)).all()


def update_asset(db: Session, asset_id: str, data: dict) -> Optional[Asset]:
    asset = get_asset(db, asset_id)
    if not asset:
        return None
    for k, v in data.items():
        setattr(asset, k, v)
    asset.updated_at = datetime.now()
    db.commit()
    db.refresh(asset)
    return asset


def update_asset_risk_score(db: Session, asset_id: str) -> float:
    """해당 자산의 미조치 취약점을 기반으로 위험 점수 재계산"""
    findings = db.query(Finding).filter(
        Finding.asset_id == asset_id,
        Finding.status == "open"
    ).all()

    score = 0.0
    for f in findings:
        if f.severity == "critical": score += 25
        elif f.severity == "high":   score += 10
        elif f.severity == "medium": score += 4
        elif f.severity == "low":    score += 1
        # 반복 취약점 가중치
        if f.repeat_count >= 3:      score += 10
        elif f.repeat_count >= 2:    score += 5

    score = min(100.0, score)
    update_asset(db, asset_id, {"risk_score": score})
    return score


def delete_asset(db: Session, asset_id: str) -> bool:
    asset = get_asset(db, asset_id)
    if not asset:
        return False
    asset.is_active = False
    db.commit()
    return True


def bulk_upsert_assets(db: Session, assets_data: List[dict], upload_id: int) -> int:
    """Excel 업로드 후 자산 일괄 등록/갱신"""
    count = 0
    for data in assets_data:
        ip = data.get("ip", "").strip()
        if not ip:
            continue
        existing = get_asset_by_ip(db, ip)
        if existing:
            update_asset(db, existing.id, data)
        else:
            create_asset(db, data)
        count += 1
    return count


# ═══════════════════════════════════════════════════════════════
# 점검 작업 (ScanJobs)
# ═══════════════════════════════════════════════════════════════

def create_scan_job(db: Session, asset_id: str, scan_types: str, triggered_by: str = "manual") -> ScanJob:
    job = ScanJob(
        id=str(uuid.uuid4()),
        asset_id=asset_id,
        scan_types=scan_types,
        status="queued",
        triggered_by=triggered_by
    )
    db.add(job)
    db.commit()
    db.refresh(job)
    return job


def get_scan_job(db: Session, job_id: str) -> Optional[ScanJob]:
    return db.query(ScanJob).filter(ScanJob.id == job_id).first()


def update_scan_job(db: Session, job_id: str, data: dict) -> Optional[ScanJob]:
    job = get_scan_job(db, job_id)
    if not job:
        return None
    for k, v in data.items():
        setattr(job, k, v)
    db.commit()
    db.refresh(job)
    return job


def get_recent_scan_jobs(db: Session, limit: int = 50) -> List[ScanJob]:
    return db.query(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit).all()


def get_asset_scan_history(db: Session, asset_id: str, limit: int = 10) -> List[ScanJob]:
    return db.query(ScanJob).filter(
        ScanJob.asset_id == asset_id,
        ScanJob.status == "completed"
    ).order_by(desc(ScanJob.created_at)).limit(limit).all()


# ═══════════════════════════════════════════════════════════════
# 취약점 (Findings)
# ═══════════════════════════════════════════════════════════════

def save_finding(db: Session, data: dict) -> Finding:
    """
    취약점 저장 — 동일 자산의 동일 vuln_id가 있으면 반복 카운트 증가
    핵심 로직: 반복 취약점 자동 감지
    """
    asset_id = data.get("asset_id")
    vuln_id  = data.get("vuln_id")

    # 이전 동일 취약점 검색 (가장 최근 것)
    existing = db.query(Finding).filter(
        Finding.asset_id == asset_id,
        Finding.vuln_id  == vuln_id,
        Finding.status   != "resolved"
    ).order_by(desc(Finding.last_seen)).first()

    if existing:
        # 반복 발견 — 카운트 증가, 최종 발견일 갱신
        existing.repeat_count += 1
        existing.last_seen = datetime.now()
        existing.scan_job_id = data.get("scan_job_id")
        # 심각도 변경이 있으면 업데이트
        if data.get("severity"):
            existing.severity = data["severity"]
        db.commit()
        db.refresh(existing)
        return existing
    else:
        # 신규 취약점
        finding = Finding(
            id=str(uuid.uuid4()),
            repeat_count=0,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            **data
        )
        db.add(finding)
        db.commit()
        db.refresh(finding)
        return finding


def get_findings_by_asset(db: Session, asset_id: str, status: str = None) -> List[Finding]:
    q = db.query(Finding).filter(Finding.asset_id == asset_id)
    if status:
        q = q.filter(Finding.status == status)
    return q.order_by(desc(Finding.severity), desc(Finding.cvss_score)).all()


def get_all_findings(
    db: Session,
    severity: str = None,
    status: str = None,
    scan_type: str = None,
    repeat_only: bool = False,
    limit: int = 200
) -> List[Finding]:
    q = db.query(Finding)
    if severity:    q = q.filter(Finding.severity == severity)
    if status:      q = q.filter(Finding.status == status)
    if scan_type:   q = q.filter(Finding.scan_type == scan_type)
    if repeat_only: q = q.filter(Finding.repeat_count >= 1)
    return q.order_by(
        desc(Finding.severity),
        desc(Finding.repeat_count),
        desc(Finding.cvss_score)
    ).limit(limit).all()


def get_repeat_findings(db: Session, threshold: int = 2) -> List[Finding]:
    """반복 취약점 (threshold회 이상 발견된 미조치 취약점)"""
    return db.query(Finding).filter(
        Finding.repeat_count >= threshold,
        Finding.status != "resolved"
    ).order_by(desc(Finding.repeat_count), desc(Finding.severity)).all()


def resolve_finding(db: Session, finding_id: str, resolved_by: str, note: str = "") -> Optional[Finding]:
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        return None
    finding.status = "resolved"
    finding.resolved_at = datetime.now()
    finding.resolved_by = resolved_by
    finding.resolution_note = note
    db.commit()
    db.refresh(finding)
    # 자산 위험 점수 재계산
    update_asset_risk_score(db, finding.asset_id)
    return finding


def get_finding_stats(db: Session) -> dict:
    """대시보드용 취약점 통계"""
    from sqlalchemy import func
    open_f   = db.query(Finding).filter(Finding.status != "resolved")
    total_all= db.query(Finding).count()
    total_res= db.query(Finding).filter(Finding.status == "resolved").count()
    resolved_pct = round(total_res / total_all * 100) if total_all > 0 else 0
    return {
        "total":        open_f.count(),
        "critical":     db.query(Finding).filter(Finding.severity=="critical", Finding.status!="resolved").count(),
        "high":         db.query(Finding).filter(Finding.severity=="high",     Finding.status!="resolved").count(),
        "medium":       db.query(Finding).filter(Finding.severity=="medium",   Finding.status!="resolved").count(),
        "low":          db.query(Finding).filter(Finding.severity=="low",      Finding.status!="resolved").count(),
        "repeat":       db.query(Finding).filter(Finding.repeat_count>=1,      Finding.status!="resolved").count(),
        "total_assets": db.query(Asset).filter(Asset.is_active==True).count(),
        "resolved_pct": resolved_pct,
        "total_all":    total_all,
        "resolved":     total_res,
    }


# ═══════════════════════════════════════════════════════════════
# 알람 (Alerts)
# ═══════════════════════════════════════════════════════════════

def create_alert(db: Session, alert_type: str, severity: str, title: str,
                 message: str, asset_id: str = None, finding_id: str = None, cve_id: str = None) -> Alert:
    alert = Alert(
        id=str(uuid.uuid4()),
        alert_type=alert_type,
        severity=severity,
        title=title,
        message=message,
        asset_id=asset_id,
        finding_id=finding_id,
        cve_id=cve_id
    )
    db.add(alert)
    db.commit()
    db.refresh(alert)
    return alert


def get_alerts(db: Session, unread_only: bool = False, limit: int = 100) -> List[Alert]:
    q = db.query(Alert)
    if unread_only:
        q = q.filter(Alert.is_read == False)
    return q.order_by(desc(Alert.created_at)).limit(limit).all()


def mark_alerts_read(db: Session, alert_ids: List[str]) -> int:
    count = db.query(Alert).filter(Alert.id.in_(alert_ids)).update(
        {"is_read": True}, synchronize_session=False
    )
    db.commit()
    return count


def get_unread_alert_count(db: Session) -> int:
    return db.query(Alert).filter(Alert.is_read == False).count()


# ═══════════════════════════════════════════════════════════════
# CVE
# ═══════════════════════════════════════════════════════════════

def upsert_cve(db: Session, data: dict) -> CVERecord:
    cve_id = data.get("id")
    existing = db.query(CVERecord).filter(CVERecord.id == cve_id).first()
    if existing:
        for k, v in data.items():
            if k != "id":
                setattr(existing, k, v)
        existing.updated_at = datetime.now()
        db.commit()
        db.refresh(existing)
        return existing
    else:
        cve = CVERecord(**data)
        db.add(cve)
        db.commit()
        db.refresh(cve)
        return cve


def get_cve(db: Session, cve_id: str) -> Optional[CVERecord]:
    return db.query(CVERecord).filter(CVERecord.id == cve_id).first()


def get_recent_cves(db: Session, days: int = 30, limit: int = 50) -> List[CVERecord]:
    cutoff = datetime.now() - timedelta(days=days)
    return db.query(CVERecord).filter(
        CVERecord.published_date >= cutoff
    ).order_by(desc(CVERecord.cvss_score)).limit(limit).all()


def get_cves_affecting_assets(db: Session) -> List[CVERecord]:
    """영향 자산이 있는 CVE만 반환"""
    return db.query(CVERecord).join(CVEImpact).filter(
        CVEImpact.status == "open"
    ).order_by(desc(CVERecord.cvss_score)).all()


def save_cve_impact(db: Session, cve_id: str, asset_id: str) -> CVEImpact:
    existing = db.query(CVEImpact).filter(
        CVEImpact.cve_id == cve_id,
        CVEImpact.asset_id == asset_id
    ).first()
    if existing:
        return existing
    impact = CVEImpact(cve_id=cve_id, asset_id=asset_id)
    db.add(impact)
    db.commit()
    db.refresh(impact)
    return impact


# ═══════════════════════════════════════════════════════════════
# 뉴스
# ═══════════════════════════════════════════════════════════════

def save_news(db: Session, data: dict) -> NewsItem:
    # URL 중복 방지
    url = data.get("url", "")
    if url:
        existing = db.query(NewsItem).filter(NewsItem.url == url).first()
        if existing:
            return existing
    news = NewsItem(**data)
    db.add(news)
    db.commit()
    db.refresh(news)
    return news


def get_news(db: Session, source: str = None, limit: int = 50) -> List[NewsItem]:
    q = db.query(NewsItem)
    if source:
        q = q.filter(NewsItem.source == source)
    return q.order_by(desc(NewsItem.published_at)).limit(limit).all()


# ═══════════════════════════════════════════════════════════════
# 업로드 이력
# ═══════════════════════════════════════════════════════════════

def save_upload_history(db: Session, filename: str, uploaded_by: str,
                        asset_count: int, file_hash: str = "") -> UploadHistory:
    # 이전 활성 기록을 아카이브로 변경
    db.query(UploadHistory).filter(UploadHistory.status == "active").update(
        {"status": "archive"}, synchronize_session=False
    )
    # 최신 버전 번호 계산
    latest = db.query(UploadHistory).order_by(desc(UploadHistory.version)).first()
    version = (latest.version + 1) if latest else 1

    upload = UploadHistory(
        filename=filename,
        uploaded_by=uploaded_by,
        asset_count=asset_count,
        version=version,
        file_hash=file_hash,
        status="active"
    )
    db.add(upload)
    db.commit()
    db.refresh(upload)
    return upload


def get_upload_history(db: Session, limit: int = 20) -> List[UploadHistory]:
    return db.query(UploadHistory).order_by(desc(UploadHistory.created_at)).limit(limit).all()


# ═══════════════════════════════════════════════════════════════
# 알람 설정
# ═══════════════════════════════════════════════════════════════

def get_alert_configs(db: Session) -> List[AlertConfig]:
    return db.query(AlertConfig).all()


def update_alert_config(db: Session, alert_type: str, data: dict) -> Optional[AlertConfig]:
    cfg = db.query(AlertConfig).filter(AlertConfig.alert_type == alert_type).first()
    if not cfg:
        return None
    for k, v in data.items():
        setattr(cfg, k, v)
    cfg.updated_at = datetime.now()
    db.commit()
    db.refresh(cfg)
    return cfg


# ═══════════════════════════════════════════════════════════════
# 대시보드 종합 통계
# ═══════════════════════════════════════════════════════════════

def get_dashboard_stats(db: Session) -> dict:
    """대시보드에 필요한 모든 통계를 한번에 조회"""
    stats = get_finding_stats(db)

    # 위험도별 자산 수
    assets = get_all_assets(db)
    risk_dist = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for a in assets:
        if a.risk_score >= 70:   risk_dist["critical"] += 1
        elif a.risk_score >= 50: risk_dist["high"] += 1
        elif a.risk_score >= 30: risk_dist["medium"] += 1
        else:                    risk_dist["low"] += 1

    # 평균 위험 점수
    avg_risk = sum(a.risk_score for a in assets) / len(assets) if assets else 0

    # 최근 7일 신규 취약점
    week_ago = datetime.now() - timedelta(days=7)
    new_this_week = db.query(Finding).filter(
        Finding.first_seen >= week_ago
    ).count()

    # 미읽은 알람
    unread_alerts = get_unread_alert_count(db)

    # 영향받는 CVE
    affected_cves = db.query(CVEImpact).filter(CVEImpact.status == "open").count()

    # 컴플라이언스 점수 (취약점 기반 간이 계산)
    total_open = stats["total"]
    compliance_score = max(0, 100 - (total_open * 2))

    return {
        **stats,
        "risk_distribution":  risk_dist,
        "avg_risk_score":     round(avg_risk, 1),
        "new_this_week":      new_this_week,
        "unread_alerts":      unread_alerts,
        "affected_cves":      affected_cves,
        "compliance_score":   compliance_score,
    }
