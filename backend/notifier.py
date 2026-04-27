"""
보안 조치 통보 모듈
담당자별 맞춤 취약점 보고서 PDF 생성 후 Exchange/SMTP로 발송
"""
import smtplib, uuid, json, asyncio
from remediation_guide import build_remediation_html, get_guide
from email.mime.multipart import MIMEMultipart
from email.mime.text      import MIMEText
from email.mime.base      import MIMEBase
from email               import encoders
from datetime            import datetime, timedelta
from pathlib             import Path
from typing              import List, Dict


# ── 담당자별 맞춤 PDF 생성 ──────────────────────────────────────
async def build_manager_pdf(manager: str, findings: list, assets: list, job_id: str) -> str:
    """담당자 전용 취약점 보고서 PDF 생성"""
    import sys; sys.path.insert(0, str(Path(__file__).parent))
    from reporter.pdf_report import _build

    data = {
        "generated_at": datetime.now().isoformat(),
        "report_type":  "technical",
        "manager_name": manager,
        "stats": {
            "critical":     sum(1 for f in findings if f.get("severity")=="critical"),
            "high":         sum(1 for f in findings if f.get("severity")=="high"),
            "medium":       sum(1 for f in findings if f.get("severity")=="medium"),
            "low":          sum(1 for f in findings if f.get("severity")=="low"),
            "repeat":       sum(1 for f in findings if (f.get("repeat_count") or 0)>0),
            "resolved_pct": 0,
            "total_all":    len(findings),
            "resolved":     0,
        },
        "findings": findings,
        "assets":   assets,
    }
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _build, job_id, data)


# ── HTML 이메일 본문 생성 ────────────────────────────────────────
def build_html_body(manager: str, department: str, findings: list, due_days: int = 7) -> str:
    due_date = (datetime.now() + timedelta(days=due_days)).strftime("%Y년 %m월 %d일")
    crit = [f for f in findings if f.get("severity")=="critical"]
    high = [f for f in findings if f.get("severity")=="high"]
    med  = [f for f in findings if f.get("severity")=="medium"]

    SEV_COLOR = {"critical":"#B71C1C","high":"#E65100","medium":"#F57F17","low":"#2E7D32"}
    SEV_LABEL = {"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험"}

    rows = ""
    for i, f in enumerate(findings[:20]):
        sev   = f.get("severity","info")
        color = SEV_COLOR.get(sev,"#546E7A")
        label = SEV_LABEL.get(sev, sev)
        bg    = "#FFF5F5" if sev=="critical" else "#FFF8F0" if sev=="high" else "#FFFDE7" if sev=="medium" else "#F1F8E9"
        rows += f"""
        <tr style="background:{bg}">
          <td style="padding:8px 10px;border-bottom:1px solid #E0E0E0;font-size:12px;font-weight:600;color:{color}">{label}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #E0E0E0;font-size:12px;color:#212121">{f.get("title","")}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #E0E0E0;font-size:11px;color:#546E7A">{f.get("asset_name","")}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #E0E0E0;font-size:11px;color:#546E7A">{f.get("asset_ip","")}</td>
          <td style="padding:8px 10px;border-bottom:1px solid #E0E0E0;font-size:11px;color:#1565C0">{f.get("recommendation","")[:60]}</td>
        </tr>"""

    # 상세 조치 가이드 (모든 긴급+고위험 취약점)
    remediation_steps = ""
    for f in (crit + high):
        remediation_steps += build_remediation_html(f)

    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;font-family:'맑은 고딕',Arial,sans-serif;background:#F5F5F5">
<div style="max-width:700px;margin:0 auto;padding:20px">

  <!-- 헤더 -->
  <div style="background:linear-gradient(135deg,#0D1B2A 0%,#1565C0 100%);padding:28px 32px;border-radius:8px 8px 0 0">
    <div style="display:flex;align-items:center;gap:14px">
      <div style="width:44px;height:44px;background:rgba(255,255,255,.15);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:24px">🛡</div>
      <div>
        <div style="color:#fff;font-size:18px;font-weight:700">보안 취약점 조치 요청</div>
        <div style="color:rgba(255,255,255,.7);font-size:12px;margin-top:2px">SecurityScanKit Enterprise | 자동 발송</div>
      </div>
    </div>
  </div>

  <!-- 본문 -->
  <div style="background:#fff;padding:28px 32px;border:1px solid #E0E0E0;border-top:none">

    <!-- 인사말 -->
    <p style="font-size:14px;color:#212121;margin:0 0 16px">
      <strong>{department} {manager} 담당자님</strong>,<br><br>
      보안 점검 결과 담당자님 소관 시스템에서 아래와 같이 보안 취약점이 발견되었습니다.<br>
      <strong style="color:#B71C1C">조치 기한: {due_date}</strong>까지 조치 완료 후 시스템에 결과를 등록해 주시기 바랍니다.
    </p>

    <!-- KPI -->
    <div style="display:flex;gap:10px;margin-bottom:20px">
      {"".join(f'<div style="flex:1;padding:12px;background:{bg};border-radius:6px;text-align:center"><div style="font-size:10px;color:{c};font-weight:700;text-transform:uppercase">{l}</div><div style="font-size:24px;font-weight:700;color:{c}">{cnt}</div></div>'
        for l,c,bg,cnt in [
          ("긴급","#B71C1C","#FFEBEE",len(crit)),
          ("고위험","#E65100","#FFF3E0",len(high)),
          ("중위험","#F57F17","#FFFDE7",len(med)),
          ("전체","#1565C0","#E3F2FD",len(findings)),
        ])}
    </div>

    <!-- 취약점 목록 -->
    <div style="font-size:13px;font-weight:700;color:#0D1B2A;margin-bottom:10px">📋 발견 취약점 목록</div>
    <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:12px">
      <thead>
        <tr style="background:#0D1B2A;color:#fff">
          <th style="padding:8px 10px;text-align:left;width:60px">심각도</th>
          <th style="padding:8px 10px;text-align:left">취약점명</th>
          <th style="padding:8px 10px;text-align:left;width:100px">자산명</th>
          <th style="padding:8px 10px;text-align:left;width:110px">IP</th>
          <th style="padding:8px 10px;text-align:left">조치 방법 요약</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>

    <!-- 상세 조치 가이드 -->
    {"<div style='font-size:13px;font-weight:700;color:#0D1B2A;margin-bottom:12px'>🔧 긴급/고위험 상세 조치 가이드</div>" + remediation_steps if (crit or high) else ""}

    <!-- 안내 -->
    <div style="background:#E3F2FD;border:1px solid #BBDEFB;border-radius:6px;padding:14px 16px;font-size:12px;color:#1565C0">
      <strong>📌 조치 완료 후 처리 방법</strong><br>
      SecurityScanKit 시스템 접속 → 점검 이력 → 해당 취약점 선택 → <strong>조치 완료 체크</strong>
    </div>
  </div>

  <!-- 푸터 -->
  <div style="background:#F5F5F5;padding:14px 32px;text-align:center;font-size:11px;color:#9E9E9E;border:1px solid #E0E0E0;border-top:none;border-radius:0 0 8px 8px">
    본 메일은 SecurityScanKit Enterprise에 의해 자동 발송되었습니다. | 문의: IT보안팀
  </div>
</div>
</body></html>"""


# ── SMTP 발송 ────────────────────────────────────────────────────
async def send_notification(
    smtp_host: str, smtp_port: int,
    smtp_user: str, smtp_pass: str,
    from_addr: str,
    to_email:  str,
    subject:   str,
    html_body: str,
    pdf_path:  str = None,
    use_tls:   bool = True,
) -> dict:
    """Exchange/SMTP로 이메일 발송"""
    def _send():
        msg = MIMEMultipart("mixed")
        msg["Subject"] = subject
        msg["From"]    = from_addr
        msg["To"]      = to_email

        # HTML 본문
        alt = MIMEMultipart("alternative")
        alt.attach(MIMEText("본 메일은 HTML 형식입니다.", "plain", "utf-8"))
        alt.attach(MIMEText(html_body, "html", "utf-8"))
        msg.attach(alt)

        # PDF 첨부
        if pdf_path and Path(pdf_path).exists():
            with open(pdf_path, "rb") as f:
                part = MIMEBase("application", "pdf")
                part.set_payload(f.read())
                encoders.encode_base64(part)
                fname = Path(pdf_path).name
                part.add_header("Content-Disposition", f'attachment; filename="{fname}"')
                msg.attach(part)

        try:
            if use_tls:
                with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as s:
                    s.ehlo(); s.starttls(); s.ehlo()
                    if smtp_user: s.login(smtp_user, smtp_pass)
                    s.sendmail(from_addr, [to_email], msg.as_bytes())
            else:
                with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15) as s:
                    if smtp_user: s.login(smtp_user, smtp_pass)
                    s.sendmail(from_addr, [to_email], msg.as_bytes())
            return {"ok": True}
        except Exception as e:
            return {"ok": False, "error": str(e)}

    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, _send)
