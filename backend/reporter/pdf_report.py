"""
PDF 리포트 생성기 — 금융권 엔터프라이즈급 보안점검 결과 보고서
한글 완전 지원 (wordWrap=CJK + NanumGothic)
"""
import os, asyncio
from datetime import datetime
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent.parent / "reports"

def _get_fonts():
    """한글 폰트 경로 반환 — 배포폰트 > Windows > Linux 순"""
    here = Path(__file__).parent
    candidates = [
        (here / "NanumGothic.ttf",     here / "NanumGothicBold.ttf"),
        (Path("C:/Windows/Fonts/malgun.ttf"),      Path("C:/Windows/Fonts/malgunbd.ttf")),
        (Path("C:/Windows/Fonts/NanumGothic.ttf"), Path("C:/Windows/Fonts/NanumGothicBold.ttf")),
        (Path("/usr/share/fonts/truetype/nanum/NanumGothic.ttf"),
         Path("/usr/share/fonts/truetype/nanum/NanumGothicBold.ttf")),
    ]
    for reg, bold in candidates:
        if reg.exists():
            return str(reg), str(bold) if bold.exists() else str(reg)
    return None, None


async def generate(job_id: str, target, data: dict) -> str:
    loop = asyncio.get_event_loop()
    rtype = data.get("report_type", "executive")
    if rtype == "technical":
        return await loop.run_in_executor(None, _build_technical, job_id, data)
    elif rtype == "compliance":
        return await loop.run_in_executor(None, _build_compliance, job_id, data)
    else:
        return await loop.run_in_executor(None, _build, job_id, data)


def _build(job_id: str, data: dict) -> str:
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.fonts import addMapping
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether
        )
    except ImportError as e:
        return _fallback_txt(job_id, data, str(e))

    # ── 폰트 등록 ───────────────────────────────────────────────
    reg_path, bold_path = _get_fonts()
    if reg_path:
        pdfmetrics.registerFont(TTFont("KF",  reg_path))
        pdfmetrics.registerFont(TTFont("KFB", bold_path))
        addMapping("KF", 0, 0, "KF")
        addMapping("KF", 1, 0, "KFB")
        print(f"[PDF] 폰트: {Path(reg_path).name}")
        FN, FNB = "KF", "KFB"
    else:
        print("[PDF] 경고: 한글 폰트 없음 — Helvetica 사용")
        FN, FNB = "Helvetica", "Helvetica-Bold"

    # ── 색상 ────────────────────────────────────────────────────
    C_NAVY  = colors.HexColor("#0D1B2A")
    C_BLUE  = colors.HexColor("#1565C0")
    C_LBLUE = colors.HexColor("#E3F2FD")
    C_CRIT  = colors.HexColor("#B71C1C")
    C_HIGH  = colors.HexColor("#E65100")
    C_MED   = colors.HexColor("#F57F17")
    C_LOW   = colors.HexColor("#2E7D32")
    C_GRAY  = colors.HexColor("#546E7A")
    C_LGRAY = colors.HexColor("#F5F7FA")
    C_LINE  = colors.HexColor("#CFD8DC")
    SEV_C   = {"critical":C_CRIT,"high":C_HIGH,"medium":C_MED,"low":C_LOW,"info":C_GRAY}
    SEV_L   = {"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험","info":"정보"}

    # ── 스타일 헬퍼 — 모두 wordWrap='CJK' 적용 ──────────────────
    def S(size=9, bold=False, color=C_NAVY, align=None, leading=None):
        kw = dict(fontName=FNB if bold else FN, fontSize=size,
                  textColor=color, leading=leading or size+5,
                  wordWrap='CJK', splitLongWords=1)
        if align == "C": kw["alignment"] = TA_CENTER
        if align == "R": kw["alignment"] = TA_RIGHT
        return ParagraphStyle(f"s{id(kw)}", **kw)

    def p(txt, size=9, bold=False, color=C_NAVY, align=None):
        """Paragraph 래퍼 — 한글 포함 모든 셀 텍스트에 사용"""
        return Paragraph(str(txt), S(size=size, bold=bold, color=color, align=align))

    def ph(txt): return p(txt, bold=True, color=C_BLUE)   # 헤더 셀
    def pw(txt): return p(txt, color=colors.white, bold=True, align="C")  # 흰글자 헤더

    def hr(t=0.5, c=C_LINE): return HRFlowable(width="100%", thickness=t, color=c)
    def sp(h=4): return Spacer(1, h*mm)

    # 기본 테이블 스타일
    BASE_TS = [
        ("FONTNAME",  (0,0),(-1,-1), FN),
        ("FONTSIZE",  (0,0),(-1,-1), 8),
        ("GRID",      (0,0),(-1,-1), 0.3, C_LINE),
        ("VALIGN",    (0,0),(-1,-1), "MIDDLE"),
        ("PADDING",   (0,0),(-1,-1), 5),
    ]

    # ── 데이터 추출 ─────────────────────────────────────────────
    now      = datetime.now()
    stats    = data.get("stats", {})
    findings = data.get("findings", [])
    assets   = data.get("assets", [])
    gen_at   = data.get("generated_at", now.isoformat())[:10]

    crit_f   = [f for f in findings if f.get("severity")=="critical"]
    high_f   = [f for f in findings if f.get("severity")=="high"]
    med_f    = [f for f in findings if f.get("severity")=="medium"]
    low_f    = [f for f in findings if f.get("severity")=="low"]
    open_f   = [f for f in findings if f.get("status")!="resolved"]
    repeat_f = [f for f in findings if (f.get("repeat_count") or 0) > 0]
    res_pct  = stats.get("resolved_pct", 0)

    risk_level = ("매우 높음" if crit_f else "높음" if len(high_f)>=3
                  else "중간" if len(med_f)>=5 else "낮음")
    risk_color = (C_CRIT if risk_level=="매우 높음" else C_HIGH if risk_level=="높음"
                  else C_MED if risk_level=="중간" else C_LOW)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = str(OUTPUT_DIR / f"report_{job_id}.pdf")

    story = []

    # ══ 표지 ══════════════════════════════════════════════════
    story += [sp(28),
        p("보안 취약점 점검 결과 보고서", size=26, bold=True, color=C_NAVY, align="C"),
        p("Security Vulnerability Assessment Report", size=11, color=C_GRAY, align="C"),
        sp(6), hr(2, C_BLUE), sp(6)]

    cov = Table([
        [ph("보고서 번호"), p(job_id),               ph("작성 일자"),  p(gen_at)],
        [ph("대상 자산 수"),p(f"{len(assets)}개"),    ph("전체 취약점"),p(f"{len(findings)}건")],
        [ph("긴급 취약점"), p(f"{len(crit_f)}건"),   ph("조치 완료율"),p(f"{res_pct}%")],
        [ph("종합 위험도"), p(risk_level, color=risk_color, bold=True),
         ph("미조치 건수"), p(f"{len(open_f)}건")],
    ], colWidths=[38*mm,47*mm,38*mm,47*mm])
    cov.setStyle(TableStyle(BASE_TS + [
        ("BACKGROUND",(0,0),(0,-1),C_LBLUE),
        ("BACKGROUND",(2,0),(2,-1),C_LBLUE),
    ]))
    story += [cov, sp(8), hr(), sp(3),
        p("본 보고서는 SecurityScanKit Enterprise Platform에 의해 자동 생성된 공식 보안점검 결과 보고서입니다. "
          "본 문서의 내용은 대외비이며 관련 법령 및 내부 규정에 따라 관리되어야 합니다.",
          size=8, color=C_GRAY),
        PageBreak()]

    # ══ 1. 경영진 요약 ════════════════════════════════════════
    story += [p("1. 경영진 요약 (Executive Summary)", size=13, bold=True, color=C_BLUE), hr(), sp(3)]

    kpi = Table([
        [pw("긴급 Critical"), pw("고위험 High"), pw("중위험 Medium"),
         pw("저위험 Low"),    pw("미조치 Open"), pw("조치율 Resolved")],
        [p(str(len(crit_f)), size=18, bold=True, color=C_CRIT, align="C"),
         p(str(len(high_f)), size=18, bold=True, color=C_HIGH, align="C"),
         p(str(len(med_f)),  size=18, bold=True, color=C_MED,  align="C"),
         p(str(len(low_f)),  size=18, bold=True, color=C_LOW,  align="C"),
         p(str(len(open_f)), size=18, bold=True, color=C_NAVY, align="C"),
         p(f"{res_pct}%",    size=18, bold=True, color=C_BLUE, align="C")],
    ], colWidths=[28*mm]*6)
    kpi.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,0),C_CRIT),("BACKGROUND",(1,0),(1,0),C_HIGH),
        ("BACKGROUND",(2,0),(2,0),C_MED), ("BACKGROUND",(3,0),(3,0),C_LOW),
        ("BACKGROUND",(4,0),(4,0),C_NAVY),("BACKGROUND",(5,0),(5,0),C_BLUE),
        ("BACKGROUND",(0,1),(-1,1),C_LGRAY),
        ("GRID",(0,0),(-1,-1),0.4,C_LINE),
        ("ROWHEIGHT",(0,0),(-1,0),16),("ROWHEIGHT",(0,1),(-1,1),22),
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"),("FONTNAME",(0,0),(-1,-1),FN),
    ]))
    story += [kpi, sp(5)]

    # 요약 문장
    for txt in [
        f"금번 보안점검 결과 총 <b>{len(findings)}건</b>의 취약점이 발견되었으며, "
        f"긴급 <b>{len(crit_f)}건</b>, 고위험 <b>{len(high_f)}건</b>으로 즉각 조치가 필요합니다.",
        f"종합 위험도는 <b>{risk_level}</b>으로 평가되며, 현재 조치 완료율은 <b>{res_pct}%</b>입니다.",
    ] + ([f"<b>{len(repeat_f)}건</b>의 반복 취약점이 확인되어 ISMS-P 심사 및 금감원 검사 시 지적 가능성이 높습니다."]
         if repeat_f else []):
        story += [Paragraph(txt, S(9, color=C_NAVY)), sp(2)]

    # 즉각 조치 권고
    if crit_f or high_f:
        story += [sp(3), p("▶ 즉각 조치 권고 사항", size=10, bold=True)]
        act_rows = [[pw("#"), pw("취약점명"), pw("자산 IP"), pw("심각도"), pw("권고 조치")]]
        for i, f in enumerate(sorted(crit_f+high_f,
                key=lambda x: x.get("cvss_score",0), reverse=True)[:10], 1):
            act_rows.append([
                p(str(i), align="C"),
                p((f.get("title","")[:42]+"…" if len(f.get("title",""))>42 else f.get("title",""))),
                p(f.get("asset_ip","")),
                p(SEV_L.get(f.get("severity",""),""), color=SEV_C.get(f.get("severity",""),C_GRAY), bold=True),
                p(f.get("recommendation","패치 적용 및 설정 강화")[:52]),
            ])
        act_t = Table(act_rows, colWidths=[8*mm,65*mm,25*mm,15*mm,55*mm])
        act_t.setStyle(TableStyle(BASE_TS + [
            ("BACKGROUND",(0,0),(-1,0),C_NAVY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY]),
        ]))
        story += [act_t]

    story.append(PageBreak())

    # ══ 2. 자산별 점검 현황 ═══════════════════════════════════
    story += [p("2. 자산별 점검 현황", size=13, bold=True, color=C_BLUE), hr(), sp(3)]
    if assets:
        ar = [[pw("자산명"),pw("IP"),pw("유형"),pw("환경"),pw("담당부서"),pw("담당자"),pw("위험점수"),pw("긴급"),pw("고위험"),pw("상태")]]
        for a in sorted(assets, key=lambda x: x.get("risk_score",0), reverse=True):
            aid = a.get("id","")
            ac  = len([f for f in findings if f.get("asset_id")==aid and f.get("severity")=="critical"])
            ah  = len([f for f in findings if f.get("asset_id")==aid and f.get("severity")=="high"])
            sc  = a.get("risk_score",0)
            sc_c= C_CRIT if sc>=70 else C_HIGH if sc>=50 else C_MED if sc>=30 else C_LOW
            ar.append([
                p(a.get("name","")[:16]), p(a.get("ip","")),
                p(a.get("asset_type","")[:8]), p(a.get("environment","")[:8]),
                p(a.get("department","")[:10]), p(a.get("manager","")[:8]),
                p(str(round(sc)), color=sc_c, bold=True, align="C"),
                p(str(ac) if ac else "-", align="C"),
                p(str(ah) if ah else "-", align="C"),
                p(a.get("status","")[:6]),
            ])
        at = Table(ar, colWidths=[28*mm,22*mm,14*mm,14*mm,20*mm,14*mm,14*mm,10*mm,12*mm,12*mm])
        at.setStyle(TableStyle(BASE_TS + [
            ("BACKGROUND",(0,0),(-1,0),C_NAVY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY]),
        ]))
        story.append(at)
    else:
        story.append(p("등록된 자산이 없습니다."))

    story.append(PageBreak())

    # ══ 3. 취약점 상세 목록 ═══════════════════════════════════
    story += [p("3. 취약점 상세 목록", size=13, bold=True, color=C_BLUE), hr(), sp(3)]
    sev_ord = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
    for f in sorted(findings, key=lambda x: sev_ord.get(x.get("severity","info"),4)):
        sev = f.get("severity","info")
        sc2 = SEV_C.get(sev, C_GRAY)
        sl  = SEV_L.get(sev, "정보")
        rep = f.get("repeat_count",0)

        hdr_t = Table([[p(f"[{sl}]  {f.get('title','(제목없음)')}", size=9, bold=True, color=C_NAVY)]],
            colWidths=[168*mm])
        hdr_t.setStyle(TableStyle([
            ("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,-1),(-1,-1),4),
            ("LINEBEFORE",(0,0),(0,-1),4,sc2),
            ("BACKGROUND",(0,0),(-1,-1),C_LGRAY),
        ]))
        det = Table([
            [ph("취약점 ID"), p(f.get("vuln_id","")),      ph("점검 유형"), p(f.get("scan_type",""))],
            [ph("대상 자산"), p(f.get("asset_name","")),   ph("IP 주소"),   p(f.get("asset_ip",""))],
            [ph("CVSS 점수"), p(str(f.get("cvss_score","N/A"))), ph("반복 발견"), p(f"{rep}회" if rep else "-")],
            [ph("조치 상태"), p("조치완료" if f.get("status")=="resolved" else "미조치"),
             ph("최초 발견"), p(str(f.get("first_seen",""))[:10])],
        ], colWidths=[22*mm,62*mm,22*mm,62*mm])
        det.setStyle(TableStyle(BASE_TS + [
            ("BACKGROUND",(0,0),(0,-1),C_LBLUE),
            ("BACKGROUND",(2,0),(2,-1),C_LBLUE),
        ]))
        desc_t = Table([
            [p("설명", size=8, color=C_GRAY)],
            [p(f.get("description","") or "상세 설명 없음")],
            [p("조치 권고", size=8, color=C_GRAY)],
            [p(f.get("recommendation","") or "담당자 검토 후 조치")],
        ], colWidths=[168*mm])
        desc_t.setStyle(TableStyle([
            ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,-1),(-1,-1),5),
            ("LINEBEFORE",(0,0),(0,-1),3,sc2),
            ("BACKGROUND",(0,0),(-1,-1),C_LGRAY),
            ("FONTNAME",(0,0),(-1,-1),FN),
        ]))
        story.append(KeepTogether([sp(1), hdr_t, det, desc_t, sp(2)]))

    story.append(PageBreak())

    # ══ 4. 컴플라이언스 ════════════════════════════════════════
    story += [p("4. 컴플라이언스 준수 현황", size=13, bold=True, color=C_BLUE), hr(), sp(3)]
    comp_map = {
        "ISMS-P":["web","ssl"], "전자금융감독규정":["port","ssl","network"],
        "금융보안원 가이드":["port","db","network"], "PCI-DSS":["web","ssl","db"],
        "ISO 27001":["port","web","ssl"], "NIST CSF":["port","web","ssl","db","network"],
    }
    base_items = {"ISMS-P":102,"전자금융감독규정":45,"금융보안원 가이드":80,
                  "PCI-DSS":64,"ISO 27001":93,"NIST CSF":108}
    comp_rows = [[pw("규정"),pw("통제항목"),pw("관련취약점"),pw("긴급/고위험"),pw("준수율"),pw("상태")]]
    for std, types in comp_map.items():
        rel  = [f for f in findings if f.get("scan_type","") in types]
        crit = [f for f in rel if f.get("severity","") in ("critical","high")]
        sc3  = max(0, 100 - min(len(crit)*3 + len(rel), 40))
        st_t = "✓ 준수" if sc3>=85 else "△ 주의" if sc3>=70 else "✗ 미준수"
        st_c = C_LOW if sc3>=85 else C_MED if sc3>=70 else C_CRIT
        comp_rows.append([
            p(std, bold=True), p(str(base_items.get(std,100)), align="C"),
            p(str(len(rel)), align="C"), p(str(len(crit)), align="C"),
            p(f"{sc3}%", align="C"),
            p(st_t, color=st_c, bold=True, align="C"),
        ])
    ct = Table(comp_rows, colWidths=[45*mm,22*mm,22*mm,22*mm,18*mm,20*mm])
    ct.setStyle(TableStyle(BASE_TS + [
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY]),
        ("ALIGN",(1,0),(-1,-1),"CENTER"),
    ]))
    story += [ct, sp(4),
        p("※ 준수율은 각 규정과 연관된 점검 유형의 긴급·고위험 취약점 발생 건수를 기반으로 자동 산출됩니다.", size=8, color=C_GRAY),
        PageBreak()]

    # ══ 5. 조치 이행 계획 ══════════════════════════════════════
    story += [p("5. 조치 이행 계획 (권고)", size=13, bold=True, color=C_BLUE), hr(), sp(3)]
    plan_rows = [[pw("구분"),pw("조치 내용"),pw("대상 건수"),pw("권고 기한"),pw("담당")]]
    for grp, desc, cnt, due, owner in [
        ("긴급 (Critical)","즉각 패치 적용 및 긴급 설정 변경",len(crit_f),"24시간 이내","IT보안팀"),
        ("고위험 (High)",  "취약점 패치 및 설정 강화",          len(high_f),"7일 이내",  "IT보안팀"),
        ("중위험 (Medium)","보안 설정 검토 및 조치",             len(med_f), "30일 이내", "시스템팀"),
        ("저위험 (Low)",   "정기 점검 시 조치",                  len(low_f), "차기 점검", "시스템팀"),
        ("반복 취약점",    "근본 원인 분석 및 재발 방지 대책",   len(repeat_f),"14일 이내","IT보안팀"),
    ]:
        plan_rows.append([p(grp,bold=True), p(desc), p(str(cnt),align="C"), p(due,align="C"), p(owner,align="C")])
    pt = Table(plan_rows, colWidths=[28*mm,75*mm,18*mm,22*mm,25*mm])
    pt.setStyle(TableStyle(BASE_TS + [
        ("BACKGROUND",(0,0),(-1,0),C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY]),
        ("ALIGN",(2,0),(-1,-1),"CENTER"),
    ]))
    story += [pt, sp(5),
        p("본 보고서는 보안점검 결과에 기반한 권고사항이며, 실제 조치는 내부 변경관리 절차에 따라 수행하시기 바랍니다.", size=8, color=C_GRAY)]

    # ── 페이지 번호 푸터 ────────────────────────────────────────
    def on_page(canvas, doc):
        canvas.saveState()
        canvas.setFont(FN, 7)
        canvas.setFillColor(C_GRAY)
        canvas.drawString(20*mm, 12*mm, f"SecurityScanKit Enterprise — 보안점검 결과 보고서 | 보고서 번호: {job_id}")
        canvas.drawRightString(190*mm, 12*mm, f"Page {doc.page}")
        canvas.setStrokeColor(C_LINE)
        canvas.setLineWidth(0.3)
        canvas.line(20*mm, 16*mm, 190*mm, 16*mm)
        canvas.restoreState()

    doc = SimpleDocTemplate(out, pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm, topMargin=22*mm, bottomMargin=22*mm)
    doc.build(story, onFirstPage=on_page, onLaterPages=on_page)
    return out



def _build_technical(job_id: str, data: dict) -> str:
    """기술 상세 보고서 — 취약점 전체 목록, CVSS, 반복 분석, 자산별 상세"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.fonts import addMapping
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether
        )
    except ImportError as e:
        return _fallback_txt(job_id, data, str(e))

    reg_path, bold_path = _get_fonts()
    if reg_path:
        pdfmetrics.registerFont(TTFont("KF",  reg_path))
        pdfmetrics.registerFont(TTFont("KFB", bold_path))
        addMapping("KF",0,0,"KF"); addMapping("KF",1,0,"KFB")
        FN, FNB = "KF", "KFB"
    else:
        FN, FNB = "Helvetica", "Helvetica-Bold"

    C_NAVY=colors.HexColor("#0D1B2A"); C_PURPLE=colors.HexColor("#5B21B6")
    C_LPURPLE=colors.HexColor("#EDE9FE"); C_CRIT=colors.HexColor("#B71C1C")
    C_HIGH=colors.HexColor("#E65100"); C_MED=colors.HexColor("#F57F17")
    C_LOW=colors.HexColor("#2E7D32"); C_GRAY=colors.HexColor("#546E7A")
    C_LGRAY=colors.HexColor("#F5F7FA"); C_LINE=colors.HexColor("#CFD8DC")
    SEV_C={"critical":C_CRIT,"high":C_HIGH,"medium":C_MED,"low":C_LOW,"info":C_GRAY}
    SEV_L={"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험","info":"정보"}

    def S(size=9,bold=False,color=C_NAVY,align=None):
        kw=dict(fontName=FNB if bold else FN,fontSize=size,textColor=color,
                leading=size+5,wordWrap="CJK",splitLongWords=1)
        if align=="C": kw["alignment"]=TA_CENTER
        if align=="R": kw["alignment"]=TA_RIGHT
        return ParagraphStyle(f"s{id(kw)}",**kw)
    def p(t,size=9,bold=False,color=C_NAVY,align=None): return Paragraph(str(t),S(size,bold,color,align))
    def ph(t): return p(t,bold=True,color=C_PURPLE)
    def pw(t): return p(t,color=colors.white,bold=True,align="C")
    def hr(t=0.5,c=C_LINE): return HRFlowable(width="100%",thickness=t,color=c)
    def sp(h=4): return Spacer(1,h*mm)

    BASE_TS=[("FONTNAME",(0,0),(-1,-1),FN),("FONTSIZE",(0,0),(-1,-1),8),
             ("GRID",(0,0),(-1,-1),0.3,C_LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("PADDING",(0,0),(-1,-1),5)]

    now=datetime.now(); gen_at=data.get("generated_at",now.isoformat())[:10]
    stats=data.get("stats",{}); findings=data.get("findings",[]); assets=data.get("assets",[])
    crit_f=[f for f in findings if f.get("severity")=="critical"]
    high_f=[f for f in findings if f.get("severity")=="high"]
    med_f=[f for f in findings if f.get("severity")=="medium"]
    low_f=[f for f in findings if f.get("severity")=="low"]
    repeat_f=[f for f in findings if (f.get("repeat_count") or 0)>0]
    open_f=[f for f in findings if f.get("status")!="resolved"]
    res_pct=stats.get("resolved_pct",0)

    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    out=str(OUTPUT_DIR/f"report_{job_id}.pdf")
    story=[]

    # ── 표지
    story+=[sp(25),
        p("기술 상세 보안점검 보고서",size=24,bold=True,color=C_NAVY,align="C"),
        p("Technical Security Assessment Report",size=11,color=C_GRAY,align="C"),
        sp(6),hr(2,C_PURPLE),sp(6)]
    cov=Table([
        [ph("보고서 번호"),p(job_id),ph("작성 일자"),p(gen_at)],
        [ph("전체 취약점"),p(f"{len(findings)}건"),ph("긴급/고위험"),p(f"{len(crit_f)+len(high_f)}건",color=C_CRIT,bold=True)],
        [ph("반복 취약점"),p(f"{len(repeat_f)}건",color=C_HIGH if repeat_f else C_LOW,bold=True),ph("조치 완료율"),p(f"{res_pct}%")],
    ],colWidths=[38*mm,47*mm,38*mm,47*mm])
    cov.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(0,-1),C_LPURPLE),("BACKGROUND",(2,0),(2,-1),C_LPURPLE)]))
    story+=[cov,sp(6),hr(),sp(3),
        p("본 보고서는 기술 담당자 및 보안 실무진을 위한 상세 취약점 분석 보고서입니다. 각 취약점의 기술적 세부사항과 조치 방법을 포함합니다.",size=8,color=C_GRAY),
        PageBreak()]

    # ── 1. 취약점 통계 요약
    story+=[p("1. 취약점 통계 요약",size=13,bold=True,color=C_PURPLE),hr(),sp(3)]
    stat_rows=[[pw("심각도"),pw("건수"),pw("비율"),pw("반복"),pw("조치완료"),pw("CVSS 평균")]]
    for sev,sev_l,items in [("critical","긴급",crit_f),("high","고위험",high_f),
                             ("medium","중위험",med_f),("low","저위험",low_f)]:
        if not items: continue
        resolved=[f for f in items if f.get("status")=="resolved"]
        repeat=[f for f in items if (f.get("repeat_count") or 0)>0]
        cvss_avg=round(sum(f.get("cvss_score") or 0 for f in items)/len(items),1) if items else 0
        pct=round(len(items)/max(len(findings),1)*100)
        stat_rows.append([p(sev_l,bold=True,color=SEV_C[sev]),p(f"{len(items)}건",align="C"),
            p(f"{pct}%",align="C"),p(f"{len(repeat)}건",align="C"),
            p(f"{len(resolved)}건",align="C"),p(str(cvss_avg),align="C")])
    st=Table(stat_rows,colWidths=[28*mm,20*mm,18*mm,18*mm,20*mm,25*mm])
    st.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
    story+=[st,sp(4)]

    # ── 2. 반복 취약점 분석
    if repeat_f:
        story+=[sp(3),p("2. 반복 취약점 분석",size=13,bold=True,color=C_PURPLE),hr(),sp(3),
            p(f"총 {len(repeat_f)}건의 취약점이 반복 발견되었습니다. 이는 조치 후 재발하거나 근본 원인이 해결되지 않은 항목입니다.",size=9,color=C_NAVY),sp(3)]
        rpt_rows=[[pw("취약점명"),pw("자산"),pw("심각도"),pw("반복"),pw("최초발견"),pw("CVSS")]]
        for f in sorted(repeat_f,key=lambda x:x.get("repeat_count",0),reverse=True)[:15]:
            rpt_rows.append([p(f.get("title","")[:38]),p(f.get("asset_name","")[:14]),
                p(SEV_L.get(f.get("severity",""),""),color=SEV_C.get(f.get("severity",""),C_GRAY),bold=True),
                p(f"{f.get('repeat_count',0)}회",align="C"),
                p(str(f.get("first_seen",""))[:10],align="C"),
                p(str(f.get("cvss_score","N/A")),align="C")])
        rt=Table(rpt_rows,colWidths=[55*mm,30*mm,18*mm,15*mm,22*mm,15*mm])
        rt.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
        story+=[rt,PageBreak()]

    # ── 3. 자산별 취약점 현황
    story+=[p("3. 자산별 취약점 현황",size=13,bold=True,color=C_PURPLE),hr(),sp(3)]
    for a in sorted(assets,key=lambda x:x.get("risk_score",0),reverse=True):
        aid=a.get("id","")
        a_finds=[f for f in findings if f.get("asset_id")==aid]
        if not a_finds: continue
        a_c=len([f for f in a_finds if f.get("severity")=="critical"])
        a_h=len([f for f in a_finds if f.get("severity")=="high"])
        sc=a.get("risk_score",0)
        sc_c=C_CRIT if sc>=70 else C_HIGH if sc>=50 else C_MED if sc>=30 else C_LOW
        hdr=Table([[p(f"🖥 {a.get('name','')}  |  {a.get('ip','')}  |  {a.get('environment','')}",
            size=10,bold=True,color=C_NAVY),
            p(f"위험점수: {round(sc)}  /  긴급: {a_c}건  /  고위험: {a_h}건",size=9,color=sc_c,align="R")]],
            colWidths=[120*mm,48*mm])
        hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_LPURPLE),
            ("FONTNAME",(0,0),(-1,-1),FN),("PADDING",(0,0),(-1,-1),7),
            ("LINEBEFORE",(0,0),(0,-1),4,C_PURPLE)]))
        detail_rows=[[pw("취약점명"),pw("심각도"),pw("CVSS"),pw("상태"),pw("반복"),pw("점검유형")]]
        for f in sorted(a_finds,key=lambda x:{"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3)):
            detail_rows.append([p(f.get("title","")[:42]),
                p(SEV_L.get(f.get("severity",""),""),color=SEV_C.get(f.get("severity",""),C_GRAY),bold=True),
                p(str(f.get("cvss_score","N/A")),align="C"),
                p("완료" if f.get("status")=="resolved" else "미조치",align="C"),
                p(f"{f.get('repeat_count',0)}회" if f.get("repeat_count") else "-",align="C"),
                p(f.get("scan_type",""))])
        dt=Table(detail_rows,colWidths=[65*mm,18*mm,15*mm,15*mm,12*mm,18*mm])
        dt.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
        story.append(KeepTogether([hdr,dt,sp(4)]))

    story.append(PageBreak())

    # ── 4. 취약점 상세 (전체)
    story+=[p("4. 취약점 전체 상세",size=13,bold=True,color=C_PURPLE),hr(),sp(3)]
    sev_ord={"critical":0,"high":1,"medium":2,"low":3,"info":4}
    for f in sorted(findings,key=lambda x:sev_ord.get(x.get("severity","info"),4)):
        sev=f.get("severity","info"); sc2=SEV_C.get(sev,C_GRAY); sl=SEV_L.get(sev,"정보")
        hdr_t=Table([[p(f"[{sl}]  {f.get('title','(제목없음)')}",size=9,bold=True,color=C_NAVY)]],colWidths=[168*mm])
        hdr_t.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),8),("TOPPADDING",(0,0),(-1,-1),5),
            ("BOTTOMPADDING",(0,-1),(-1,-1),4),("LINEBEFORE",(0,0),(0,-1),4,sc2),
            ("BACKGROUND",(0,0),(-1,-1),C_LGRAY),("FONTNAME",(0,0),(-1,-1),FN)]))
        det=Table([
            [ph("취약점 ID"),p(f.get("vuln_id","")),ph("점검 유형"),p(f.get("scan_type",""))],
            [ph("대상 자산"),p(f.get("asset_name","")),ph("IP 주소"),p(f.get("asset_ip",""))],
            [ph("CVSS 점수"),p(str(f.get("cvss_score","N/A"))),ph("반복 발견"),p(f"{f.get('repeat_count',0)}회" if f.get("repeat_count") else "-")],
            [ph("조치 상태"),p("조치완료" if f.get("status")=="resolved" else "미조치"),ph("최초 발견"),p(str(f.get("first_seen",""))[:10])],
        ],colWidths=[22*mm,62*mm,22*mm,62*mm])
        det.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(0,-1),C_LPURPLE),("BACKGROUND",(2,0),(2,-1),C_LPURPLE)]))
        desc_t=Table([[p("설명",size=8,color=C_GRAY)],[p(f.get("description","") or "상세 설명 없음")],
            [p("조치 권고",size=8,color=C_GRAY)],[p(f.get("recommendation","") or "담당자 검토 후 조치")]],colWidths=[168*mm])
        desc_t.setStyle(TableStyle([("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),
            ("TOPPADDING",(0,0),(-1,-1),3),("BOTTOMPADDING",(0,-1),(-1,-1),5),
            ("LINEBEFORE",(0,0),(0,-1),3,sc2),("BACKGROUND",(0,0),(-1,-1),C_LGRAY),("FONTNAME",(0,0),(-1,-1),FN)]))
        story.append(KeepTogether([sp(1),hdr_t,det,desc_t,sp(2)]))

    def on_page(canvas,doc):
        canvas.saveState(); canvas.setFont(FN,7); canvas.setFillColor(C_GRAY)
        canvas.drawString(20*mm,12*mm,f"SecurityScanKit Enterprise — 기술 상세 보고서 | ID: {job_id}")
        canvas.drawRightString(190*mm,12*mm,f"Page {doc.page}")
        canvas.setStrokeColor(C_LINE); canvas.setLineWidth(0.3); canvas.line(20*mm,16*mm,190*mm,16*mm)
        canvas.restoreState()
    doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=20*mm,leftMargin=20*mm,topMargin=22*mm,bottomMargin=22*mm)
    doc.build(story,onFirstPage=on_page,onLaterPages=on_page)
    return out


def _build_compliance(job_id: str, data: dict) -> str:
    """컴플라이언스 보고서 — ISMS-P, 전자금융감독규정 등 규정별 상세 준수 현황"""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.units import mm
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_JUSTIFY
        from reportlab.lib.styles import ParagraphStyle
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont
        from reportlab.lib.fonts import addMapping
        from reportlab.platypus import (
            SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
            HRFlowable, PageBreak, KeepTogether
        )
    except ImportError as e:
        return _fallback_txt(job_id, data, str(e))

    reg_path, bold_path = _get_fonts()
    if reg_path:
        pdfmetrics.registerFont(TTFont("KF",  reg_path))
        pdfmetrics.registerFont(TTFont("KFB", bold_path))
        addMapping("KF",0,0,"KF"); addMapping("KF",1,0,"KFB")
        FN, FNB = "KF", "KFB"
    else:
        FN, FNB = "Helvetica", "Helvetica-Bold"

    C_NAVY=colors.HexColor("#0D1B2A"); C_GREEN=colors.HexColor("#065F46")
    C_LGREEN=colors.HexColor("#D1FAE5"); C_OK=colors.HexColor("#059669")
    C_WARN=colors.HexColor("#D97706"); C_FAIL=colors.HexColor("#B91C1C")
    C_GRAY=colors.HexColor("#546E7A"); C_LGRAY=colors.HexColor("#F5F7FA")
    C_LINE=colors.HexColor("#CFD8DC")

    def S(size=9,bold=False,color=C_NAVY,align=None):
        kw=dict(fontName=FNB if bold else FN,fontSize=size,textColor=color,leading=size+5,wordWrap="CJK",splitLongWords=1)
        if align=="C": kw["alignment"]=TA_CENTER
        if align=="R": kw["alignment"]=TA_RIGHT
        if align=="J": kw["alignment"]=TA_JUSTIFY
        return ParagraphStyle(f"s{id(kw)}",**kw)
    def p(t,size=9,bold=False,color=C_NAVY,align=None): return Paragraph(str(t),S(size,bold,color,align))
    def ph(t): return p(t,bold=True,color=C_GREEN)
    def pw(t): return p(t,color=colors.white,bold=True,align="C")
    def hr(t=0.5,c=C_LINE): return HRFlowable(width="100%",thickness=t,color=c)
    def sp(h=4): return Spacer(1,h*mm)

    BASE_TS=[("FONTNAME",(0,0),(-1,-1),FN),("FONTSIZE",(0,0),(-1,-1),8),
             ("GRID",(0,0),(-1,-1),0.3,C_LINE),("VALIGN",(0,0),(-1,-1),"MIDDLE"),("PADDING",(0,0),(-1,-1),5)]

    now=datetime.now(); gen_at=data.get("generated_at",now.isoformat())[:10]
    stats=data.get("stats",{}); findings=data.get("findings",[]); assets=data.get("assets",[])

    COMP_DEF = {
        "ISMS-P": {
            "full":"정보보호 및 개인정보보호 관리체계 (ISMS-P)",
            "org":"한국인터넷진흥원 (KISA)",
            "types":["web","ssl"],
            "items":102, "desc":"정보보호 관리체계 인증. 금융권 의무 취득 대상.",
            "controls":[
                ("보호대책","접근통제","web","비인가 접근 차단, 권한 관리"),
                ("보호대책","암호화 적용","ssl","데이터 전송·저장 시 암호화"),
                ("보호대책","보안취약점 점검","port","정기적 취약점 점검 및 조치"),
                ("개인정보","안전성 확보","db","개인정보 DB 접근통제 및 암호화"),
            ]
        },
        "전자금융감독규정": {
            "full":"전자금융감독규정",
            "org":"금융감독원 (FSS)",
            "types":["port","ssl","network"],
            "items":45, "desc":"금융회사 전자금융업무 보안기준. 위반 시 행정제재.",
            "controls":[
                ("제12조","정보처리시스템 보안","port","포트 및 서비스 최소화"),
                ("제13조","암호기술 적용","ssl","SSL/TLS 최신 버전 적용"),
                ("제14조","네트워크 보안","network","방화벽, IDS/IPS 운영"),
                ("제15조","DB 접근통제","db","DB 접근권한 최소화"),
            ]
        },
        "금융보안원 가이드": {
            "full":"금융보안원 금융부문 보안가이드",
            "org":"금융보안원 (FSec)",
            "types":["port","db","network"],
            "items":80, "desc":"금융권 특화 사이버 보안 가이드라인.",
            "controls":[
                ("가이드","취약점 관리","port","정기 취약점 스캔 및 패치"),
                ("가이드","DB 보안","db","DB 계정·권한·감사로그"),
                ("가이드","네트워크 분리","network","업무망/인터넷망 분리"),
            ]
        },
        "PCI-DSS": {
            "full":"Payment Card Industry Data Security Standard",
            "org":"PCI Security Standards Council",
            "types":["web","ssl","db"],
            "items":64, "desc":"카드정보 보호 국제 표준. 카드사·PG사 의무 준수.",
            "controls":[
                ("Req.1","네트워크 보안","port","방화벽 구성 및 관리"),
                ("Req.2","시스템 보안","web","기본값 변경, 보안 구성"),
                ("Req.4","전송 암호화","ssl","카드데이터 전송 암호화"),
                ("Req.6","취약점 관리","web","보안 패치 적기 적용"),
            ]
        },
        "ISO 27001": {
            "full":"ISO/IEC 27001 정보보호 관리체계",
            "org":"ISO / 한국인정기구",
            "types":["port","web","ssl"],
            "items":93, "desc":"국제 정보보호 관리체계 인증. 글로벌 비즈니스 필수.",
            "controls":[
                ("A.8","자산 관리","port","자산 식별 및 보안 분류"),
                ("A.9","접근 통제","web","접근 정책 및 권한 관리"),
                ("A.10","암호화","ssl","암호화 정책 및 키 관리"),
                ("A.12","운영 보안","port","변경관리, 용량관리"),
            ]
        },
        "NIST CSF": {
            "full":"NIST Cybersecurity Framework",
            "org":"미국 국립표준기술연구소 (NIST)",
            "types":["port","web","ssl","db","network"],
            "items":108, "desc":"식별-보호-탐지-대응-복구 5개 기능 프레임워크.",
            "controls":[
                ("IDENTIFY","자산 관리","port","자산 인벤토리 관리"),
                ("PROTECT","접근 제어","web","최소 권한 원칙 적용"),
                ("PROTECT","데이터 보안","ssl","암호화·무결성 보호"),
                ("DETECT","취약점 모니터링","port","지속적 취약점 탐지"),
            ]
        },
    }

    OUTPUT_DIR.mkdir(parents=True,exist_ok=True)
    out=str(OUTPUT_DIR/f"report_{job_id}.pdf")
    story=[]

    # ── 표지
    story+=[sp(25),
        p("컴플라이언스 준수 현황 보고서",size=24,bold=True,color=C_NAVY,align="C"),
        p("Compliance Status Report",size=11,color=C_GRAY,align="C"),
        sp(6),hr(2,C_OK),sp(6)]
    total_ok=sum(1 for std,cd in COMP_DEF.items()
        if max(0,100-min(len([f for f in findings if f.get("scan_type","") in cd["types"]
            and f.get("severity","") in ("critical","high")])*3+
            len([f for f in findings if f.get("scan_type","") in cd["types"]]),40))>=85)
    cov=Table([
        [ph("보고서 번호"),p(job_id),ph("작성 일자"),p(gen_at)],
        [ph("점검 규정"),p(f"{len(COMP_DEF)}개"),ph("준수"),p(f"{total_ok}개",color=C_OK,bold=True)],
        [ph("주의/미준수"),p(f"{len(COMP_DEF)-total_ok}개",color=C_FAIL if len(COMP_DEF)-total_ok>0 else C_OK,bold=True),ph("전체 취약점"),p(f"{len(findings)}건")],
    ],colWidths=[38*mm,47*mm,38*mm,47*mm])
    cov.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(0,-1),C_LGREEN),("BACKGROUND",(2,0),(2,-1),C_LGREEN)]))
    story+=[cov,sp(6),hr(),sp(3),
        p("본 보고서는 당사 정보보호 관련 주요 규정 및 표준의 준수 현황을 취약점 점검 결과 기반으로 자동 산출한 것입니다. "
          "실제 심사에서는 추가 증빙 자료가 필요할 수 있습니다.",size=8,color=C_GRAY),
        PageBreak()]

    # ── 1. 준수 현황 요약
    story+=[p("1. 규정별 준수 현황 요약",size=13,bold=True,color=C_GREEN),hr(),sp(3)]
    sum_rows=[[pw("규정명"),pw("주관기관"),pw("통제항목"),pw("관련취약점"),pw("긴급/고위험"),pw("준수율"),pw("상태")]]
    for std,cd in COMP_DEF.items():
        rel=[f for f in findings if f.get("scan_type","") in cd["types"]]
        crit=[f for f in rel if f.get("severity","") in ("critical","high")]
        score=max(0,100-min(len(crit)*3+len(rel),40))
        st_t="✓ 준수" if score>=85 else "△ 주의" if score>=70 else "✗ 미준수"
        st_c=C_OK if score>=85 else C_WARN if score>=70 else C_FAIL
        sum_rows.append([p(std,bold=True),p(cd["org"][:12]),p(str(cd["items"]),align="C"),
            p(str(len(rel)),align="C"),p(str(len(crit)),align="C"),
            p(f"{score}%",align="C"),p(st_t,color=st_c,bold=True,align="C")])
    st_t=Table(sum_rows,colWidths=[30*mm,28*mm,18*mm,18*mm,18*mm,15*mm,18*mm])
    st_t.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
    story+=[st_t,PageBreak()]

    # ── 2. 규정별 상세
    story+=[p("2. 규정별 상세 준수 현황",size=13,bold=True,color=C_GREEN),hr(),sp(3)]
    for std,cd in COMP_DEF.items():
        rel=[f for f in findings if f.get("scan_type","") in cd["types"]]
        crit=[f for f in rel if f.get("severity","") in ("critical","high")]
        score=max(0,100-min(len(crit)*3+len(rel),40))
        st_t2="✓ 준수" if score>=85 else "△ 주의" if score>=70 else "✗ 미준수"
        st_c2=C_OK if score>=85 else C_WARN if score>=70 else C_FAIL

        # 규정 헤더 박스
        hdr=Table([[
            p(f"{std}",size=12,bold=True,color=C_NAVY),
            p(f"{st_t2}  {score}%",size=11,bold=True,color=st_c2,align="R")
        ]],colWidths=[120*mm,48*mm])
        hdr.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,-1),C_LGREEN),
            ("FONTNAME",(0,0),(-1,-1),FN),("PADDING",(0,0),(-1,-1),8),
            ("LINEBEFORE",(0,0),(0,-1),4,C_OK)]))
        story+=[hdr,sp(2)]
        story.append(p(f"주관: {cd['org']}  |  통제항목: {cd['items']}개  |  {cd['desc']}",size=8,color=C_GRAY))
        story.append(sp(3))

        # 통제 항목별 현황
        ctrl_rows=[[pw("조항"),pw("통제 항목"),pw("관련 취약점"),pw("상태")]]
        for clause,ctrl,stype,desc in cd["controls"]:
            ctrl_finds=[f for f in findings if f.get("scan_type","")==stype]
            has_crit=any(f.get("severity","") in ("critical","high") for f in ctrl_finds)
            ctrl_st=p("✓ 이상없음",color=C_OK,bold=True,align="C") if not ctrl_finds else                     p("✗ 취약점 존재",color=C_FAIL,bold=True,align="C") if has_crit else                     p("△ 경미한 취약점",color=C_WARN,bold=True,align="C")
            ctrl_rows.append([p(clause,align="C"),p(f"{ctrl}\n{desc}",size=8),
                p(f"{len(ctrl_finds)}건",align="C"),ctrl_st])
        ct2=Table(ctrl_rows,colWidths=[18*mm,75*mm,18*mm,30*mm])
        ct2.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
            ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
        story.append(ct2)

        # 관련 취약점 목록
        if rel:
            story.append(sp(2))
            story.append(p(f"관련 취약점 ({len(rel)}건)",size=9,bold=True,color=C_NAVY))
            vuln_rows=[[pw("취약점명"),pw("자산 IP"),pw("심각도"),pw("CVSS"),pw("상태")]]
            for f in sorted(rel,key=lambda x:{"critical":0,"high":1,"medium":2,"low":3}.get(x.get("severity","low"),3))[:10]:
                sev=f.get("severity","info")
                vuln_rows.append([p(f.get("title","")[:45]),p(f.get("asset_ip","")),
                    p({"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험"}.get(sev,sev),
                      color={"critical":C_FAIL,"high":C_WARN}.get(sev,C_GRAY),bold=True),
                    p(str(f.get("cvss_score","N/A")),align="C"),
                    p("완료" if f.get("status")=="resolved" else "미조치",align="C")])
            vt=Table(vuln_rows,colWidths=[65*mm,25*mm,18*mm,15*mm,15*mm])
            vt.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
                ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
            story.append(vt)
        story.append(sp(6))

    story.append(PageBreak())

    # ── 3. 개선 권고
    story+=[p("3. 개선 권고 사항",size=13,bold=True,color=C_GREEN),hr(),sp(3)]
    imp_rows=[[pw("우선순위"),pw("개선 항목"),pw("관련 규정"),pw("기한"),pw("담당")]]
    imp_data=[
        ("1","긴급 취약점 즉시 패치","전자금융감독규정, ISMS-P","24시간","IT보안팀"),
        ("2","SSL/TLS 최신 버전 적용","PCI-DSS, ISO 27001","7일","인프라팀"),
        ("3","DB 접근권한 최소화","전자금융감독규정, 금융보안원","14일","DBA팀"),
        ("4","네트워크 장비 점검","NIST CSF, 금융보안원","30일","네트워크팀"),
        ("5","반복 취약점 근본 원인 분석","ISMS-P","14일","IT보안팀"),
    ]
    for row in imp_data:
        imp_rows.append([p(row[0],align="C"),p(row[1]),p(row[2]),p(row[3],align="C"),p(row[4],align="C")])
    it=Table(imp_rows,colWidths=[15*mm,65*mm,55*mm,18*mm,15*mm])
    it.setStyle(TableStyle(BASE_TS+[("BACKGROUND",(0,0),(-1,0),C_NAVY),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,C_LGRAY])]))
    story+=[it,sp(5),
        p("※ 본 준수율은 취약점 점검 결과 기반의 자동 산출값입니다. 정확한 인증 준비를 위해서는 전문 컨설팅을 권장합니다.",size=8,color=C_GRAY)]

    def on_page(canvas,doc):
        canvas.saveState(); canvas.setFont(FN,7); canvas.setFillColor(C_GRAY)
        canvas.drawString(20*mm,12*mm,f"SecurityScanKit Enterprise — 컴플라이언스 보고서 | ID: {job_id}")
        canvas.drawRightString(190*mm,12*mm,f"Page {doc.page}")
        canvas.setStrokeColor(C_LINE); canvas.setLineWidth(0.3); canvas.line(20*mm,16*mm,190*mm,16*mm)
        canvas.restoreState()
    doc=SimpleDocTemplate(out,pagesize=A4,rightMargin=20*mm,leftMargin=20*mm,topMargin=22*mm,bottomMargin=22*mm)
    doc.build(story,onFirstPage=on_page,onLaterPages=on_page)
    return out


def _fallback_txt(job_id: str, data: dict, err: str) -> str:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    out = str(OUTPUT_DIR / f"report_{job_id}.txt")
    stats = data.get("stats", {})
    with open(out, "w", encoding="utf-8") as f:
        f.write(f"보안점검 결과 보고서 — {job_id}\n생성일시: {datetime.now()}\n\n")
        for k in ("critical","high","medium","low","repeat"):
            f.write(f"  {k}: {stats.get(k,0)}\n")
        f.write(f"\n※ reportlab 미설치: {err}\n")
    return out
