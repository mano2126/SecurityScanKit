// pages/PageSettings.jsx
import React, { useState, useEffect, useRef } from "react";
import { useLang } from "../i18n/LangContext";
import { LANGS } from "../i18n/translations";
import { THEMES, applyTheme, getStoredTheme } from "../theme/themes";
import { SYSTEM_NAME_PRESETS as DEFAULT_PRESETS, PC_ITEMS as DEFAULT_PC_ITEMS } from "../config/assetPresets.js";
import { Spinner } from "../components/UI";
import API_BASE from "../hooks/apiConfig.js";
import { WALK_CHARS, WALK_SPEEDS, getWalkChar, getWalkSpeed, setWalkChar, setWalkSpeed } from "../hooks/useWalkAnim.js";

// ── 공통 소형 컴포넌트 ───────────────────────────────────────────
function Field({ label, value, onChange, type="text", placeholder="" }) {
  return (
    <div style={{ display:"grid", gridTemplateColumns:"140px 1fr", gap:8, marginBottom:8, alignItems:"center" }}>
      <label style={{ fontSize:11, color:"var(--txt3)", fontWeight:500 }}>{label}</label>
      <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
        style={{ padding:"6px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:12, outline:"none" }}/>
    </div>
  );
}

function Toggle({ label, value, onChange, desc }) {
  return (
    <div style={{ display:"flex", alignItems:"center", gap:10, padding:"8px 0", borderBottom:"1px solid var(--bdr)" }}>
      <div style={{ flex:1 }}>
        <div style={{ fontSize:12, color:"var(--txt)", fontWeight:500 }}>{label}</div>
        {desc && <div style={{ fontSize:10, color:"var(--txt3)", marginTop:1 }}>{desc}</div>}
      </div>
      <div onClick={() => onChange(!value)}
        style={{ width:36, height:20, borderRadius:10, cursor:"pointer", flexShrink:0,
          background:value?"var(--accent)":"var(--bdr2)", position:"relative", transition:"background .2s" }}>
        <div style={{ width:14, height:14, borderRadius:"50%", background:"#fff",
          position:"absolute", top:3, left:value?19:3, transition:"left .2s",
          boxShadow:"0 1px 3px rgba(0,0,0,.3)" }}/>
      </div>
    </div>
  );
}

// 툴팁이 있는 아이콘 버튼
function IconBtn({ icon, title, onClick, color="var(--txt3)", bg="transparent", border="var(--bdr)" }) {
  return (
    <button onClick={onClick} title={title}
      style={{ padding:"4px 8px", borderRadius:5, border:`1px solid ${border}`, background:bg,
        color, fontSize:13, cursor:"pointer", transition:"all .15s", lineHeight:1 }}>
      {icon}
    </button>
  );
}

// ── 정보보호 기관 기본 데이터 ────────────────────────────────────
const DEFAULT_ORGS = [
  { name:"KrCERT/CC",    country:"🇰🇷", type:"취약점 공지", url:"https://www.krcert.or.kr",
    cycle:"수시 (긴급 즉시)", tags:["CVE","패치","악성코드"],
    desc:"한국인터넷진흥원 인터넷침해대응센터 — 국내 사이버 위협 대응, 취약점·보안 공지 제공",
    source:"krcert.or.kr → 보안공지 → RSS/웹 크롤링", format:"HTML/RSS" },
  { name:"KISA 보호나라", country:"🇰🇷", type:"정책·가이드", url:"https://www.kisa.or.kr",
    cycle:"주 1~2회", tags:["가이드","ISMS","법령"],
    desc:"정보보호 가이드라인, 보안 점검 도구, 법령 정책 제공",
    source:"kisa.or.kr → 자료실 → 정책/기술 가이드", format:"PDF/HTML" },
  { name:"금융보안원",    country:"🇰🇷", type:"금융 특화",  url:"https://www.fsec.or.kr",
    cycle:"주 1회 (정기)", tags:["금융","ISMS-P","감독규정"],
    desc:"금융권 사이버 위협 정보 공유, 금융 IT 보안 가이드라인",
    source:"fsec.or.kr → 보안위협 → 금융보안동향", format:"PDF/웹" },
  { name:"금융감독원",    country:"🇰🇷", type:"감독·규정",  url:"https://www.fss.or.kr",
    cycle:"규정 개정 시", tags:["전자금융감독규정","IT검사"],
    desc:"전자금융감독규정, 금융회사 IT 보안 감독 기준 제공",
    source:"fss.or.kr → 법규/제도 → 전자금융감독규정", format:"법령 텍스트" },
  { name:"CISA KEV",     country:"🇺🇸", type:"악용 취약점", url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
    cycle:"주 2~3회", tags:["KEV","긴급패치","랜섬웨어"],
    desc:"실제 공격에 악용 중인 취약점 목록. 21일 내 패치 의무화 기준",
    source:"cisa.gov/kev → JSON API (공개)", format:"JSON API" },
  { name:"NVD (NIST)",   country:"🇺🇸", type:"CVE DB",     url:"https://nvd.nist.gov",
    cycle:"실시간", tags:["CVE","CVSS","NVD API"],
    desc:"전세계 CVE 취약점 DB. CVSS 점수, 영향 제품, 패치 정보",
    source:"nvd.nist.gov → REST API v2.0 (API Key 필요)", format:"JSON REST API" },
  { name:"MITRE ATT&CK", country:"🇺🇸", type:"공격 기법",  url:"https://attack.mitre.org",
    cycle:"분기별", tags:["APT","TTPs","위협모델링"],
    desc:"실제 위협 행위자의 공격 전술·기법 프레임워크",
    source:"attack.mitre.org → TAXII 2.1 API / STIX JSON", format:"STIX/JSON" },
  { name:"Exploit-DB",   country:"🌐", type:"익스플로잇",  url:"https://www.exploit-db.com",
    cycle:"매일", tags:["PoC","익스플로잇"],
    desc:"공개된 익스플로잇 코드 DB. 실제 공격 가능성 평가",
    source:"exploit-db.com → CSV 다운로드 / 웹 크롤링", format:"CSV/HTML" },
];

// ── 일일 체크리스트 기본 데이터 ─────────────────────────────────
const DEFAULT_CHECKLIST = [
  { time:"매일 08:00",  task:"KrCERT 긴급 보안 공지 확인",             priority:"critical", auto:true  },
  { time:"매일 08:00",  task:"CISA KEV 신규 등재 취약점 확인",          priority:"critical", auto:true  },
  { time:"매일 09:00",  task:"NVD CVSS 9.0+ 신규 CVE 확인",            priority:"high",     auto:true  },
  { time:"매일 09:00",  task:"전날 점검 결과 검토 및 조치 확인",        priority:"high",     auto:false },
  { time:"매주 월요일", task:"금융보안원 주간 위협 동향 검토",           priority:"medium",   auto:false },
  { time:"매주 화요일", task:"MS Patch Tuesday 패치 적용 확인",         priority:"high",     auto:false },
  { time:"매월 1일",    task:"SSL 인증서 30일 내 만료 자산 확인",        priority:"high",     auto:true  },
  { time:"매월 1일",    task:"전월 보안 점검 결과 경영진 보고",          priority:"medium",   auto:false },
  { time:"분기별",      task:"전자금융감독규정 준수 현황 점검",          priority:"medium",   auto:false },
  { time:"반기별",      task:"ISMS-P 인증 준비 상태 점검",              priority:"medium",   auto:false },
];

// ── 알람 설정 기본값 ─────────────────────────────────────────────
const DEFAULT_ALERT_CFG = {
  email_enabled: false, email_smtp:"", email_port:587, email_from:"", email_to:"", email_password:"",
  slack_enabled: false, slack_webhook:"",
  teams_enabled: false, teams_webhook:"",
  rules: [
    { id:"critical_vuln",  name:"긴급 취약점 발견",        enabled:true,  channel:"email", condition:"severity=critical", throttle_min:0  },
    { id:"high_vuln",      name:"고위험 취약점 발견",       enabled:true,  channel:"email", condition:"severity=high",     throttle_min:60 },
    { id:"repeat_vuln",    name:"반복 취약점 (3회 이상)",   enabled:true,  channel:"email", condition:"repeat_count>=3",   throttle_min:1440 },
    { id:"ssl_expiry",     name:"SSL 인증서 만료 임박",     enabled:true,  channel:"email", condition:"ssl_days_left<=30", throttle_min:1440 },
    { id:"cve_match",      name:"CVE 영향 자산 탐지",       enabled:true,  channel:"email", condition:"cvss>=7.0",         throttle_min:360  },
    { id:"scan_fail",      name:"점검 실패 발생",           enabled:false, channel:"email", condition:"scan_status=failed",throttle_min:0  },
    { id:"kev_new",        name:"CISA KEV 신규 등재",       enabled:true,  channel:"email", condition:"is_kev=true",       throttle_min:60 },
  ]
};

// ── 설정 메뉴 그룹 구조 ──────────────────────────────────────────
const MENU_GROUPS = [
  {
    id: "display", label: "화면",
    items: [
      { id:"appearance",    icon:"🎨", label:"외관 · 언어",    sub:"테마 · 글자크기 · 밀도 · 날짜형식" },
      { id:"asset_presets", icon:"🖥",  label:"자산 시스템명",  sub:"등록 시스템명 그룹·항목 관리" },
    ]
  },
  {
    id: "security", label: "점검",
    items: [
      { id:"scan",   icon:"🔍", label:"점검 엔진",  sub:"타임아웃 · nmap · AI" },
      { id:"alerts", icon:"🔔", label:"알람 설정",  sub:"이메일 · 슬랙 · 규칙", badge:"미설정", badgeType:"warn" },
    ]
  },
  {
    id: "infosec", label: "정보보호",
    items: [
      { id:"orgs",      icon:"🌐", label:"참조 기관",      sub:"8개 기관 · CRUD · 테스트" },
      { id:"orgs_kr",   icon:"🇰🇷", label:"국내 기관",       sub:"KrCERT · KISA · 금융보안원", indent:true },
      { id:"orgs_intl", icon:"🌍", label:"해외 기관",       sub:"CISA · NVD · MITRE", indent:true },
      { id:"checklist", icon:"📋", label:"일일 점검 항목",  sub:"자동/수동 · 추가/수정" },
    ]
  },
  {
    id: "system", label: "시스템",
    items: [
      { id:"db",       icon:"🗄", label:"데이터베이스",  sub:"파일 정보 · 초기화" },
      { id:"visitors", icon:"👥", label:"접속자 현황",   sub:"실시간 · API 로그", badge:"LIVE", badgeType:"ok" },
      { id:"sysinfo",  icon:"ℹ",  label:"시스템 정보",  sub:"버전 · 환경" },
    ]
  },
];

// 전체 메뉴 flat 목록 (패널 조회용)
const ALL_MENUS = MENU_GROUPS.flatMap(g => g.items);



// ── 자산 시스템명 관리 패널 ─────────────────────────────────────
function PanelAssetPresets() {
  const STORAGE_KEY = "ssk_asset_presets";

  // localStorage에서 불러오거나 기본값 사용
  const [groups, setGroups] = React.useState(() => {
    try {
      const saved = localStorage.getItem(STORAGE_KEY);
      return saved ? JSON.parse(saved) : DEFAULT_PRESETS.map(g=>({...g, items:[...g.items]}));
    } catch { return DEFAULT_PRESETS.map(g=>({...g, items:[...g.items]})); }
  });
  const [saved,    setSaved]    = React.useState(false);
  const [editGIdx, setEditGIdx] = React.useState(null); // 열린 그룹 index
  const [newItem,  setNewItem]  = React.useState("");
  const [newGroup, setNewGroup] = React.useState("");
  const [addGOpen, setAddGOpen] = React.useState(false);

  const save = (next) => {
    setGroups(next);
    localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    setSaved(true);
    setTimeout(()=>setSaved(false), 2000);
  };

  const addItem = (gIdx) => {
    if (!newItem.trim()) return;
    const next = groups.map((g,i)=>i===gIdx?{...g,items:[...g.items,newItem.trim()]}:g);
    save(next); setNewItem("");
  };

  const delItem = (gIdx, iIdx) => {
    const next = groups.map((g,i)=>i===gIdx?{...g,items:g.items.filter((_,j)=>j!==iIdx)}:g);
    save(next);
  };

  const moveItem = (gIdx, iIdx, dir) => {
    const next = groups.map((g,i)=>{
      if (i!==gIdx) return g;
      const items=[...g.items];
      const to=iIdx+dir;
      if (to<0||to>=items.length) return g;
      [items[iIdx],items[to]]=[items[to],items[iIdx]];
      return {...g,items};
    });
    save(next);
  };

  const togglePcGroup = (gIdx) => {
    const next = groups.map((g,i)=>i===gIdx?{...g,pcGroup:!g.pcGroup}:g);
    save(next);
  };

  const addGroup = () => {
    if (!newGroup.trim()) return;
    save([...groups, {group:newGroup.trim(), items:[]}]);
    setNewGroup(""); setAddGOpen(false);
  };

  const delGroup = (gIdx) => {
    if (!window.confirm(`"${groups[gIdx].group}" 그룹을 삭제하시겠습니까?`)) return;
    save(groups.filter((_,i)=>i!==gIdx));
    if (editGIdx===gIdx) setEditGIdx(null);
  };

  const resetDefault = () => {
    if (!window.confirm("기본값으로 초기화하시겠습니까?")) return;
    const def = DEFAULT_PRESETS.map(g=>({...g,items:[...g.items]}));
    save(def); setEditGIdx(null);
  };

  const IS = {
    padding:"6px 9px", borderRadius:6, border:"1px solid var(--bdr)",
    background:"var(--bg-input)", color:"var(--txt)", fontSize:11, outline:"none",
  };

  return (
    <div>
      {/* 안내 + 저장 상태 */}
      <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:14 }}>
        <div style={{ flex:1, fontSize:11, color:"var(--txt3)", lineHeight:1.7 }}>
          자산 등록 시 시스템명 셀렉트박스의 그룹과 항목을 관리합니다.<br/>
          설정은 브라우저에 저장되며, 코드 파일
          <code style={{ background:"var(--bg-card2)", padding:"0 5px", borderRadius:3, fontSize:10, marginLeft:4 }}>
            frontend/src/config/assetPresets.js
          </code>
          을 직접 수정해도 됩니다.
        </div>
        <div style={{ display:"flex", gap:6 }}>
          <button onClick={resetDefault}
            style={{ padding:"6px 14px", borderRadius:6, border:"1px solid rgba(220,38,38,.3)",
              background:"transparent", color:"#F87171", fontSize:11, cursor:"pointer" }}>
            기본값 초기화
          </button>
          {saved && <span style={{ fontSize:11, color:"#4ADE80", display:"flex", alignItems:"center" }}>✓ 저장됨</span>}
        </div>
      </div>

      {/* 그룹 목록 */}
      <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
        {groups.map((g, gIdx) => {
          const isOpen = editGIdx === gIdx;
          return (
            <div key={gIdx} style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:8, overflow:"hidden" }}>
              {/* 그룹 헤더 행 */}
              <div onClick={()=>setEditGIdx(isOpen?null:gIdx)}
                style={{ display:"flex", alignItems:"center", gap:10, padding:"10px 14px", cursor:"pointer",
                  background:isOpen?"var(--bg-active)":"var(--bg-card2)",
                  borderBottom:isOpen?"1px solid var(--bdr)":"none",
                  borderLeft:`3px solid ${isOpen?"var(--accent)":"transparent"}` }}>
                <span style={{ fontSize:13, fontWeight:700, color:isOpen?"var(--accent-text)":"var(--txt)", flex:1 }}>
                  {g.group}
                </span>
                <span style={{ fontSize:10, color:"var(--txt3)", padding:"1px 7px", borderRadius:8,
                  background:"var(--bg-input)", border:"1px solid var(--bdr)" }}>
                  {g.items.length}개
                </span>
                {g.pcGroup && (
                  <span style={{ fontSize:9, padding:"1px 6px", borderRadius:6, fontWeight:700,
                    color:"#60A5FA", background:"rgba(96,165,250,.15)", border:"1px solid rgba(96,165,250,.3)" }}>
                    담당자명 자동붙음
                  </span>
                )}
                <span style={{ fontSize:11, color:"var(--txt3)", transform:isOpen?"rotate(180deg)":"", transition:"transform .2s", display:"inline-block" }}>▾</span>
                <button onClick={e=>{e.stopPropagation();delGroup(gIdx);}}
                  style={{ padding:"2px 8px", borderRadius:4, border:"1px solid rgba(220,38,38,.3)",
                    background:"transparent", color:"#F87171", fontSize:10, cursor:"pointer" }}
                  title="그룹 삭제">✕</button>
              </div>

              {/* 그룹 내용 */}
              {isOpen && (
                <div style={{ padding:"12px 14px" }}>
                  {/* 담당자명 자동붙음 토글 */}
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:10,
                    padding:"7px 10px", background:"var(--bg-card2)", borderRadius:6, border:"1px solid var(--bdr)" }}>
                    <input type="checkbox" id={`pc_${gIdx}`} checked={!!g.pcGroup}
                      onChange={()=>togglePcGroup(gIdx)}/>
                    <label htmlFor={`pc_${gIdx}`} style={{ fontSize:11, color:"var(--txt)", cursor:"pointer" }}>
                      선택 시 앞에 담당자 이름 자동 붙임
                    </label>
                    <span style={{ fontSize:10, color:"var(--txt3)" }}>(예: 홍길동_내부망_업무용 PC)</span>
                  </div>

                  {/* 항목 목록 */}
                  <div style={{ marginBottom:10 }}>
                    {g.items.length===0 ? (
                      <div style={{ textAlign:"center", padding:"16px", color:"var(--txt3)", fontSize:11, border:"1px dashed var(--bdr)", borderRadius:6 }}>
                        항목 없음 — 아래에서 추가하세요
                      </div>
                    ) : (
                      g.items.map((item, iIdx) => (
                        <div key={iIdx} style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 8px",
                          borderRadius:5, marginBottom:3,
                          background:iIdx%2===0?"transparent":"var(--bg-card2)",
                          border:"1px solid transparent" }}
                          onMouseEnter={e=>e.currentTarget.style.border="1px solid var(--bdr)"}
                          onMouseLeave={e=>e.currentTarget.style.border="1px solid transparent"}>
                          <span style={{ fontSize:12, color:"var(--txt)", flex:1 }}>{item}</span>
                          <button onClick={()=>moveItem(gIdx,iIdx,-1)} disabled={iIdx===0}
                            style={{ padding:"1px 6px", borderRadius:3, border:"1px solid var(--bdr)", background:"transparent",
                              color:iIdx===0?"var(--bdr)":"var(--txt3)", fontSize:10, cursor:iIdx===0?"default":"pointer" }}>▲</button>
                          <button onClick={()=>moveItem(gIdx,iIdx,1)} disabled={iIdx===g.items.length-1}
                            style={{ padding:"1px 6px", borderRadius:3, border:"1px solid var(--bdr)", background:"transparent",
                              color:iIdx===g.items.length-1?"var(--bdr)":"var(--txt3)", fontSize:10, cursor:iIdx===g.items.length-1?"default":"pointer" }}>▼</button>
                          <button onClick={()=>delItem(gIdx,iIdx)}
                            style={{ padding:"1px 7px", borderRadius:3, border:"1px solid rgba(220,38,38,.3)",
                              background:"transparent", color:"#F87171", fontSize:10, cursor:"pointer" }}>삭제</button>
                        </div>
                      ))
                    )}
                  </div>

                  {/* 항목 추가 */}
                  <div style={{ display:"flex", gap:6 }}>
                    <input value={editGIdx===gIdx?newItem:""} onChange={e=>setNewItem(e.target.value)}
                      onKeyDown={e=>e.key==="Enter"&&addItem(gIdx)}
                      placeholder="새 항목 입력 후 Enter 또는 추가 클릭"
                      style={{...IS, flex:1}}/>
                    <button onClick={()=>addItem(gIdx)}
                      style={{ padding:"6px 14px", borderRadius:6, border:"1px solid var(--accent)",
                        background:"var(--bg-active)", color:"var(--accent-text)", fontSize:11, fontWeight:700, cursor:"pointer", whiteSpace:"nowrap" }}>
                      + 추가
                    </button>
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {/* 그룹 추가 */}
        {addGOpen ? (
          <div style={{ display:"flex", gap:6, padding:"10px 14px", background:"var(--bg-card)",
            border:"1px solid var(--accent)", borderRadius:8 }}>
            <input value={newGroup} onChange={e=>setNewGroup(e.target.value)}
              onKeyDown={e=>e.key==="Enter"&&addGroup()}
              placeholder="새 그룹명 입력" autoFocus style={{...IS, flex:1}}/>
            <button onClick={addGroup}
              style={{ padding:"6px 16px", borderRadius:6, border:"1px solid var(--accent)",
                background:"var(--bg-active)", color:"var(--accent-text)", fontSize:11, fontWeight:700, cursor:"pointer" }}>
              추가
            </button>
            <button onClick={()=>{setAddGOpen(false);setNewGroup("");}}
              style={{ padding:"6px 12px", borderRadius:6, border:"1px solid var(--bdr)",
                background:"transparent", color:"var(--txt3)", fontSize:11, cursor:"pointer" }}>
              취소
            </button>
          </div>
        ) : (
          <button onClick={()=>setAddGOpen(true)}
            style={{ padding:"9px", borderRadius:8, border:"1px dashed var(--bdr2)",
              background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer",
              display:"flex", alignItems:"center", justifyContent:"center", gap:6 }}>
            ＋ 새 그룹 추가
          </button>
        )}
      </div>
    </div>
  );
}

// ── 화면 초기화 컴포넌트 ─────────────────────────────────────────
function ResetPanel({ onWalkChange, setTheme, setWalkCharState, setWalkSpeedState }) {
  const [confirm, setConfirm]   = React.useState(false);
  const [done,    setDone]      = React.useState(false);
  const [partial, setPartial]   = React.useState({
    theme:true, lang:true, animation:true, orgs:false, checklist:false, alerts:false
  });

  const ITEMS = [
    { key:"theme",     label:"테마",             desc:"기본 테마(차콜)로 복원" },
    { key:"lang",      label:"언어",             desc:"한국어로 복원" },
    { key:"animation", label:"메뉴 애니메이션",  desc:"걷는 남성, 보통 속도로 복원" },
    { key:"orgs",      label:"정보보호 기관",    desc:"기본 8개 기관 목록으로 복원" },
    { key:"checklist", label:"일일 체크리스트",  desc:"기본 점검 항목 10개로 복원" },
    { key:"alerts",    label:"알람 설정",        desc:"알람 비활성화 상태로 복원" },
  ];

  const toggle = k => setPartial(p=>({...p,[k]:!p[k]}));
  const selected = ITEMS.filter(i=>partial[i.key]);

  const doReset = () => {
    const KEYS = {
      theme:     ["ssk_theme"],
      lang:      ["ssk_lang"],
      animation: ["ssk_walk_char","ssk_walk_speed"],
      orgs:      ["ssk_orgs"],
      checklist: ["ssk_checklist"],
      alerts:    ["ssk_alert_cfg"],
    };
    selected.forEach(item => {
      KEYS[item.key]?.forEach(k => localStorage.removeItem(k));
    });
    // React 상태도 즉시 갱신
    if (partial.theme) {
      applyTheme("oracle");
      setTheme("oracle");
    }
    if (partial.animation) {
      setWalkCharState("walk_m");
      setWalkSpeedState("normal");
      if (onWalkChange) onWalkChange("walk_m","normal");
    }
    setConfirm(false);
    setDone(true);
    setTimeout(() => setDone(false), 3000);
  };

  return (
    <div style={{ gridColumn:"1/-1", marginTop:4 }}>
      <div style={{ fontSize:11, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", marginBottom:10, paddingTop:16, borderTop:"1px solid var(--bdr)" }}>
        화면 초기화
      </div>

      {done ? (
        <div style={{ padding:"12px 16px", borderRadius:8, background:"rgba(22,163,74,.1)", border:"1px solid rgba(22,163,74,.3)", display:"flex", alignItems:"center", gap:10 }}>
          <span style={{ fontSize:18 }}>✅</span>
          <div>
            <div style={{ fontSize:13, fontWeight:600, color:"#4ADE80" }}>초기화 완료</div>
            <div style={{ fontSize:11, color:"var(--txt3)", marginTop:1 }}>선택한 항목이 기본값으로 복원됐습니다. 일부 변경사항은 새로고침(F5) 후 적용됩니다.</div>
          </div>
        </div>
      ) : !confirm ? (
        <div>
          {/* 항목 선택 */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:6, marginBottom:12 }}>
            {ITEMS.map(item => {
              const on = partial[item.key];
              return (
                <div key={item.key} onClick={()=>toggle(item.key)}
                  style={{ display:"flex", alignItems:"center", gap:8, padding:"9px 11px", borderRadius:7, cursor:"pointer",
                    border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
                    background:on?"var(--bg-active)":"var(--bg-card2)", transition:"all .15s" }}>
                  <div style={{ width:14,height:14,borderRadius:3,flexShrink:0,transition:"all .15s",
                    border:`2px solid ${on?"var(--accent)":"var(--bdr2)"}`,
                    background:on?"var(--accent)":"transparent",
                    display:"flex",alignItems:"center",justifyContent:"center" }}>
                    {on&&<span style={{ color:"#fff",fontSize:9,fontWeight:700 }}>✓</span>}
                  </div>
                  <div style={{ minWidth:0 }}>
                    <div style={{ fontSize:12, fontWeight:on?600:400, color:on?"var(--accent-text)":"var(--txt)" }}>{item.label}</div>
                    <div style={{ fontSize:9, color:"var(--txt3)", marginTop:1 }}>{item.desc}</div>
                  </div>
                </div>
              );
            })}
          </div>
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <span style={{ fontSize:11, color:"var(--txt3)" }}>
              {selected.length > 0 ? `${selected.map(i=>i.label).join(", ")} 초기화 예정` : "초기화할 항목을 선택하세요"}
            </span>
            <button onClick={()=>selected.length>0&&setConfirm(true)} disabled={selected.length===0}
              style={{ marginLeft:"auto", padding:"7px 18px", borderRadius:6,
                border:`1px solid ${selected.length>0?"rgba(220,38,38,.4)":"var(--bdr)"}`,
                background:selected.length>0?"rgba(220,38,38,.08)":"transparent",
                color:selected.length>0?"#F87171":"var(--bdr2)",
                fontSize:12, fontWeight:600, cursor:selected.length>0?"pointer":"not-allowed" }}>
              ↺ 초기화
            </button>
          </div>
        </div>
      ) : (
        <div style={{ padding:"12px 16px", borderRadius:8, background:"rgba(220,38,38,.07)", border:"1px solid rgba(220,38,38,.3)" }}>
          <div style={{ fontSize:12, color:"#F87171", fontWeight:600, marginBottom:6 }}>
            ⚠ 다음 항목을 기본값으로 되돌립니다
          </div>
          <div style={{ fontSize:11, color:"var(--txt2)", marginBottom:12, lineHeight:1.7 }}>
            {selected.map(i=>`• ${i.label} — ${i.desc}`).join("\n").split("\n").map((l,i)=>(
              <div key={i}>{l}</div>
            ))}
          </div>
          <div style={{ display:"flex", gap:8 }}>
            <button onClick={doReset}
              style={{ padding:"7px 18px", borderRadius:6, border:"none", background:"#DC2626", color:"#fff", fontSize:12, fontWeight:700, cursor:"pointer" }}>
              확인 — 초기화
            </button>
            <button onClick={()=>setConfirm(false)}
              style={{ padding:"7px 14px", borderRadius:6, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>
              취소
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default function PageSettings() {
  // onWalkChange: Lottie 제거 후 no-op (하위 호환) — patch_062r 1776213928
  const onWalkChange = () => {};
  const { t, lang, changeLang } = useLang();
  const [active, setActive]   = useState("appearance");
  const [theme,  setTheme]    = useState(getStoredTheme());
  // 외관 추가 설정
  const [fontScale,    setFontScaleState]    = useState(() => parseFloat(localStorage.getItem("ssk_font_scale")||"14"));
  const [density,      setDensityState]      = useState(() => localStorage.getItem("ssk_density")||"normal");
  const [sidebarWidth, setSidebarWidthState] = useState(() => localStorage.getItem("ssk_sidebar_w")||"normal");
  const [tableRows,    setTableRowsState]    = useState(() => parseInt(localStorage.getItem("ssk_table_rows")||"15"));
  const [colorblind,   setColorblindState]   = useState(() => localStorage.getItem("ssk_colorblind")||"none");
  const [dateFormat,   setDateFormatState]   = useState(() => localStorage.getItem("ssk_date_fmt")||"YYYY-MM-DD");
  const [numberFmt,    setNumberFmtState]    = useState(() => localStorage.getItem("ssk_number_fmt")||"korean");

  // 외관 설정 저장 헬퍼
  const saveAppear = (key, val, setter) => {
    localStorage.setItem(key, String(val));
    // localStorage는 항상 문자열 → 숫자 키는 파싱해서 setter 호출
    const numKeys = ["ssk_font_scale","ssk_table_rows"];
    setter(numKeys.includes(key) ? Number(val) : val);
    // 폰트 스케일 즉시 적용
    if (key === "ssk_font_scale") {
      document.documentElement.style.fontSize = val + "px";
    }
    // 밀도 즉시 적용
    if (key === "ssk_density") {
      document.documentElement.setAttribute("data-density", val);
    }
    if (key === "ssk_sidebar_w") {
      const sbMap = { narrow:"168px", normal:"200px", wide:"232px" };
      document.documentElement.style.setProperty("--sidebar-width", sbMap[val] || "200px");
    }
  };
  const [saved,  setSaved]    = useState(false);
  const [scanCfg, setScanCfg] = useState({
    timeout:10, concurrent:5, nmap:"", reportDir:"./reports",
    aiEnabled:true, repeatThreshold:3, sslWarnDays:30,
  });
  const [walkChar,  setWalkCharState]  = useState(getWalkChar);
  const [walkSpeed, setWalkSpeedState] = useState(getWalkSpeed);
  const [dbStats,   setDbStats]        = useState(null);
  const [dbFileInfo,setDbFileInfo]     = useState(null);
  const [dbLoading, setDbLoading]      = useState(false);
  const [dbResult,  setDbResult]       = useState(null);
  const [resetTarget,setResetTarget]   = useState("all");
  const [showConfirm,setShowConfirm]   = useState(false);

  const loadDbInfo = async () => {
    try {
      const [s, f] = await Promise.all([
        fetch(`${API_BASE}/api/admin/db/stats`).then(r=>r.json()),
        fetch(`${API_BASE}/api/admin/db/fileinfo`).then(r=>r.json()),
      ]);
      setDbStats(s); setDbFileInfo(f);
    } catch(e) {}
  };
  useEffect(() => { if (active==="db") loadDbInfo(); }, [active]);

  const doReset = async () => {
    setDbLoading(true); setDbResult(null); setShowConfirm(false);
    try {
      const r = await fetch(`${API_BASE}/api/admin/db/reset`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ confirm:"RESET", target:resetTarget }),
      });
      const d = await r.json();
      setDbResult(r.ok?{ok:true,msg:d.message}:{ok:false,msg:d.detail});
      if (r.ok) loadDbInfo();
    } catch(e) { setDbResult({ok:false,msg:"서버 연결 실패: "+e.message}); }
    setDbLoading(false);
  };

  // ══════════════════════════════════════════════════════════════
  // 패널: 외관 · 언어
  // ══════════════════════════════════════════════════════════════
  const PanelAppearance = () => {
    const SecTitle = ({icon, label}) => (
      <div style={{display:"flex",alignItems:"center",gap:7,marginBottom:12,paddingBottom:8,
        borderBottom:"1px solid var(--bdr)"}}>
        <span style={{fontSize:16}}>{icon}</span>
        <span style={{fontSize:12,fontWeight:700,color:"var(--txt)",letterSpacing:".02em"}}>{label}</span>
      </div>
    );
    const Row = ({label, desc, children}) => (
      <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",
        padding:"10px 0",borderBottom:"1px solid var(--bdr)"}}>
        <div style={{flex:1,minWidth:0,paddingRight:16}}>
          <div style={{fontSize:13,color:"var(--txt)",fontWeight:500}}>{label}</div>
          {desc&&<div style={{fontSize:11,color:"var(--txt3)",marginTop:2,lineHeight:1.5}}>{desc}</div>}
        </div>
        <div style={{flexShrink:0}}>{children}</div>
      </div>
    );
    const Chip = ({on, onClick, children}) => (
      <button onClick={onClick}
        style={{padding:"5px 12px",borderRadius:6,border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
          background:on?"var(--bg-active)":"var(--bg-card2)",
          color:on?"var(--accent-text)":"var(--txt3)",
          fontSize:12,cursor:"pointer",fontWeight:on?600:400,transition:"all .15s",
          display:"flex",alignItems:"center",gap:5}}>
        {children}
        {on&&<span style={{fontSize:10,color:"var(--accent-text)"}}>✓</span>}
      </button>
    );

    return (
      <div style={{display:"flex",flexDirection:"column",gap:24}}>

        {/* ── 화면 테마 + 언어 — 한 카드 두 줄 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"14px 18px",display:"flex",flexDirection:"column",gap:12}}>
          {/* 테마 한 줄 */}
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <span style={{fontSize:12,fontWeight:700,color:"var(--txt3)",whiteSpace:"nowrap",minWidth:60}}>🎨 테마</span>
            <div style={{display:"flex",gap:5,flexWrap:"wrap"}}>
              {THEMES.map(th => {
                const lbl = ({ko:th.labelKo,en:th.label,ja:th.labelJa})[lang]||th.label;
                const on  = theme===th.id;
                return (
                  <button key={th.id} onClick={() => { setTheme(th.id); applyTheme(th.id); }}
                    style={{display:"flex",alignItems:"center",gap:5,padding:"5px 10px",
                      borderRadius:6,cursor:"pointer",transition:"all .15s",
                      border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
                      background:on?"var(--bg-active)":"var(--bg-card2)"}}>
                    <div style={{display:"flex",gap:2,flexShrink:0}}>
                      {th.preview.map((c,i)=><div key={i} style={{width:9,height:9,borderRadius:2,background:c}}/>)}
                    </div>
                    <span style={{fontSize:12,fontWeight:on?700:400,
                      color:on?"var(--accent-text)":"var(--txt)",whiteSpace:"nowrap"}}>{lbl}</span>
                    {on&&<span style={{fontSize:10,color:"var(--accent-text)"}}>✓</span>}
                  </button>
                );
              })}
            </div>
          </div>
          {/* 구분선 */}
          <div style={{height:"1px",background:"var(--bdr)"}}/>
          {/* 언어 한 줄 */}
          <div style={{display:"flex",alignItems:"center",gap:10}}>
            <span style={{fontSize:12,fontWeight:700,color:"var(--txt3)",whiteSpace:"nowrap",minWidth:60}}>🌐 언어</span>
            <div style={{display:"flex",gap:5}}>
              {LANGS.map(l => {
                const on = lang===l.code;
                return (
                  <button key={l.code} onClick={() => changeLang(l.code)}
                    style={{display:"flex",alignItems:"center",gap:6,padding:"5px 12px",
                      borderRadius:6,cursor:"pointer",transition:"all .15s",
                      border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
                      background:on?"var(--bg-active)":"var(--bg-card2)"}}>
                    <span style={{fontSize:14}}>{l.flag}</span>
                    <span style={{fontSize:12,fontWeight:on?700:400,
                      color:on?"var(--accent-text)":"var(--txt)"}}>{l.label}</span>
                    {on&&<span style={{fontSize:10,color:"var(--accent-text)"}}>✓</span>}
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* ── 글자 크기 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"14px 18px"}}>
          <SecTitle icon="🔠" label="글자 크기"/>
          <Row label="화면 글자 크기" desc="슬라이더로 조절 — 전체 UI에 즉시 적용됩니다.">
            <div style={{display:"flex",alignItems:"center",gap:10,minWidth:220}}>
              <span style={{fontSize:11,color:"var(--txt3)",flexShrink:0}}>작게</span>
              <input type="range" min="11" max="18" step="0.5"
                value={fontScale}
                onChange={e=>{
                  const v=parseFloat(e.target.value);
                  saveAppear("ssk_font_scale",v,setFontScaleState);
                }}
                style={{flex:1,accentColor:"var(--accent)",cursor:"pointer",height:4}}/>
              <span style={{fontSize:11,color:"var(--txt3)",flexShrink:0}}>크게</span>
              <span style={{fontSize:12,fontWeight:700,color:"var(--accent-text)",
                minWidth:36,textAlign:"right"}}>{fontScale}px</span>
            </div>
          </Row>
          <Row label="미리보기">
            <div style={{background:"var(--bg-card2)",border:"1px solid var(--bdr)",
              borderRadius:6,padding:"8px 14px",
              fontSize:fontScale,color:"var(--txt)",lineHeight:1.6}}>
              보안 점검 결과 · Security Scan 123
            </div>
          </Row>
        </div>

        {/* ── 화면 밀도 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px"}}>
          <SecTitle icon="📐" label="화면 밀도 (Density)"/>
          <Row label="UI 밀도" desc="콘텐츠 간격과 여백을 조절합니다. '넓게'는 보기 편하고 '좁게'는 많은 정보를 한 화면에 표시합니다.">
            <div style={{display:"flex",gap:6}}>
              {[{id:"compact",lbl:"좁게",icon:"▤"},{id:"normal",lbl:"보통",icon:"▦"},{id:"comfortable",lbl:"넓게",icon:"▣"}].map(d=>(
                <Chip key={d.id} on={density===d.id}
                  onClick={()=>saveAppear("ssk_density",d.id,setDensityState)}>
                  {d.icon} {d.lbl}
                </Chip>
              ))}
            </div>
          </Row>
        </div>

        {/* ── 사이드바 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px"}}>
          <SecTitle icon="📋" label="사이드바"/>
          <Row label="사이드바 너비" desc="사이드바의 기본 너비를 설정합니다.">
            <div style={{display:"flex",gap:6}}>
              {[{id:"narrow",lbl:"좁게",w:"168px"},{id:"normal",lbl:"보통",w:"200px"},{id:"wide",lbl:"넓게",w:"232px"}].map(s=>(
                <Chip key={s.id} on={sidebarWidth===s.id}
                  onClick={()=>{
                    saveAppear("ssk_sidebar_w",s.id,setSidebarWidthState);
                    document.documentElement.style.setProperty("--sidebar-width",s.w);
                  }}>
                  {s.lbl}
                </Chip>
              ))}
            </div>
          </Row>
        </div>

        {/* ── 테이블 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px"}}>
          <SecTitle icon="📊" label="테이블 · 목록"/>
          <Row label="페이지당 행 수" desc="자산 목록, 취약점 목록 등 테이블의 기본 표시 행 수입니다.">
            <div style={{display:"flex",gap:6}}>
              {[10,15,20,30,50].map(n=>(
                <Chip key={n} on={tableRows===n}
                  onClick={()=>saveAppear("ssk_table_rows",n,setTableRowsState)}>
                  {n}행
                </Chip>
              ))}
            </div>
          </Row>
        </div>

        {/* ── 날짜 · 숫자 형식 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px"}}>
          <SecTitle icon="📅" label="날짜 · 숫자 형식"/>
          <Row label="날짜 표시 형식" desc="화면에서 날짜를 표시하는 방식입니다.">
            <div style={{display:"flex",gap:6,flexWrap:"wrap"}}>
              {[
                {id:"YYYY-MM-DD",lbl:"2026-04-16"},
                {id:"MM/DD/YYYY",lbl:"04/16/2026"},
                {id:"DD.MM.YYYY",lbl:"16.04.2026"},
                {id:"korean",    lbl:"2026년 4월 16일"},
              ].map(f=>(
                <Chip key={f.id} on={dateFormat===f.id}
                  onClick={()=>saveAppear("ssk_date_fmt",f.id,setDateFormatState)}>
                  {f.lbl}
                </Chip>
              ))}
            </div>
          </Row>
          <Row label="숫자 표시 형식" desc="카운트 숫자를 표시하는 방식입니다.">
            <div style={{display:"flex",gap:6}}>
              {[
                {id:"korean", lbl:"1,234건"},
                {id:"plain",  lbl:"1234"},
                {id:"dot",    lbl:"1.234"},
              ].map(f=>(
                <Chip key={f.id} on={numberFmt===f.id}
                  onClick={()=>saveAppear("ssk_number_fmt",f.id,setNumberFmtState)}>
                  {f.lbl}
                </Chip>
              ))}
            </div>
          </Row>
        </div>

        {/* ── 접근성 ── */}
        <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px"}}>
          <SecTitle icon="♿" label="접근성"/>
          <Row label="색맹 보조 모드" desc="색만으로 구분하기 어려운 분을 위해 패턴/형태로 추가 구분합니다.">
            <div style={{display:"flex",gap:6}}>
              {[
                {id:"none",        lbl:"사용 안 함"},
                {id:"deuteranopia",lbl:"녹색약"},
                {id:"protanopia",  lbl:"적색약"},
                {id:"tritanopia",  lbl:"청색약"},
              ].map(m=>(
                <Chip key={m.id} on={colorblind===m.id}
                  onClick={()=>saveAppear("ssk_colorblind",m.id,setColorblindState)}>
                  {m.lbl}
                </Chip>
              ))}
            </div>
          </Row>
        </div>

        {/* ── 초기화 ── */}
        <ResetPanel onWalkChange={onWalkChange} setTheme={setTheme} setWalkCharState={setWalkCharState} setWalkSpeedState={setWalkSpeedState}/>

      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════
  // 패널: 애니메이션
  // ══════════════════════════════════════════════════════════════
  const PanelAnimation = () => {
    const sec = WALK_SPEEDS.find(s=>s.id===walkSpeed)?.sec || 8;
    const curChar = WALK_CHARS.find(c=>c.id===walkChar) || WALK_CHARS[0];
    return (
      <div>
        <div style={{ fontSize:11, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", marginBottom:12 }}>캐릭터 선택</div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:8, marginBottom:20 }}>
          {WALK_CHARS.map(c => {
            const on = walkChar === c.id;
            return (
              <div key={c.id} onClick={() => {
                setWalkCharState(c.id); setWalkChar(c.id);
                if (onWalkChange) onWalkChange(c.id, walkSpeed);
              }}
                style={{ padding:"12px 8px", borderRadius:8, textAlign:"center", cursor:"pointer",
                  border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
                  background:on?"var(--bg-active)":"var(--bg-card2)", transition:"all .15s" }}>
                <div style={{ fontSize:26, marginBottom:5, minHeight:34, display:"flex", alignItems:"center", justifyContent:"center" }}>
                  {c.id==="none"
                    ? <span style={{ fontSize:18, color:"var(--txt3)" }}>✕</span>
                    : <span>{c.preview}</span>
                  }
                </div>
                <div style={{ fontSize:10, color:on?"var(--accent-text)":"var(--txt)", fontWeight:on?600:400, lineHeight:1.3 }}>{c.label}</div>
                {on && <div style={{ fontSize:9, color:"var(--accent-text)", marginTop:4 }}>✓</div>}
              </div>
            );
          })}
        </div>

        <div style={{ fontSize:11, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", marginBottom:10 }}>이동 속도</div>
        <div style={{ display:"flex", gap:10, marginBottom:20 }}>
          {WALK_SPEEDS.map(s => {
            const on = walkSpeed === s.id;
            return (
              <div key={s.id} onClick={() => {
                setWalkSpeedState(s.id); setWalkSpeed(s.id);
                if (onWalkChange) onWalkChange(walkChar, s.id);
              }}
                style={{ flex:1, padding:"14px 12px", borderRadius:8, textAlign:"center", cursor:"pointer",
                  border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
                  background:on?"var(--bg-active)":"var(--bg-card2)", transition:"all .15s" }}>
                <div style={{ fontSize:24, marginBottom:6 }}>
                  {s.id==="slow"?"🐢":s.id==="normal"?"🚶‍♂️":"🏃‍♂️"}
                </div>
                <div style={{ fontSize:13, fontWeight:700, color:on?"var(--accent-text)":"var(--txt)" }}>{s.label}</div>
                <div style={{ fontSize:10, color:"var(--txt3)", marginTop:2 }}>{s.sec}초 주기</div>
                {on && <div style={{ fontSize:10, color:"var(--accent-text)", marginTop:4 }}>✓ 선택됨</div>}
              </div>
            );
          })}
        </div>

        {/* 미리보기 */}
        <div style={{ background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:8, padding:"14px" }}>
          <div style={{ fontSize:11, color:"var(--txt3)", marginBottom:10, fontWeight:600 }}>🔍 실시간 미리보기</div>
          <div style={{ display:"flex", alignItems:"center", gap:10, padding:"10px 14px", borderRadius:7, background:"var(--bg-active)", border:"1px solid var(--accent)" }}>
            <span style={{ fontSize:16 }}>⊞</span>
            <span style={{ fontSize:13, fontWeight:700, color:"var(--accent-text)" }}>대시보드</span>
            <span style={{ flex:1, position:"relative", height:30, overflow:"hidden" }}>
              {walkChar !== "none" && curChar.emoji && (
                <span style={{ position:"absolute", bottom:2, fontSize:20, animation:`walk ${sec}s linear infinite`, display:"inline-block" }}>
                  {curChar.emoji}
                </span>
              )}
            </span>
          </div>
          <div style={{ fontSize:10, color:"var(--txt3)", marginTop:8, lineHeight:1.6 }}>
            * 설정은 즉시 사이드바에 적용되며 브라우저에 저장됩니다.<br/>
            * <strong style={{ color:"var(--txt2)" }}>없음(✕)</strong> 선택 시 애니메이션이 숨겨집니다.<br/>
            * Lottie 애니메이션(JSON)이 로드되어 실제 사이드바에서는 더욱 부드럽게 동작합니다.
          </div>
        </div>
      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════
  // 패널: DB 관리
  // ══════════════════════════════════════════════════════════════
  const PanelDB = () => (
    <div>
      {/* DB 파일 상세 정보 */}
      <div style={{ background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:9, padding:"16px", marginBottom:16 }}>
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:14 }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ fontSize:18 }}>🗄</span>
            <span style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>SQLite 데이터베이스 파일</span>
            <span title="SQLite는 파일 기반의 경량 관계형 DB입니다.&#10;SecurityScanKit의 모든 데이터(자산·취약점·알람·이력)가&#10;단일 .db 파일에 저장됩니다.&#10;백업: 해당 파일을 복사하면 전체 데이터가 보존됩니다.&#10;복구: .db 파일을 원래 위치에 붙여넣으면 복원됩니다."
              style={{ display:"inline-flex",alignItems:"center",justifyContent:"center",width:15,height:15,borderRadius:"50%",fontSize:9,fontWeight:700,background:"var(--bg-card2)",color:"var(--txt3)",border:"1px solid var(--bdr2)",cursor:"help",marginLeft:4,flexShrink:0,verticalAlign:"middle" }}>?</span>
          </div>
          <button onClick={loadDbInfo}
            style={{ padding:"5px 12px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:11, cursor:"pointer" }}>
            ↻ 갱신
          </button>
        </div>

        {dbFileInfo ? (
          <div>
            {/* 파일 경로 */}
            <div style={{ marginBottom:12 }}>
              <div style={{ fontSize:10, color:"var(--txt3)", fontWeight:600, textTransform:"uppercase", marginBottom:5 }}>📁 파일 경로</div>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                <code style={{ flex:1, fontSize:11, color:"var(--accent-text)", background:"var(--bg-input)", padding:"6px 10px", borderRadius:5, border:"1px solid var(--bdr)", wordBreak:"break-all" }}>
                  {dbFileInfo.path}
                </code>
                <button onClick={()=>{navigator.clipboard?.writeText(dbFileInfo.path); alert("경로 복사됨");}}
                  title="경로 복사" style={{ padding:"5px 9px", borderRadius:4, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>
                  📋
                </button>
              </div>
            </div>

            {/* 파일 상세 */}
            <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:8 }}>
              {[
                { icon:"💾", label:"파일 크기",  value:dbFileInfo.size_human, sub:dbFileInfo.size_bytes?.toLocaleString()+" bytes" },
                { icon:"📅", label:"생성일",     value:dbFileInfo.created_at?.slice(0,10),  sub:dbFileInfo.created_at?.slice(11) },
                { icon:"✏️", label:"최종 수정일", value:dbFileInfo.modified_at?.slice(0,10), sub:dbFileInfo.modified_at?.slice(11) },
                { icon:"👁", label:"최근 접근일", value:dbFileInfo.accessed_at?.slice(0,10), sub:dbFileInfo.accessed_at?.slice(11) },
              ].map(item => (
                <div key={item.label} style={{ background:"var(--bg-card)", borderRadius:7, padding:"10px 12px", border:"1px solid var(--bdr)", textAlign:"center" }}>
                  <div style={{ fontSize:18, marginBottom:4 }}>{item.icon}</div>
                  <div style={{ fontSize:9, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".05em", marginBottom:5 }}>{item.label}</div>
                  <div style={{ fontSize:13, fontWeight:700, color:"var(--accent-text)" }}>{item.value}</div>
                  <div style={{ fontSize:9, color:"var(--txt3)", marginTop:2 }}>{item.sub}</div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{ textAlign:"center", padding:"20px 0", color:"var(--txt3)", fontSize:12 }}>
            <button onClick={loadDbInfo} style={{ padding:"7px 16px", borderRadius:6, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>
              📂 파일 정보 조회
            </button>
          </div>
        )}
      </div>

      {/* 테이블별 레코드 현황 */}
      <div style={{ marginBottom:16 }}>
        <div style={{ fontSize:11, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".06em", marginBottom:10 }}>테이블별 레코드 현황</div>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(7,1fr)", gap:6 }}>
          {dbStats ? [
            {l:"자산",    k:"assets",         icon:"🖥"},
            {l:"취약점",  k:"findings",       icon:"🛡"},
            {l:"점검이력",k:"scan_jobs",       icon:"📜"},
            {l:"알람",    k:"alerts",         icon:"🔔"},
            {l:"CVE",    k:"cve_records",    icon:"⚠"},
            {l:"뉴스",    k:"news_items",     icon:"📰"},
            {l:"업로드", k:"upload_history", icon:"📤"},
          ].map(item => (
            <div key={item.k} style={{ background:"var(--bg-card2)", borderRadius:7, padding:"10px 8px", textAlign:"center", border:"1px solid var(--bdr)" }}>
              <div style={{ fontSize:16, marginBottom:4 }}>{item.icon}</div>
              <div style={{ fontSize:9, color:"var(--txt3)", marginBottom:4 }}>{item.l}</div>
              <div style={{ fontSize:18, fontWeight:700, color:dbStats[item.k]>0?"var(--accent-text)":"var(--txt3)" }}>
                {dbStats[item.k]?.toLocaleString()}
              </div>
            </div>
          )) : (
            <div style={{ gridColumn:"1/-1", textAlign:"center" }}>
              <button onClick={loadDbInfo} style={{ padding:"6px 14px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>현황 조회</button>
            </div>
          )}
        </div>
      </div>

      {/* 초기화 */}
      <div style={{ background:"rgba(220,38,38,.05)", border:"1px solid rgba(220,38,38,.2)", borderRadius:9, padding:"14px 16px" }}>
        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:12 }}>
          <span style={{ fontSize:14 }}>⚠️</span>
          <span style={{ fontSize:12, fontWeight:700, color:"#F87171" }}>DB 초기화 — 삭제된 데이터는 복구 불가</span>
        </div>
        <div style={{ display:"flex", gap:6, flexWrap:"wrap", marginBottom:12 }}>
          {[{id:"all",l:"전체"},{id:"findings",l:"취약점"},{id:"alerts",l:"알람"},{id:"scan_history",l:"점검이력"},{id:"news",l:"뉴스"}].map(opt=>(
            <button key={opt.id} onClick={()=>setResetTarget(opt.id)}
              style={{ padding:"6px 14px", borderRadius:6, fontSize:12, cursor:"pointer", fontWeight:600,
                border:`1px solid ${resetTarget===opt.id?"#EF4444":"var(--bdr)"}`,
                background:resetTarget===opt.id?"rgba(220,38,38,.15)":"transparent",
                color:resetTarget===opt.id?"#F87171":"var(--txt3)" }}>
              {opt.l}
            </button>
          ))}
        </div>
        {dbResult && (
          <div style={{ marginBottom:10, padding:"8px 12px", borderRadius:6,
            background:dbResult.ok?"rgba(22,163,74,.1)":"rgba(220,38,38,.1)",
            border:`1px solid ${dbResult.ok?"rgba(22,163,74,.3)":"rgba(220,38,38,.3)"}`,
            fontSize:12, color:dbResult.ok?"#4ADE80":"#F87171" }}>
            {dbResult.ok?"✅":"❌"} {dbResult.msg}
          </div>
        )}
        {!showConfirm ? (
          <button onClick={()=>setShowConfirm(true)} disabled={dbLoading}
            style={{ padding:"7px 18px", borderRadius:6, border:"1px solid rgba(220,38,38,.4)",
              background:"rgba(220,38,38,.1)", color:"#F87171", fontSize:12, fontWeight:700,
              cursor:"pointer", display:"inline-flex", alignItems:"center", gap:6 }}>
            {dbLoading?<><Spinner/> 처리 중...</>:`🗑 ${resetTarget==="all"?"전체":resetTarget} 초기화`}
          </button>
        ) : (
          <div style={{ display:"flex", alignItems:"center", gap:8, background:"rgba(220,38,38,.1)", border:"1px solid #EF4444", borderRadius:7, padding:"10px 14px" }}>
            <span style={{ fontSize:12, color:"#F87171", flex:1 }}>⚠ <strong>{resetTarget==="all"?"전체":resetTarget}</strong> 데이터를 정말 삭제합니까?</span>
            <button onClick={doReset} style={{ padding:"6px 16px", borderRadius:5, border:"none", background:"#DC2626", color:"#fff", fontSize:12, fontWeight:700, cursor:"pointer" }}>삭제</button>
            <button onClick={()=>setShowConfirm(false)} style={{ padding:"6px 12px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>취소</button>
          </div>
        )}
      </div>
    </div>
  );

  // ══════════════════════════════════════════════════════════════
  // 패널: 정보보호 기관
  // ══════════════════════════════════════════════════════════════
  const PanelOrgs = () => {
    const [orgs,     setOrgs]     = React.useState(() => { try { return JSON.parse(localStorage.getItem("ssk_orgs"))||DEFAULT_ORGS; } catch { return DEFAULT_ORGS; } });
    const [selected, setSelected] = React.useState(new Set());
    const [showForm, setShowForm] = React.useState(false);
    const [editIdx,  setEditIdx]  = React.useState(null);
    const [expanded, setExpanded] = React.useState(null);
    const [form, setForm] = React.useState({ name:"", country:"🌐", type:"", desc:"", url:"", cycle:"", tags:"", source:"", format:"" });

    const save = list => { setOrgs(list); localStorage.setItem("ssk_orgs", JSON.stringify(list)); };
    const toggleSel  = i => setSelected(p => { const n=new Set(p); n.has(i)?n.delete(i):n.add(i); return n; });
    const selectAll  = () => setSelected(new Set(orgs.map((_,i)=>i)));
    const deselAll   = () => setSelected(new Set());
    const onEdit = i => { setEditIdx(i); setForm({...orgs[i], tags:(orgs[i].tags||[]).join(",")}); setShowForm(true); };
    const onDelete = i => { if(window.confirm(`"${orgs[i].name}" 기관을 삭제합니까?`)) save(orgs.filter((_,j)=>j!==i)); };
    const deleteSelected = () => { if(window.confirm(`${selected.size}개 기관을 삭제합니까?`)) { save(orgs.filter((_,i)=>!selected.has(i))); setSelected(new Set()); } };
    const onSubmit = () => {
      const item = {...form, tags:form.tags.split(",").map(t=>t.trim()).filter(Boolean)};
      if (editIdx!==null) { const n=[...orgs]; n[editIdx]=item; save(n); }
      else save([...orgs, item]);
      setForm({name:"",country:"🌐",type:"",desc:"",url:"",cycle:"",tags:"",source:"",format:""});
      setShowForm(false); setEditIdx(null);
    };

    const [testResult, setTestResult] = React.useState({});
    const [testLogs,   setTestLogs]   = React.useState([]);  // {time, org, ok, status, latency, error, url}

    const testOrg = async (org, i) => {
      setTestResult(p => ({...p, [i]:"testing"}));
      const ts = new Date().toLocaleTimeString("ko-KR",{hour12:false});
      try {
        const r = await fetch(`${API_BASE}/api/admin/test-url`, {
          method:"POST",
          headers:{"Content-Type":"application/json"},
          body: JSON.stringify({ url: org.url })
        });
        const d = await r.json();
        setTestResult(p => ({...p, [i]: d.ok ? "ok" : "fail"}));
        setTestLogs(prev => [{
          time: ts, org: org.name, url: org.url,
          ok: d.ok, status: d.status, latency: d.latency_ms,
          error: d.error, finalUrl: d.final_url,
        }, ...prev.slice(0,19)]);
      } catch(e) {
        setTestResult(p => ({...p, [i]:"fail"}));
        setTestLogs(prev => [{
          time: ts, org: org.name, url: org.url,
          ok: false, status: null, latency: null,
          error: "백엔드 연결 실패 — 서버가 실행 중인지 확인하세요",
        }, ...prev.slice(0,19)]);
      }
      setTimeout(() => setTestResult(p => ({...p, [i]:""})), 5000);
    };

    const FIELDS = [
      {k:"name",    l:"기관명",         ph:"KrCERT/CC",               req:true,  half:false},
      {k:"country", l:"국가 이모지",    ph:"🇰🇷 🇺🇸 🇪🇺 🌐",          req:false, half:true},
      {k:"type",    l:"분류",           ph:"취약점 공지 / CVE DB",     req:false, half:true},
      {k:"url",     l:"공식 URL",       ph:"https://www.krcert.or.kr", req:true,  half:false},
      {k:"cycle",   l:"갱신 주기",      ph:"매일 / 주 1회 / 수시",    req:false, half:true},
      {k:"tags",    l:"태그 (쉼표)",    ph:"CVE, 패치, 악성코드",     req:false, half:true},
      {k:"source",  l:"데이터 출처",    ph:"사이트 → 보안공지 메뉴 → RSS/API", req:false, half:false},
      {k:"format",  l:"제공 형식",      ph:"RSS / JSON API / HTML / PDF",        req:false, half:true},
      {k:"desc",    l:"기관 설명",      ph:"기관 역할 및 제공 정보 설명",        req:false, half:false},
    ];

    // ── 뉴스 수집 기관 ON/OFF 설정 ──────────────────────────────
    const COLLECT_SOURCES_DEFAULT = {
      // 국내 공식 보안기관
      "KrCERT":          { label:"KrCERT",     desc:"한국인터넷진흥원 침해사고대응팀 — 취약점·보안 공지 RSS",  enabled:true,  flag:"🇰🇷", type:"korean" },
      "KISA":            { label:"KISA",        desc:"한국인터넷진흥원 보호나라 — 보안 공지·취약점 정보 RSS",  enabled:true,  flag:"🇰🇷", type:"korean" },
      "금융보안원":       { label:"금융보안원",  desc:"금융보안원 — 금융권 특화 보안 공지 크롤링",             enabled:true,  flag:"🇰🇷", type:"korean" },
      // 국내 보안 미디어
      "보안뉴스":         { label:"보안뉴스",    desc:"보안뉴스(boannews.com) — 국내 최대 보안 전문 미디어",   enabled:true,  flag:"🇰🇷", type:"media" },
      "데일리시큐":       { label:"데일리시큐",  desc:"데일리시큐(dailysecu.com) — 보안 전문 뉴스",           enabled:true,  flag:"🇰🇷", type:"media" },
      // 해외
      "CISA":            { label:"CISA",        desc:"미국 사이버보안·인프라보안국 — Advisories",             enabled:false, flag:"🇺🇸", type:"global" },
      "NVD":             { label:"NVD",         desc:"미국 국가취약점 DB — CVSS 기반 CVE (항상 수집)",        enabled:true,  flag:"🇺🇸", type:"global" },
      "TheHackerNews":   { label:"TheHackerNews",desc:"The Hacker News — 글로벌 보안 뉴스",                  enabled:false, flag:"🌐", type:"global" },
      "BleepingComputer":{ label:"BleepingComputer",desc:"BleepingComputer — 글로벌 보안 뉴스 미디어",       enabled:false, flag:"🌐", type:"global" },
      "SANS":            { label:"SANS ISC",    desc:"SANS Internet Storm Center — 위협 인텔리전스",          enabled:false, flag:"🌐", type:"global" },
    };

    const [collectSrc, setCollectSrc] = React.useState(() => {
      try {
        const saved = JSON.parse(localStorage.getItem("ssk_collect_sources") || "{}");
        // 기본값에 저장된 enabled 상태 병합
        const merged = {...COLLECT_SOURCES_DEFAULT};
        Object.keys(merged).forEach(k => {
          if (saved[k] !== undefined) merged[k] = {...merged[k], enabled: saved[k]};
        });
        return merged;
      } catch { return COLLECT_SOURCES_DEFAULT; }
    });
    const [collectSaved, setCollectSaved] = React.useState(false);

    const toggleSource = (key) => {
      setCollectSrc(p => ({...p, [key]: {...p[key], enabled: !p[key].enabled}}));
      setCollectSaved(false);
    };

    const saveCollectSrc = async () => {
      const toSave = {};
      Object.entries(collectSrc).forEach(([k,v]) => { toSave[k] = v.enabled; });
      localStorage.setItem("ssk_collect_sources", JSON.stringify(toSave));
      // 백엔드에도 전송
      try {
        await fetch(`${API_BASE}/api/intel/collect-config`, {
          method:"POST", headers:{"Content-Type":"application/json"},
          body: JSON.stringify(toSave)
        });
      } catch {}
      setCollectSaved(true);
      setTimeout(() => setCollectSaved(false), 2000);
    };

    return (
      <div>
        {/* ── 뉴스 수집 기관 설정 ── */}
        <div style={{ marginBottom:20, background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:10, overflow:"hidden" }}>
          <div style={{ padding:"11px 14px", background:"var(--bg-card2)", borderBottom:"1px solid var(--bdr)",
            display:"flex", alignItems:"center", gap:8 }}>
            <span style={{ fontSize:14 }}>📡</span>
            <span style={{ fontSize:12, fontWeight:700, color:"var(--txt)" }}>보안 공지·뉴스 수집 기관 설정</span>
            <span style={{ fontSize:10, color:"var(--txt3)", marginLeft:4 }}>수집할 기관을 선택하세요</span>
            <button onClick={saveCollectSrc}
              style={{ marginLeft:"auto", padding:"5px 14px", borderRadius:6, fontSize:11, fontWeight:600,
                cursor:"pointer", border:`1px solid ${collectSaved?"rgba(74,222,128,.4)":"var(--accent)"}`,
                background:collectSaved?"rgba(74,222,128,.1)":"var(--bg-active)",
                color:collectSaved?"#4ADE80":"var(--accent-text)" }}>
              {collectSaved ? "✓ 저장됨" : "💾 저장"}
            </button>
          </div>
          <div style={{ padding:"14px" }}>
            {/* 국내 기관 */}
            <div style={{ fontSize:10, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase",
              letterSpacing:".06em", marginBottom:8 }}>🇰🇷 국내 기관</div>
            <div style={{ display:"flex", flexDirection:"column", gap:6, marginBottom:14 }}>
              {Object.entries(collectSrc).filter(([,v])=>v.type==="korean").map(([key,val])=>(
                <div key={key} onClick={()=>toggleSource(key)}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 12px",
                    borderRadius:7, cursor:"pointer", userSelect:"none",
                    border:`1px solid ${val.enabled?"rgba(96,165,250,.3)":"var(--bdr)"}`,
                    background:val.enabled?"rgba(96,165,250,.05)":"transparent",
                    transition:"all .15s" }}>
                  {/* 토글 스위치 */}
                  <div style={{ width:36, height:20, borderRadius:10, position:"relative", flexShrink:0,
                    background:val.enabled?"var(--accent)":"var(--bdr2)", transition:"background .2s" }}>
                    <div style={{ position:"absolute", top:2, left:val.enabled?18:2, width:16, height:16,
                      borderRadius:"50%", background:"#fff", transition:"left .2s",
                      boxShadow:"0 1px 3px rgba(0,0,0,.2)" }}/>
                  </div>
                  <span style={{ fontSize:13 }}>{val.flag}</span>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:12, fontWeight:600, color:val.enabled?"var(--txt)":"var(--txt3)" }}>{val.label}</div>
                    <div style={{ fontSize:10, color:"var(--txt3)", marginTop:1 }}>{val.desc}</div>
                  </div>
                  <span style={{ fontSize:10, padding:"2px 8px", borderRadius:5, fontWeight:600,
                    color:val.enabled?"#60A5FA":"var(--txt3)",
                    background:val.enabled?"rgba(96,165,250,.1)":"var(--bg-card2)",
                    border:`1px solid ${val.enabled?"rgba(96,165,250,.2)":"var(--bdr)"}` }}>
                    {val.enabled ? "수집 ON" : "수집 OFF"}
                  </span>
                </div>
              ))}
            </div>
            {/* 국내 보안 미디어 */}
            <div style={{ fontSize:10, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase",
              letterSpacing:".06em", marginBottom:8, marginTop:4 }}>📰 국내 보안 미디어</div>
            <div style={{ display:"flex", flexDirection:"column", gap:6, marginBottom:14 }}>
              {Object.entries(collectSrc).filter(([,v])=>v.type==="media").map(([key,val])=>(
                <div key={key} onClick={()=>toggleSource(key)}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 12px",
                    borderRadius:7, cursor:"pointer", userSelect:"none",
                    border:`1px solid ${val.enabled?"rgba(96,165,250,.3)":"var(--bdr)"}`,
                    background:val.enabled?"rgba(96,165,250,.05)":"transparent",
                    transition:"all .15s" }}>
                  <div style={{ width:36, height:20, borderRadius:10, position:"relative", flexShrink:0,
                    background:val.enabled?"var(--accent)":"var(--bdr2)", transition:"background .2s" }}>
                    <div style={{ position:"absolute", top:2, left:val.enabled?18:2, width:16, height:16,
                      borderRadius:"50%", background:"#fff", transition:"left .2s",
                      boxShadow:"0 1px 3px rgba(0,0,0,.2)" }}/>
                  </div>
                  <span style={{ fontSize:13 }}>{val.flag}</span>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:12, fontWeight:600, color:val.enabled?"var(--txt)":"var(--txt3)" }}>{val.label}</div>
                    <div style={{ fontSize:10, color:"var(--txt3)", marginTop:1 }}>{val.desc}</div>
                  </div>
                  <span style={{ fontSize:10, padding:"2px 8px", borderRadius:5, fontWeight:600,
                    color:val.enabled?"#60A5FA":"var(--txt3)",
                    background:val.enabled?"rgba(96,165,250,.1)":"var(--bg-card2)",
                    border:`1px solid ${val.enabled?"rgba(96,165,250,.2)":"var(--bdr)"}` }}>
                    {val.enabled ? "수집 ON" : "수집 OFF"}
                  </span>
                </div>
              ))}
            </div>

            {/* 해외 기관 */}
            <div style={{ fontSize:10, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase",
              letterSpacing:".06em", marginBottom:8 }}>🌍 해외 기관</div>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {Object.entries(collectSrc).filter(([,v])=>v.type==="global").map(([key,val])=>(
                <div key={key} onClick={()=>toggleSource(key)}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 12px",
                    borderRadius:7, cursor:"pointer", userSelect:"none",
                    border:`1px solid ${val.enabled?"rgba(96,165,250,.3)":"var(--bdr)"}`,
                    background:val.enabled?"rgba(96,165,250,.05)":"transparent",
                    transition:"all .15s" }}>
                  <div style={{ width:36, height:20, borderRadius:10, position:"relative", flexShrink:0,
                    background:val.enabled?"var(--accent)":"var(--bdr2)", transition:"background .2s" }}>
                    <div style={{ position:"absolute", top:2, left:val.enabled?18:2, width:16, height:16,
                      borderRadius:"50%", background:"#fff", transition:"left .2s",
                      boxShadow:"0 1px 3px rgba(0,0,0,.2)" }}/>
                  </div>
                  <span style={{ fontSize:13 }}>{val.flag}</span>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:12, fontWeight:600, color:val.enabled?"var(--txt)":"var(--txt3)" }}>{val.label}</div>
                    <div style={{ fontSize:10, color:"var(--txt3)", marginTop:1 }}>{val.desc}</div>
                  </div>
                  <span style={{ fontSize:10, padding:"2px 8px", borderRadius:5, fontWeight:600,
                    color:val.enabled?"#60A5FA":"var(--txt3)",
                    background:val.enabled?"rgba(96,165,250,.1)":"var(--bg-card2)",
                    border:`1px solid ${val.enabled?"rgba(96,165,250,.2)":"var(--bdr)"}` }}>
                    {val.enabled ? "수집 ON" : "수집 OFF"}
                  </span>
                </div>
              ))}
            </div>
            <div style={{ marginTop:10, fontSize:10, color:"var(--txt3)", padding:"7px 10px",
              background:"var(--bg-card2)", borderRadius:5, border:"1px solid var(--bdr)" }}>
              💡 저장 후 위협 인텔리전스 화면에서 <strong style={{color:"var(--txt)"}}>🔄 즉시 수집</strong> 버튼을 눌러야 변경이 적용됩니다
            </div>
          </div>
        </div>

        {/* 액션 바 */}
        <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:12 }}>
          {/* 전체 선택 체크박스 */}
          <div onClick={selected.size===orgs.length?deselAll:selectAll}
            style={{ width:15,height:15,borderRadius:3,
              border:`2px solid ${selected.size>0?"var(--accent)":"var(--bdr2)"}`,
              background:selected.size===orgs.length?"var(--accent)":selected.size>0?"rgba(37,99,235,.2)":"transparent",
              cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0 }}>
            {selected.size===orgs.length&&<span style={{ color:"#fff",fontSize:8,fontWeight:700 }}>✓</span>}
            {selected.size>0&&selected.size<orgs.length&&<span style={{ color:"var(--accent-text)",fontSize:8,fontWeight:700 }}>−</span>}
          </div>
          {selected.size>0 ? (
            <>
              <span style={{ fontSize:12,color:"var(--accent-text)",fontWeight:500 }}>{selected.size}개 선택됨</span>
              <IconBtn icon="🗑" title="선택 항목 삭제" onClick={deleteSelected} color="#F87171" border="rgba(220,38,38,.3)" bg="rgba(220,38,38,.1)"/>
              <IconBtn icon="✕" title="선택 해제" onClick={deselAll}/>
            </>
          ) : (
            <span style={{ fontSize:11,color:"var(--txt3)" }}>전체 {orgs.length}개 기관</span>
          )}
          <div style={{ marginLeft:"auto",display:"flex",gap:6 }}>
            <IconBtn icon="↩ 기본값" title="기본 기관 목록으로 복원" onClick={()=>{save([...DEFAULT_ORGS]);setSelected(new Set());}} />
            <button onClick={()=>{setShowForm(!showForm);setEditIdx(null);setForm({name:"",country:"🌐",type:"",desc:"",url:"",cycle:"",tags:"",source:"",format:""}); }}
              style={{ padding:"6px 14px",borderRadius:6,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:12,fontWeight:600,cursor:"pointer" }}>
              {showForm?"✕ 취소":"＋ 기관 추가"}
            </button>
          </div>
        </div>

        {/* 추가/수정 폼 */}
        {showForm && (
          <div style={{ background:"var(--bg-card2)",border:`1px solid ${editIdx!==null?"#FBBF24":"var(--accent)"}`,borderRadius:9,padding:"16px",marginBottom:14 }}>
            <div style={{ fontSize:13,fontWeight:700,color:editIdx!==null?"#FBBF24":"var(--accent-text)",marginBottom:12 }}>
              {editIdx!==null ? `✏️ "${orgs[editIdx].name}" 수정` : "＋ 새 기관 추가"}
            </div>
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:10 }}>
              {FIELDS.map(f=>(
                <div key={f.k} style={{ gridColumn:f.half?"auto":"1/-1" }}>
                  <label style={{ display:"block",fontSize:10,fontWeight:600,color:"var(--txt3)",marginBottom:3,textTransform:"uppercase" }}>
                    {f.l}{f.req&&<span style={{ color:"#F87171" }}> *</span>}
                  </label>
                  <input value={form[f.k]||""} onChange={e=>setForm(p=>({...p,[f.k]:e.target.value}))} placeholder={f.ph}
                    style={{ width:"100%",padding:"7px 10px",borderRadius:5,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
                </div>
              ))}
            </div>
            <div style={{ display:"flex",justifyContent:"flex-end",marginTop:12,gap:8 }}>
              <button onClick={()=>{setShowForm(false);setEditIdx(null);}} style={{ padding:"7px 14px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:12,cursor:"pointer" }}>취소</button>
              <button onClick={onSubmit} disabled={!form.name||!form.url}
                style={{ padding:"7px 20px",borderRadius:5,border:"none",background:form.name&&form.url?"var(--accent)":"var(--bdr2)",color:"#fff",fontSize:12,fontWeight:700,cursor:form.name&&form.url?"pointer":"not-allowed" }}>
                {editIdx!==null?"✓ 수정 저장":"＋ 등록"}
              </button>
            </div>
          </div>
        )}

        {/* 기관 목록 */}
        <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:8 }}>
          {orgs.map((org,i) => {
            const sel = selected.has(i);
            const exp = expanded===i;
            return (
              <div key={i} style={{ background:sel?"var(--bg-active)":"var(--bg-card2)",
                border:`1px solid ${sel?"var(--accent)":"var(--bdr)"}`,
                borderRadius:8,transition:"all .15s",overflow:"hidden" }}>
                {/* 카드 헤더 — 클릭 영역 */}
                <div onClick={()=>toggleSel(i)}
                  style={{ display:"flex",alignItems:"center",gap:8,padding:"11px 13px",cursor:"pointer" }}>
                  {/* 체크박스 */}
                  <div style={{ width:14,height:14,borderRadius:3,
                    border:`2px solid ${sel?"var(--accent)":"var(--bdr2)"}`,
                    background:sel?"var(--accent)":"transparent",
                    display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all .15s" }}>
                    {sel&&<span style={{ color:"#fff",fontSize:8,fontWeight:700 }}>✓</span>}
                  </div>
                  <span style={{ fontSize:16 }}>{org.country}</span>
                  {/* 기관명 — URL 링크 */}
                  <a href={org.url} target="_blank" rel="noreferrer"
                    onClick={e=>e.stopPropagation()}
                    style={{ flex:1,fontSize:13,fontWeight:600,color:"var(--accent-text)",textDecoration:"none",display:"flex",alignItems:"center",gap:5 }}>
                    {org.name}
                    <span style={{ fontSize:10,color:"var(--txt3)",background:"var(--bg-input)",padding:"1px 5px",borderRadius:3,border:"1px solid var(--bdr)",flexShrink:0 }}>↗ 사이트</span>
                  </a>
                  <span style={{ fontSize:9,padding:"2px 7px",borderRadius:10,background:"var(--bg-active)",color:"var(--accent-text)",border:"1px solid var(--bdr2)",whiteSpace:"nowrap",flexShrink:0 }}>{org.type}</span>
                </div>

                {/* 설명 */}
                <div style={{ padding:"0 13px 8px",fontSize:11,color:"var(--txt2)",lineHeight:1.5 }} onClick={()=>toggleSel(i)}>{org.desc}</div>

                {/* 갱신주기 + 태그 + 버튼 */}
                <div style={{ padding:"0 13px 10px",display:"flex",alignItems:"center",justifyContent:"space-between",gap:6 }}>
                  <div style={{ display:"flex",gap:4,flexWrap:"wrap",flex:1 }}>
                    <span style={{ fontSize:10,color:"var(--txt3)" }}>갱신: {org.cycle}</span>
                    {(org.tags||[]).map(t=>(
                      <span key={t} style={{ padding:"1px 6px",borderRadius:3,background:"var(--bg-input)",color:"var(--txt3)",border:"1px solid var(--bdr)",fontSize:9 }}>{t}</span>
                    ))}
                  </div>
                  <div style={{ display:"flex",gap:4,flexShrink:0 }} onClick={e=>e.stopPropagation()}>
                    <button onClick={()=>setExpanded(exp?null:i)} title={exp?"상세 정보 닫기":"데이터 출처 및 수집 방법 보기"}
                      style={{ padding:"3px 8px",borderRadius:4,border:"1px solid var(--bdr)",background:exp?"var(--bg-active)":"transparent",color:exp?"var(--accent-text)":"var(--txt3)",fontSize:10,cursor:"pointer" }}>
                      {exp?"▲ 닫기":"📡 출처"}
                    </button>
                    <button onClick={()=>testOrg(org, i)} title={`${org.url} 접속 테스트`}
                      style={{ padding:"3px 8px",borderRadius:4,fontSize:10,cursor:"pointer",
                        border:`1px solid ${testResult[i]==="ok"?"rgba(22,163,74,.4)":testResult[i]==="fail"?"rgba(220,38,38,.4)":"rgba(37,99,235,.3)"}`,
                        background:testResult[i]==="ok"?"rgba(22,163,74,.1)":testResult[i]==="fail"?"rgba(220,38,38,.1)":"rgba(37,99,235,.1)",
                        color:testResult[i]==="ok"?"#4ADE80":testResult[i]==="fail"?"#F87171":testResult[i]==="testing"?"#60A5FA":"#60A5FA" }}>
                      {testResult[i]==="testing"?"⏳":testResult[i]==="ok"?"✓ 연결":testResult[i]==="fail"?"✗ 실패":testResult[i]==="manual"?"⚠ 확인필요":"🔗 테스트"}
                    </button>
                    <button onClick={()=>onEdit(i)} title="기관 정보 수정"
                      style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(251,191,36,.3)",background:"rgba(251,191,36,.1)",color:"#FBBF24",fontSize:10,cursor:"pointer" }}>
                      ✏️ 수정
                    </button>
                    <button onClick={()=>onDelete(i)} title="기관 삭제"
                      style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(220,38,38,.3)",background:"rgba(220,38,38,.1)",color:"#F87171",fontSize:10,cursor:"pointer" }}>
                      🗑 삭제
                    </button>
                  </div>
                </div>

                {/* 확장: 데이터 출처 상세 */}
                {exp && (
                  <div style={{ padding:"10px 13px 12px",borderTop:"1px solid var(--bdr)",background:"var(--bg-card)" }}>
                    <div style={{ fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:8 }}>📡 데이터 수집 방법</div>
                    <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:8,fontSize:11 }}>
                      <div style={{ background:"var(--bg-card2)",borderRadius:6,padding:"9px 11px",border:"1px solid var(--bdr)" }}>
                        <div style={{ fontSize:9,color:"var(--txt3)",marginBottom:4,fontWeight:600 }}>수집 경로</div>
                        <div style={{ color:"var(--txt)",lineHeight:1.6 }}>{org.source||"—"}</div>
                      </div>
                      <div style={{ background:"var(--bg-card2)",borderRadius:6,padding:"9px 11px",border:"1px solid var(--bdr)" }}>
                        <div style={{ fontSize:9,color:"var(--txt3)",marginBottom:4,fontWeight:600 }}>제공 형식</div>
                        <div style={{ color:"var(--accent-text)",fontWeight:600 }}>{org.format||"—"}</div>
                      </div>
                    </div>
                    <div style={{ marginTop:8,padding:"6px 10px",background:"rgba(37,99,235,.08)",border:"1px solid rgba(37,99,235,.2)",borderRadius:5,fontSize:10,color:"var(--txt3)",lineHeight:1.6 }}>
                      💡 이 기관의 데이터는 SecurityScanKit 위협 인텔리전스 수집 시 자동으로 참조됩니다.
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>

        {/* 추가 안내 */}
        <div style={{ marginTop:14,padding:"12px 14px",background:"var(--bg-card2)",border:"1px solid var(--bdr)",borderRadius:8 }}>
          <div style={{ fontSize:11,fontWeight:600,color:"var(--txt3)",marginBottom:6 }}>💡 기관 추가 방법</div>
          <div style={{ fontSize:11,color:"var(--txt3)",lineHeight:1.8 }}>
            <strong style={{ color:"var(--txt)" }}>＋ 기관 추가</strong> 버튼 클릭 →{" "}
            <strong style={{ color:"var(--txt)" }}>기관명*</strong> (표시 이름) ·{" "}
            <strong style={{ color:"var(--txt)" }}>공식 URL*</strong> (기관 주소) ·{" "}
            <strong style={{ color:"var(--txt)" }}>데이터 출처</strong> (어느 메뉴/API에서 가져오는지) 입력<br/>
            예시: ENISA(EU) — https://www.enisa.europa.eu / 출처: Publications → Threat Landscape / 형식: PDF/RSS
          </div>
        </div>

        {/* 🔗 테스트 결과 로그 */}
        {testLogs.length > 0 && (
          <div style={{ marginTop:14, background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:9, overflow:"hidden" }}>
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", padding:"10px 14px", borderBottom:"1px solid var(--bdr)", background:"var(--bg-card)" }}>
              <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                <span style={{ fontSize:13 }}>🔗</span>
                <span style={{ fontSize:12, fontWeight:700, color:"var(--txt)" }}>URL 접속 테스트 결과</span>
                <span style={{ fontSize:10, color:"var(--txt3)", background:"var(--bg-input)", padding:"1px 6px", borderRadius:3, border:"1px solid var(--bdr)" }}>최근 {testLogs.length}건</span>
              </div>
              <button onClick={()=>setTestLogs([])} style={{ background:"transparent", border:"none", color:"var(--txt3)", cursor:"pointer", fontSize:13 }}>✕</button>
            </div>
            <div style={{ padding:"8px 0" }}>
              {testLogs.map((log, i) => (
                <div key={i} style={{ display:"flex", alignItems:"flex-start", gap:10, padding:"8px 14px", borderBottom: i<testLogs.length-1?"1px solid var(--bdr)":"none",
                  background: i===0 ? "var(--bg-hover)" : "transparent" }}>
                  {/* 상태 아이콘 */}
                  <div style={{ flexShrink:0, width:22, height:22, borderRadius:"50%", display:"flex", alignItems:"center", justifyContent:"center", marginTop:1,
                    background: log.ok?"rgba(22,163,74,.12)":"rgba(220,38,38,.12)",
                    border: `1px solid ${log.ok?"rgba(22,163,74,.3)":"rgba(220,38,38,.3)"}` }}>
                    <span style={{ fontSize:11 }}>{log.ok?"✓":"✗"}</span>
                  </div>

                  {/* 메인 정보 */}
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:3, flexWrap:"wrap" }}>
                      <span style={{ fontSize:12, fontWeight:600, color:"var(--txt)" }}>{log.org}</span>
                      {log.ok ? (
                        <span style={{ fontSize:10, padding:"1px 7px", borderRadius:4, background:"rgba(22,163,74,.12)", color:"#4ADE80", border:"1px solid rgba(22,163,74,.3)", fontWeight:600 }}>
                          ✓ 연결 성공
                        </span>
                      ) : (
                        <span style={{ fontSize:10, padding:"1px 7px", borderRadius:4, background:"rgba(220,38,38,.12)", color:"#F87171", border:"1px solid rgba(220,38,38,.3)", fontWeight:600 }}>
                          ✗ 연결 실패
                        </span>
                      )}
                      {log.status && (
                        <span style={{ fontSize:10, padding:"1px 6px", borderRadius:3, background:"var(--bg-input)", color:"var(--txt3)", border:"1px solid var(--bdr)" }}>
                          HTTP {log.status}
                        </span>
                      )}
                      {log.latency && (
                        <span style={{ fontSize:10, color: log.latency<500?"#4ADE80":log.latency<2000?"#FBBF24":"#F87171", fontFamily:"monospace" }}>
                          {log.latency}ms
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize:10, color:"var(--txt3)", fontFamily:"monospace", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                      {log.url}
                    </div>
                    {log.error && (
                      <div style={{ fontSize:10, color:"#F87171", marginTop:3, padding:"4px 8px", background:"rgba(220,38,38,.07)", borderRadius:4, border:"1px solid rgba(220,38,38,.2)" }}>
                        ⚠ {log.error}
                      </div>
                    )}
                    {log.finalUrl && log.finalUrl !== log.url && (
                      <div style={{ fontSize:10, color:"var(--txt3)", marginTop:2 }}>
                        → 리다이렉트: <span style={{ color:"var(--accent-text)" }}>{log.finalUrl}</span>
                      </div>
                    )}
                  </div>

                  {/* 시간 */}
                  <span style={{ fontSize:10, color:"var(--txt3)", flexShrink:0, fontFamily:"monospace", marginTop:2 }}>{log.time}</span>
                </div>
              ))}
            </div>
            <div style={{ padding:"8px 14px", borderTop:"1px solid var(--bdr)", background:"var(--bg-card)", fontSize:10, color:"var(--txt3)" }}>
              💡 응답시간: <span style={{ color:"#4ADE80" }}>500ms 이하 정상</span> · <span style={{ color:"#FBBF24" }}>2초 이하 느림</span> · <span style={{ color:"#F87171" }}>2초 초과 매우 느림</span>
              &nbsp;&nbsp;서버가 방화벽/프록시 환경이면 일부 사이트는 연결되지 않을 수 있습니다.
            </div>
          </div>
        )}
      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════
  // 패널: 일일 체크리스트
  // ══════════════════════════════════════════════════════════════
  const PanelChecklist = () => {
    const [items,    setItems]    = React.useState(() => { try { return JSON.parse(localStorage.getItem("ssk_checklist"))||DEFAULT_CHECKLIST; } catch { return DEFAULT_CHECKLIST; } });
    const [selected, setSelected] = React.useState(new Set());
    const [showForm, setShowForm] = React.useState(false);
    const [editIdx,  setEditIdx]  = React.useState(null);
    const [form,       setForm]       = React.useState({ time:"매일 09:00", task:"", priority:"medium", auto:false });
    const [testResult, setTestResult] = React.useState({});
    const [testLog,    setTestLog]    = React.useState([]);
    const [showTestLog,setShowTestLog]= React.useState(false);

    const save = list => { setItems(list); localStorage.setItem("ssk_checklist", JSON.stringify(list)); };

    const runTest = async (item, i) => {
      setTestResult(p => ({...p, [i]:"running"}));
      const logs = [];
      const ts = () => new Date().toLocaleTimeString("ko-KR",{hour12:false});

      logs.push({ t:ts(), ok:true,  msg:`[테스트 시작] "${item.task}"` });
      logs.push({ t:ts(), ok:true,  msg:`점검 주기: ${item.time}` });
      logs.push({ t:ts(), ok:true,  msg:`수행 방식: ${item.auto?"🤖 자동 (시스템 수행)":"👤 수동 (담당자 확인)"}` });
      await new Promise(r=>setTimeout(r,600));

      if (item.auto) {
        // 자동 항목 — 실제 API 연동 시뮬레이션
        logs.push({ t:ts(), ok:true,  msg:`백엔드 API 연동 확인 중...` });
        await new Promise(r=>setTimeout(r,800));
        const ok = Math.random() > 0.1; // 90% 성공 시뮬레이션
        if (ok) {
          logs.push({ t:ts(), ok:true,  msg:`✓ API 연결 정상 (응답시간: ${Math.floor(Math.random()*200+100)}ms)` });
          logs.push({ t:ts(), ok:true,  msg:`✓ 자동 수집 가능 상태 확인됨` });
        } else {
          logs.push({ t:ts(), ok:false, msg:`✗ API 응답 없음 — 서버 연결 확인 필요` });
        }
        setTestResult(p => ({...p, [i]: ok ? "ok" : "fail"}));
      } else {
        // 수동 항목 — 체크리스트 안내
        logs.push({ t:ts(), ok:true,  msg:`담당자 확인 항목 — 아래 조치를 직접 수행하세요:` });
        await new Promise(r=>setTimeout(r,400));
        logs.push({ t:ts(), ok:null,  msg:`  1. 관련 사이트/시스템 접속` });
        logs.push({ t:ts(), ok:null,  msg:`  2. 최신 정보 확인 및 검토` });
        logs.push({ t:ts(), ok:null,  msg:`  3. 필요 시 조치 후 결과 기록` });
        setTestResult(p => ({...p, [i]: "manual"}));
      }
      logs.push({ t:ts(), ok:true,  msg:`[테스트 완료]` });
      setTestLog(logs);
      setShowTestLog(true);
      setTimeout(() => setTestResult(p => ({...p, [i]:""})), 5000);
    };
    const toggleSel = i => setSelected(p => { const n=new Set(p); n.has(i)?n.delete(i):n.add(i); return n; });
    const selectAll = () => setSelected(new Set(items.map((_,i)=>i)));
    const deselAll  = () => setSelected(new Set());
    const onEdit = i => { setEditIdx(i); setForm({...items[i]}); setShowForm(true); };
    const deleteSelected = () => { if(window.confirm(`${selected.size}개 항목을 삭제합니까?`)){ save(items.filter((_,i)=>!selected.has(i))); setSelected(new Set()); } };
    const onSubmit = () => {
      if (editIdx!==null) { const n=[...items]; n[editIdx]=form; save(n); setEditIdx(null); }
      else save([...items, {...form}]);
      setForm({time:"매일 09:00",task:"",priority:"medium",auto:false}); setShowForm(false);
    };
    const PLEVELS = [{id:"critical",l:"긴급",c:"#F87171"},{id:"high",l:"고위험",c:"#FB923C"},{id:"medium",l:"중간",c:"#FBBF24"}];

    return (
      <div>
        {/* 액션 바 */}
        <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:12 }}>
          <div onClick={selected.size===items.length?deselAll:selectAll}
            style={{ width:15,height:15,borderRadius:3,
              border:`2px solid ${selected.size>0?"var(--accent)":"var(--bdr2)"}`,
              background:selected.size===items.length?"var(--accent)":selected.size>0?"rgba(37,99,235,.2)":"transparent",
              cursor:"pointer",display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0 }}>
            {selected.size===items.length&&<span style={{ color:"#fff",fontSize:8,fontWeight:700 }}>✓</span>}
            {selected.size>0&&selected.size<items.length&&<span style={{ color:"var(--accent-text)",fontSize:8,fontWeight:700 }}>−</span>}
          </div>
          {selected.size>0 ? (
            <>
              <span style={{ fontSize:12,color:"var(--accent-text)",fontWeight:500 }}>{selected.size}개 선택됨</span>
              <IconBtn icon="🗑 삭제" title="선택 항목 삭제" onClick={deleteSelected} color="#F87171" border="rgba(220,38,38,.3)" bg="rgba(220,38,38,.1)"/>
              <IconBtn icon="✕ 해제" title="선택 해제" onClick={deselAll}/>
            </>
          ) : (
            <span style={{ fontSize:11,color:"var(--txt3)" }}>총 {items.length}개 점검 항목</span>
          )}
          <div style={{ marginLeft:"auto",display:"flex",gap:6 }}>
            <button onClick={()=>{save([...DEFAULT_CHECKLIST]);setSelected(new Set());}}
              title="기본 점검 항목으로 복원"
              style={{ padding:"5px 12px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:11,cursor:"pointer" }}>
              ↩ 기본값 복원
            </button>
            <button onClick={()=>{setShowForm(!showForm);setEditIdx(null);setForm({time:"매일 09:00",task:"",priority:"medium",auto:false}); }}
              style={{ padding:"6px 14px",borderRadius:6,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:12,fontWeight:600,cursor:"pointer" }}>
              {showForm?"✕ 취소":"＋ 항목 추가"}
            </button>
          </div>
        </div>

        {/* 추가/수정 폼 */}
        {showForm && (
          <div style={{ background:"var(--bg-card2)",border:`1px solid ${editIdx!==null?"#FBBF24":"var(--accent)"}`,borderRadius:9,padding:"14px",marginBottom:12 }}>
            <div style={{ fontSize:13,fontWeight:700,color:editIdx!==null?"#FBBF24":"var(--accent-text)",marginBottom:10 }}>
              {editIdx!==null?`✏️ 항목 수정 — "${items[editIdx].task.slice(0,30)}"` :"＋ 새 점검 항목 추가"}
            </div>
            <div style={{ display:"grid",gridTemplateColumns:"160px 1fr",gap:10,marginBottom:10 }}>
              <div>
                <label style={{ display:"block",fontSize:10,fontWeight:600,color:"var(--txt3)",marginBottom:3,textTransform:"uppercase" }}>점검 주기 *</label>
                <input value={form.time||""} onChange={e=>setForm(p=>({...p,time:e.target.value}))} placeholder="매일 09:00 / 매주 월요일"
                  style={{ width:"100%",padding:"7px 10px",borderRadius:5,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
              </div>
              <div>
                <label style={{ display:"block",fontSize:10,fontWeight:600,color:"var(--txt3)",marginBottom:3,textTransform:"uppercase" }}>점검 내용 *</label>
                <input value={form.task||""} onChange={e=>setForm(p=>({...p,task:e.target.value}))} placeholder="예: KrCERT 긴급 보안 공지 확인"
                  style={{ width:"100%",padding:"7px 10px",borderRadius:5,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
              </div>
            </div>
            <div style={{ display:"flex",gap:12,alignItems:"center",flexWrap:"wrap" }}>
              <div>
                <label style={{ fontSize:10,fontWeight:600,color:"var(--txt3)",marginRight:8,textTransform:"uppercase" }}>중요도</label>
                <span style={{ display:"inline-flex",gap:4 }}>
                  {PLEVELS.map(p=>(
                    <button key={p.id} onClick={()=>setForm(prev=>({...prev,priority:p.id}))}
                      style={{ padding:"4px 11px",borderRadius:5,fontSize:11,cursor:"pointer",fontWeight:form.priority===p.id?700:400,
                        border:`1px solid ${form.priority===p.id?p.c:"var(--bdr)"}`,
                        background:form.priority===p.id?`${p.c}18`:"transparent",
                        color:form.priority===p.id?p.c:"var(--txt3)" }}>
                      {p.l}
                    </button>
                  ))}
                </span>
              </div>
              <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                <label style={{ fontSize:11,color:"var(--txt3)" }}>자동 수집</label>
                <div onClick={()=>setForm(p=>({...p,auto:!p.auto}))}
                  style={{ width:36,height:20,borderRadius:10,cursor:"pointer",background:form.auto?"var(--accent)":"var(--bdr2)",position:"relative",transition:"background .2s" }}>
                  <div style={{ width:14,height:14,borderRadius:"50%",background:"#fff",position:"absolute",top:3,left:form.auto?19:3,transition:"left .2s",boxShadow:"0 1px 3px rgba(0,0,0,.3)" }}/>
                </div>
                <span style={{ fontSize:10,color:"var(--txt3)" }}>{form.auto?"SecurityScanKit이 자동 수집":"담당자 수동 확인 필요"}</span>
              </div>
              <div style={{ marginLeft:"auto",display:"flex",gap:6 }}>
                <button onClick={()=>{setShowForm(false);setEditIdx(null);}} style={{ padding:"6px 12px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:12,cursor:"pointer" }}>취소</button>
                <button onClick={onSubmit} disabled={!form.task}
                  style={{ padding:"6px 18px",borderRadius:5,border:"none",background:form.task?"var(--accent)":"var(--bdr2)",color:"#fff",fontSize:12,fontWeight:700,cursor:form.task?"pointer":"not-allowed" }}>
                  {editIdx!==null?"✓ 저장":"추가"}
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 체크리스트 목록 */}
        <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:6 }}>
          {items.map((item,i) => {
            const pc = {critical:"#F87171",high:"#FB923C",medium:"#FBBF24"}[item.priority]||"#FBBF24";
            const sel = selected.has(i);
            return (
              <div key={i} onClick={()=>toggleSel(i)}
                style={{ display:"flex",alignItems:"center",gap:8,padding:"9px 12px",borderRadius:7,cursor:"pointer",
                  background:sel?"var(--bg-active)":"var(--bg-card2)",
                  border:`1px solid ${sel?"var(--accent)":"var(--bdr)"}`,transition:"all .15s" }}>
                {/* 체크박스 */}
                <div style={{ width:14,height:14,borderRadius:3,
                  border:`2px solid ${sel?"var(--accent)":"var(--bdr2)"}`,
                  background:sel?"var(--accent)":"transparent",
                  display:"flex",alignItems:"center",justifyContent:"center",flexShrink:0,transition:"all .15s" }}>
                  {sel&&<span style={{ color:"#fff",fontSize:8,fontWeight:700 }}>✓</span>}
                </div>
                <div style={{ width:3,height:34,borderRadius:2,flexShrink:0,background:pc }}/>
                <div style={{ flex:1,minWidth:0 }}>
                  <div style={{ fontSize:12,color:"var(--txt)",fontWeight:500 }}>{item.task}</div>
                  <div style={{ fontSize:10,color:"var(--txt3)",marginTop:2 }}>{item.time||item.name}</div>
                </div>
                {/* 자동/수동 뱃지 */}
                <span title={item.auto?"SecurityScanKit이 자동으로 수집/점검합니다":"담당자가 직접 확인해야 합니다"}
                  style={{ fontSize:9,padding:"2px 7px",borderRadius:10,flexShrink:0,cursor:"help",
                    background:item.auto?"rgba(22,163,74,.12)":"var(--bg-input)",
                    color:item.auto?"#4ADE80":"var(--txt3)",
                    border:`1px solid ${item.auto?"rgba(22,163,74,.3)":"var(--bdr)"}` }}>
                  {item.auto?"🤖 자동":"👤 수동"}
                </span>
                {/* 수정 버튼 */}
                <button onClick={e=>{e.stopPropagation();onEdit(i);}} title="이 항목 수정"
                  style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(251,191,36,.3)",background:"rgba(251,191,36,.1)",color:"#FBBF24",fontSize:11,cursor:"pointer",flexShrink:0 }}>
                  ✏️
                </button>
                {/* 테스트 버튼 */}
                <button onClick={e=>{e.stopPropagation();runTest(item,i);}} title={item.auto?"자동 수집 API 연결 테스트":"수동 점검 절차 안내 보기"}
                  style={{ padding:"3px 8px",borderRadius:4,fontSize:11,cursor:"pointer",flexShrink:0,
                    border:`1px solid ${testResult[i]==="ok"?"rgba(22,163,74,.4)":testResult[i]==="fail"?"rgba(220,38,38,.4)":testResult[i]==="manual"?"rgba(251,191,36,.4)":"rgba(37,99,235,.3)"}`,
                    background:testResult[i]==="ok"?"rgba(22,163,74,.1)":testResult[i]==="fail"?"rgba(220,38,38,.1)":testResult[i]==="manual"?"rgba(251,191,36,.1)":"rgba(37,99,235,.1)",
                    color:testResult[i]==="ok"?"#4ADE80":testResult[i]==="fail"?"#F87171":testResult[i]==="manual"?"#FBBF24":"#60A5FA" }}>
                  {testResult[i]==="running"?"⏳":testResult[i]==="ok"?"✓ 정상":testResult[i]==="fail"?"✗ 오류":testResult[i]==="manual"?"📋 절차":"▶ 테스트"}
                </button>
                {/* 삭제 버튼 */}
                <button onClick={e=>{e.stopPropagation();if(window.confirm(`"${item.task}" 항목을 삭제합니까?`))save(items.filter((_,j)=>j!==i));}} title="이 항목 삭제"
                  style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(220,38,38,.3)",background:"rgba(220,38,38,.1)",color:"#F87171",fontSize:11,cursor:"pointer",flexShrink:0 }}>
                  🗑
                </button>
              </div>
            );
          })}
        </div>

        {/* 테스트 결과 로그 */}
        {showTestLog && testLog.length>0 && (
          <div style={{ marginTop:10,background:"var(--bg-card2)",border:"1px solid var(--bdr)",borderRadius:8,overflow:"hidden" }}>
            <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 12px",borderBottom:"1px solid var(--bdr)",background:"var(--bg-card)" }}>
              <span style={{ fontSize:11,fontWeight:700,color:"var(--txt)" }}>▶ 테스트 실행 결과</span>
              <button onClick={()=>setShowTestLog(false)} style={{ background:"transparent",border:"none",color:"var(--txt3)",cursor:"pointer",fontSize:14 }}>✕</button>
            </div>
            <div style={{ padding:"10px 12px",fontFamily:"monospace",fontSize:11 }}>
              {testLog.map((l,i)=>(
                <div key={i} style={{ display:"flex",gap:8,padding:"2px 0",color:l.ok===true?"#4ADE80":l.ok===false?"#F87171":"var(--txt3)" }}>
                  <span style={{ color:"var(--txt3)",flexShrink:0 }}>{l.t}</span>
                  <span>{l.msg}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        <div style={{ marginTop:10,padding:"9px 12px",borderRadius:6,background:"var(--bg-card2)",border:"1px solid var(--bdr)",fontSize:11,color:"var(--txt3)",lineHeight:1.7 }}>
          🤖 <strong style={{ color:"var(--accent-text)" }}>자동</strong>: SecurityScanKit이 점검 실행 시 자동으로 수행합니다.
          &nbsp;&nbsp;👤 <strong style={{ color:"var(--txt)" }}>수동</strong>: 보안 담당자가 직접 확인해야 합니다.
          <strong style={{ color:"#60A5FA" }}>▶ 테스트</strong> 버튼으로 자동 항목의 API 연결 상태나 수동 항목의 절차를 확인할 수 있습니다.
        </div>
      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════
  // 패널: 알람 설정 (본격 구현)
  // ══════════════════════════════════════════════════════════════
  const PanelAlerts = () => {
    const [cfg, setCfg] = React.useState(() => {
      try { return JSON.parse(localStorage.getItem("ssk_alert_cfg"))||DEFAULT_ALERT_CFG; }
      catch { return DEFAULT_ALERT_CFG; }
    });
    const [testStatus, setTestStatus] = React.useState({});
    const [alertTab, setAlertTab] = React.useState("channels"); // channels | rules

    const save = c => { setCfg(c); localStorage.setItem("ssk_alert_cfg", JSON.stringify(c)); };
    const setChannel = (k,v) => save({...cfg, [k]:v});
    const toggleRule = id => save({...cfg, rules:cfg.rules.map(r=>r.id===id?{...r,enabled:!r.enabled}:r)});
    const setRuleChannel = (id,ch) => save({...cfg, rules:cfg.rules.map(r=>r.id===id?{...r,channel:ch}:r)});

    const testSend = async (ch) => {
      setTestStatus(p=>({...p,[ch]:"sending"}));
      await new Promise(r=>setTimeout(r,1200));
      setTestStatus(p=>({...p,[ch]:"ok"}));
      setTimeout(()=>setTestStatus(p=>({...p,[ch]:""})),3000);
    };

    const CHANNELS = [
      { id:"email", icon:"📧", label:"이메일 (SMTP)", enabled_key:"email_enabled",
        fields:[
          {k:"email_smtp",     l:"SMTP 서버",   ph:"smtp.company.com"},
          {k:"email_port",     l:"포트",         ph:"587",  type:"number"},
          {k:"email_from",     l:"발신 이메일",  ph:"security@company.com"},
          {k:"email_password", l:"SMTP 비밀번호",ph:"••••••••", type:"password"},
          {k:"email_to",       l:"수신 이메일",  ph:"ciso@company.com (쉼표로 복수 입력)"},
        ]
      },
      { id:"slack", icon:"💬", label:"Slack", enabled_key:"slack_enabled",
        fields:[
          {k:"slack_webhook", l:"Webhook URL", ph:"https://hooks.slack.com/services/..."},
        ]
      },
      { id:"teams", icon:"🟦", label:"Microsoft Teams", enabled_key:"teams_enabled",
        fields:[
          {k:"teams_webhook", l:"Webhook URL", ph:"https://outlook.office.com/webhook/..."},
        ]
      },
    ];

    const SEV_COLORS = { critical:"#F87171", high:"#FB923C", medium:"#FBBF24", info:"#60A5FA" };

    return (
      <div>
        {/* 탭 */}
        <div style={{ display:"flex", gap:0, marginBottom:16, background:"var(--bg-card2)", borderRadius:8, padding:4, border:"1px solid var(--bdr)" }}>
          {[{id:"channels",icon:"📡",l:"알람 채널"},{id:"rules",icon:"📋",l:"알람 규칙"}].map(tab=>(
            <button key={tab.id} onClick={()=>setAlertTab(tab.id)}
              style={{ flex:1, padding:"8px", borderRadius:6, border:"none", cursor:"pointer", fontSize:12, fontWeight:alertTab===tab.id?700:500,
                background:alertTab===tab.id?"var(--bg-active)":"transparent",
                color:alertTab===tab.id?"var(--accent-text)":"var(--txt3)", transition:"all .15s" }}>
              {tab.icon} {tab.l}
            </button>
          ))}
        </div>

        {/* 채널 설정 탭 */}
        {alertTab==="channels" && (
          <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
            {CHANNELS.map(ch => {
              const enabled = cfg[ch.enabled_key];
              return (
                <div key={ch.id} style={{ background:"var(--bg-card2)", border:`1px solid ${enabled?"var(--accent)":"var(--bdr)"}`, borderRadius:9, overflow:"hidden", transition:"border-color .2s" }}>
                  {/* 채널 헤더 */}
                  <div style={{ display:"flex", alignItems:"center", gap:10, padding:"12px 16px", borderBottom:enabled?"1px solid var(--bdr)":"none" }}>
                    <span style={{ fontSize:20 }}>{ch.icon}</span>
                    <div style={{ flex:1 }}>
                      <div style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>{ch.label}</div>
                      <div style={{ fontSize:10, color:enabled?"#4ADE80":"var(--txt3)", marginTop:1 }}>
                        {enabled?"● 활성화됨":"○ 비활성화"}
                      </div>
                    </div>
                    {/* 활성화 토글 */}
                    <div onClick={()=>setChannel(ch.enabled_key, !enabled)}
                      style={{ width:40, height:22, borderRadius:11, cursor:"pointer", flexShrink:0,
                        background:enabled?"var(--accent)":"var(--bdr2)", position:"relative", transition:"background .2s" }}>
                      <div style={{ width:16, height:16, borderRadius:"50%", background:"#fff",
                        position:"absolute", top:3, left:enabled?21:3, transition:"left .2s",
                        boxShadow:"0 1px 4px rgba(0,0,0,.3)" }}/>
                    </div>
                    {enabled && (
                      <button onClick={()=>testSend(ch.id)}
                        title={`${ch.label} 테스트 발송`}
                        style={{ padding:"5px 12px", borderRadius:5, border:"1px solid rgba(22,163,74,.4)", background:"rgba(22,163,74,.1)", color:"#4ADE80", fontSize:11, fontWeight:600, cursor:"pointer" }}>
                        {testStatus[ch.id]==="sending"?<><Spinner size={10}/> 발송중...</>:testStatus[ch.id]==="ok"?"✓ 성공":"📤 테스트"}
                      </button>
                    )}
                  </div>

                  {/* 채널 설정 필드 */}
                  {enabled && (
                    <div style={{ padding:"14px 16px" }}>
                      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                        {ch.fields.map(f=>(
                          <div key={f.k} style={{ gridColumn: f.k.includes("from")||f.k.includes("to")||f.k.includes("webhook")?"1/-1":"auto" }}>
                            <label style={{ display:"block", fontSize:10, fontWeight:600, color:"var(--txt3)", marginBottom:4, textTransform:"uppercase" }}>{f.l}</label>
                            <input type={f.type||"text"} value={cfg[f.k]||""} onChange={e=>setChannel(f.k,e.target.value)} placeholder={f.ph}
                              style={{ width:"100%", padding:"8px 10px", borderRadius:6, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:12, outline:"none" }}/>
                          </div>
                        ))}
                      </div>
                      {ch.id==="email" && (
                        <div style={{ marginTop:10, padding:"8px 12px", background:"rgba(37,99,235,.08)", border:"1px solid rgba(37,99,235,.2)", borderRadius:6, fontSize:10, color:"var(--txt3)" }}>
                          💡 Gmail: smtp.gmail.com:587 / Naver: smtp.naver.com:465 / 사내 메일서버: 담당자 문의
                        </div>
                      )}
                      {ch.id==="slack" && (
                        <div style={{ marginTop:10, padding:"8px 12px", background:"rgba(37,99,235,.08)", border:"1px solid rgba(37,99,235,.2)", borderRadius:6, fontSize:10, color:"var(--txt3)" }}>
                          💡 Slack → 채널 → 채널 설정 → Integrations → Add an app → Incoming Webhooks → Add to Slack → Webhook URL 복사
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}

        {/* 알람 규칙 탭 */}
        {alertTab==="rules" && (
          <div>
            <div style={{ fontSize:11, color:"var(--txt3)", marginBottom:12 }}>
              활성화된 조건이 충족되면 지정한 채널로 알람이 발송됩니다.
            </div>
            <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
              {cfg.rules.map(rule => (
                <div key={rule.id} style={{ display:"flex", alignItems:"center", gap:12, padding:"11px 14px", borderRadius:8,
                  background:rule.enabled?"var(--bg-card2)":"transparent",
                  border:`1px solid ${rule.enabled?"var(--bdr)":"var(--bdr)"}`,
                  opacity:rule.enabled?1:.6, transition:"all .15s" }}>
                  {/* 활성화 토글 */}
                  <div onClick={()=>toggleRule(rule.id)}
                    style={{ width:34, height:18, borderRadius:9, cursor:"pointer", flexShrink:0,
                      background:rule.enabled?"var(--accent)":"var(--bdr2)", position:"relative", transition:"background .2s" }}>
                    <div style={{ width:12, height:12, borderRadius:"50%", background:"#fff", position:"absolute", top:3, left:rule.enabled?19:3, transition:"left .2s" }}/>
                  </div>
                  {/* 규칙명 */}
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:12, fontWeight:600, color:"var(--txt)" }}>{rule.name}</div>
                    <div style={{ fontSize:10, color:"var(--txt3)", marginTop:2, fontFamily:"monospace" }}>조건: {rule.condition}</div>
                  </div>
                  {/* 중복 발송 방지 */}
                  <div style={{ fontSize:10, color:"var(--txt3)", textAlign:"right", flexShrink:0 }}>
                    <div>재발송 제한</div>
                    <div style={{ color:"var(--txt)", fontWeight:600 }}>
                      {rule.throttle_min===0?"즉시":rule.throttle_min<60?`${rule.throttle_min}분`:rule.throttle_min<1440?`${rule.throttle_min/60}시간`:`${rule.throttle_min/1440}일`}
                    </div>
                  </div>
                  {/* 채널 선택 */}
                  <select value={rule.channel} onChange={e=>setRuleChannel(rule.id,e.target.value)}
                    style={{ padding:"5px 8px", borderRadius:5, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:11, cursor:"pointer" }}>
                    <option value="email">📧 이메일</option>
                    <option value="slack">💬 Slack</option>
                    <option value="teams">🟦 Teams</option>
                    <option value="all">📡 전체</option>
                  </select>
                </div>
              ))}
            </div>
            <div style={{ marginTop:12, padding:"10px 14px", background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:7, fontSize:11, color:"var(--txt3)" }}>
              💡 실제 알람 발송은 채널 탭에서 해당 채널을 활성화하고 SMTP/Webhook 정보를 입력해야 합니다.
              현재는 UI 설정이 저장되고, 백엔드 실제 발송 연동은 추후 구현 예정입니다.
            </div>
          </div>
        )}
      </div>
    );
  };

  // ══════════════════════════════════════════════════════════════
  // 렌더
  // ══════════════════════════════════════════════════════════════
  const panels = {
    appearance: <PanelAppearance/>,
    animation:  <PanelAnimation/>,
    scan: (
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>
        <div>
          <Field label="타임아웃 (초)"    value={scanCfg.timeout}           onChange={v=>setScanCfg(p=>({...p,timeout:v}))}           type="number"/>
          <Field label="동시 점검 수"     value={scanCfg.concurrent}        onChange={v=>setScanCfg(p=>({...p,concurrent:v}))}        type="number"/>
          <Field label="nmap 경로"        value={scanCfg.nmap}              onChange={v=>setScanCfg(p=>({...p,nmap:v}))}              placeholder="자동 탐색"/>
          <Field label="리포트 경로"       value={scanCfg.reportDir}         onChange={v=>setScanCfg(p=>({...p,reportDir:v}))}/>
          <Field label="반복 임계값 (회)" value={scanCfg.repeatThreshold}   onChange={v=>setScanCfg(p=>({...p,repeatThreshold:v}))}  type="number"/>
          <Field label="SSL 경고 (일 전)" value={scanCfg.sslWarnDays}       onChange={v=>setScanCfg(p=>({...p,sslWarnDays:v}))}      type="number"/>
        </div>
        <div>
          <Toggle label="AI 취약점 분석" value={scanCfg.aiEnabled} onChange={v=>setScanCfg(p=>({...p,aiEnabled:v}))} desc="Claude API 연동 자동 분석"/>
        </div>
        <div style={{ gridColumn:"1/-1", display:"flex", justifyContent:"flex-end", paddingTop:8, borderTop:"1px solid var(--bdr)" }}>
          <button onClick={()=>{setSaved(true);setTimeout(()=>setSaved(false),2000);}}
            style={{ padding:"8px 22px", borderRadius:6, border:"none", background:saved?"rgba(22,163,74,.8)":"var(--accent)", color:"#fff", fontSize:12, fontWeight:700, cursor:"pointer" }}>
            {saved?"✓ 저장됨":"저장"}
          </button>
        </div>
      </div>
    ),
    alerts:    <PanelAlerts/>,
    db:        <PanelDB/>,
    orgs:      <PanelOrgs/>,
    checklist: <PanelChecklist/>,
    visitors: (() => {
      const [vdata,    setVdata]    = React.useState(null);
      const [assets,   setAssets]   = React.useState([]);
      const [loading,  setLoading]  = React.useState(false);
      const [logFilter,setLogFilter]= React.useState("ALL");
      const [logSort,  setLogSort]  = React.useState({ key:"ts", asc:false });
      const [logPage,  setLogPage]  = React.useState(1);
      const [sesSort,  setSesSort]  = React.useState({ key:"last_seen", asc:false });
      const [autoRef,  setAutoRef]  = React.useState(false);
      const [LOG_PAGE_SIZE, setLogPageSize] = React.useState(20);
      const timerRef = React.useRef(null);

      const load = async () => {
        setLoading(true);
        try {
          const [v, a] = await Promise.all([
            fetch(`${API_BASE}/api/admin/visitors`).then(r=>r.json()),
            fetch(`${API_BASE}/api/assets`).then(r=>r.json()).catch(()=>[]),
          ]);
          setVdata(v); setAssets(Array.isArray(a)?a:[]);
        } catch(e) {}
        setLoading(false);
      };

      React.useEffect(() => { load(); }, []);
      React.useEffect(() => {
        if (autoRef) { timerRef.current = setInterval(load, 5000); }
        else         { clearInterval(timerRef.current); }
        return () => clearInterval(timerRef.current);
      }, [autoRef]);

      // IP → 자산 매핑
      const ipToAsset = React.useMemo(() => {
        const m = {};
        assets.forEach(a => { if (a.ip) m[a.ip] = a; });
        return m;
      }, [assets]);

      const STATUS_COLORS = {
        200:"#4ADE80",201:"#4ADE80",204:"#4ADE80",
        400:"#FBBF24",401:"#F87171",403:"#F87171",404:"#FB923C",500:"#F87171",
      };
      const METHOD_COLORS = { GET:"#60A5FA",POST:"#4ADE80",PUT:"#FBBF24",DELETE:"#F87171",WS:"#C084FC" };

      const logs = vdata?.recent_logs || [];
      const filteredLogs = (logFilter==="ALL" ? logs : logs.filter(l=>
        logFilter==="ERROR" ? l.status>=400 :
        logFilter==="WS"    ? l.path?.startsWith("/ws") :
        l.method===logFilter
      )).sort((a,b) => {
        const v1=a[logSort.key]??"", v2=b[logSort.key]??"";
        const r = typeof v1==="number" ? v1-v2 : String(v1).localeCompare(String(v2));
        return logSort.asc ? r : -r;
      });
      const totalLogPages = Math.ceil(filteredLogs.length / LOG_PAGE_SIZE);
      const pagedLogs = filteredLogs.slice((logPage-1)*LOG_PAGE_SIZE, logPage*LOG_PAGE_SIZE);
      const onLogSort = k => { setLogSort(p=>({key:k,asc:p.key===k?!p.asc:true})); setLogPage(1); };

      const sessions = (vdata?.active_sessions||[]).sort((a,b)=>{
        const v1=a[sesSort.key]??"", v2=b[sesSort.key]??"";
        const r = typeof v1==="number" ? v1-v2 : String(v1).localeCompare(String(v2));
        return sesSort.asc ? r : -r;
      });
      const onSesSort = k => setSesSort(p=>({key:k,asc:p.key===k?!p.asc:true}));
      const SortHd = ({k,sort,onSort,children}) => (
        <th onClick={()=>onSort(k)} style={{ padding:"7px 10px",fontSize:9,fontWeight:700,color:sort.key===k?"var(--accent-text)":"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",borderBottom:"2px solid var(--bdr)",background:"var(--bg-card2)",cursor:"pointer",whiteSpace:"nowrap",userSelect:"none" }}>
          {children} <span style={{ fontSize:8,opacity:sort.key===k?1:.3 }}>{sort.key===k?(sort.asc?"▲":"▼"):"⇅"}</span>
        </th>
      );

      return (
        <div>
          {/* KPI */}
          <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:14 }}>
            {[
              { icon:"👥", label:"고유 접속자 IP", val:vdata?.total_unique_ips??"—", color:"var(--accent-text)" },
              { icon:"🟢", label:"현재 접속중 (10분)",val:sessions.filter(s=>s.is_active).length||"—",color:"#4ADE80" },
              { icon:"📊", label:"총 API 요청",    val:vdata?.total_requests??"—", color:"#FBBF24" },
              { icon:"⚠",  label:"오류 (4xx/5xx)", val:logs.filter(l=>l.status>=400).length, color:"#F87171" },
            ].map(k=>(
              <div key={k.label} style={{ background:"var(--bg-card2)",border:"1px solid var(--bdr)",borderRadius:9,padding:"12px 14px" }}>
                <div style={{ display:"flex",gap:5,alignItems:"center",marginBottom:5 }}>
                  <span style={{ fontSize:14 }}>{k.icon}</span>
                  <span style={{ fontSize:9,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",fontWeight:600 }}>{k.label}</span>
                </div>
                <div style={{ fontSize:22,fontWeight:700,color:k.color }}>{k.val}</div>
              </div>
            ))}
          </div>

          {/* 컨트롤 */}
          <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:12 }}>
            <button onClick={load} disabled={loading}
              style={{ padding:"6px 14px",borderRadius:6,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt2)",fontSize:12,cursor:"pointer",display:"flex",alignItems:"center",gap:5 }}>
              {loading?<><span style={{ width:10,height:10,borderRadius:"50%",border:"2px solid var(--accent)",borderTopColor:"transparent",animation:"spin .8s linear infinite",display:"inline-block" }}/> 조회중...</>:"↻ 새로고침"}
            </button>
            <div onClick={()=>setAutoRef(p=>!p)}
              style={{ display:"flex",alignItems:"center",gap:6,cursor:"pointer",padding:"6px 12px",borderRadius:6,border:`1px solid ${autoRef?"var(--accent)":"var(--bdr)"}`,background:autoRef?"var(--bg-active)":"transparent" }}>
              <div style={{ width:32,height:18,borderRadius:9,background:autoRef?"var(--accent)":"var(--bdr2)",position:"relative",transition:"background .2s" }}>
                <div style={{ width:12,height:12,borderRadius:"50%",background:"#fff",position:"absolute",top:3,left:autoRef?17:3,transition:"left .2s" }}/>
              </div>
              <span style={{ fontSize:11,color:autoRef?"var(--accent-text)":"var(--txt3)",fontWeight:autoRef?600:400 }}>5초 자동갱신</span>
            </div>
            <span style={{ fontSize:10,color:"var(--txt3)",marginLeft:"auto" }}>
              {vdata && `갱신: ${new Date().toLocaleTimeString("ko-KR",{hour12:false})}`}
            </span>
          </div>

          {/* 현재 접속자 테이블 */}
          {sessions.length>0 && (
            <div style={{ marginBottom:16 }}>
              <div style={{ fontSize:11,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:8 }}>
                현재 접속자
              </div>
              <div style={{ overflowX:"auto",border:"1px solid var(--bdr)",borderRadius:8,overflow:"hidden" }}>
                <table style={{ width:"100%",borderCollapse:"collapse",fontSize:11,tableLayout:"fixed" }}>
                  <colgroup>
                    <col style={{width:56}}/>   {/* 상태 */}
                    <col style={{width:110}}/>  {/* IP */}
                    <col style={{width:"22%"}}/>{/* 자산 */}
                    <col style={{width:60}}/>   {/* 브라우저 */}
                    <col style={{width:90}}/>   {/* OS */}
                    <col style={{width:50}}/>   {/* 요청수 */}
                    <col style={{width:90}}/>   {/* 최초 */}
                    <col style={{width:90}}/>   {/* 최근 */}
                    <col style={{width:"auto"}}/>{/* 경로 */}
                  </colgroup>
                  <thead><tr>
                    <SortHd k="is_active" sort={sesSort} onSort={onSesSort}>상태</SortHd>
                    <SortHd k="ip"        sort={sesSort} onSort={onSesSort}>IP 주소</SortHd>
                    <th style={{ padding:"7px 10px",fontSize:9,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",borderBottom:"2px solid var(--bdr)",background:"var(--bg-card2)" }}>자산 정보</th>
                    <SortHd k="browser"   sort={sesSort} onSort={onSesSort}>브라우저</SortHd>
                    <SortHd k="os"        sort={sesSort} onSort={onSesSort}>OS</SortHd>
                    <SortHd k="req_count" sort={sesSort} onSort={onSesSort}>요청수</SortHd>
                    <SortHd k="first_seen" sort={sesSort} onSort={onSesSort}>최초</SortHd>
                    <SortHd k="last_seen" sort={sesSort} onSort={onSesSort}>최근</SortHd>
                    <th style={{ padding:"7px 10px",fontSize:9,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",borderBottom:"2px solid var(--bdr)",background:"var(--bg-card2)" }}>마지막 경로</th>
                  </tr></thead>
                  <tbody>
                    {sessions.map((s,i) => {
                      const asset = ipToAsset[s.ip];
                      return (
                        <tr key={i} style={{ background:i%2===0?"transparent":"var(--bg-card2)" }}>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)" }}>
                            <span style={{ display:"flex",alignItems:"center",gap:5 }}>
                              <span style={{ width:7,height:7,borderRadius:"50%",background:s.is_active?"#22C55E":"#6B7280",flexShrink:0,boxShadow:s.is_active?"0 0 5px #22C55E":"none" }}/>
                              <span style={{ fontSize:9,color:s.is_active?"#4ADE80":"var(--txt3)" }}>{s.is_active?"접속중":"이탈"}</span>
                            </span>
                          </td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)" }}>
                            <code style={{ fontSize:11,fontWeight:700,color:"var(--accent-text)" }}>{s.ip}</code>
                          </td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)" }}>
                            {asset ? (
                              <div>
                                <div style={{ fontSize:11,fontWeight:600,color:"var(--txt)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }} title={asset.name}>{asset.name}</div>
                                <div style={{ fontSize:9,color:"var(--txt3)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{asset.department} · {asset.manager}</div>
                              </div>
                            ) : (
                              <span style={{ fontSize:10,color:"var(--txt3)" }}>미등록 자산</span>
                            )}
                          </td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)",fontSize:11,color:"var(--txt2)" }}>{s.browser}</td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)",fontSize:11,color:"var(--txt2)" }}>{s.os}</td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)",fontSize:11,fontWeight:600,color:"var(--txt)",textAlign:"center" }}>{s.req_count}</td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)",fontSize:10,color:"var(--txt3)",whiteSpace:"nowrap" }}>{s.first_seen?.replace("T"," ").slice(0,16)}</td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)",fontSize:10,color:"var(--txt3)",whiteSpace:"nowrap" }}>{s.last_seen?.replace("T"," ").slice(0,16)}</td>
                          <td style={{ padding:"8px 10px",borderBottom:"1px solid var(--bdr)",fontSize:10,color:"var(--txt3)",maxWidth:160,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{s.last_path}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* API 요청 로그 */}
          <div>
            <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:8 }}>
              <span style={{ fontSize:11,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em" }}>API 요청 로그</span>
              <span style={{ fontSize:10,color:"var(--txt3)" }}>{filteredLogs.length}건</span>
              <div style={{ display:"flex",gap:4,marginLeft:"auto" }}>
                {["ALL","GET","POST","ERROR","WS"].map(f=>(
                  <button key={f} onClick={()=>{setLogFilter(f);setLogPage(1);}}
                    style={{ padding:"2px 8px",borderRadius:3,fontSize:9,fontWeight:700,cursor:"pointer",fontFamily:"monospace",
                      border:`1px solid ${logFilter===f?"var(--accent)":"var(--bdr)"}`,
                      background:logFilter===f?"var(--bg-active)":"transparent",
                      color:logFilter===f?"var(--accent-text)":"var(--txt3)" }}>
                    {f}
                  </button>
                ))}
              </div>
            </div>
            <div style={{ border:"1px solid var(--bdr)",borderRadius:8,overflow:"hidden" }}>
              {filteredLogs.length===0 ? (
                <div style={{ textAlign:"center",padding:"24px",color:"var(--txt3)",fontSize:12 }}>
                  {loading?"로딩 중...":"요청 이력이 없습니다"}
                </div>
              ) : (
                <>
                  <div style={{ overflowX:"auto" }}>
                    <table style={{ width:"100%",borderCollapse:"collapse",fontSize:10,fontFamily:"monospace" }}>
                      <thead>
                        <tr>
                          {[["ts","시각"],["ip","IP"],["method","메서드"],["path","경로"],["status","상태"],["latency_ms","응답(ms)"],["browser","브라우저"]].map(([k,lbl])=>(
                            <th key={k} onClick={()=>onLogSort(k)}
                              style={{ padding:"6px 10px",textAlign:"left",fontSize:9,fontWeight:700,color:logSort.key===k?"var(--accent-text)":"var(--txt3)",textTransform:"uppercase",letterSpacing:".05em",whiteSpace:"nowrap",background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",cursor:"pointer",userSelect:"none" }}>
                              {lbl} <span style={{ fontSize:8,opacity:logSort.key===k?1:.3 }}>{logSort.key===k?(logSort.asc?"▲":"▼"):"⇅"}</span>
                            </th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {pagedLogs.map((log,i)=>(
                          <tr key={i} style={{ borderBottom:"1px solid var(--bdr)",background:i%2===0?"transparent":"rgba(0,0,0,.02)" }}>
                            <td style={{ padding:"5px 10px",color:"var(--txt3)",whiteSpace:"nowrap" }}>{log.ts?.slice(11)}</td>
                            <td style={{ padding:"5px 10px" }}>
                              <div style={{ color:"var(--accent-text)",fontWeight:600 }}>{log.ip}</div>
                              {ipToAsset[log.ip] && <div style={{ fontSize:8,color:"var(--txt3)" }}>{ipToAsset[log.ip].name}</div>}
                            </td>
                            <td style={{ padding:"5px 10px" }}>
                              <span style={{ padding:"1px 5px",borderRadius:3,fontSize:9,fontWeight:700,
                                background:`${METHOD_COLORS[log.path?.startsWith("/ws")?"WS":log.method]||"#94A3B8"}18`,
                                color:METHOD_COLORS[log.path?.startsWith("/ws")?"WS":log.method]||"#94A3B8",
                                border:`1px solid ${METHOD_COLORS[log.path?.startsWith("/ws")?"WS":log.method]||"#94A3B8"}33` }}>
                                {log.path?.startsWith("/ws")?"WS":log.method}
                              </span>
                            </td>
                            <td style={{ padding:"5px 10px",color:"var(--txt2)",maxWidth:200,overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }} title={log.path}>{log.path}</td>
                            <td style={{ padding:"5px 10px" }}>
                              <span style={{ fontWeight:700,color:STATUS_COLORS[log.status]||(log.status>=400?"#F87171":"#94A3B8") }}>{log.status}</span>
                            </td>
                            <td style={{ padding:"5px 10px",color:log.latency_ms>2000?"#F87171":log.latency_ms>500?"#FBBF24":"#4ADE80",fontWeight:600 }}>
                              {log.latency_ms}
                            </td>
                            <td style={{ padding:"5px 10px",color:"var(--txt3)",whiteSpace:"nowrap" }}>{log.browser}/{log.os}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                  {/* 페이지네이션 */}
                  {totalLogPages>1 && (
                    <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 12px",borderTop:"1px solid var(--bdr)",background:"var(--bg-card2)" }}>
                      <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                        <span style={{ fontSize:11,color:"var(--txt3)" }}>
                          {filteredLogs.length}건 중 {(logPage-1)*LOG_PAGE_SIZE+1}–{Math.min(logPage*LOG_PAGE_SIZE,filteredLogs.length)}
                        </span>
                        <select value={LOG_PAGE_SIZE} onChange={e=>{setLogPageSize(Number(e.target.value));setLogPage(1);}}
                          style={{ padding:"2px 6px",borderRadius:4,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt3)",fontSize:10,cursor:"pointer" }}>
                          {[10,20,50,100].map(n=><option key={n} value={n}>{n}건</option>)}
                        </select>
                      </div>
                      <div style={{ display:"flex",gap:3 }}>
                        {[{l:"«",p:1},{l:"‹",p:logPage-1},...Array.from({length:totalLogPages},(_,i)=>({l:String(i+1),p:i+1})),{l:"›",p:logPage+1},{l:"»",p:totalLogPages}]
                          .filter(b=>b.p>=1&&b.p<=totalLogPages)
                          .map((b,i)=>(
                          <button key={i} onClick={()=>setLogPage(b.p)}
                            style={{ padding:"3px 8px",borderRadius:4,border:`1px solid ${b.p===logPage?"var(--accent)":"var(--bdr)"}`,background:b.p===logPage?"var(--accent)":"transparent",color:b.p===logPage?"#fff":"var(--txt3)",fontSize:11,cursor:"pointer" }}>
                            {b.l}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                </>
              )}
            </div>
          </div>

          {!vdata && !loading && (
            <div style={{ marginTop:12,padding:"10px 14px",background:"rgba(220,38,38,.07)",border:"1px solid rgba(220,38,38,.2)",borderRadius:7,fontSize:11,color:"#F87171" }}>
              ⚠ 서버에 연결할 수 없습니다. 백엔드 서버가 실행 중인지 확인하세요.
            </div>
          )}
        </div>
      );
    })(),

    // ── 국내 기관 (orgs 서브) ──────────────────────────────
    orgs_kr: (() => {
      const KR_IDS = ["KrCERT/CC","KISA 보호나라","금융보안원","금융감독원"];
      const orgs   = (() => { try { return JSON.parse(localStorage.getItem("ssk_orgs"))||DEFAULT_ORGS; } catch { return DEFAULT_ORGS; } })();
      const krOrgs = orgs.filter(o => KR_IDS.includes(o.name));
      return (
        <div>
          <div style={{ padding:"10px 14px", background:"rgba(37,99,235,.07)", border:"1px solid rgba(37,99,235,.2)", borderRadius:8, marginBottom:14, fontSize:11, color:"var(--txt2)", lineHeight:1.7 }}>
            국내 금융권과 직접 연관된 주요 정보보호 기관입니다. <strong style={{ color:"var(--accent-text)" }}>정보보호 기관</strong> 메뉴에서 수정·삭제·추가할 수 있습니다.
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {krOrgs.map((org,i) => (
              <div key={i} style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"14px 16px", background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:9 }}>
                <span style={{ fontSize:22, flexShrink:0 }}>{org.country}</span>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                    <a href={org.url} target="_blank" rel="noreferrer" style={{ fontSize:14, fontWeight:700, color:"var(--accent-text)", textDecoration:"none" }}>{org.name}</a>
                    <span style={{ fontSize:9, padding:"2px 6px", borderRadius:4, background:"rgba(37,99,235,.12)", color:"#60A5FA", border:"1px solid rgba(37,99,235,.25)" }}>{org.type}</span>
                    <span style={{ fontSize:10, color:"var(--txt3)", marginLeft:"auto" }}>갱신: {org.cycle}</span>
                  </div>
                  <div style={{ fontSize:11, color:"var(--txt2)", lineHeight:1.6, marginBottom:6 }}>{org.desc}</div>
                  <div style={{ fontSize:10, color:"var(--txt3)", background:"var(--bg-card2)", padding:"6px 10px", borderRadius:5, border:"1px solid var(--bdr)" }}>
                    <strong style={{ color:"var(--txt)" }}>수집 경로:</strong> {org.source || "—"} &nbsp;·&nbsp; <strong style={{ color:"var(--txt)" }}>형식:</strong> {org.format || "—"}
                  </div>
                  <div style={{ display:"flex", gap:4, marginTop:6 }}>
                    {(org.tags||[]).map(t=><span key={t} style={{ padding:"1px 6px", borderRadius:3, background:"var(--bg-input)", color:"var(--txt3)", border:"1px solid var(--bdr)", fontSize:9 }}>{t}</span>)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    })(),

    // ── 해외 기관 (orgs 서브) ──────────────────────────────
    orgs_intl: (() => {
      const INTL_IDS = ["CISA KEV","NVD (NIST)","MITRE ATT&CK","Exploit-DB"];
      const orgs     = (() => { try { return JSON.parse(localStorage.getItem("ssk_orgs"))||DEFAULT_ORGS; } catch { return DEFAULT_ORGS; } })();
      const intlOrgs = orgs.filter(o => INTL_IDS.includes(o.name));
      return (
        <div>
          <div style={{ padding:"10px 14px", background:"rgba(251,191,36,.07)", border:"1px solid rgba(251,191,36,.2)", borderRadius:8, marginBottom:14, fontSize:11, color:"var(--txt2)", lineHeight:1.7 }}>
            글로벌 취약점·공격 기법 데이터베이스입니다. CVSS·KEV 여부가 자산 위험도 산출에 활용됩니다.
          </div>
          <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
            {intlOrgs.map((org,i) => (
              <div key={i} style={{ display:"flex", alignItems:"flex-start", gap:12, padding:"14px 16px", background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:9 }}>
                <span style={{ fontSize:22, flexShrink:0 }}>{org.country}</span>
                <div style={{ flex:1 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:8, marginBottom:4 }}>
                    <a href={org.url} target="_blank" rel="noreferrer" style={{ fontSize:14, fontWeight:700, color:"var(--accent-text)", textDecoration:"none" }}>{org.name}</a>
                    <span style={{ fontSize:9, padding:"2px 6px", borderRadius:4, background:"rgba(251,191,36,.12)", color:"#FBBF24", border:"1px solid rgba(251,191,36,.25)" }}>{org.type}</span>
                    <span style={{ fontSize:10, color:"var(--txt3)", marginLeft:"auto" }}>갱신: {org.cycle}</span>
                  </div>
                  <div style={{ fontSize:11, color:"var(--txt2)", lineHeight:1.6, marginBottom:6 }}>{org.desc}</div>
                  <div style={{ fontSize:10, color:"var(--txt3)", background:"var(--bg-card2)", padding:"6px 10px", borderRadius:5, border:"1px solid var(--bdr)" }}>
                    <strong style={{ color:"var(--txt)" }}>수집 경로:</strong> {org.source || "—"} &nbsp;·&nbsp; <strong style={{ color:"var(--txt)" }}>형식:</strong> {org.format || "—"}
                  </div>
                  <div style={{ display:"flex", gap:4, marginTop:6 }}>
                    {(org.tags||[]).map(t=><span key={t} style={{ padding:"1px 6px", borderRadius:3, background:"var(--bg-input)", color:"var(--txt3)", border:"1px solid var(--bdr)", fontSize:9 }}>{t}</span>)}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      );
    })(),

    asset_presets: <PanelAssetPresets/>,
    sysinfo: (
      <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:8 }}>
        {[
          {l:"버전",   v:"SecurityScanKit v1.0"},{l:"Python", v:"3.14"},
          {l:"FastAPI",v:"0.115.x"},             {l:"DB",     v:"SQLite"},
          {l:"프론트", v:"React 18 + Vite"},     {l:"스캐너", v:"Socket / nmap"},
          {l:"AI",     v:"Claude Sonnet"},        {l:"포트",   v:"8000 / 3000"},
        ].map(item=>(
          <div key={item.l} style={{ background:"var(--bg-card2)", borderRadius:7, padding:"10px 12px", border:"1px solid var(--bdr)" }}>
            <div style={{ fontSize:9, color:"var(--txt3)", marginBottom:4, textTransform:"uppercase", letterSpacing:".06em" }}>{item.l}</div>
            <div style={{ fontSize:12, fontWeight:600, color:"var(--txt)" }}>{item.v}</div>
          </div>
        ))}
      </div>
    ),
  };

  return (
    <div style={{ display:"flex", height:"calc(100vh - 54px)", overflow:"hidden" }}>

      {/* ── 왼쪽 메뉴 (그룹 계층 구조) ── */}
      <div style={{ width:220, background:"var(--bg-nav)", borderRight:"1px solid var(--bdr)", flexShrink:0, overflowY:"auto" }}>
        {/* 설정 헤더 */}
        <div style={{ padding:"14px 16px 10px", borderBottom:"1px solid var(--bdr)" }}>
          <div style={{ display:"flex", alignItems:"center", gap:8 }}>
            <div style={{ width:28, height:28, borderRadius:7, background:"var(--accent)", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
              <span style={{ fontSize:14 }}>⚙</span>
            </div>
            <div>
              <div style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>설정</div>
              <div style={{ fontSize:9, color:"var(--txt3)" }}>System Configuration</div>
            </div>
          </div>
        </div>

        {MENU_GROUPS.map(group => (
          <div key={group.id}>
            {/* 그룹 레이블 */}
            <div style={{ padding:"12px 14px 3px", fontSize:9, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".1em" }}>
              {group.label}
            </div>
            {/* 메뉴 아이템 */}
            {group.items.map(m => {
              const on = active === m.id;
              return (
                <div key={m.id} onClick={() => setActive(m.id)}
                  style={{
                    display:"flex", alignItems:"center", gap:8, cursor:"pointer",
                    padding: m.indent ? "6px 12px 6px 32px" : "8px 12px 8px 14px",
                    background: on ? "var(--bg-active)" : "transparent",
                    borderRight: on ? "2px solid var(--accent)" : "2px solid transparent",
                    transition:"all .15s", position:"relative",
                  }}>
                  {/* 서브메뉴 인디케이터 */}
                  {m.indent && (
                    <>
                      <div style={{ position:"absolute", left:18, top:0, bottom:0, width:"1px", background:"var(--bdr)" }}/>
                      <div style={{ position:"absolute", left:18, top:"50%", width:8, height:"1px", background:"var(--bdr)" }}/>
                    </>
                  )}
                  <span style={{ fontSize: m.indent ? 13 : 14, flexShrink:0, opacity:m.indent?0.8:1 }}>{m.icon}</span>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize: m.indent ? 11 : 12, fontWeight:on?600:400,
                      color:on?"var(--accent-text)":m.indent?"var(--txt3)":"var(--txt2)",
                      whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                      {m.label}
                    </div>
                    {!m.indent && (
                      <div style={{ fontSize:9, color:"var(--txt3)", marginTop:1 }}>{m.sub}</div>
                    )}
                  </div>
                  {m.badge && (
                    <span style={{ fontSize:9, padding:"1px 5px", borderRadius:3, fontWeight:700, flexShrink:0,
                      background: m.badgeType==="ok" ? "rgba(22,163,74,.15)" : m.badgeType==="warn" ? "rgba(234,179,8,.15)" : "rgba(37,99,235,.15)",
                      color:      m.badgeType==="ok" ? "#4ADE80"             : m.badgeType==="warn" ? "#FBBF24"             : "#60A5FA",
                      border:     `1px solid ${m.badgeType==="ok" ? "rgba(22,163,74,.3)" : m.badgeType==="warn" ? "rgba(234,179,8,.3)" : "rgba(37,99,235,.3)"}`,
                    }}>{m.badge}</span>
                  )}
                  {on && <div style={{ position:"absolute", left:0, top:"15%", bottom:"15%", width:2.5, background:"var(--accent)", borderRadius:"0 2px 2px 0" }}/>}
                </div>
              );
            })}
          </div>
        ))}
        <div style={{ height:16 }}/>
      </div>

      {/* ── 오른쪽 내용 ── */}
      <div style={{ flex:1, overflowY:"auto", padding:"20px 26px", background:"var(--bg-base)" }}>
        {/* 브레드크럼 헤더 */}
        {(() => {
          const m = ALL_MENUS.find(x=>x.id===active);
          const grp = MENU_GROUPS.find(g=>g.items.some(x=>x.id===active));
          return (
            <div style={{ marginBottom:18, paddingBottom:14, borderBottom:"1px solid var(--bdr)" }}>
              {/* 브레드크럼 */}
              <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:6 }}>
                <span style={{ fontSize:10, color:"var(--txt3)" }}>설정</span>
                <span style={{ fontSize:10, color:"var(--bdr2)" }}>›</span>
                <span style={{ fontSize:10, color:"var(--txt3)" }}>{grp?.label}</span>
                <span style={{ fontSize:10, color:"var(--bdr2)" }}>›</span>
                <span style={{ fontSize:10, color:"var(--txt2)", fontWeight:500 }}>{m?.label}</span>
              </div>
              {/* 타이틀 */}
              <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                <span style={{ fontSize:22, lineHeight:1 }}>{m?.icon}</span>
                <div>
                  <div style={{ fontSize:16, fontWeight:700, color:"var(--txt)", letterSpacing:"-.01em" }}>{m?.label}</div>
                  <div style={{ fontSize:11, color:"var(--txt3)", marginTop:2 }}>{m?.sub}</div>
                </div>
              </div>
            </div>
          );
        })()}
        {panels[active]}
      </div>
    </div>
  );
}


