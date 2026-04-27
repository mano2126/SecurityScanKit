// pages/PageScan.jsx
import { useState, useEffect, useRef, useCallback } from "react";
import { Spinner } from "../components/UI";
import { fetchAssets, startScan, fetchScanStatus, fetchScanHistory } from "../hooks/useAPI";
import API_BASE from "../hooks/apiConfig.js";

const WS_BASE = API_BASE.replace(/^http/, "ws");

const ALL_SCAN_TYPES = [
  { id:"port",    icon:"🔌", label:"포트 스캔",  desc:"위험 포트 / 개방 여부" },
  { id:"web",     icon:"🌐", label:"웹 취약점",  desc:"헤더 / 민감 경로" },
  { id:"ssl",     icon:"🔒", label:"SSL/TLS",    desc:"인증서 / 프로토콜" },
  { id:"db",      icon:"🗄",  label:"DB 보안",    desc:"포트 / 인증 설정" },
  { id:"network", icon:"📡", label:"네트워크",    desc:"SNMP / Telnet" },
];

const LC = {
  CRITICAL:"#F87171", HIGH:"#FB923C", WARN:"#E3B341",
  INFO:"var(--txt)",  DONE:"#4ADE80", REPEAT:"#C084FC",
  ERROR:"#F87171",    START:"#818CF8", RUN:"#60A5FA",
};
const ENV_C = { Production:"#F87171", Staging:"#FB923C", DR:"#C084FC", Development:"#60A5FA" };


// ── 점검 단계 가이드 데이터 ──────────────────────────────────────
const SCAN_GUIDE = {
  port: {
    icon:"🔌", label:"포트 스캔", color:"#60A5FA",
    summary:"서버에 열려있는 포트를 탐색해 불필요하거나 위험한 포트를 찾아냅니다.",
    why:"열린 포트는 공격자의 진입 통로입니다. 업무에 불필요한 포트가 열려있으면 해킹 시도의 표적이 됩니다.",
    steps:[
      { label:"포트 스캔 시작",   desc:"1~65535번 중 위험 포트 목록을 우선 검사합니다." },
      { label:"서비스 식별",      desc:"포트에서 실행 중인 서비스(SSH/RDP/HTTP 등)의 종류와 버전을 확인합니다." },
      { label:"위험 포트 판정",   desc:"금융보안원 기준 위험 포트(23/Telnet, 3389/RDP, 1433/MSSQL 등)를 판정합니다." },
      { label:"결과 저장",        desc:"발견된 취약점을 DB에 저장하고 심각도를 산정합니다." },
      { label:"점검 종료",        desc:"포트 스캔이 완료됐습니다. 결과 확인 탭에서 발견된 취약점을 확인하고 조치 계획을 수립하세요.", done:true },
    ],
    tip:"22(SSH), 3389(RDP), 445(SMB)는 외부 노출 시 즉시 조치가 필요합니다."
  },
  web: {
    icon:"🌐", label:"웹 취약점 점검", color:"#34D399",
    summary:"웹 서버의 보안 설정을 검사해 해킹에 악용될 수 있는 취약점을 찾습니다.",
    why:"웹 서버 설정 미흡은 개인정보 유출, 홈페이지 변조의 주요 원인입니다. 금감원 IT 검사 필수 항목입니다.",
    steps:[
      { label:"HTTP 응답 헤더 검사",  desc:"보안 헤더(X-Frame-Options, CSP 등) 누락 여부를 확인합니다." },
      { label:"민감 경로 노출 검사",  desc:"관리자 페이지, 백업 파일, 설정 파일의 외부 노출 여부를 확인합니다." },
      { label:"HTTP→HTTPS 전환 검사", desc:"암호화 없이 평문 전송되는 경로가 있는지 확인합니다." },
      { label:"결과 저장",            desc:"발견된 항목을 OWASP 기준으로 분류해 저장합니다." },
      { label:"점검 종료",            desc:"웹 취약점 점검이 완료됐습니다. 보안 헤더 미설정 및 경로 노출 항목을 우선 조치하세요.", done:true },
    ],
    tip:"관리자 페이지(/admin, /wp-admin)가 외부에 노출됐다면 즉시 차단하세요."
  },
  ssl: {
    icon:"🔒", label:"SSL/TLS 점검", color:"#A78BFA",
    summary:"암호화 통신 설정의 안전성을 검사합니다. 인증서 유효성과 프로토콜 버전을 확인합니다.",
    why:"취약한 SSL 설정은 통신 도청(중간자 공격)을 가능하게 합니다. 금융서비스는 TLS 1.2 이상이 의무입니다.",
    steps:[
      { label:"SSL 연결 시도",       desc:"HTTPS 포트(443)에 연결해 인증서 정보를 가져옵니다." },
      { label:"인증서 유효성 확인",  desc:"만료일, 발급기관(공인CA 여부), 자체서명 여부를 검사합니다." },
      { label:"프로토콜 버전 검사",  desc:"TLSv1.0/1.1 등 취약한 버전 사용 여부를 확인합니다." },
      { label:"암호화 알고리즘 검사",desc:"RC4, DES 등 취약한 암호화 알고리즘 사용 여부를 확인합니다." },
      { label:"점검 종료",           desc:"SSL/TLS 점검이 완료됐습니다. 인증서 만료 임박 및 취약 프로토콜 항목을 즉시 조치하세요.", done:true },
    ],
    tip:"인증서 만료 30일 전부터 갱신을 준비하세요. 자체서명 인증서는 공인 CA로 교체해야 합니다."
  },
  db: {
    icon:"🗄", label:"DB 보안 점검", color:"#FB923C",
    summary:"데이터베이스 포트 노출 여부와 기본 설정의 위험성을 검사합니다.",
    why:"DB 직접 노출은 개인정보·금융정보 대규모 유출로 이어집니다. 내부망에서만 접근 가능해야 합니다.",
    steps:[
      { label:"DB 포트 스캔",     desc:"MSSQL(1433), MySQL(3306), Oracle(1521) 등 포트 개방 여부를 확인합니다." },
      { label:"외부 접근 가능성", desc:"DB 포트가 인터넷에 직접 노출됐는지 판정합니다." },
      { label:"기본 계정 확인",   desc:"SA, root 등 기본 관리자 계정이 활성화됐는지 확인합니다." },
      { label:"결과 저장",        desc:"발견된 취약점을 저장합니다." },
      { label:"점검 종료",        desc:"DB 보안 점검이 완료됐습니다. 외부 노출된 DB 포트는 즉시 방화벽 차단이 필요합니다.", done:true },
    ],
    tip:"DB는 반드시 내부망에서만 접근 가능하도록 방화벽 설정이 필요합니다."
  },
  network: {
    icon:"📡", label:"네트워크 점검", color:"#FBBF24",
    summary:"SNMP, Telnet 등 구형 네트워크 프로토콜의 위험 노출 여부를 검사합니다.",
    why:"Telnet은 비암호화 통신, SNMP v1/v2는 community string 노출로 네트워크 장비 정보가 탈취될 수 있습니다.",
    steps:[
      { label:"Telnet 포트 검사",    desc:"23번 포트 개방 여부를 확인합니다. Telnet은 SSH로 대체되어야 합니다." },
      { label:"SNMP 검사",           desc:"161번 포트 SNMP 응답과 기본 community string 사용 여부를 확인합니다." },
      { label:"기본 자격증명 시도",  desc:"네트워크 장비의 기본 계정(admin/admin 등) 사용 여부를 확인합니다." },
      { label:"결과 저장",           desc:"발견된 취약점을 저장합니다." },
      { label:"점검 종료",           desc:"네트워크 점검이 완료됐습니다. Telnet 비활성화 및 SNMP v3 전환을 우선 조치하세요.", done:true },
    ],
    tip:"Telnet을 즉시 비활성화하고 SSH로 전환하세요. SNMP는 v3로 업그레이드가 필요합니다."
  }
};

// ── 점검 단계 가이드 패널 ──────────────────────────────────────────
function ScanGuidePanel({ activeScanType, activeStep, onStepChange, scanning, scanTypes }) {
  const [open,         setOpen]         = useState(false); // 기본 접힘
  const [selected,     setSelected]     = useState(null);
  const [manualStep,   setManualStep]   = useState(null);
  const [autoOverride, setAutoOverride] = useState(false);

  // 점검 유형이 바뀌면 자동으로 해당 탭 선택 + 수동 오버라이드 해제
  useEffect(() => {
    if (activeScanType && SCAN_GUIDE[activeScanType]) {
      setSelected(activeScanType);
      setAutoOverride(false);
      setManualStep(null);
      setOpen(true); // 점검 시작 시 자동 펼침
    }
  }, [activeScanType]);

  // 현재 표시할 단계: 수동 선택 우선, 없으면 자동
  const displayStep = manualStep !== null ? manualStep : activeStep;

  // activeStep 바뀌면 수동 선택 해제 (점검 진행 중에만)
  useEffect(() => {
    if (scanning) setManualStep(null);
  }, [activeStep, scanning]);

  const handleStepClick = (si) => {
    setManualStep(si === manualStep ? null : si); // 같은 거 클릭하면 해제
    onStepChange(si);
  };

  const guide = selected ? SCAN_GUIDE[selected] : null;
  const currentStep = guide?.steps?.[displayStep] ?? null;

  return (
    <div style={{ flexShrink:0, borderBottom:"1px solid var(--bdr)",
      background:"var(--bg-base)", maxHeight:open?320:36,
      display:"flex", flexDirection:"column", transition:"max-height .2s ease",
      overflow:"hidden" }}>

      {/* 접기/펼치기 헤더 + 점검 유형 탭 */}
      <div style={{ display:"flex", alignItems:"center", gap:4, padding:"5px 10px",
        borderBottom: open ? "1px solid var(--bdr)" : "none",
        background:"var(--bg-card2)", flexShrink:0, overflowX:"auto",
        cursor:"pointer" }}
        onClick={()=>setOpen(o=>!o)}>
        <span style={{
          fontSize:"0.86rem",marginRight:4,
          color: open?"var(--txt3)":"var(--accent-text)",
          animation: open?"none":"guidePulse 1.5s ease-in-out infinite",
          display:"inline-block"
        }}>{open?"▼":"▶"}</span>
        <span style={{fontSize:"0.79rem",fontWeight:700,
          color:open?"var(--txt3)":"var(--accent-text)",
          textTransform:"uppercase",letterSpacing:".05em",marginRight:8}}>
          점검 단계 가이드
        </span>
        <style>{`
          @keyframes guidePulse {
            0%,100%{ opacity:.45; }
            50%    { opacity:1; }
          }
        `}</style>
        <span style={{ fontSize:12, fontWeight:700, color:"var(--txt3)",
          whiteSpace:"nowrap", marginRight:4 }}>점검 안내</span>
        {scanTypes.map(tid => {
          const g = SCAN_GUIDE[tid];
          if (!g) return null;
          const isActive = activeScanType === tid && scanning;
          const isSel    = selected === tid;
          return (
            <button key={tid} onClick={e=>{ e.stopPropagation(); setSelected(isSel ? null : tid); setAutoOverride(false); setManualStep(null); }}
              style={{ display:"flex", alignItems:"center", gap:4,
                padding:"4px 10px", borderRadius:5, cursor:"pointer",
                fontSize:12, fontWeight:isSel ? 700 : 400, flexShrink:0,
                border:`1px solid ${isSel ? g.color : isActive ? g.color+"66" : "var(--bdr)"}`,
                background: isSel ? `${g.color}18` : isActive ? `${g.color}0D` : "transparent",
                color: isSel ? g.color : isActive ? g.color : "var(--txt3)",
                transition:"all .2s",
                boxShadow: isActive ? `0 0 8px ${g.color}33` : "none" }}>
              {g.icon}
              <span>{g.label}</span>
              {isActive && (
                <span style={{ width:6, height:6, borderRadius:"50%",
                  background:g.color, display:"inline-block",
                  animation:"pulse 1s infinite" }}/>
              )}
            </button>
          );
        })}
        {selected && (
          <button onClick={() => setSelected(null)}
            style={{ marginLeft:"auto", padding:"2px 7px", borderRadius:4,
              border:"1px solid var(--bdr)", background:"transparent",
              color:"var(--txt3)", fontSize:12, cursor:"pointer", flexShrink:0 }}>
            ✕
          </button>
        )}
      </div>

      {/* 가이드 상세 — 3컬럼: 개요 | 단계목록 | 단계설명 */}
      {guide && (
        <div style={{ flex:1, overflow:"hidden", minHeight:0,
          display:"grid", gridTemplateColumns:"1fr 220px 1fr", gap:0 }}>

          {/* ① 왼쪽: 점검 유형 개요 */}
          <div style={{ padding:"10px 12px", overflowY:"auto",
            borderRight:"1px solid var(--bdr)" }}>
            <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:6 }}>
              <span style={{ fontSize:16 }}>{guide.icon}</span>
              <span style={{ fontSize:12, fontWeight:700, color:guide.color }}>{guide.label}</span>
            </div>
            <div style={{ fontSize:12, color:"var(--txt)", lineHeight:1.7, marginBottom:7 }}>
              {guide.summary}
            </div>
            <div style={{ fontSize:12, color:"var(--txt2)", lineHeight:1.65,
              padding:"7px 9px", background:`${guide.color}08`,
              border:`1px solid ${guide.color}20`, borderRadius:6, marginBottom:7 }}>
              <span style={{ fontWeight:700, color:guide.color }}>⚠ 왜 위험한가?</span>
              <br/>{guide.why}
            </div>
            <div style={{ fontSize:12, color:"#FBBF24", padding:"7px 10px",
              background:"rgba(251,191,36,.06)", border:"1px solid rgba(251,191,36,.2)",
              borderRadius:5 }}>
              💡 {guide.tip}
            </div>
          </div>

          {/* ② 가운데: 단계 번호 + 레이블 목록 */}
          <div style={{ display:"flex", flexDirection:"column", overflowY:"auto",
            borderRight:"1px solid var(--bdr)" }}>
            <div style={{ padding:"6px 10px", fontSize:12, fontWeight:700,
              color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".06em",
              borderBottom:"1px solid var(--bdr)", background:"var(--bg-card2)",
              flexShrink:0 }}>
              점검 단계
              {autoOverride && (
                <span style={{ marginLeft:6, fontSize:"0.86rem", color:"#FBBF24",
                  fontWeight:400, textTransform:"none" }}>수동 선택</span>
              )}
            </div>
            <div style={{ flex:1, display:"flex", flexDirection:"column", padding:"4px 6px", gap:3 }}>
              {guide.steps.map((step, si) => {
                const isActive  = activeScanType===selected; // 현재 선택된 유형
                const isRunning = isActive && scanning && si===activeStep;
                const isDone    = isActive && si<activeStep;
                const isSel     = displayStep === si;
                return (
                  <div key={si}
                    onClick={() => handleStepClick(si)}
                    style={{ display:"flex", alignItems:"center", gap:7,
                      padding:"7px 10px", borderRadius:6, cursor:"pointer",
                      transition:"all .15s",
                      background: step.done && isSel ? "rgba(74,222,128,.1)"
                                : isSel ? `${guide.color}15` : "transparent",
                      border:`1px solid ${step.done && isSel ? "rgba(74,222,128,.4)"
                            : isSel ? guide.color+"55" : "transparent"}` }}
                    onMouseEnter={e => { if(!isSel) e.currentTarget.style.background="var(--bg-hover)"; }}
                    onMouseLeave={e => { if(!isSel) e.currentTarget.style.background="transparent"; }}>
                    {/* 번호 원형 */}
                    <div style={{ width:20, height:20, borderRadius:"50%", flexShrink:0,
                      display:"flex", alignItems:"center", justifyContent:"center",
                      fontSize:12, fontWeight:700, transition:"all .2s",
                      background: step.done && isSel ? "#4ADE80"
                                : step.done ? "rgba(74,222,128,.2)"
                                : isRunning ? guide.color
                                : isDone    ? "#4ADE80"
                                : isSel     ? guide.color
                                : "var(--bg-card2)",
                      color: (step.done && isSel)||isRunning||isDone||isSel ? "#fff"
                           : step.done ? "#4ADE80" : "var(--txt3)",
                      boxShadow: isRunning ? `0 0 10px ${guide.color}88`
                               : (step.done && isSel) ? "0 0 10px rgba(74,222,128,.5)" : "none",
                      animation: isRunning ? "pulse 1s infinite" : "none" }}>
                      {step.done ? "✓" : isDone ? "✓" : si+1}
                    </div>
                    {/* 단계명 */}
                    <span style={{ fontSize:12, fontWeight: isSel ? 700 : 400,
                      color: step.done && isSel ? "#4ADE80"
                           : isSel ? guide.color : step.done ? "rgba(74,222,128,.6)" : "var(--txt)",
                      lineHeight:1.3, flex:1 }}>
                      {step.label}
                    </span>
                    {/* 진행 중 점 */}
                    {isRunning && (
                      <span style={{ width:5, height:5, borderRadius:"50%", flexShrink:0,
                        background:guide.color, animation:"pulse 1s infinite" }}/>
                    )}
                  </div>
                );
              })}
            </div>
          </div>

          {/* ③ 오른쪽: 선택된 단계 설명 */}
          <div style={{ padding:"10px 12px", overflowY:"auto" }}>
            {currentStep ? (
              <div style={{ height:"100%", display:"flex", flexDirection:"column", gap:8 }}>
                {/* 단계 헤더 */}
                <div style={{ display:"flex", alignItems:"center", gap:8, flexShrink:0 }}>
                  <div style={{ width:24, height:24, borderRadius:"50%", flexShrink:0,
                    background: currentStep.done ? "#4ADE80" : guide.color,
                    display:"flex", alignItems:"center",
                    justifyContent:"center", fontSize:12, fontWeight:700, color:"#fff",
                    boxShadow: currentStep.done ? "0 0 12px rgba(74,222,128,.5)" : "none" }}>
                    {currentStep.done ? "✓" : displayStep+1}
                  </div>
                  <span style={{ fontSize:12, fontWeight:700,
                    color: currentStep.done ? "#4ADE80" : guide.color, lineHeight:1.3 }}>
                    {currentStep.label}
                  </span>
                  {activeScanType===selected && scanning && displayStep===activeStep && (
                    <span style={{ fontSize:12, padding:"1px 6px", borderRadius:8,
                      background:`${guide.color}20`, color:guide.color,
                      border:`1px solid ${guide.color}40`, fontWeight:700,
                      animation:"pulse 1s infinite", flexShrink:0 }}>진행 중</span>
                  )}
                  {autoOverride && (
                    <span style={{ fontSize:12, padding:"1px 6px", borderRadius:8,
                      background:"rgba(251,191,36,.15)", color:"#FBBF24",
                      border:"1px solid rgba(251,191,36,.3)", fontWeight:700, flexShrink:0 }}>
                      수동 선택
                    </span>
                  )}
                </div>
                {/* 단계 설명 본문 */}
                <div style={{ fontSize:12, color:"var(--txt)", lineHeight:1.8,
                  padding:"9px 11px",
                  background: currentStep.done ? "rgba(74,222,128,.07)" : `${guide.color}08`,
                  border: `1px solid ${currentStep.done ? "rgba(74,222,128,.25)" : guide.color+"18"}`,
                  borderRadius:7, flex:1 }}>
                  {currentStep.desc}
                </div>
                {/* 이전/다음 힌트 */}
                <div style={{ display:"flex", justifyContent:"space-between",
                  fontSize:12, color:"var(--txt3)", flexShrink:0 }}>
                  {displayStep > 0 ? (
                    <span style={{ cursor:"pointer", color:"var(--txt3)" }}
                      onClick={() => handleStepClick(displayStep-1)}>
                      ← {guide.steps[displayStep-1].label}
                    </span>
                  ) : <span/>}
                  {displayStep < guide.steps.length-1 ? (
                    <span style={{ cursor:"pointer", color:"var(--txt3)" }}
                      onClick={() => handleStepClick(displayStep+1)}>
                      {guide.steps[displayStep+1].label} →
                    </span>
                  ) : <span/>}
                </div>
              </div>
            ) : (
              <div style={{ height:"100%", display:"flex", alignItems:"center",
                justifyContent:"center", flexDirection:"column", gap:6,
                color:"var(--txt3)", textAlign:"center" }}>
                <div style={{ fontSize:"1.43rem", opacity:.3 }}>👆</div>
                <div style={{ fontSize:11 }}>왼쪽에서 단계를 클릭하면<br/>상세 설명이 표시됩니다</div>
              </div>
            )}
          </div>
        </div>
      )}

      {!guide && !scanning && (
        <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center",
          color:"var(--txt3)", fontSize:11 }}>
          위 버튼을 클릭하면 각 점검 항목에 대한 상세 설명을 확인할 수 있습니다
        </div>
      )}
      {!guide && scanning && (
        <div style={{ flex:1, display:"flex", alignItems:"center", justifyContent:"center",
          gap:8, color:"var(--txt3)", fontSize:11 }}>
          <span style={{ animation:"pulse 1s infinite" }}>⟳</span>
          점검 진행 중 — 위 탭을 클릭하면 점검 내용을 확인할 수 있습니다
        </div>
      )}
    </div>
  );
}

// ── 로그 한 줄 ────────────────────────────────────────────────────
function LogLine({ entry, fs=12 }) {
  const c  = LC[entry.level] || "var(--txt2)";
  const hi = ["CRITICAL","ERROR"].includes(entry.level);
  const ok = ["DONE","START"].includes(entry.level);
  const wn = entry.level === "WARN";
  return (
    <div style={{ display:"flex", gap:0, padding:"1.5px 0",
      background: hi?"rgba(220,38,38,.06)":ok?"rgba(22,163,74,.05)":wn?"rgba(234,179,8,.04)":"transparent",
      borderLeft:`2px solid ${(hi||ok||wn)?c:"transparent"}`, paddingLeft:5 }}>
      <span style={{ color:"var(--txt3)",fontSize:"0.85em",flexShrink:0,minWidth:54,
        fontFamily:"monospace",lineHeight:1.7 }}>{entry.time}</span>
      <span style={{ fontSize:"0.85em",fontWeight:700,minWidth:46,textAlign:"center",flexShrink:0,
        padding:"0 3px",borderRadius:2,marginRight:6,
        background:`${c}18`,color:c,border:`1px solid ${c}30`,
        fontFamily:"monospace",lineHeight:1.6 }}>
        {(entry.tag||entry.level).slice(0,7)}
      </span>
      <span style={{ color:c,fontSize:"1em",fontFamily:"'Consolas','Courier New',monospace",
        lineHeight:1.65,wordBreak:"break-word",flex:1 }}>
        {entry.message}
      </span>
    </div>
  );
}

// ── 자산 선택기 (강화된 조회 조건) ─────────────────────────────
function AssetSelector({ assets, selectedIds, setSelectedIds, onNav, currentUser }) {
  const [search,     setSearch]     = useState("");
  const myDept = currentUser?.dept || currentUser?.division || "";
  const myName = currentUser?.name || "";
  const [filterDept, setFilterDept] = useState(myDept);
  const [filterEnv,  setFilterEnv]  = useState("");
  const [filterType, setFilterType] = useState("");
  const [filterMgr,  setFilterMgr]  = useState("");
  const [sortBy,     setSortBy]     = useState("dept"); // dept | env | name | manager

  const depts   = [...new Set(assets.map(a=>a.department).filter(Boolean))].sort();
  const envs    = [...new Set(assets.map(a=>a.environment).filter(Boolean))].sort();
  const types   = [...new Set(assets.map(a=>a.asset_type).filter(Boolean))].sort();
  const managers= [...new Set(assets.map(a=>a.manager).filter(Boolean))].sort();

  const filtered = assets.filter(a => {
    if (search && !a.name?.toLowerCase().includes(search.toLowerCase())
      && !a.ip?.includes(search) && !a.manager?.toLowerCase().includes(search.toLowerCase())
      && !a.department?.toLowerCase().includes(search.toLowerCase())) return false;
    if (filterDept && a.department !== filterDept) return false;
    if (filterEnv  && a.environment !== filterEnv)  return false;
    if (filterType && a.asset_type  !== filterType)  return false;
    if (filterMgr  && a.manager    !== filterMgr)    return false;
    return true;
  });

  // 그룹핑
  const grouped = (() => {
    const key = sortBy==="dept" ? "department"
              : sortBy==="env"  ? "environment"
              : sortBy==="manager" ? "manager"
              : null;
    if (!key) {
      const sorted = [...filtered].sort((a,b)=>(a.name||"").localeCompare(b.name||""));
      return { "전체": sorted };
    }
    const g = {};
    filtered.forEach(a => {
      const k = a[key] || "미분류";
      (g[k]||(g[k]=[])).push(a);
    });
    return g;
  })();

  const [collapsed, setCollapsed] = useState({});
  const gKeys = Object.keys(grouped).sort();
  const allIds = filtered.map(a=>a.id);
  const allSel = allIds.length>0 && allIds.every(id=>selectedIds.includes(id));

  const toggleGroup = ids => {
    const allOn = ids.every(id=>selectedIds.includes(id));
    setSelectedIds(p => allOn ? p.filter(id=>!ids.includes(id)) : [...new Set([...p,...ids])]);
  };

  const hasFilter = search || filterDept || filterEnv || filterType || filterMgr;
  const clearAll  = () => { setSearch(""); setFilterDept(""); setFilterEnv(""); setFilterType(""); setFilterMgr(""); };

  const ENV_C = { Production:"#F87171", Staging:"#FB923C", DR:"#C084FC", Development:"#60A5FA" };

  return (
    <div style={{ display:"flex",flexDirection:"column",height:"100%",
      background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:8,overflow:"hidden" }}>

      {/* ── 검색/필터 영역 ── */}
      <div style={{ padding:"8px",borderBottom:"1px solid var(--bdr)",
        background:"var(--bg-card2)",flexShrink:0 }}>

        {/* 검색창 */}
        <div style={{ position:"relative",marginBottom:6 }}>
          <span style={{ position:"absolute",left:8,top:"50%",transform:"translateY(-50%)",
            fontSize:12,color:"var(--txt3)",pointerEvents:"none" }}>⌕</span>
          <input value={search} onChange={e=>setSearch(e.target.value)}
            placeholder="시스템명, IP, 담당자, 부서 통합 검색..."
            style={{ width:"100%",padding:"6px 8px 6px 26px",borderRadius:6,fontSize:12,
              border:"1px solid var(--bdr)",background:"var(--bg-input)",
              color:"var(--txt)",outline:"none",boxSizing:"border-box" }}/>
        </div>

        {/* 필터 셀렉트 2열 */}
        <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:4,marginBottom:6 }}>
          <select value={filterDept} onChange={e=>setFilterDept(e.target.value)}
            style={{ padding:"5px 7px",borderRadius:5,
              border:`1px solid ${filterDept===myDept&&myDept?"var(--accent)":filterDept?"var(--accent)":"var(--bdr)"}`,
              background:"var(--bg-input)",
              color:filterDept?"var(--accent-text)":"var(--txt3)",
              fontSize:11,cursor:"pointer",outline:"none",fontWeight:filterDept===myDept&&myDept?700:400 }}>
            <option value="">🏢 전체 본부/부서</option>
            {depts.map(d=><option key={d} value={d}>
              {d}{d===myDept?" ★ 내 부서":""}
            </option>)}
          </select>
          <select value={filterEnv} onChange={e=>setFilterEnv(e.target.value)}
            style={{ padding:"5px 7px",borderRadius:5,border:`1px solid ${filterEnv?"var(--accent)":"var(--bdr)"}`,
              background:"var(--bg-input)",color:filterEnv?"var(--accent-text)":"var(--txt3)",
              fontSize:11,cursor:"pointer",outline:"none" }}>
            <option value="">🌐 전체 환경</option>
            {envs.map(e=><option key={e} value={e}>{e}</option>)}
          </select>
          <select value={filterType} onChange={e=>setFilterType(e.target.value)}
            style={{ padding:"5px 7px",borderRadius:5,border:`1px solid ${filterType?"var(--accent)":"var(--bdr)"}`,
              background:"var(--bg-input)",color:filterType?"var(--accent-text)":"var(--txt3)",
              fontSize:11,cursor:"pointer",outline:"none" }}>
            <option value="">🖥 전체 시스템유형</option>
            {types.map(t=><option key={t} value={t}>{t}</option>)}
          </select>
          <select value={filterMgr} onChange={e=>setFilterMgr(e.target.value)}
            style={{ padding:"5px 7px",borderRadius:5,border:`1px solid ${filterMgr?"var(--accent)":"var(--bdr)"}`,
              background:"var(--bg-input)",color:filterMgr?"var(--accent-text)":"var(--txt3)",
              fontSize:11,cursor:"pointer",outline:"none" }}>
            <option value="">👤 전체 담당자</option>
            {managers.map(m=><option key={m} value={m}>{m}</option>)}
          </select>
        </div>

        {/* 정렬/결과/액션 */}
        <div style={{ display:"flex",alignItems:"center",gap:6,padding:"2px 0 2px 6px" }}>
          <span style={{ fontSize:10,color:"var(--txt3)",fontWeight:600 }}>그룹:</span>
          {[["dept","본부별"],["env","환경별"],["manager","담당자별"],["name","이름순"]].map(([v,l])=>(
            <button key={v} onClick={()=>setSortBy(v)}
              style={{ padding:"2px 6px",borderRadius:3,fontSize:11,cursor:"pointer",
                border:`1px solid ${sortBy===v?"var(--accent)":"var(--bdr)"}`,
                background:sortBy===v?"var(--bg-active)":"transparent",
                color:sortBy===v?"var(--accent-text)":"var(--txt3)" }}>{l}</button>
          ))}
          <span style={{ fontSize:10,color:"var(--txt3)",marginLeft:"auto" }}>
            <span style={{ color:"var(--accent-text)",fontWeight:700 }}>{filtered.length}</span>/{assets.length}개
          </span>
          {hasFilter&&(
            <button onClick={clearAll}
              style={{ padding:"2px 6px",borderRadius:3,fontSize:11,cursor:"pointer",
                border:"1px solid rgba(248,113,113,.3)",background:"rgba(248,113,113,.08)",
                color:"#F87171" }}>✕ 초기화</button>
          )}
          <button onClick={()=>setSelectedIds(allSel?[]:allIds)}
            style={{ padding:"2px 6px",borderRadius:3,fontSize:11,cursor:"pointer",
              border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)" }}>
            {allSel?"전체해제":"전체선택"}
          </button>
        </div>
      </div>

      {/* ── 자산 목록 ── */}
      <div style={{ flex:1,overflowY:"auto",minHeight:0 }}>
        {assets.length===0 ? (
          <div style={{ padding:"24px",textAlign:"center",color:"var(--txt3)",fontSize:11 }}>
            <div style={{ fontSize:"2rem",marginBottom:8,opacity:.3 }}>🖥</div>
            등록된 자산이 없습니다
            <button onClick={()=>onNav("assets")}
              style={{ display:"block",margin:"10px auto 0",padding:"6px 14px",borderRadius:6,
                border:"1px solid var(--accent)",background:"var(--bg-active)",
                color:"var(--accent-text)",fontSize:12,cursor:"pointer",fontWeight:600 }}>
              + 자산 등록하기
            </button>
          </div>
        ) : filtered.length===0 ? (
          <div style={{ padding:"20px",textAlign:"center",color:"var(--txt3)",fontSize:11 }}>
            <div style={{ fontSize:"1.71rem",marginBottom:6,opacity:.3 }}>🔍</div>
            조건에 맞는 자산이 없습니다
            <button onClick={clearAll}
              style={{ display:"block",margin:"8px auto 0",padding:"4px 12px",borderRadius:5,
                border:"1px solid var(--bdr)",background:"transparent",
                color:"var(--txt3)",fontSize:12,cursor:"pointer" }}>필터 초기화</button>
          </div>
        ) : gKeys.map(gk => {
          const items = grouped[gk];
          const gIds  = items.map(a=>a.id);
          const gSel  = gIds.length>0 && gIds.every(id=>selectedIds.includes(id));
          const col   = collapsed[gk];
          const selCount = gIds.filter(id=>selectedIds.includes(id)).length;
          return (
            <div key={gk}>
              {/* 그룹 헤더 */}
              <div onClick={()=>setCollapsed(p=>({...p,[gk]:!col}))}
                style={{ display:"flex",alignItems:"center",gap:6,padding:"6px 14px",
                  background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",
                  cursor:"pointer",position:"sticky",top:0,zIndex:1,userSelect:"none" }}>
                <span style={{ fontSize:12,color:"var(--txt3)",fontWeight:700,width:10 }}>
                  {col?"▶":"▼"}
                </span>
                <span style={{ fontSize:12,fontWeight:700,color:"var(--txt)",flex:1,letterSpacing:".02em" }}>{gk}</span>
                {selCount>0&&(
                  <span style={{ fontSize:12,padding:"1px 5px",borderRadius:3,
                    background:"rgba(37,99,235,.15)",color:"var(--accent-text)",fontWeight:700 }}>
                    {selCount}선택
                  </span>
                )}
                <span style={{ fontSize:12,color:"var(--txt3)" }}>{items.length}개</span>
                <div onClick={e=>{e.stopPropagation();toggleGroup(gIds);}}
                  style={{ width:14,height:14,borderRadius:3,cursor:"pointer",
                    border:`1.5px solid ${gSel?"var(--accent)":"var(--bdr2)"}`,
                    background:gSel?"var(--accent)":"transparent",
                    display:"flex",alignItems:"center",justifyContent:"center" }}>
                  {gSel&&<span style={{ color:"#fff",fontSize:"0.71rem",fontWeight:700 }}>✓</span>}
                </div>
              </div>
              {/* 그룹 아이템 — 본인 담당 자산 상단 */}
              {!col && [...items].sort((a,b) => {
                const aMe = myName && a.manager?.trim()===myName.trim() ? 0 : 1;
                const bMe = myName && b.manager?.trim()===myName.trim() ? 0 : 1;
                return aMe - bMe;
              }).map((a,i) => {
                const sel   = selectedIds.includes(a.id);
                const ec    = ENV_C[a.environment] || "var(--txt3)";
                const isMe  = myName && a.manager?.trim() === myName.trim();
                return (
                  <div key={a.id}
                    onClick={()=>setSelectedIds(p=>sel?p.filter(x=>x!==a.id):[...p,a.id])}
                    style={{ display:"flex",alignItems:"center",gap:8,padding:"7px 14px",
                      borderBottom:"1px solid var(--bdr)",cursor:"pointer",
                      borderLeft:`3px solid ${isMe?"var(--accent)":sel?"var(--accent)":"transparent"}`,
                      background:sel?"var(--bg-active)":isMe?"rgba(37,99,235,.04)":i%2===0?"transparent":"rgba(0,0,0,.015)" }}
                    onMouseEnter={e=>!sel&&(e.currentTarget.style.background="var(--bg-hover)")}
                    onMouseLeave={e=>!sel&&(e.currentTarget.style.background=
                      sel?"var(--bg-active)":isMe?"rgba(37,99,235,.04)":i%2===0?"transparent":"rgba(0,0,0,.015)")}>
                    {/* 체크박스 */}
                    <div style={{ width:14,height:14,borderRadius:3,flexShrink:0,
                      border:`1.5px solid ${sel?"var(--accent)":"var(--bdr2)"}`,
                      background:sel?"var(--accent)":"transparent",
                      display:"flex",alignItems:"center",justifyContent:"center" }}>
                      {sel&&<span style={{ color:"#fff",fontSize:"0.71rem",fontWeight:700 }}>✓</span>}
                    </div>
                    {/* 자산 정보 — 한 줄: [자산명 고정] [IP] [담당자 우측] */}
                    <div style={{ flex:1,minWidth:0,display:"flex",alignItems:"center",gap:8 }}>
                      {/* 자산명 — 고정폭, 왼쪽 정렬, 넘치면 말줄임 */}
                      <span style={{ width:160,flexShrink:0,
                        fontSize:12,fontWeight:sel?700:500,
                        color:sel?"var(--accent-text)":"var(--txt)",
                        overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>
                        {a.name}
                      </span>
                      {/* IP — 왼쪽 정렬 */}
                      <code style={{ flex:1,fontSize:"0.79rem",color:"var(--txt3)",
                        background:"var(--bg-card2)",padding:"1px 5px",borderRadius:3,
                        whiteSpace:"nowrap",overflow:"hidden",textOverflow:"ellipsis" }}>
                        {a.ip}
                      </code>
                      {/* 담당자 — 오른쪽 고정 */}
                      {a.manager&&(
                        <span style={{ flexShrink:0,fontSize:"0.79rem",
                          color:isMe?"var(--accent-text)":"var(--txt3)",
                          fontWeight:isMe?700:400,
                          background:isMe?"rgba(37,99,235,.12)":"transparent",
                          padding:isMe?"2px 6px":"0",
                          borderRadius:isMe?4:0,
                          border:isMe?"1px solid rgba(37,99,235,.25)":"none",
                          whiteSpace:"nowrap" }}>
                          {isMe?"🙋 나":a.manager}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          );
        })}
      </div>

      {/* ── 선택 요약 ── */}
      {selectedIds.length>0&&(
        <div style={{ padding:"5px 10px",borderTop:"1px solid var(--bdr)",
          background:"rgba(37,99,235,.06)",flexShrink:0,
          display:"flex",alignItems:"center",gap:6 }}>
          <span style={{ fontSize:12,color:"var(--accent-text)",fontWeight:700 }}>
            ✓ {selectedIds.length}개 선택됨
          </span>
          <button onClick={()=>setSelectedIds([])}
            style={{ marginLeft:"auto",padding:"1px 7px",borderRadius:3,fontSize:12,
              border:"1px solid var(--bdr)",background:"transparent",
              color:"var(--txt3)",cursor:"pointer" }}>선택 해제</button>
        </div>
      )}
    </div>
  );
}

// ── 메인 컴포넌트 ─────────────────────────────────────────────────
export default function PageScan({ onNav, onNavWithFilter, initAssetId, onTargetUsed, currentUser }) {
  const [assets,      setAssets]      = useState([]);
  const [selectedIds, setSelectedIds] = useState([]);
  const [scanTypes,   setScanTypes]   = useState(["port","web","ssl"]);
  const [scanning,    setScanning]    = useState(false);
  const [jobs,        setJobs]        = useState([]);
  const [logs,        setLogs]        = useState([]);
  const [wsStatus,    setWsStatus]    = useState("idle");
  const [logFilter,   setLogFilter]   = useState("ALL");
  const [autoScroll,  setAutoScroll]  = useState(true);
  const [logFontSize, setLogFontSize] = useState(() =>
    parseFloat(localStorage.getItem("ssk_log_font") || "12")
  );
  const [blink,           setBlink]           = useState(true);
  const [activeScanType,  setActiveScanType]   = useState(null);
  const [activeStep,      setActiveStep]       = useState(0);
  const logRef   = useRef(null);
  const wsRef    = useRef(null);
  const pollRef  = useRef(null);
  const blinkRef = useRef(null);
  const jobsRef  = useRef([]);  // 최신 jobs 상태 추적용

  useEffect(() => {
    blinkRef.current = setInterval(() => setBlink(b=>!b), 650);
    return () => clearInterval(blinkRef.current);
  }, []);

  useEffect(() => {
    fetchAssets().then(list => {
      setAssets(list);
      if (initAssetId) { setSelectedIds([initAssetId]); if (onTargetUsed) onTargetUsed(); }
    }).catch(()=>{});
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
      if (wsRef.current)   wsRef.current.close();
    };
  }, []);

  useEffect(() => {
    if (autoScroll && logRef.current)
      logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [logs, autoScroll]);

  const addLog = useCallback((level, tag, msg) => {
    const ts = new Date().toLocaleTimeString("ko-KR",{hour12:false});
    setLogs(prev=>[...prev.slice(-800),{time:ts,level,tag,message:msg}]);

    // ── 로그 메시지 → 점검 유형 + 단계 정확 매핑 ──
    // 백엔드 로그 패턴: "[포트] STEP1", "[웹] STEP2", "[SSL] STEP3" 등
    const ml = msg.toLowerCase();
    let newType = null;
    let newStep = null;

    // ── STEP 번호 직접 추출 ── 가장 정확한 방법
    const stepMatch = msg.match(/STEP(\d)/);
    const stepNum   = stepMatch ? parseInt(stepMatch[1]) - 1 : null; // 0-based

    // ── 포트 스캔 ──
    if (msg.includes("[포트]") || ml.includes("포트 스캔 시작")) {
      newType = "port";
      newStep = stepNum !== null ? stepNum : 0;
    }
    // ── 웹 취약점 ──
    else if (msg.includes("[웹]") || ml.includes("웹 취약점 점검 시작")) {
      newType = "web";
      newStep = stepNum !== null ? stepNum : 0;
    }
    // ── SSL/TLS ──
    else if (msg.includes("[SSL]") || ml.includes("ssl/tls 점검 시작")) {
      newType = "ssl";
      newStep = stepNum !== null ? stepNum : 0;
    }
    // ── DB ──
    else if (msg.includes("[DB]") || ml.includes("db 점검 시작")) {
      newType = "db";
      newStep = stepNum !== null ? stepNum : 0;
    }
    // ── 네트워크 ──
    else if (msg.includes("[네트워크]") || ml.includes("네트워크 장비 점검 시작")) {
      newType = "network";
      newStep = stepNum !== null ? stepNum : 0;
    }

    if (newType) {
      setActiveScanType(newType);
      if (newStep !== null) setActiveStep(newStep);
    }
  }, []);

  const connectWS = useCallback((jobId) => {
    // WS/폴링 중 하나만 활성 — 이중 수신으로 인한 로그 중복 방지
    let lastLogCount = 0;
    let wsActive = false;  // WS 연결 성공 시 true → 폴링 비활성화
    let destroyed = false;

    // ── HTTP 폴링 (WS 실패 시 폴백 or WS 비활성 구간 커버) ──
    const logPoll = setInterval(async() => {
      if (wsActive || destroyed) return;  // WS 살아있으면 폴링 스킵
      try {
        const r = await fetch(`${API_BASE}/api/scan/logs/${jobId}`);
        if (r.ok) {
          const d = await r.json();
          if (d.logs?.length && d.logs.length > lastLogCount) {
            const newLogs = d.logs.slice(lastLogCount);
            newLogs.forEach(l => addLog(l.level, l.tag, l.message));
            lastLogCount = d.logs.length;
          }
        }
      } catch {}
    }, 1200);

    // ── WS 연결 시도 ──
    try {
      const ws = new WebSocket(`${WS_BASE}/ws/scan/${jobId}`);
      wsRef.current = ws;
      ws.onopen = () => {
        wsActive = true;          // WS 연결 성공 → 폴링 차단
        setWsStatus("connected");
      };
      ws.onmessage = e => {
        try {
          const log = JSON.parse(e.data);
          addLog(log.level, log.tag, log.message);
          lastLogCount++;         // WS 수신 시 카운터 동기화
        } catch {}
      };
      ws.onclose = () => {
        wsActive = false;         // WS 끊기면 폴링 재활성
        setWsStatus("closed");
      };
      ws.onerror = () => {
        wsActive = false;
        setWsStatus("idle");
      };
    } catch {
      wsActive = false;
      setWsStatus("idle");
    }

    setWsStatus("connecting");
    return () => {
      destroyed = true;
      clearInterval(logPoll);
    };
  },[addLog]);

  const toggleType = id => setScanTypes(p=>p.includes(id)?p.filter(x=>x!==id):[...p,id]);

  const onStart = async () => {
    if (!selectedIds.length) { alert("점검 대상을 선택하세요"); return; }
    if (!scanTypes.length)   { alert("점검 유형을 선택하세요"); return; }
    setScanning(true); setLogs([]); setJobs([]);
    addLog("START","START",`══ 점검 시작 ══  자산:${selectedIds.length}개  유형:${scanTypes.join(",")}`);
    try {
      const res = await startScan(selectedIds, scanTypes.join(","));
      // 백엔드 응답: {message, jobs:[{job_id, asset_id, asset_name}]}
      const rawJobs = res?.jobs || (Array.isArray(res) ? res : [res]);
      const jobs0 = rawJobs.filter(j => j?.job_id || j?.id);
      if (jobs0.length === 0) {
        addLog("ERROR","ERR","점검 작업 생성 실패 — 자산을 확인하세요");
        setScanning(false);
        return;
      }
      const initJobs = jobs0.map(j=>({
        ...j,
        job_id: j.job_id || j.id,
        progress:0, current_step:"대기 중..."
      }));
      jobsRef.current = initJobs;
      setJobs(initJobs);
      initJobs.forEach(j => connectWS(j.job_id));
      pollRef.current = setInterval(async()=>{
        // jobsRef.current 로 항상 최신 상태 참조
        const upd = jobsRef.current.map(j=>({...j}));
        let allDone = true;
        for (let i=0; i<upd.length; i++) {
          try {
            const st = await fetchScanStatus(upd[i].job_id);
            // st.id가 있으면 job_id로도 유지 (백엔드 응답이 id 필드)
            const merged = {...upd[i], ...st};
            if (!merged.job_id && merged.id) merged.job_id = merged.id;
            upd[i] = merged;
            const s = st.status;
            if (s === "running" || s === "pending" || s === "queued" || !s) allDone = false;
          } catch { allDone = false; }
        }
        jobsRef.current = upd;
        setJobs([...upd]);
        if (allDone && upd.every(j=>j.status==="completed"||j.status==="failed")) {
          clearInterval(pollRef.current);
          pollRef.current = null;
          setScanning(false);
          // 완료 — 점검 종료 단계(마지막)로 하이라이트
          // activeScanType은 유지, step을 마지막(done:true)으로 이동
          setActiveStep(4);
          const C = upd.reduce((s,j)=>s+(j.crit_count||0),0);
          const H = upd.reduce((s,j)=>s+(j.high_count||0),0);
          addLog("DONE","DONE",`══ 완료 ══  C:${C}  H:${H}`);
        }
      },3000);
    } catch(e) { addLog("ERROR","ERR","점검 시작 실패: "+e.message); setScanning(false); }
  };

  const allDone      = jobs.length>0 && jobs.every(j=>j.status==="completed"||j.status==="failed");
  const filteredLogs = logFilter==="ALL"?logs:logs.filter(l=>l.level===logFilter||l.tag===logFilter);
  const wsC = { idle:"var(--txt3)",connecting:"#FBBF24",connected:"#22C55E",closed:"var(--txt3)",error:"#EF4444" };

  // ── 좌우 패널 리사이즈 ──
  const [leftWidth, setLeftWidth] = useState(() =>
    parseInt(localStorage.getItem("ssk_scan_left_w") || "440")
  );
  const isDragging = useRef(false);
  const startX     = useRef(0);
  const startW     = useRef(0);

  const onDividerMouseDown = (e) => {
    isDragging.current = true;
    startX.current = e.clientX;
    startW.current = leftWidth;
    e.preventDefault();
  };

  useEffect(() => {
    const onMove = (e) => {
      if (!isDragging.current) return;
      const delta = e.clientX - startX.current;
      const newW  = Math.min(700, Math.max(320, startW.current + delta));
      setLeftWidth(newW);
    };
    const onUp = (e) => {
      if (!isDragging.current) return;
      isDragging.current = false;
      const delta = e.clientX - startX.current;
      const newW  = Math.min(700, Math.max(320, startW.current + delta));
      localStorage.setItem("ssk_scan_left_w", String(newW));
    };
    window.addEventListener("mousemove", onMove);
    window.addEventListener("mouseup", onUp);
    return () => {
      window.removeEventListener("mousemove", onMove);
      window.removeEventListener("mouseup", onUp);
    };
  }, []);

  return (
    <div style={{ display:"flex", height:"calc(100vh - 54px)", overflow:"hidden" }}>

      {/* ══ 왼쪽 패널 ══ */}
      <div style={{ display:"flex",flexDirection:"column",
        width:leftWidth,flexShrink:0,
        borderRight:"none",background:"var(--bg-base)",
        overflow:"hidden",padding:"12px 10px",gap:10 }}>

        {/* STEP 1 */}
        <div style={{ display:"flex",alignItems:"center",gap:8,padding:"9px 12px",flexShrink:0,
          background:selectedIds.length>0?"rgba(37,99,235,.06)":blink?"rgba(37,99,235,.08)":"transparent",
          border:`1px solid ${selectedIds.length>0?"var(--accent)":blink?"rgba(37,99,235,.35)":"var(--bdr)"}`,
          borderRadius:7,transition:"all .3s" }}>
          <div style={{ width:22,height:22,borderRadius:"50%",flexShrink:0,fontSize:12,fontWeight:700,
            background:selectedIds.length>0?"var(--accent)":"var(--bdr2)",
            color:selectedIds.length>0?"#fff":"var(--txt3)",
            display:"flex",alignItems:"center",justifyContent:"center" }}>1</div>
          <div>
            <div style={{ fontSize:12,fontWeight:700,color:"var(--txt)" }}>점검 대상 자산 선택</div>
            <div style={{ fontSize:12,color:"var(--txt3)" }}>
              {selectedIds.length>0?`✅ ${selectedIds.length}개 선택됨`:"아래 목록에서 선택하세요"}
            </div>
          </div>
        </div>

        {/* 자산 목록 */}
        <div style={{ flex:1,overflow:"hidden",minHeight:0 }}>
          <AssetSelector assets={assets} selectedIds={selectedIds}
            setSelectedIds={setSelectedIds} onNav={onNav} currentUser={currentUser}/>
        </div>

        {/* STEP 2 */}
        <div style={{ display:"flex",alignItems:"center",gap:8,padding:"9px 12px",flexShrink:0,
          background:scanTypes.length>0?"rgba(37,99,235,.04)":"transparent",
          border:`1px solid ${scanTypes.length>0?"rgba(37,99,235,.25)":"var(--bdr)"}`,
          borderRadius:7 }}>
          <div style={{ width:22,height:22,borderRadius:"50%",flexShrink:0,fontSize:12,fontWeight:700,
            background:scanTypes.length>0?"var(--accent)":"var(--bdr2)",
            color:scanTypes.length>0?"#fff":"var(--txt3)",
            display:"flex",alignItems:"center",justifyContent:"center" }}>2</div>
          <div style={{ fontSize:12,fontWeight:700,color:"var(--txt)" }}>점검 유형 선택</div>
        </div>

        {/* 유형 칩 */}
        <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",
          borderRadius:7,padding:"8px",flexShrink:0 }}>
          <div style={{ display:"flex",justifyContent:"flex-end",gap:4,marginBottom:6 }}>
            <button onClick={()=>setScanTypes(ALL_SCAN_TYPES.map(s=>s.id))}
              style={{ padding:"1px 7px",borderRadius:3,border:"1px solid var(--bdr)",
                background:"transparent",color:"var(--txt3)",fontSize:12,cursor:"pointer" }}>전체</button>
            <button onClick={()=>setScanTypes([])}
              style={{ padding:"1px 7px",borderRadius:3,border:"1px solid var(--bdr)",
                background:"transparent",color:"var(--txt3)",fontSize:12,cursor:"pointer" }}>해제</button>
          </div>
          <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr 1fr",gap:4 }}>
            {ALL_SCAN_TYPES.map(s=>{
              const on=scanTypes.includes(s.id);
              return (
                <div key={s.id} onClick={()=>toggleType(s.id)}
                  style={{ display:"flex",alignItems:"center",gap:5,padding:"5px 7px",
                    borderRadius:5,cursor:"pointer",transition:"all .15s",
                    background:on?"var(--bg-active)":"transparent",
                    border:`1px solid ${on?"var(--accent)":"var(--bdr)"}` }}>
                  <span style={{ fontSize:12,flexShrink:0 }}>{s.icon}</span>
                  <span style={{ fontSize:12,fontWeight:on?600:400,flex:1,
                    color:on?"var(--accent-text)":"var(--txt)",
                    overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{s.label}</span>
                  <div style={{ width:10,height:10,borderRadius:2,flexShrink:0,
                    border:`1.5px solid ${on?"var(--accent)":"var(--bdr2)"}`,
                    background:on?"var(--accent)":"transparent",
                    display:"flex",alignItems:"center",justifyContent:"center" }}>
                    {on&&<span style={{ color:"#fff",fontSize:"0.71rem",fontWeight:700 }}>✓</span>}
                  </div>
                </div>
              );
            })}
          </div>
          {scanTypes.length===0&&(
            <div style={{ fontSize:10,color:"#F87171",marginTop:5,textAlign:"center" }}>
              ⚠ 유형을 선택하세요
            </div>
          )}
        </div>

        {/* 진행 현황 */}
        {jobs.length>0&&(
          <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",
            borderRadius:7,padding:"8px",flexShrink:0 }}>
            <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:6 }}>
              <span style={{ fontSize:12,fontWeight:700,color:"var(--txt)" }}>진행 현황</span>
              {scanning
                ? <span style={{ fontSize:12,color:"#FBBF24",display:"flex",alignItems:"center",gap:3 }}>
                    <Spinner size={8}/> 진행중</span>
                : <span style={{ fontSize:12,color:"#4ADE80" }}>✓ 완료</span>}
            </div>
            {jobs.map(j=>(
              <div key={j.job_id} style={{ marginBottom:5 }}>
                <div style={{ display:"flex",justifyContent:"space-between",marginBottom:2 }}>
                  <span style={{ fontSize:12,fontWeight:600,color:"var(--txt)",
                    overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",flex:1 }}>
                    {j.asset_name}
                  </span>
                  <div style={{ display:"flex",gap:3,flexShrink:0 }}>
                    {j.crit_count>0&&<span style={{ fontSize:"0.6rem",fontWeight:700,color:"#F87171" }}>{j.crit_count}C</span>}
                    {j.high_count>0&&<span style={{ fontSize:"0.6rem",fontWeight:700,color:"#FB923C" }}>{j.high_count}H</span>}
                  </div>
                </div>
                <div style={{ height:4,borderRadius:2,background:"var(--bg-card2)",overflow:"hidden" }}>
                  <div style={{ height:"100%",borderRadius:2,transition:"width .5s",
                    width:`${j.progress||0}%`,
                    background:j.status==="completed"?"#22C55E":j.status==="failed"?"#EF4444":"var(--accent)" }}/>
                </div>
                <div style={{ fontSize:12,color:"var(--txt3)",marginTop:1,
                  display:"flex",justifyContent:"space-between" }}>
                  <span style={{ overflow:"hidden",textOverflow:"ellipsis",
                    whiteSpace:"nowrap",maxWidth:"80%" }}>{j.current_step}</span>
                  <span>{j.progress||0}%</span>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* 실행 버튼 */}
        <div style={{ display:"flex",gap:6,flexShrink:0 }}>
          <button onClick={onStart} disabled={scanning}
            style={{ flex:1,padding:"11px 0",borderRadius:7,fontWeight:700,fontSize:12,
              cursor:scanning?"not-allowed":"pointer",transition:"all .3s",
              display:"flex",alignItems:"center",justifyContent:"center",gap:6,
              background: scanning            ? "var(--bg-card2)"
                        : allDone             ? "var(--bg-card2)"
                        : !selectedIds.length ? "var(--bg-card2)"
                        : blink               ? "var(--accent)" : "rgba(37,99,235,.8)",
              color:(scanning||!selectedIds.length||allDone)?"var(--txt3)":"#fff",
              border:`1px solid ${(scanning||!selectedIds.length||allDone)?"var(--bdr)":"var(--accent)"}`,
              opacity:allDone?0.55:1,
              boxShadow:(!scanning&&!allDone&&selectedIds.length&&blink)
                ?"0 0 14px rgba(37,99,235,.4)":"none" }}>
            {scanning   ? <><Spinner size={11}/> 점검 중...</>
              : allDone ? "↺  재점검"
              : "▶  점검 시작"}
          </button>
          {allDone&&(
            <button onClick={()=>{
                // 이번 점검 jobId와 자산 정보를 함께 전달
                const firstJob = jobs[0];
                const filter = {
                  jobId:     firstJob?.job_id,
                  assetIp:   firstJob?.asset_ip || "",
                  assetName: firstJob?.asset_name || "",
                };
                if (onNavWithFilter) onNavWithFilter(filter);
                else onNav("findings");
              }}
              style={{ padding:"11px 16px",borderRadius:7,fontWeight:700,fontSize:12,
                cursor:"pointer",whiteSpace:"nowrap",transition:"all .3s",
                background:blink?"rgba(22,163,74,.18)":"rgba(22,163,74,.07)",
                color:"#4ADE80",
                border:`1px solid ${blink?"rgba(22,163,74,.45)":"rgba(22,163,74,.2)"}`,
                boxShadow:blink?"0 0 10px rgba(74,222,128,.25)":"none" }}>
              ✅ 결과 확인 →
            </button>
          )}
        </div>
      </div>

      {/* ── 리사이즈 핸들 ── */}
      <div
        onMouseDown={onDividerMouseDown}
        style={{ width:12, flexShrink:0, cursor:"col-resize",
          background:"transparent", position:"relative",
          display:"flex", alignItems:"center", justifyContent:"center",
          transition:"background .15s", zIndex:10 }}
        onMouseEnter={e=>{
          e.currentTarget.style.background="rgba(59,130,246,.08)";
          const dot = e.currentTarget.querySelector(".resize-dot");
          if(dot) dot.style.opacity="1";
        }}
        onMouseLeave={e=>{
          e.currentTarget.style.background="transparent";
          const dot = e.currentTarget.querySelector(".resize-dot");
          if(dot) dot.style.opacity="";
        }}>
        {/* 세로 점선 */}
        <div style={{ position:"absolute", top:0, bottom:0, left:"50%",
          width:1, background:"var(--bdr2)", transform:"translateX(-50%)" }}/>
        {/* 중앙 핸들 아이콘 — 깜박임 */}
        <div className="resize-dot" style={{
          position:"absolute", top:"50%", left:"50%",
          transform:"translate(-50%,-50%)",
          width:18, height:42, borderRadius:9,
          background:"var(--bdr2)", border:"1px solid var(--bdr)",
          display:"flex", flexDirection:"column",
          alignItems:"center", justifyContent:"center", gap:3,
          animation:"resizePulse 2s ease-in-out infinite",
          boxShadow:"0 0 6px rgba(59,130,246,.2)",
          cursor:"col-resize" }}>
          <div style={{ width:2, height:2, borderRadius:"50%", background:"var(--txt3)" }}/>
          <div style={{ width:2, height:2, borderRadius:"50%", background:"var(--txt3)" }}/>
          <div style={{ width:2, height:2, borderRadius:"50%", background:"var(--txt3)" }}/>
        </div>
        <style>{`
          @keyframes resizePulse {
            0%,100% { opacity:.5; box-shadow:0 0 4px rgba(59,130,246,.15); }
            50%      { opacity:1; box-shadow:0 0 10px rgba(59,130,246,.45); background:rgba(59,130,246,.15); }
          }
          .resize-dot:hover {
            background: rgba(59,130,246,.25) !important;
            border-color: var(--accent) !important;
          }
          .resize-dot:hover div {
            background: var(--accent) !important;
          }
        `}</style>
      </div>

      {/* ══ 오른쪽: 로그 패널 ══ */}
      <div style={{ display:"flex",flexDirection:"column",
        flex:1,overflow:"hidden",background:"var(--bg-card)" }}>

        {/* 점검 단계 가이드 패널 */}
        <ScanGuidePanel
          activeScanType={activeScanType}
          activeStep={activeStep}
          onStepChange={setActiveStep}
          scanning={scanning}
          scanTypes={scanTypes}
        />

        {/* 로그 툴바 */}
        <div style={{ display:"flex",alignItems:"center",gap:8,padding:"6px 12px",
          borderBottom:"1px solid var(--bdr)",flexShrink:0,background:"var(--bg-card2)" }}>
          <span style={{ fontSize:12,fontWeight:700,color:"var(--txt)",fontFamily:"monospace" }}>
            SCAN LOG
          </span>
          <span style={{ display:"flex",alignItems:"center",gap:4,fontSize:9.5 }}>
            <span style={{ width:6,height:6,borderRadius:"50%",background:wsC[wsStatus],
              display:"inline-block",
              boxShadow:wsStatus==="connected"?`0 0 5px ${wsC[wsStatus]}`:"none" }}/>
            <span style={{ color:wsC[wsStatus],fontFamily:"monospace",fontWeight:600 }}>
              {wsStatus==="connected"?"LIVE":wsStatus==="connecting"?"CONN":"IDLE"}
            </span>
          </span>
          <span style={{ fontSize:12,color:"var(--txt3)",fontFamily:"monospace" }}>{logs.length}L</span>
          <div style={{ display:"flex",gap:3,marginLeft:"auto" }}>
            {["ALL","ERROR","WARN","DONE","INFO"].map(f=>(
              <button key={f} onClick={()=>setLogFilter(f)}
                style={{ padding:"2px 7px",borderRadius:3,fontSize:"0.6rem",fontWeight:700,
                  cursor:"pointer",fontFamily:"monospace",
                  border:`1px solid ${logFilter===f?(LC[f]||"var(--accent)"):"var(--bdr)"}`,
                  background:logFilter===f?`${LC[f]||"var(--accent)"}18`:"transparent",
                  color:logFilter===f?(LC[f]||"var(--accent-text)"):"var(--txt3)" }}>
                {f}
              </button>
            ))}
          </div>
          <button onClick={()=>setAutoScroll(p=>!p)}
            style={{ padding:"2px 7px",borderRadius:3,border:"1px solid var(--bdr)",
              fontSize:"0.6rem",cursor:"pointer",fontFamily:"monospace",
              background:autoScroll?"var(--bg-active)":"transparent",
              color:autoScroll?"var(--accent-text)":"var(--txt3)" }}>
            {autoScroll?"AUTO▼":"MANUAL"}
          </button>
          <button onClick={()=>setLogs([])}
            style={{ padding:"2px 7px",borderRadius:3,border:"1px solid var(--bdr)",
              background:"transparent",color:"var(--txt3)",fontSize:"0.6rem",
              cursor:"pointer",fontFamily:"monospace" }}>CLR</button>
          {/* 로그 전용 폰트 크기 */}
          <div style={{ display:"flex",alignItems:"center",gap:4,
            borderLeft:"1px solid var(--bdr)",paddingLeft:8,marginLeft:4 }}>
            <span style={{ fontSize:"0.6rem",color:"var(--txt3)",fontFamily:"monospace",
              whiteSpace:"nowrap",marginRight:2 }}>LOG폰트</span>
            <span style={{ fontSize:"0.6rem",color:"var(--txt3)",fontFamily:"monospace",
              whiteSpace:"nowrap" }}>A</span>
            <input type="range" min="10" max="16" step="1"
              value={logFontSize}
              onChange={e=>{
                const v=parseInt(e.target.value);
                setLogFontSize(v);
                localStorage.setItem("ssk_log_font", String(v));
              }}
              style={{ width:52,accentColor:"var(--accent)",cursor:"pointer",height:3 }}/>
            <span style={{ fontSize:"0.79rem",color:"var(--txt3)",fontFamily:"monospace",
              whiteSpace:"nowrap" }}>A</span>
            <span style={{ fontSize:"0.6rem",color:"var(--accent-text)",
              fontFamily:"monospace",minWidth:20 }}>{logFontSize}px</span>
          </div>
        </div>

        {/* 로그 바디 — 전체 높이 채움 */}
        <div ref={logRef}
          onScroll={e=>{
            const el=e.currentTarget;
            if(el.scrollHeight-el.scrollTop-el.clientHeight>40&&autoScroll)
              setAutoScroll(false);
          }}
          style={{ flex:1,overflowY:"auto",padding:"10px 14px",
            background:"var(--bg-card)",minHeight:0,
            fontSize:logFontSize   /* 로그 전용 폰트 — 전역 설정과 독립 */ }}>
          {filteredLogs.length===0 ? (
            <div style={{ color:"var(--txt3)",fontFamily:"monospace",fontSize:12,lineHeight:2.2 }}>
              <div>&gt; SecurityScanKit v1.0 — Scan Engine Ready</div>
              <div>&gt; 왼쪽에서 자산과 점검 유형을 선택한 후{" "}
                <span style={{ color:"var(--accent-text)",fontWeight:700 }}>▶ 점검 시작</span>을 클릭하세요.
              </div>
              <div style={{ marginTop:16,opacity:.2 }}>▌</div>
            </div>
          ) : filteredLogs.map((entry,i)=><LogLine key={i} entry={entry} fs={logFontSize}/>)}
          {scanning&&(
            <div style={{ color:"var(--accent-text)",fontFamily:"monospace",fontSize:12,
              marginTop:4,animation:"pulse 1s infinite" }}>▌</div>
          )}
        </div>

        {/* 완료 결과 요약 */}
        {allDone&&jobs.length>0&&(
          <div style={{ flexShrink:0,borderTop:"2px solid var(--accent)",
            background:"var(--bg-card2)",padding:"12px 16px" }}>
            <div style={{ fontSize:12,fontWeight:700,color:"var(--txt)",marginBottom:8 }}>
              ✅ 점검 완료
            </div>
            <div style={{ display:"flex",gap:8,flexWrap:"wrap" }}>
              {jobs.map(j=>(
                <div key={j.job_id}
                  style={{ display:"flex",alignItems:"center",gap:10,padding:"10px 14px",
                    borderRadius:6,background:"var(--bg-card)",border:"1px solid var(--bdr)",
                    flex:1,minWidth:200 }}>
                  <div style={{ flex:1,minWidth:0 }}>
                    <div style={{ fontSize:12,fontWeight:600,color:"var(--txt)",
                      overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>
                      {j.asset_name}
                    </div>
                    <div style={{ fontSize:12,color:"var(--txt3)",marginTop:2 }}>
                      소요: {j.duration_sec?Math.round(j.duration_sec)+"초":"—"}
                    </div>
                  </div>
                  <div style={{ display:"flex",gap:8,flexShrink:0 }}>
                    {[
                      {l:"긴급",  v:j.crit_count||0, c:"#F87171"},
                      {l:"고위험",v:j.high_count||0,  c:"#FB923C"},
                      {l:"중위험",v:j.med_count||0,   c:"#FBBF24"},
                    ].map(({l,v,c})=>(
                      <div key={l} style={{ textAlign:"center",minWidth:32 }}>
                        <div style={{ fontSize:"1.29rem",fontWeight:700,color:v>0?c:"var(--txt3)" }}>{v}</div>
                        <div style={{ fontSize:12,color:"var(--txt3)" }}>{l}</div>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* 범례 */}
        <div style={{ display:"flex",gap:10,padding:"4px 12px",
          borderTop:"1px solid var(--bdr)",flexShrink:0,
          background:"var(--bg-card2)",flexWrap:"wrap" }}>
          {[["CRIT","#F87171"],["HIGH","#FB923C"],["WARN","#E3B341"],
            ["INFO","var(--txt2)"],["DONE","#4ADE80"],["RPT","#C084FC"]].map(([k,col])=>(
            <span key={k} onClick={()=>setLogFilter(logFilter===k?"ALL":k)}
              style={{ display:"flex",alignItems:"center",gap:3,fontSize:"0.6rem",
                color:logFilter===k?col:"var(--txt3)",
                fontFamily:"monospace",cursor:"pointer" }}>
              <span style={{ width:5,height:5,borderRadius:1,
                background:col,display:"inline-block",flexShrink:0 }}/>
              {k}
            </span>
          ))}
        </div>
      </div>

      <style>{`@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}`}</style>
    </div>
  );
}
