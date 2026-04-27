// App.jsx — SecurityScanKit Enterprise Platform v1.0
import { useState, useEffect, useRef, createContext, useContext, useCallback } from "react";
import { LangProvider, useLang } from "./i18n/LangContext";
import { LANGS } from "./i18n/translations";
import { THEMES, applyTheme, getStoredTheme } from "./theme/themes";
import { Badge, Spinner } from "./components/UI";
import PageDashboard from "./pages/PageDashboard";
import PageScan from "./pages/PageScan";
import PageGate from "./pages/PageGate";
import PageSettings from "./pages/PageSettings";
import PageApiClient from "./pages/PageApiClient";
import PageThreatIntel   from "./pages/PageThreatIntel.jsx";
import PageCheckLibrary from "./pages/PageCheckLibrary.jsx";
import PageNotify      from "./pages/PageNotify.jsx";
import PageLogViewer   from "./pages/PageLogViewer.jsx";
import API_BASE from "./hooks/apiConfig.js";

// ── 전역 본부/부서 Context ──────────────────────────────────
export const OrgContext = createContext({ divs:[], depts:[], reload:()=>{} });
export const useOrg = () => useContext(OrgContext);
import {
  PageFindings, PageAlerts, PageAssets,
  PageCompliance,
  PageReports, PageHistory, PageUpload, PageAdmin
} from "./pages/OtherPages";

// ── 언어 선택기 ────────────────────────────────────────────────────
function LangSelector() {
  const { lang, changeLang } = useLang();
  const [open, setOpen] = useState(false);
  const cur = LANGS.find(l => l.code === lang);
  return (
    <div style={{ position:"relative" }}>
      <button onClick={() => setOpen(o=>!o)} style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 10px", borderRadius:6, background:open?"var(--bg-active)":"transparent", border:`1px solid ${open?"var(--accent)":"var(--bdr)"}`, color:open?"var(--accent-text)":"var(--txt2)", cursor:"pointer", fontSize:13, fontWeight:600, transition:"all .15s" }}>
        <span style={{ fontSize:14 }}>{cur?.flag}</span>
        <span>{cur?.label}</span>
        <span style={{ fontSize:13, opacity:.7 }}>{open?"▲":"▼"}</span>
      </button>
      {open && (
        <div style={{ position:"absolute", top:"calc(100% + 6px)", right:0, zIndex:9999, background:"var(--bg-nav)", border:"1px solid var(--bdr2)", borderRadius:8, overflow:"hidden", minWidth:140, boxShadow:"0 8px 24px rgba(0,0,0,.5)" }}>
          {LANGS.map(l => (
            <button key={l.code} onClick={() => { changeLang(l.code); setOpen(false); }} style={{ display:"flex", alignItems:"center", gap:10, width:"100%", padding:"9px 14px", border:"none", cursor:"pointer", fontSize:13, background:lang===l.code?"var(--bg-active)":"transparent", color:lang===l.code?"var(--accent-text)":"var(--txt)", fontWeight:lang===l.code?600:400, borderBottom:"1px solid var(--bdr)", transition:"background .1s" }}>
              <span style={{ fontSize:16 }}>{l.flag}</span>
              <span>{l.label}</span>
              {lang===l.code && <span style={{ marginLeft:"auto", fontSize:13, color:"var(--accent-text)" }}>✓</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── 테마 선택기 ──────────────────────────────────────────────────
function ThemeSelector() {
  const { lang } = useLang();
  const [theme, setTheme] = useState(getStoredTheme());
  const [open, setOpen] = useState(false);
  const cur = THEMES.find(th => th.id === theme);
  const lbl = (th) => ({ ko:th.labelKo, en:th.label, ja:th.labelJa })[lang] || th.label;

  return (
    <div style={{ position:"relative" }}>
      <button onClick={() => setOpen(o=>!o)}
        style={{ display:"flex", alignItems:"center", gap:7, padding:"5px 11px", borderRadius:6,
          background:"transparent", border:"1px solid var(--bdr2)",
          color:"var(--txt3)", cursor:"pointer", fontSize:13, fontWeight:500 }}>
        <span style={{ fontSize:13 }}>◐</span>
        <span>{lbl(cur||THEMES[0])}</span>
        <span style={{ fontSize:13, opacity:.6 }}>{open?"▲":"▼"}</span>
      </button>
      {open && (
        <div style={{ position:"absolute", top:"calc(100% + 6px)", right:0, zIndex:9999,
          background:"var(--bg-nav)", border:"1px solid var(--bdr2)", borderRadius:8,
          overflow:"hidden", minWidth:230, boxShadow:"0 12px 32px rgba(0,0,0,.4)" }}>
          <div style={{ padding:"8px 14px", fontSize:13, fontWeight:700, color:"var(--txt3)",
            textTransform:"uppercase", letterSpacing:".1em", borderBottom:"1px solid var(--bdr)" }}>
            화면 테마
          </div>
          {THEMES.map(th => (
            <button key={th.id} onClick={() => { setTheme(th.id); applyTheme(th.id); setOpen(false); }}
              style={{ display:"flex", alignItems:"center", gap:10, width:"100%",
                padding:"10px 14px", border:"none", cursor:"pointer", textAlign:"left",
                background:theme===th.id?"var(--bg-active)":"transparent",
                color:theme===th.id?"var(--accent-text)":"var(--txt)",
                fontWeight:theme===th.id?600:400, borderBottom:"1px solid var(--bdr)" }}>
              <div style={{ display:"flex", gap:3, flexShrink:0 }}>
                {th.preview.map((c,i) => <div key={i} style={{ width:12, height:12, borderRadius:2, background:c, border:"1px solid rgba(255,255,255,.08)" }} />)}
              </div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:12 }}>{lbl(th)}</div>
                {th.desc && <div style={{ fontSize:13, color:"var(--txt3)", marginTop:1 }}>{th.desc}</div>}
              </div>
              {theme===th.id && <span style={{ color:"var(--accent-text)", fontSize:13, flexShrink:0 }}>✓</span>}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Lottie 캐릭터 애니메이션 ─────────────────────────────────────
// ── 메뉴 진행 표시 스피너 ───────────────────────────────────────
function MenuSpinner() {
  return (
    <span style={{ width:16,height:16,flexShrink:0,display:"inline-block",
      borderRadius:"50%",border:"2px solid var(--accent)",borderTopColor:"transparent",
      animation:"spin .8s linear infinite" }}/>
  );
}

// ── 사이드바 ────────────────────────────────────────────────────────
function Sidebar({ page, onNav, dashboardCtrl, badges={} }) {
  const { t } = useLang();
  const [collapsed,   setSbCollapsed] = useState(false);
  const [openGroups,  setOpenGroups]  = useState({ assets:true, scan:true, intel:true, report:true });
  const toggleGroup = key => setOpenGroups(p => ({...p, [key]:!p[key]}));
  const sbW = collapsed ? 52 : 220;

  const PAGES_ASSET = ["upload","assets"];
  const PAGES_SCAN  = ["scan","findings","history"];
  const PAGES_INTEL = ["threat","library"];
  const PAGES_REP   = ["compliance","reports","notify"];

  // 섹션 구분선
  const Sec = ({ lbl }) => collapsed ? null : (
    <div style={{ padding:"14px 14px 3px", fontSize:10, fontWeight:700,
      color:"var(--section-text)", letterSpacing:".12em", textTransform:"uppercase",
      display:"flex", alignItems:"center", gap:6,
      borderTop:"1px solid var(--bdr-nav, var(--bdr))",
      marginTop:4 }}>
      <div style={{ flex:1, height:"0.5px", background:"var(--bdr)" }}/>
      <span>{lbl}</span>
      <div style={{ flex:1, height:"0.5px", background:"var(--bdr)" }}/>
    </div>
  );

  // 단독 메뉴 아이템 (대시보드, 알람, 설정)
  const Item = ({ id, icon, lbl, badge, bt, spinning }) => {
    const on = page === id;
    const badgeStyle = {
      marginLeft:"auto", padding:"1px 6px", borderRadius:10, fontSize:13, fontWeight:700,
      background: bt==="red"?"rgba(220,38,38,.2)": bt==="amber"?"rgba(180,115,0,.2)":"var(--accent-dim)",
      color:      bt==="red"?"#FCA5A5":            bt==="amber"?"#FCD34D":            "var(--accent-text)",
    };
    return (
      <div onClick={() => onNav(id)}
        style={{ display:"flex", alignItems:"center", gap:9, padding:"7px 12px 7px 14px",
          cursor:"pointer", fontSize:13, fontWeight:on?600:400,
          background:on?"var(--bg-active)":"transparent",
          color:on?"var(--accent-text)":"var(--nav-text)",
          transition:"background .12s", position:"relative" }}>
        {on && <div style={{ position:"absolute", left:0, top:"18%", bottom:"18%", width:2.5, background:"var(--accent)", borderRadius:"0 2px 2px 0" }}/>}
        <span style={{ fontSize:15, flexShrink:0 }}>{icon}</span>
        {!collapsed && <span style={{ flex:1, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{lbl}</span>}
        {!collapsed && spinning && <MenuSpinner/>}
        {!collapsed && !spinning && badge && <span style={badgeStyle}>{badge}</span>}
        {on && !collapsed && !spinning && !badge && (
          <span style={{ width:5,height:5,borderRadius:"50%",background:"var(--accent)",flexShrink:0,marginLeft:"auto" }}/>
        )}
      </div>
    );
  };

  // 큰 메뉴 (접기/펼치기)
  const Group = ({ groupKey, icon, lbl, pages, children }) => {
    const isOpen    = openGroups[groupKey];
    const hasActive = pages.some(p => p === page);
    return (
      <div>
        <div onClick={() => collapsed ? toggleGroup(groupKey) : toggleGroup(groupKey)}
          style={{ display:"flex", alignItems:"center", gap:9, padding:"7px 12px 7px 14px",
            cursor:"pointer", fontSize:13, fontWeight:600,
            color: hasActive ? "var(--accent-text)" : "var(--nav-text)",
            background: hasActive && !isOpen ? "var(--bg-active)" : "transparent",
            transition:"background .12s", userSelect:"none", position:"relative",
            justifyContent: collapsed ? "center" : "flex-start" }}
          onMouseEnter={e=>{ if(!hasActive||isOpen) e.currentTarget.style.background="var(--bg-hover)"; }}
          onMouseLeave={e=>{ e.currentTarget.style.background=(hasActive&&!isOpen)?"var(--bg-active)":"transparent"; }}>
          {hasActive && !isOpen && <div style={{ position:"absolute", left:0, top:"18%", bottom:"18%", width:2.5, background:"var(--accent)", borderRadius:"0 2px 2px 0" }}/>}
          <span style={{ fontSize:15, flexShrink:0 }} title={collapsed?lbl:undefined}>{icon}</span>
          {!collapsed && <span style={{ flex:1 }}>{lbl}</span>}
          {!collapsed && <span style={{ fontSize:13, color:"var(--txt3)", transition:"transform .2s", transform:isOpen?"rotate(0)":"rotate(-90deg)", flexShrink:0 }}>▾</span>}
        </div>
        {/* collapsed 시: 활성 아이템 아이콘만 표시 / 펼침 시: 전체 표시 */}
        {(!collapsed && isOpen) && (
          <div style={{ paddingBottom:2 }}>
            {children}
          </div>
        )}
      </div>
    );
  };

  // 하위 메뉴 아이템
  const Sub = ({ id, lbl, badge, bt }) => {
    const on = page === id;
    const badgeStyle = {
      marginLeft:"auto", padding:"1px 5px", borderRadius:8, fontSize:13, fontWeight:700, flexShrink:0,
      background: bt==="red"?"rgba(220,38,38,.2)": bt==="amber"?"rgba(180,115,0,.2)":"var(--accent-dim)",
      color:      bt==="red"?"#FCA5A5":            bt==="amber"?"#FCD34D":            "var(--accent-text)",
    };
    return (
      <div onClick={() => onNav(id)}
        style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 12px 5px 40px",
          cursor:"pointer", fontSize:13, fontWeight:on?600:400,
          color: on?"var(--accent-text)":"var(--nav-text)",
          background:on?"var(--bg-active)":"transparent",
          transition:"background .12s", position:"relative",
          borderBottom:"1px solid var(--bdr-nav, transparent)" }}
        onMouseEnter={e=>!on&&(e.currentTarget.style.background="var(--bg-hover)")}
        onMouseLeave={e=>!on&&(e.currentTarget.style.background="transparent")}>
        {/* 들여쓰기 연결선 */}
        <div style={{ position:"absolute", left:24, top:0, bottom:0, width:"0.5px", background:"var(--bdr)" }}/>
        <div style={{ position:"absolute", left:24, top:"50%", width:8, height:"0.5px", background:"var(--bdr)" }}/>
        {on && <div style={{ position:"absolute", left:0, top:"15%", bottom:"15%", width:2.5, background:"var(--accent)", borderRadius:"0 2px 2px 0" }}/>}
        <span style={{ flex:1 }}>{lbl}</span>
        {on && !badge && <span style={{ width:4,height:4,borderRadius:"50%",background:"var(--accent)",flexShrink:0,marginLeft:"auto" }}/>}
        {!collapsed && badge && <span style={badgeStyle}>{badge}</span>}
      </div>
    );
  };

  return (
    <div style={{ background:"var(--bg-nav)", borderRight:"1px solid var(--bdr)", display:"flex", flexDirection:"column",
      width:sbW, flexShrink:0, overflowY:"auto", overflowX:"hidden",
      transition:"width .25s cubic-bezier(.4,0,.2,1)" }}>

      {/* 로고 */}
      <div onClick={() => onNav("dashboard")}
        style={{ height:54, padding:"0 16px", borderBottom:"1px solid var(--bdr)", cursor:"pointer", display:"flex", alignItems:"center", flexShrink:0, transition:"background .15s" }}>
        {!collapsed && (
          <div style={{ display:"flex", alignItems:"center", gap:10 }}>
            <div style={{ width:34, height:34, background:"var(--accent)", borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
              <svg width="18" height="18" viewBox="0 0 24 24" fill="white"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/></svg>
            </div>
            <div>
              <div style={{ fontSize:14, fontWeight:700, color:"var(--logo-text)" }}>{t("brand")}</div>
              <div style={{ fontSize:13, color:"var(--nav-text)", marginTop:1 }}>{t("version")}</div>
            </div>
          </div>
        )}
        {collapsed && (
          <div style={{ width:34, height:34, background:"var(--accent)", borderRadius:8, display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0, margin:"0 auto" }}>
            <svg width="18" height="18" viewBox="0 0 24 24" fill="white"><path d="M12 2L3 7v5c0 5.25 3.75 10.15 9 11.35C17.25 22.15 21 17.25 21 12V7L12 2z"/></svg>
          </div>
        )}
        <button onClick={e=>{ e.stopPropagation(); setSbCollapsed(p=>!p); }}
          title={collapsed?"메뉴 펼치기":"메뉴 접기"}
          style={{
            marginLeft: collapsed ? "auto" : "auto",
            background: collapsed ? "var(--accent)" : "transparent",
            border: `1px solid ${collapsed ? "var(--accent)" : "var(--bdr)"}`,
            cursor:"pointer",
            color: collapsed ? "#fff" : "var(--nav-text)",
            fontSize: collapsed ? 14 : 13,
            padding: collapsed ? "5px 8px" : "4px 7px",
            borderRadius: collapsed ? 6 : 4,
            flexShrink:0,
            transition:"all .2s",
            display:"flex", alignItems:"center",
            animation: collapsed ? "expandPulse 2s ease-in-out infinite" : "none",
            boxShadow: collapsed ? "0 0 8px rgba(59,130,246,.4)" : "none",
          }}
          onMouseEnter={e=>{ e.currentTarget.style.opacity="0.85"; }}
          onMouseLeave={e=>{ e.currentTarget.style.opacity="1"; }}>
          {collapsed ? "▶▶" : "◀"}
          <style>{`
            @keyframes expandPulse {
              0%,100% { box-shadow:0 0 4px rgba(59,130,246,.3); }
              50%      { box-shadow:0 0 12px rgba(59,130,246,.7); }
            }
          `}</style>
        </button>
      </div>

      {/* 단독 메뉴 */}
      <div style={{ paddingTop:6 }}>
        <Item id="dashboard" icon="⊞" lbl="대시보드"/>
        <Item id="alerts"    icon="🔔" lbl="알람" badge={badges.alerts||null} bt="red"/>
      </div>

      {/* 자산 · 점검 */}
      <Sec lbl="자산 · 점검"/>
      <Group groupKey="assets" icon="🖥" lbl="자산" pages={PAGES_ASSET}>
        <Sub id="upload"  lbl="자산 등록"/>
        <Sub id="assets"  lbl="자산 목록" badge={badges.assets||null} bt="blue"/>
      </Group>
      <Group groupKey="scan" icon="🔍" lbl="점검" pages={PAGES_SCAN}>
        <Sub id="scan"     lbl="점검 실행"/>
        <Sub id="findings" lbl="취약점"   badge={badges.findings||null} bt="red"/>
        <Sub id="history"  lbl="점검 이력"/>
      </Group>

      {/* 인텔리전스 */}
      <Sec lbl="인텔리전스"/>
      <Group groupKey="intel" icon="📡" lbl="위협 동향" pages={PAGES_INTEL}>
        <Sub id="threat"   lbl="보안 점검 현황 센터" badge={badges.cve||null} bt="amber"/>
        <Sub id="library"  lbl="점검 항목 라이브러리"/>
      </Group>

      {/* 보고 · 준수 */}
      <Sec lbl="보고 · 준수"/>
      <Group groupKey="report" icon="📋" lbl="보고서" pages={PAGES_REP}>
        <Sub id="compliance" lbl="컴플라이언스"/>
        <Sub id="reports"    lbl="리포트"/>
        <Sub id="notify"     lbl="조치 통보" badge={badges.notify||null} bt="red"/>
      </Group>

      {/* 관리자 · 설정 */}
      <div style={{ height:"0.5px", background:"var(--bdr)", margin:"8px 14px" }}/>
      <Item id="logs"     icon="📋" lbl="로그 뷰어"/>
      <Item id="admin"    icon="🔧" lbl="관리자"/>
      <Item id="settings" icon="⚙"  lbl="설정"/>

      {/* 하단 상태 */}
      <div style={{ marginTop:"auto", padding:"10px 12px 14px" }}>
        {page === "dashboard" && dashboardCtrl && (
          <div style={{ background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:8, padding:"9px 11px", marginBottom:8 }}>
            <div style={{ fontSize:13, color:"var(--txt3)", marginBottom:7, lineHeight:1.5 }}>
              <span style={{ opacity:.6 }}>⠿</span> 블록 드래그로 위치 변경
            </div>
            <div style={{ display:"flex", gap:5 }}>
              <button onClick={dashboardCtrl.reset}
                style={{ flex:1, padding:"5px 0", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>초기화</button>
              <button onClick={dashboardCtrl.refresh}
                style={{ flex:1, padding:"5px 0", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>↻ 새로고침</button>
            </div>
          </div>
        )}
        <div style={{ background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:8, padding:"9px 11px" }}>
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:4 }}>
            <span style={{ fontSize:13, color:"var(--txt)", fontWeight:500, display:"flex", alignItems:"center", gap:5 }}>
              <span style={{ width:6, height:6, borderRadius:"50%", background:"#22C55E", display:"inline-block" }}/>
              시스템 정상
            </span>
            <span style={{ fontSize:13, color:"var(--txt3)" }}>v1.0</span>
          </div>
          <div style={{ fontSize:13, color:"var(--txt3)" }}>마지막 점검: 2분 전</div>
        </div>
      </div>
    </div>
  );
}

// ── 상단 바 ────────────────────────────────────────────────────────
function Topbar({ title, crumb, onApiClient, badges, currentUser, onLogout }) {
  const [now, setNow] = useState(() => new Date());
  const [stats, setStats] = useState(null);

  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 1000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    fetch(`${API_BASE}/api/findings/stats`).then(r=>r.json()).then(setStats).catch(()=>{});
  }, []);

  const pad = n => String(n).padStart(2,"0");
  const kst = `KST ${now.getFullYear()}-${pad(now.getMonth()+1)}-${pad(now.getDate())} ${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;

  const pills = stats ? [
    { lbl:`${stats.critical||0} Critical`, bg:"rgba(239,68,68,.15)",  bdr:"rgba(239,68,68,.3)",  color:"#FCA5A5" },
    { lbl:`${stats.high||0} High`,         bg:"rgba(249,115,22,.1)",  bdr:"rgba(249,115,22,.3)", color:"#FDBA74" },
    { lbl:`${stats.repeat||0} Repeat`,     bg:"rgba(37,99,235,.15)",  bdr:"rgba(37,99,235,.3)",  color:"#93C5FD" },
    { lbl:`${stats.resolved_pct||0}% 조치`, bg:"rgba(34,197,94,.1)",   bdr:"rgba(34,197,94,.3)",  color:"#86EFAC" },
  ] : [];

  return (
    <div style={{ background:"var(--topbar-bg)", borderBottom:"1px solid var(--bdr)", height:54, display:"flex", alignItems:"center", padding:"0 22px", gap:10, flexShrink:0 }}>
      <div style={{ flex:1, minWidth:0 }}>
        <div style={{ fontSize:15, fontWeight:700, color:"var(--txt)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{title}</div>
        <div style={{ fontSize:13, color:"var(--txt3)" }}>{crumb}</div>
      </div>
      <div style={{ display:"flex", gap:6, alignItems:"center", flexShrink:0 }}>
        {pills.map(p => (
          <div key={p.lbl} style={{ padding:"4px 9px", borderRadius:5, fontSize:13, fontWeight:600, background:p.bg, border:`1px solid ${p.bdr}`, color:p.color, whiteSpace:"nowrap" }}>{p.lbl}</div>
        ))}
      </div>
      <div style={{ fontSize:13, color:"var(--txt3)", whiteSpace:"nowrap", fontFamily:"monospace", flexShrink:0 }}>{kst}</div>
      <ThemeSelector />
      <LangSelector />
      <button onClick={onApiClient}
        style={{ display:"flex", alignItems:"center", gap:6, padding:"5px 11px", borderRadius:6,
          border:"1px solid var(--bdr2)", background:"transparent",
          color:"var(--txt3)", cursor:"pointer", fontSize:13, fontWeight:500,
          whiteSpace:"nowrap" }}>
        <span style={{ fontSize:13 }}>⚡</span> API 테스트
      </button>
      {/* 미등록 자산 알림 */}
      {badges.assets === 0 && currentUser && (
        <div onClick={()=>{ if(typeof window !== "undefined") window.location.hash="upload"; }}
          style={{ display:"flex", alignItems:"center", gap:6,
            padding:"5px 12px", borderRadius:20,
            border:"2px solid #DC2626",
            background:"rgba(220,38,38,.08)",
            cursor:"pointer", flexShrink:0,
            animation:"noAssetBlink 1.2s ease-in-out infinite" }}>
          <style>{`@keyframes noAssetBlink{0%,100%{border-color:#DC2626;opacity:.6}50%{border-color:#DC2626;opacity:1}}`}</style>
          <span style={{ width:7, height:7, borderRadius:"50%",
            background:"#DC2626", flexShrink:0,
            boxShadow:"0 0 6px #DC2626" }}/>
          <span style={{ fontSize:12, fontWeight:700, color:"#DC2626",
            whiteSpace:"nowrap" }}>자산을 등록해주세요</span>
        </div>
      )}

      {/* 사용자 아바타 + 로그아웃 */}
      <div style={{ position:"relative" }}>
        <div
          onClick={()=>{
            const m = document.getElementById("ssk-user-menu");
            if(m) m.style.display = m.style.display==="block"?"none":"block";
          }}
          style={{ width:32, height:32, borderRadius:"50%",
            background: badges.assets===0 ? "rgba(220,38,38,.15)" : "var(--bg-active)",
            border: badges.assets===0 ? "2px solid #DC2626" : "2px solid var(--accent)",
            display:"flex", alignItems:"center", justifyContent:"center",
            fontSize:12, fontWeight:700,
            color: badges.assets===0 ? "#DC2626" : "var(--accent-text)",
            cursor:"pointer", userSelect:"none", flexShrink:0 }}
          title={currentUser?.name||"사용자"}>
          {(currentUser?.name||"?").slice(0,1)}
        </div>
        <div id="ssk-user-menu"
          style={{ display:"none", position:"absolute", top:"calc(100% + 6px)", right:0,
            zIndex:9999, background:"var(--bg-card)", border:"1px solid var(--bdr2)",
            borderRadius:8, minWidth:160, boxShadow:"0 8px 24px rgba(0,0,0,.3)",
            overflow:"hidden" }}>
          <div style={{ padding:"10px 14px", borderBottom:"1px solid var(--bdr)",
            background:"var(--bg-card2)" }}>
            <div style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>
              {currentUser?.name||"—"}
            </div>
            <div style={{ fontSize:11, color:"var(--txt3)", marginTop:2 }}>
              {[currentUser?.division, currentUser?.dept].filter(Boolean).join(" · ")||"소속 미설정"}
            </div>
          </div>
          <div
            onClick={()=>{
              document.getElementById("ssk-user-menu").style.display="none";
              if(onLogout) onLogout();
            }}
            style={{ padding:"9px 14px", fontSize:13, color:"#F87171",
              cursor:"pointer", display:"flex", alignItems:"center", gap:7,
              transition:"background .12s" }}
            onMouseEnter={e=>e.currentTarget.style.background="rgba(248,113,113,.08)"}
            onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
            <span>→</span> 로그아웃
          </div>
        </div>
      </div>
    </div>
  );
}

// ── 메인 앱 ─────────────────────────────────────────────────────────
function AppInner() {
  const { t } = useLang();
  const [currentUser, setCurrentUser] = useState(() => {
    try { return JSON.parse(localStorage.getItem("ssk_current_user")||"null"); } catch { return null; }
  });
  const [orgDivs,  setOrgDivs]  = useState([]);
  const [orgDepts, setOrgDepts] = useState([]);

  const reloadOrg = useCallback(async () => {
    try {
      const [dRes, ptRes] = await Promise.all([
        fetch(`${API_BASE}/api/divisions`).then(r=>r.json()).catch(()=>[]),
        fetch(`${API_BASE}/api/departments`).then(r=>r.json()).catch(()=>[]),
      ]);
      if (Array.isArray(dRes))  setOrgDivs(dRes.map(d=>d.name));
      if (Array.isArray(ptRes)) setOrgDepts(ptRes.map(d=>d.name));
    } catch {}
  }, []);

  useEffect(() => { reloadOrg(); }, []);
  // 시작 시 currentUser 있으면 자산 체크 후 결정, 없으면 gate
  const [page, setPage] = useState(() => {
    try {
      const user = JSON.parse(localStorage.getItem("ssk_current_user")||"null");
      return user ? "checking" : "gate"; // checking = 자산 체크 중
    } catch { return "gate"; }
  });
  const [dashboardCtrl, setDashboardCtrl] = useState(null);
  const [navFilter,    setNavFilter]    = useState(null);
  const [scanTarget,   setScanTarget]   = useState(null);

  // 로그아웃
  const doLogout = () => {
    localStorage.removeItem("ssk_current_user");
    localStorage.removeItem("ssk_last_page");
    setCurrentUser(null);
    setPage("gate");
    window.history.replaceState({ page:"gate" }, "", "#gate");
  };

  // ── 앱 시작 시 자산 체크 → 라우팅 결정 ──────────────────────────
  useEffect(() => {
    if (page !== "checking") return;
    (async () => {
      try {
        const assets = await fetch(`${API_BASE}/api/assets`).then(r=>r.json()).catch(()=>[]);
        // 본인 담당 자산만 확인
        const me = (() => { try { return JSON.parse(localStorage.getItem("ssk_current_user")||"null"); } catch { return null; } })();
        const myAssets = Array.isArray(assets)
          ? assets.filter(a => a.manager && me?.name && a.manager === me.name)
          : [];
        if (myAssets.length === 0) {
          setPage("upload"); // 내 자산 없으면 등록 화면
        } else {
          setPage("scan");   // 내 자산 있으면 점검 엔진
        }
      } catch {
        setPage("scan");
      }
    })();
  }, [page]);

  // ── 브라우저 history API 연동 ──
  // 페이지 이동 시 URL hash + history.pushState → 뒤로/앞으로 버튼 동작
  const navTo = (p) => {
    setPage(p);
    if (p !== "gate" && p !== "apiclient") {
      localStorage.setItem("ssk_last_page", p);
      // 현재와 다른 페이지일 때만 pushState
      if (window.location.hash !== "#" + p) {
        window.history.pushState({ page: p }, "", "#" + p);
      }
    }
  };

  // ── 브라우저 history 연동 ──────────────────────────────────────
  useEffect(() => {
    const user = (() => {
      try { return JSON.parse(localStorage.getItem("ssk_current_user")||"null"); } catch { return null; }
    })();

    // 초기 진입: 현재 페이지를 history 스택에 올려놓음
    // → 뒤로가기 눌러도 앱 안에 머뭄 (빠져나가지 않음)
    const initPage = (() => {
      const hash = window.location.hash.replace("#","");
      const saved = localStorage.getItem("ssk_last_page") || "dashboard";
      const skip = ["gate","apiclient",""];
      if (user && hash && !skip.includes(hash)) return hash;
      if (user) return saved;
      return "gate";
    })();

    // gate에서 시작 — onEnter에서 자산 체크 후 페이지 결정
    // initPage 복원 불필요

    // 뒤로/앞으로 버튼 감지
    const onPopState = (e) => {
      const u = (() => {
        try { return JSON.parse(localStorage.getItem("ssk_current_user")||"null"); } catch { return null; }
      })();
      if (!u) return;

      const target = e.state?.page
        || window.location.hash.replace("#","")
        || "dashboard";

      const skip = ["gate","apiclient"];
      const dest = skip.includes(target) ? "dashboard" : target;
      setPage(dest);
      localStorage.setItem("ssk_last_page", dest);
    };

    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []); // 최초 1회
  const [badges, setBadges] = useState({ alerts:0, assets:0, findings:0, cve:0 });

  // 뱃지 갱신 함수 — 외부에서 호출 가능
  const refreshBadges = async () => {
    if (!currentUser) return;
    try {
      const [ac, assets, findings, cve] = await Promise.all([
        fetch(`${API_BASE}/api/alerts/count`).then(r=>r.json()).catch(()=>({unread:0})),
        fetch(`${API_BASE}/api/assets`).then(r=>r.json()).catch(()=>[]),
        fetch(`${API_BASE}/api/findings?status=open`).then(r=>r.json()).catch(()=>[]),
        fetch(`${API_BASE}/api/cve?days=7`).then(r=>r.json()).catch(()=>[]),
      ]);
      setBadges({
        alerts:   ac.unread || 0,
        assets:   Array.isArray(assets)   ? assets.length   : 0,
        findings: Array.isArray(findings) ? findings.length : 0,
        cve:      Array.isArray(cve)      ? cve.filter(c=>c.cvss_score>=9).length : 0,
      });
    } catch {}
  };

  // 로그인 시 즉시 + 5분 주기 폴링
  useEffect(() => {
    if (!currentUser) return;
    refreshBadges();
    const t = setInterval(refreshBadges, 300000);
    return () => clearInterval(t);
  }, [currentUser]);

  // 페이지 이동 시 즉시 갱신 (삭제/등록 후 바로 반영)
  useEffect(() => {
    if (currentUser && page !== "gate" && page !== "checking") {
      refreshBadges();
    }
  }, [page]);
  useEffect(() => {
    applyTheme(getStoredTheme());

    // ── 저장된 외관 설정 복원 ──
    // 글자 크기 — html font-size 변경 → rem 전체 스케일
    const scale = parseFloat(localStorage.getItem("ssk_font_scale") || "14");
    document.documentElement.style.fontSize = scale + "px";

    // 화면 밀도
    const density = localStorage.getItem("ssk_density") || "normal";
    document.documentElement.setAttribute("data-density", density);

    // 사이드바 너비
    const sbMap = { narrow:"168px", normal:"200px", wide:"232px" };
    const sbKey = localStorage.getItem("ssk_sidebar_w") || "normal";
    document.documentElement.style.setProperty("--sidebar-width", sbMap[sbKey] || "200px");
  }, []);

  const pageMeta = {
    dashboard:  { title:t("page_dashboard"),   crumb:"Dashboard / Overview" },
    alerts:     { title:t("page_alerts"),      crumb:"Alerts / Repeat Tracker" },
    upload:     { title:"자산 등록",            crumb:"Vulnerability Mgmt / Asset Register" },
    assets:     { title:t("page_assets"),      crumb:"Vulnerability Mgmt / Assets" },
    scan:       { title:t("page_scan"),        crumb:"Vulnerability Mgmt / Scan" },
    findings:   { title:t("page_findings"),    crumb:"Vulnerability Mgmt / Findings" },
    history:    { title:"점검 이력",             crumb:"Vulnerability Mgmt / Scan History" },
    threat:     { title:"보안 점검 현황 센터",     crumb:"Intelligence / Threat Intel" },
    library:    { title:"점검 항목 라이브러리",    crumb:"Intelligence / Check Library" },
    compliance: { title:t("page_compliance"),  crumb:"Reports / Compliance" },
    reports:    { title:t("page_reports"),     crumb:"Reports / Generate" },
    settings:   { title:t("page_settings"),    crumb:"System / Settings" },
    admin:      { title:"관리자",               crumb:"System / Admin" },
    logs:       { title:"실시간 로그 뷰어",    crumb:"System / Logs" },
    notify:     { title:"보안 조치 통보 센터",   crumb:"Security / Notify" },
    apiclient:  { title:"API 테스트 클라이언트",   crumb:"System / API Client" },
  };

  const m = pageMeta[page] || { title:page, crumb:page };

  const renderPage = () => {
    if (page === "checking") return (
      <div style={{ display:"flex", alignItems:"center", justifyContent:"center",
        height:"100vh", color:"var(--txt3)", fontSize:14 }}>
        <span>잠시만요...</span>
      </div>
    );
    switch (page) {
      case "gate":       return <PageGate onEnter={async ({user, goto}) => {
        if (user) setCurrentUser(user);
        // 자산 유무에 따라 이동 결정
        try {
          const assets = await fetch(`${API_BASE}/api/assets`).then(r=>r.json()).catch(()=>[]);
          const myAssets = Array.isArray(assets)
            ? assets.filter(a => a.manager && user?.name && a.manager === user.name)
            : [];
          if (myAssets.length === 0) {
            navTo("upload");
          } else {
            navTo("scan");
          }
          return;
        } catch {}
        navTo("dashboard");
      }} />;
      case "dashboard":  return <PageDashboard onNav={navTo} onCtrl={setDashboardCtrl} onNavWithFilter={(page,filter)=>{setNavFilter(filter);navTo(page);}} />;
      case "scan":       return <PageScan onNav={navTo} onNavWithFilter={(f)=>{setNavFilter(f);navTo("findings");}} initAssetId={scanTarget} onTargetUsed={()=>setScanTarget(null)} currentUser={currentUser} />;
      case "findings":   return <PageFindings onNav={navTo} initFilter={navFilter} onFilterUsed={()=>setNavFilter(null)} />;
      case "alerts":     return <PageAlerts onNav={navTo} initTab={typeof navFilter==="string"?navFilter:null} onTabUsed={()=>setNavFilter(null)} />;
      case "assets":     return <PageAssets onNav={navTo} onScanNav={(assetId)=>{ setScanTarget(assetId); navTo('scan'); }} currentUser={currentUser} />;
      case "upload":     return <PageUpload onNav={navTo} />;
      case "threat":     return <PageThreatIntel />;
      case "library":    return <PageCheckLibrary />;
      case "compliance": return <PageCompliance onNav={navTo} />;
      case "reports":    return <PageReports />;
      case "history":    return <PageHistory onNav={navTo} onNavWithFilter={setNavFilter} currentUser={currentUser} />;
      case "settings":   return <PageSettings />;
      case "admin":      return <PageAdmin onNav={navTo} />;
      case "notify":     return <PageNotify onNav={navTo} />;
      case "logs":       return <PageLogViewer />;
      case "apiclient":  return <PageApiClient />;
      default:           return <PageDashboard onNav={navTo} />;
    }
  };

  // 로그인 안 된 상태에서 gate 아닌 페이지 접근 → gate로 강제
  const isLoggedIn = !!currentUser;
  const isGatePage = (page === "gate" || page === "checking");

  // 미로그인 + gate 아닌 페이지면 gate 렌더
  if (!isLoggedIn && !isGatePage) {
    return (
      <div style={{ display:"flex", minHeight:"100vh", background:"var(--bg-base)" }}>
        <PageGate onEnter={async ({user, goto}) => {
          if (user) setCurrentUser(user);
          try {
            const assets = await fetch(`${API_BASE}/api/assets`).then(r=>r.json()).catch(()=>[]);
            const myAssets = Array.isArray(assets)
              ? assets.filter(a => a.manager && user?.name && a.manager === user.name)
              : [];
            if (myAssets.length === 0) {
              navTo("upload");
            } else {
              navTo("scan");
            }
            return;
          } catch {}
          navTo("dashboard");
        }} />
      </div>
    );
  }

  return (
    <div style={{ display:"flex", minHeight:"100vh", background:"var(--bg-base)" }}>
      {/* gate 페이지: 사이드바/탑바 없이 전체 화면 */}
      {isGatePage ? (
        <div style={{ flex:1 }}>{renderPage()}</div>
      ) : (<>
        <Sidebar page={page} onNav={navTo} dashboardCtrl={dashboardCtrl} badges={badges} />
        <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden" }}>
          <Topbar title={m.title} crumb={m.crumb} onApiClient={() => setPage("apiclient")} badges={badges} currentUser={currentUser} onLogout={doLogout} />
          <div style={{ flex:1, overflowY:"auto" }} key={page} className="page-enter">
            {renderPage()}
          </div>
        </div>
      </>)}
    </div>
  );
}

export default function App() {
  return <LangProvider><AppInner /></LangProvider>;
}

