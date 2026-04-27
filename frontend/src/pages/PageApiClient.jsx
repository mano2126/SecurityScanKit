// pages/PageApiClient.jsx
// 백엔드 API 테스트 클라이언트 — React 앱 내장형
import { useState, useRef } from "react";

import API_BASE from "../hooks/apiConfig.js";

const APIS = [
  // 시스템
  { id:"health",    method:"GET",  path:"/api/health",    desc:"서버 상태 확인",          section:"시스템" },
  { id:"dashboard", method:"GET",  path:"/api/dashboard", desc:"종합 대시보드 통계",       section:"시스템" },

  // 자산
  { id:"list-assets",    method:"GET",  path:"/api/assets",                desc:"전체 자산 목록 조회",      section:"자산 관리" },
  { id:"add-asset",      method:"POST", path:"/api/assets",                desc:"자산 신규 등록",           section:"자산 관리",
    body:'{\n  "name": "운영 웹서버",\n  "ip": "172.17.230.121",\n  "asset_type": "웹서버",\n  "environment": "Production",\n  "department": "IT운영팀",\n  "manager": "홍길동",\n  "priority": "critical",\n  "scan_types": "port,web,ssl",\n  "http_port": 80,\n  "https_port": 443\n}' },
  { id:"get-asset",      method:"GET",  path:"/api/assets/:id",            desc:"자산 상세 + 취약점 조회",  section:"자산 관리",
    params:[{name:"id", label:"Asset ID", ph:"UUID 입력"}] },
  { id:"upload-history", method:"GET",  path:"/api/assets/upload/history", desc:"업로드 이력 조회",          section:"자산 관리" },

  // 점검
  { id:"scan-start",  method:"POST", path:"/api/scan/start",       desc:"보안 점검 시작",          section:"점검 엔진",
    body:'{\n  "asset_ids": ["여기에 Asset ID 입력"],\n  "scan_types": "port,web,ssl"\n}' },
  { id:"scan-status", method:"GET",  path:"/api/scan/status/:id",  desc:"점검 진행 상태 확인",      section:"점검 엔진",
    params:[{name:"id", label:"Job ID", ph:"점검 후 받은 job_id"}] },
  { id:"scan-history",method:"GET",  path:"/api/scan/history",     desc:"전체 점검 이력 조회",      section:"점검 엔진" },

  // 취약점
  { id:"findings",         method:"GET",  path:"/api/findings",             desc:"취약점 전체 목록",         section:"취약점",
    params:[{name:"severity",label:"심각도",ph:"critical/high/medium/low"},{name:"repeat_only",label:"반복만",ph:"true"}] },
  { id:"findings-stats",   method:"GET",  path:"/api/findings/stats",       desc:"취약점 통계 요약",         section:"취약점" },
  { id:"findings-repeat",  method:"GET",  path:"/api/findings/repeat",      desc:"반복 취약점 목록",         section:"취약점" },
  { id:"findings-resolve", method:"POST", path:"/api/findings/:id/resolve", desc:"취약점 조치 완료 처리",    section:"취약점",
    params:[{name:"id",label:"Finding ID",ph:"취약점 UUID"}],
    body:'{\n  "resolved_by": "홍길동",\n  "note": "방화벽 차단 완료"\n}' },

  // 알람
  { id:"alerts",       method:"GET",  path:"/api/alerts",          desc:"알람 목록 조회",           section:"알람",
    params:[{name:"unread_only",label:"미읽음만",ph:"true"}] },
  { id:"alert-count",  method:"GET",  path:"/api/alerts/count",    desc:"미읽음 알람 건수",         section:"알람" },
  { id:"alert-config", method:"GET",  path:"/api/alerts/config",   desc:"알람 설정 목록",           section:"알람" },

  // 인텔리전스
  { id:"cve",        method:"GET",  path:"/api/cve",         desc:"CVE 취약점 목록",         section:"인텔리전스",
    params:[{name:"days",label:"최근 N일",ph:"30"}] },
  { id:"news",       method:"GET",  path:"/api/news",        desc:"보안 뉴스 피드",          section:"인텔리전스",
    params:[{name:"source",label:"출처",ph:"KrCERT/KISA/CISA"}] },
  { id:"news-fetch", method:"POST", path:"/api/news/fetch",  desc:"보안 뉴스 수동 수집",     section:"인텔리전스" },

  // 리포트
  { id:"compliance", method:"GET",  path:"/api/compliance",      desc:"규정별 준수율 현황",      section:"리포트" },
  { id:"report-gen", method:"POST", path:"/api/report/generate", desc:"보안 리포트 생성",        section:"리포트",
    params:[{name:"report_type",label:"리포트 유형",ph:"executive/technical/excel"}] },
];

const SECTIONS = ["시스템","자산 관리","점검 엔진","취약점","알람","인텔리전스","리포트"];
const METHOD_BG = { GET:"#0C3A2A", POST:"#0C1A3A", PUT:"#2A1A00", DELETE:"#2A0A0A" };
const METHOD_TX = { GET:"#86EFAC", POST:"#93C5FD", PUT:"#FCD34D", DELETE:"#FCA5A5" };

function colorJSON(s) {
  return s
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?)/g, m => {
      if (/^"/.test(m)) return /:$/.test(m)
        ? `<span style="color:#93C5FD;">${m}</span>`
        : `<span style="color:#86EFAC;">${m}</span>`;
      if (/true|false/.test(m)) return `<span style="color:#FDA4AF;">${m}</span>`;
      if (/null/.test(m))       return `<span style="color:#94A3B8;">${m}</span>`;
      return `<span style="color:#FDE047;">${m}</span>`;
    });
}

export default function PageApiClient() {
  const [search,   setSearch]   = useState("");
  const [tabs,     setTabs]     = useState([]);
  const [activeId, setActiveId] = useState(null);
  const [tabCnt,   setTabCnt]   = useState(0);

  // ── 탭 관리 ────────────────────────────────────────────────────
  const openTab = (api) => {
    const ex = tabs.find(t => t.apiId === api.id);
    if (ex) { setActiveId(ex.id); return; }
    const id = tabCnt + 1;
    setTabCnt(id);
    const newTab = { id, apiId:api.id, api, params:{}, body:api.body||"", result:null, loading:false, status:null, ms:null };
    setTabs(prev => [...prev, newTab]);
    setActiveId(id);
  };

  const closeTab = (id, e) => {
    e.stopPropagation();
    const remaining = tabs.filter(t => t.id !== id);
    setTabs(remaining);
    if (activeId === id) setActiveId(remaining.length ? remaining[remaining.length-1].id : null);
  };

  const updateTab = (id, data) => setTabs(prev => prev.map(t => t.id===id ? {...t,...data} : t));

  const active = tabs.find(t => t.id === activeId);

  // ── URL 빌드 ───────────────────────────────────────────────────
  const buildURL = (tab) => {
    if (!tab) return API_BASE;
    let path = tab.api.path;
    const qs = [];
    (tab.api.params||[]).forEach(p => {
      const v = (tab.params[p.name]||"").trim();
      if (!v) return;
      if (path.includes(`:${p.name}`)) path = path.replace(`:${p.name}`, encodeURIComponent(v));
      else qs.push(`${p.name}=${encodeURIComponent(v)}`);
    });
    return API_BASE + path + (qs.length ? "?"+qs.join("&") : "");
  };

  // ── API 실행 ───────────────────────────────────────────────────
  const runAPI = async (tab) => {
    updateTab(tab.id, { loading:true, result:null, status:null });
    const t0 = Date.now();
    try {
      const url = buildURL(tab);
      const opts = { method: tab.api.method, headers:{} };
      if (tab.api.method !== "GET" && tab.body?.trim()) {
        try { JSON.parse(tab.body); }
        catch(e) { updateTab(tab.id, { loading:false, result:`JSON 오류: ${e.message}`, status:400, ms:0 }); return; }
        opts.body = tab.body;
        opts.headers["Content-Type"] = "application/json";
      }
      const r = await fetch(url, opts);
      const ms = Date.now() - t0;
      const txt = await r.text();
      let fmt = txt;
      try { fmt = JSON.stringify(JSON.parse(txt), null, 2); } catch(e){}
      updateTab(tab.id, { loading:false, result:fmt, status:r.status, ms });
    } catch(e) {
      updateTab(tab.id, { loading:false, result:`연결 실패: ${e.message}\n\n서버가 실행 중인지 확인하세요.`, status:0, ms:Date.now()-t0 });
    }
  };

  const filtered = APIS.filter(a =>
    !search || a.path.toLowerCase().includes(search.toLowerCase()) || a.desc.includes(search) || a.method.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div style={{ display:"flex", height:"calc(100vh - 54px)", overflow:"hidden" }}>

      {/* ── 왼쪽 사이드 ── */}
      <div style={{ width:340, background:"#0D1117", borderRight:"1px solid #21262D", display:"flex", flexDirection:"column", flexShrink:0 }}>
        {/* 검색 */}
        <div style={{ padding:"10px 12px", borderBottom:"1px solid #21262D" }}>
          <input value={search} onChange={e=>setSearch(e.target.value)}
            placeholder="🔍  API 검색..."
            style={{ width:"100%", padding:"7px 10px", borderRadius:6, border:"1px solid #30363D", background:"#161B22", color:"#C9D1D9", fontSize:12, outline:"none" }}/>
        </div>

        {/* 컬럼 헤더 */}
        <div style={{ display:"grid", gridTemplateColumns:"46px 1fr 1fr", padding:"5px 12px", borderBottom:"1px solid #21262D", background:"#080D13" }}>
          {["메서드","경로","설명"].map(h => (
            <span key={h} style={{ fontSize:9, fontWeight:700, color:"#484F58", textTransform:"uppercase", letterSpacing:".08em" }}>{h}</span>
          ))}
        </div>

        {/* API 목록 */}
        <div style={{ flex:1, overflowY:"auto" }}>
          {SECTIONS.map(sec => {
            const items = filtered.filter(a => a.section === sec);
            if (!items.length) return null;
            return (
              <div key={sec}>
                <div style={{ padding:"7px 12px 3px", fontSize:9, fontWeight:700, color:"#3B82F6", letterSpacing:".1em", textTransform:"uppercase", background:"#080D13", borderTop:"1px solid #21262D", borderBottom:"1px solid #0D1117" }}>
                  {sec}
                </div>
                {items.map(api => {
                  const isOpen = tabs.some(t => t.apiId === api.id);
                  const isActive = activeId !== null && tabs.find(t=>t.id===activeId)?.apiId === api.id;
                  return (
                    <div key={api.id} onClick={() => openTab(api)}
                      style={{ display:"grid", gridTemplateColumns:"46px 1fr 1fr", padding:"7px 12px", cursor:"pointer", borderBottom:"1px solid #0D1117",
                        background:isActive?"#1F2937":isOpen?"#161B22":"transparent",
                        transition:"background .1s" }}>
                      <div>
                        <span style={{ padding:"2px 5px", borderRadius:3, fontSize:9, fontWeight:700, background:METHOD_BG[api.method]||"#161B22", color:METHOD_TX[api.method]||"#93C5FD" }}>
                          {api.method}
                        </span>
                      </div>
                      <div style={{ fontSize:10, color:"#8B949E", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", paddingRight:6, fontFamily:"monospace" }}>
                        {api.path.replace("/api/","")}
                      </div>
                      <div style={{ fontSize:11, color:isActive?"#93C5FD":"#6E7681", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {api.desc}
                      </div>
                    </div>
                  );
                })}
              </div>
            );
          })}
        </div>

        {/* 서버 주소 표시 */}
        <div style={{ padding:"8px 12px", borderTop:"1px solid #21262D", fontSize:10, color:"#484F58" }}>
          서버: <span style={{ color:"#3B82F6" }}>{API_BASE}</span>
        </div>
      </div>

      {/* ── 오른쪽 메인 ── */}
      <div style={{ flex:1, display:"flex", flexDirection:"column", overflow:"hidden", background:"var(--bg-base)" }}>

        {/* 탭 바 */}
        <div style={{ background:"var(--bg-nav)", borderBottom:"1px solid var(--bdr)", display:"flex", alignItems:"center", overflowX:"auto", flexShrink:0, minHeight:40 }}>
          {tabs.length === 0 ? (
            <div style={{ padding:"0 16px", fontSize:12, color:"var(--txt3)", display:"flex", alignItems:"center", height:40 }}>
              ← 왼쪽에서 API를 클릭하면 탭이 열립니다
            </div>
          ) : tabs.map(tab => (
            <div key={tab.id} onClick={() => setActiveId(tab.id)}
              style={{ display:"flex", alignItems:"center", gap:6, padding:"0 14px", height:40, cursor:"pointer",
                borderRight:"1px solid var(--bdr)", whiteSpace:"nowrap", fontSize:11,
                color:tab.id===activeId?"var(--txt)":"var(--txt3)",
                background:tab.id===activeId?"var(--bg-card)":"transparent",
                borderBottom:tab.id===activeId?"2px solid var(--accent)":"none",
                fontWeight:tab.id===activeId?600:400, flexShrink:0 }}>
              <span style={{ padding:"1px 5px", borderRadius:3, fontSize:9, fontWeight:700, background:METHOD_BG[tab.api.method], color:METHOD_TX[tab.api.method] }}>
                {tab.api.method}
              </span>
              <span style={{ maxWidth:160, overflow:"hidden", textOverflow:"ellipsis" }}>{tab.api.desc}</span>
              <span onClick={e=>closeTab(tab.id,e)} style={{ color:"var(--txt3)", fontSize:15, padding:"0 2px", borderRadius:3, lineHeight:1 }}>×</span>
            </div>
          ))}
        </div>

        {/* 패널 */}
        {!active ? (
          <div style={{ flex:1, display:"flex", flexDirection:"column", alignItems:"center", justifyContent:"center", color:"var(--txt3)" }}>
            <div style={{ fontSize:36, marginBottom:14, opacity:.3 }}>⚡</div>
            <div style={{ fontSize:14, fontWeight:500, marginBottom:4 }}>API를 선택하세요</div>
            <div style={{ fontSize:12, opacity:.7 }}>왼쪽 목록에서 API를 클릭하면 여기서 테스트할 수 있습니다</div>
          </div>
        ) : (
          <div style={{ flex:1, overflowY:"auto", padding:"18px 22px" }}>

            {/* 헤더 */}
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:14, paddingBottom:12, borderBottom:"1px solid var(--bdr)" }}>
              <span style={{ padding:"4px 10px", borderRadius:4, fontSize:12, fontWeight:700, background:METHOD_BG[active.api.method], color:METHOD_TX[active.api.method] }}>
                {active.api.method}
              </span>
              <div>
                <div style={{ fontFamily:"monospace", fontSize:14, fontWeight:600, color:"var(--txt)" }}>{active.api.path}</div>
                <div style={{ fontSize:12, color:"var(--txt3)", marginTop:2 }}>{active.api.desc}</div>
              </div>
            </div>

            {/* URL 미리보기 */}
            <div style={{ fontSize:11, color:"var(--txt3)", background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:5, padding:"7px 10px", marginBottom:14, fontFamily:"monospace", wordBreak:"break-all" }}>
              <span style={{ color:"var(--txt3)" }}>URL: </span>
              <span style={{ color:"var(--accent-text)" }}>{buildURL(active)}</span>
            </div>

            {/* 파라미터 */}
            {active.api.params?.length > 0 && (
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:10, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".05em", marginBottom:6 }}>파라미터</div>
                {active.api.params.map(p => (
                  <div key={p.name} style={{ display:"grid", gridTemplateColumns:"120px 1fr", gap:8, marginBottom:7, alignItems:"center" }}>
                    <span style={{ fontSize:11, color:"var(--txt2)", fontWeight:500 }}>{p.label}</span>
                    <input value={active.params[p.name]||""} placeholder={p.ph||""}
                      onChange={e => updateTab(active.id, { params:{...active.params,[p.name]:e.target.value} })}
                      style={{ padding:"7px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:12, outline:"none", fontFamily:"monospace" }}/>
                  </div>
                ))}
              </div>
            )}

            {/* Body */}
            {active.api.method !== "GET" && (
              <div style={{ marginBottom:14 }}>
                <div style={{ fontSize:10, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".05em", marginBottom:6 }}>Request Body (JSON)</div>
                <textarea value={active.body||""} onChange={e => updateTab(active.id, { body:e.target.value })}
                  style={{ width:"100%", height:130, padding:"9px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:12, outline:"none", fontFamily:"monospace", resize:"vertical", lineHeight:1.5 }}/>
              </div>
            )}

            {/* 실행 버튼 */}
            <button onClick={() => runAPI(active)} disabled={active.loading}
              style={{ padding:"9px 24px", background:active.loading?"var(--bg-hover)":"var(--accent)", color:"#fff", border:"none", borderRadius:7, fontWeight:700, fontSize:13, cursor:active.loading?"not-allowed":"pointer", display:"inline-flex", alignItems:"center", gap:8, marginBottom:16 }}>
              {active.loading ? (
                <><span style={{ width:12, height:12, borderRadius:"50%", border:"2px solid #fff", borderTopColor:"transparent", animation:"spin .8s linear infinite", display:"inline-block" }}/> 실행 중...</>
              ) : "▶ 실행"}
            </button>

            {/* 결과 */}
            {active.result !== null && (
              <div>
                <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:8 }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                    <span style={{ padding:"3px 10px", borderRadius:20, fontSize:11, fontWeight:700,
                      background:active.status>=200&&active.status<300?"#122D1A":active.status===0?"#1C1428":"#2D1515",
                      color:active.status>=200&&active.status<300?"#4ADE80":active.status===0?"#C084FC":"#F87171",
                      border:`1px solid ${active.status>=200&&active.status<300?"#1F5C32":active.status===0?"#6B21A8":"#5C2626"}` }}>
                      {active.status === 0 ? "Connection Error" : `${active.status} ${active.status>=200&&active.status<300?"OK":"Error"}`}
                    </span>
                    <span style={{ fontSize:11, color:"var(--txt3)" }}>{active.ms}ms</span>
                  </div>
                  <button onClick={() => navigator.clipboard.writeText(active.result||"")}
                    style={{ padding:"4px 12px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:11, cursor:"pointer" }}>
                    📋 복사
                  </button>
                </div>
                <div style={{ background:"#0D1117", border:"1px solid #21262D", borderRadius:8, padding:"14px", overflowX:"auto", maxHeight:500, overflowY:"auto" }}>
                  <pre style={{ fontFamily:"'Consolas','Courier New',monospace", fontSize:12, color:"#C9D1D9", whiteSpace:"pre-wrap", wordBreak:"break-word", lineHeight:1.6, margin:0 }}
                    dangerouslySetInnerHTML={{ __html: colorJSON(active.result) }}/>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
