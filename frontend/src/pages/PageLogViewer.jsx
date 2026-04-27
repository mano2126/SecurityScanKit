/**
 * PageLogViewer — 엔터프라이즈급 실시간 로그 뷰어
 * - 페이지 이동 후 복귀 시 설정 유지 (localStorage)
 * - WebSocket 실시간 스트림 + 자동 재연결
 * - 레벨/태그/로거 필터, 풀텍스트 검색 + 하이라이트
 * - 시퀀스 번호 기반 무중복 증분 수신
 * - 로그 레벨 런타임 변경
 * - 텍스트/JSON 내보내기
 */
import { useState, useEffect, useRef, useCallback, useMemo } from "react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const WS_BASE  = API_BASE.replace(/^http/, "ws");
const LS_KEY   = "ssk_logviewer_prefs";  // localStorage 영속화 키

// ── 상수 ────────────────────────────────────────────────────────
const LEVEL = {
  debug:    { label:"DEBUG",    color:"#64748B", bg:"rgba(100,116,139,.1)",  border:"rgba(100,116,139,.2)" },
  info:     { label:"INFO",     color:"#60A5FA", bg:"rgba(96,165,250,.1)",   border:"rgba(96,165,250,.2)" },
  warn:     { label:"WARN",     color:"#FBBF24", bg:"rgba(251,191,36,.1)",   border:"rgba(251,191,36,.2)" },
  error:    { label:"ERROR",    color:"#F87171", bg:"rgba(248,113,113,.12)", border:"rgba(248,113,113,.3)" },
  critical: { label:"CRITICAL", color:"#F43F5E", bg:"rgba(244,63,94,.15)",   border:"rgba(244,63,94,.35)" },
};
const LEVEL_ORDER = { debug:0, info:1, warn:2, error:3, critical:4 };
const LEVELS_ALL  = ["debug","info","warn","error","critical"];

// ── localStorage 영속화 헬퍼 ────────────────────────────────────
const loadPrefs = () => {
  try { return JSON.parse(localStorage.getItem(LS_KEY)||"{}"); } catch { return {}; }
};
const savePrefs = (p) => {
  try { localStorage.setItem(LS_KEY, JSON.stringify(p)); } catch {}
};

// ── 메시지 하이라이트 ────────────────────────────────────────────
const Highlight = ({ text, kw }) => {
  if (!kw || !text) return <>{text}</>;
  const parts = text.split(new RegExp(`(${kw.replace(/[.*+?^${}()|[\]\\]/g,"\\$&")})`, "gi"));
  return <>{parts.map((p,i) =>
    i%2===1
      ? <mark key={i} style={{background:"rgba(251,191,36,.45)",color:"inherit",borderRadius:2,padding:"0 1px"}}>{p}</mark>
      : p
  )}</>;
};

// ── 레벨 배지 ────────────────────────────────────────────────────
const LevelBadge = ({ level, small }) => {
  const s = LEVEL[level] || LEVEL.info;
  return (
    <span style={{
      fontSize:small?9:10, padding:small?"0 5px":"1px 7px", borderRadius:4,
      fontWeight:700, color:s.color, background:s.bg,
      border:`1px solid ${s.border}`, flexShrink:0, fontFamily:"monospace",
      letterSpacing:".04em", whiteSpace:"nowrap"
    }}>{s.label}</span>
  );
};

// ── 메인 컴포넌트 ─────────────────────────────────────────────────
export default function PageLogViewer() {
  const prefs = loadPrefs();

  // ── 로그 데이터 ──────────────────────────────────────────────
  const [logs,       setLogs]       = useState([]);
  const [stats,      setStats]      = useState({});
  const [connected,  setConnected]  = useState(false);
  const [connStatus, setConnStatus] = useState("disconnected"); // connecting|connected|reconnecting|disconnected

  // ── 필터 (localStorage 영속화) ────────────────────────────────
  const [filterLevel,  setFilterLevel]  = useState(prefs.filterLevel  || "all");
  const [filterTag,    setFilterTag]    = useState(prefs.filterTag    || "");
  const [filterLogger, setFilterLogger] = useState(prefs.filterLogger || "");
  const [filterQ,      setFilterQ]      = useState(prefs.filterQ      || "");

  // ── UI 설정 (영속화) ─────────────────────────────────────────
  const [autoScroll,  setAutoScroll]  = useState(prefs.autoScroll  !== false);
  const [paused,      setPaused]      = useState(false);
  const [showDetail,  setShowDetail]  = useState(prefs.showDetail  !== false);
  const [minLevel,    setMinLevel]    = useState(prefs.minLevel    || "debug"); // 서버 레벨
  const [selectedLog, setSelectedLog] = useState(null);
  const [maxLines,    setMaxLines]    = useState(prefs.maxLines    || 3000);

  // ── ref ──────────────────────────────────────────────────────
  const listRef    = useRef(null);
  const wsRef      = useRef(null);
  const pauseRef   = useRef(false);
  const seqRef     = useRef(0);     // 마지막 수신 seq
  const reconnectT = useRef(null);

  // ── 필터 변경 시 localStorage 저장 ──────────────────────────
  useEffect(()=>{ savePrefs({filterLevel,filterTag,filterLogger,filterQ,autoScroll,showDetail,minLevel,maxLines}); },
    [filterLevel,filterTag,filterLogger,filterQ,autoScroll,showDetail,minLevel,maxLines]);

  // ── 로그 추가 (중복 방지 + 최대 maxLines) ────────────────────
  const addEntries = useCallback((entries) => {
    if (pauseRef.current || !entries.length) return;
    setLogs(prev => {
      const newE = entries.filter(e => e.seq > seqRef.current);
      if (!newE.length) return prev;
      seqRef.current = Math.max(...newE.map(e=>e.seq));
      return [...prev, ...newE].slice(-maxLines);
    });
  }, [maxLines]);

  // ── 통계 로드 ────────────────────────────────────────────────
  const loadStats = useCallback(async () => {
    try { setStats(await fetch(`${API_BASE}/api/logs/stats`).then(r=>r.json())); }
    catch {}
  }, []);

  // ── 폴링 방식으로 로그 수신 (2초 간격) ─────────────────────
  const pollRef = useRef(null);

  const startPolling = useCallback(() => {
    const poll = async () => {
      if (pauseRef.current) return;
      try {
        const after = seqRef.current;
        const url = after > 0
          ? `${API_BASE}/api/logs?after=${after}&limit=200`
          : `${API_BASE}/api/logs?limit=200`;
        const data = await fetch(url).then(r=>r.json());
        if (Array.isArray(data) && data.length > 0) {
          addEntries(data);
        }
      } catch {}
    };

    poll(); // 즉시 1회
    pollRef.current = setInterval(poll, 2000);
    setConnected(true);
    setConnStatus("connected");
  }, [addEntries]);

  // ── WebSocket 시도 → 실패 시 폴링 fallback ───────────────────
  const connectWS = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;
    setConnStatus("connecting");
    try {
      const ws = new WebSocket(`${WS_BASE}/ws/logs`);
      wsRef.current = ws;

      let wsWorking = false;
      const wsTimeout = setTimeout(() => {
        if (!wsWorking) {
          ws.close();
          startPolling();
        }
      }, 3000); // 3초 내 연결 안 되면 폴링

      ws.onopen = () => {
        wsWorking = true;
        clearTimeout(wsTimeout);
        setConnected(true); setConnStatus("connected");
        if (reconnectT.current) { clearTimeout(reconnectT.current); reconnectT.current=null; }
        const ping = setInterval(()=>{
          if(ws.readyState===WebSocket.OPEN) ws.send(JSON.stringify({type:"ping"}));
        }, 15000);
        ws._pingInterval = ping;
      };
      ws.onclose = () => {
        clearTimeout(wsTimeout);
        setConnected(false); setConnStatus("reconnecting");
        if (ws._pingInterval) clearInterval(ws._pingInterval);
        // WS 끊기면 폴링으로 전환
        if (!pollRef.current) startPolling();
        else reconnectT.current = setTimeout(connectWS, 10000);
      };
      ws.onerror = () => {
        clearTimeout(wsTimeout);
        setConnected(false);
        if (!pollRef.current) startPolling();
      };
      ws.onmessage = (e) => {
        try {
          const data = JSON.parse(e.data);
          if (data.type === "bulk")      { addEntries(data.entries||[]); }
          else if (data.type === "heartbeat" || data.type === "pong") {
            setStats(p=>({...p, seq_max:data.seq||p.seq_max}));
          } else if (data.seq) {
            addEntries([data]);
          }
        } catch {}
      };
    } catch {
      setConnected(false);
      startPolling(); // WS 자체 실패 시 즉시 폴링
    }
  }, [addEntries, startPolling]);

  useEffect(() => {
    connectWS();
    const statsT = setInterval(loadStats, 5000);
    loadStats();
    return () => {
      clearInterval(statsT);
      if (pollRef.current)  { clearInterval(pollRef.current); pollRef.current=null; }
      if (reconnectT.current) clearTimeout(reconnectT.current);
      if (wsRef.current) { wsRef.current.onclose=null; wsRef.current.close(); }
    };
  }, [connectWS, loadStats]);

  // ── 자동 스크롤 ────────────────────────────────────────────
  useEffect(() => {
    if (autoScroll && listRef.current) listRef.current.scrollTop = listRef.current.scrollHeight;
  }, [logs, autoScroll]);

  // ── 서버 로그 레벨 변경 ──────────────────────────────────────
  const changeServerLevel = async (level) => {
    try {
      await fetch(`${API_BASE}/api/logs/level`, {
        method:"PATCH", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({level})
      });
      setMinLevel(level);
    } catch {}
  };

  // ── 로그 클리어 ──────────────────────────────────────────────
  const clearLogs = async () => {
    try { await fetch(`${API_BASE}/api/logs`, {method:"DELETE"}); } catch {}
    setLogs([]); seqRef.current=0; setSelectedLog(null);
    setStats({}); 
  };

  // ── 내보내기 ──────────────────────────────────────────────────
  const exportLogs = (fmt) => {
    window.open(`${API_BASE}/api/logs/export?fmt=${fmt}&level=${filterLevel}`, "_blank");
  };

  // ── 필터링 (useMemo) ──────────────────────────────────────────
  const filtered = useMemo(() => {
    let result = logs;
    if (filterLevel !== "all") result = result.filter(l=>l.level===filterLevel);
    if (filterTag)    result = result.filter(l=>l.tag?.toUpperCase()===filterTag.toUpperCase());
    if (filterLogger) result = result.filter(l=>l.logger?.toLowerCase().includes(filterLogger.toLowerCase()));
    if (filterQ) {
      const ql = filterQ.toLowerCase();
      result = result.filter(l=>l.msg?.toLowerCase().includes(ql)||l.logger?.toLowerCase().includes(ql)||l.tag?.toLowerCase().includes(ql));
    }
    return result;
  }, [logs, filterLevel, filterTag, filterLogger, filterQ]);

  const uniqTags    = useMemo(()=>[...new Set(logs.map(l=>l.tag).filter(Boolean))].sort(), [logs]);
  const uniqLoggers = useMemo(()=>[...new Set(logs.map(l=>l.logger).filter(Boolean))].sort(), [logs]);

  // ── 연결 상태 표시 ────────────────────────────────────────────
  const connColor = {connected:"#4ADE80",reconnecting:"#FBBF24",connecting:"#60A5FA",disconnected:"#F87171"}[connStatus]||"#94A3B8";
  const connLabel = {connected:"● LIVE",reconnecting:"↻ 재연결 중",connecting:"○ 연결 중",disconnected:"✕ 끊김"}[connStatus]||"";

  return (
    <div style={{padding:"12px 16px",display:"flex",flexDirection:"column",height:"calc(100vh - 56px)",gap:8,overflow:"hidden"}}>

      {/* ══ 헤더 ══ */}
      <div style={{display:"flex",alignItems:"center",gap:10,flexShrink:0}}>
        <div style={{width:36,height:36,borderRadius:8,background:"rgba(96,165,250,.1)",
          border:"1px solid rgba(96,165,250,.2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:17}}>📋</div>
        <div style={{flex:1}}>
          <div style={{fontSize:14,fontWeight:700,color:"var(--txt)"}}>실시간 로그 뷰어</div>
          <div style={{fontSize:10,color:"var(--txt3)",display:"flex",alignItems:"center",gap:8}}>
            <span style={{color:connColor,fontWeight:600}}>{connLabel}</span>
            <span>버퍼 {logs.length}/{maxLines}</span>
            {stats.uptime_s && <span>가동 {Math.floor(stats.uptime_s/3600)}h {Math.floor((stats.uptime_s%3600)/60)}m</span>}
            {stats.err_1m>0 && <span style={{color:"#F87171",fontWeight:700}}>⚠ 최근 1분 에러 {stats.err_1m}건</span>}
          </div>
        </div>

        {/* 서버 레벨 설정 */}
        <div style={{display:"flex",alignItems:"center",gap:4}}>
          <span style={{fontSize:10,color:"var(--txt3)"}}>서버 레벨</span>
          <select value={minLevel} onChange={e=>changeServerLevel(e.target.value)}
            style={{padding:"4px 8px",borderRadius:5,border:"1px solid var(--bdr)",background:"var(--bg-input)",
              color:"var(--accent-text)",fontSize:11,cursor:"pointer",fontWeight:600}}>
            {LEVELS_ALL.map(l=><option key={l} value={l}>{l.toUpperCase()}</option>)}
          </select>
        </div>

        {/* 컨트롤 버튼 */}
        <div style={{display:"flex",gap:5}}>
          <button onClick={()=>{setPaused(p=>{const n=!p;pauseRef.current=n;return n;})}}
            style={{padding:"5px 11px",borderRadius:6,border:`1px solid ${paused?"rgba(251,191,36,.4)":"var(--bdr)"}`,
              background:paused?"rgba(251,191,36,.08)":"transparent",
              color:paused?"#FBBF24":"var(--txt3)",fontSize:11,cursor:"pointer",fontWeight:paused?700:400}}>
            {paused?"▶ 재개":"⏸ 정지"}
          </button>
          <button onClick={()=>setAutoScroll(p=>!p)}
            style={{padding:"5px 11px",borderRadius:6,
              border:`1px solid ${autoScroll?"rgba(96,165,250,.3)":"var(--bdr)"}`,
              background:autoScroll?"rgba(96,165,250,.07)":"transparent",
              color:autoScroll?"#60A5FA":"var(--txt3)",fontSize:11,cursor:"pointer"}}>
            ↓ {autoScroll?"자동":"고정"}
          </button>
          <button onClick={()=>setShowDetail(p=>!p)}
            style={{padding:"5px 11px",borderRadius:6,
              border:`1px solid ${showDetail?"rgba(74,222,128,.3)":"var(--bdr)"}`,
              background:showDetail?"rgba(74,222,128,.07)":"transparent",
              color:showDetail?"#4ADE80":"var(--txt3)",fontSize:11,cursor:"pointer"}}>
            ☰ 상세
          </button>
          <button onClick={()=>exportLogs("text")} title="텍스트 다운로드"
            style={{padding:"5px 11px",borderRadius:6,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:11,cursor:"pointer"}}>
            ↓ TXT
          </button>
          <button onClick={()=>exportLogs("json")} title="JSON 다운로드"
            style={{padding:"5px 11px",borderRadius:6,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:11,cursor:"pointer"}}>
            ↓ JSON
          </button>
          <button onClick={clearLogs}
            style={{padding:"5px 11px",borderRadius:6,border:"1px solid rgba(220,38,38,.3)",background:"transparent",color:"#F87171",fontSize:11,cursor:"pointer"}}>
            🗑 초기화
          </button>
        </div>
      </div>

      {/* ══ KPI 바 ══ */}
      <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:5,flexShrink:0}}>
        {[
          {k:"all",      l:"전체",     v:stats.total||0,    c:"var(--txt)"},
          {k:"info",     l:"INFO",     v:stats.info||0,     c:LEVEL.info.color},
          {k:"warn",     l:"WARN",     v:stats.warn||0,     c:LEVEL.warn.color},
          {k:"error",    l:"ERROR",    v:stats.error||0,    c:LEVEL.error.color},
          {k:"critical", l:"CRITICAL", v:stats.critical||0, c:LEVEL.critical.color},
          {k:"debug",    l:"DEBUG",    v:stats.debug||0,    c:LEVEL.debug.color},
        ].map(k=>{
          const active = filterLevel===k.k;
          return (
            <div key={k.k} onClick={()=>setFilterLevel(active?"all":k.k)}
              style={{background:"var(--bg-card)",border:`1px solid ${active?k.c+"55":"var(--bdr)"}`,
                borderTop:`2px solid ${active?k.c:"transparent"}`,
                borderRadius:7,padding:"6px 8px",cursor:"pointer",transition:"all .15s",
                opacity:filterLevel!=="all"&&!active?.5:1}}>
              <div style={{fontSize:8,color:"var(--txt3)",marginBottom:2,textTransform:"uppercase",letterSpacing:".05em"}}>{k.l}</div>
              <div style={{fontSize:16,fontWeight:700,color:k.c}}>{k.v.toLocaleString()}</div>
            </div>
          );
        })}
      </div>

      {/* ══ 필터 바 ══ */}
      <div style={{display:"flex",gap:6,flexShrink:0,flexWrap:"wrap",alignItems:"center"}}>
        {/* 검색 */}
        <div style={{position:"relative",flex:1,minWidth:180}}>
          <span style={{position:"absolute",left:8,top:"50%",transform:"translateY(-50%)",fontSize:11,color:"var(--txt3)",pointerEvents:"none"}}>⌕</span>
          <input value={filterQ} onChange={e=>setFilterQ(e.target.value)}
            placeholder="메시지·로거·태그 검색"
            style={{width:"100%",padding:"6px 8px 6px 24px",borderRadius:6,border:"1px solid var(--bdr)",
              background:"var(--bg-input)",color:"var(--txt)",fontSize:11,outline:"none"}}/>
          {filterQ&&<span onClick={()=>setFilterQ("")} style={{position:"absolute",right:7,top:"50%",transform:"translateY(-50%)",cursor:"pointer",color:"var(--txt3)",fontSize:11}}>✕</span>}
        </div>
        {/* 태그 */}
        <select value={filterTag} onChange={e=>setFilterTag(e.target.value)}
          style={{padding:"6px 8px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",
            color:filterTag?"var(--accent-text)":"var(--txt3)",fontSize:11,cursor:"pointer",minWidth:100}}>
          <option value="">전체 태그</option>
          {uniqTags.map(t=><option key={t} value={t}>{t}</option>)}
        </select>
        {/* 로거 */}
        <select value={filterLogger} onChange={e=>setFilterLogger(e.target.value)}
          style={{padding:"6px 8px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",
            color:filterLogger?"var(--accent-text)":"var(--txt3)",fontSize:11,cursor:"pointer",minWidth:130}}>
          <option value="">전체 로거</option>
          {uniqLoggers.map(l=><option key={l} value={l}>{l}</option>)}
        </select>
        {/* 활성 필터 리셋 */}
        {(filterLevel!=="all"||filterTag||filterLogger||filterQ) && (
          <button onClick={()=>{setFilterLevel("all");setFilterTag("");setFilterLogger("");setFilterQ("");}}
            style={{padding:"5px 10px",borderRadius:6,border:"1px solid rgba(248,113,113,.3)",background:"rgba(248,113,113,.06)",color:"#F87171",fontSize:10,cursor:"pointer"}}>
            ✕ 필터 초기화
          </button>
        )}
        <span style={{fontSize:10,color:"var(--txt3)",padding:"0 8px",background:"var(--bg-card2)",
          borderRadius:5,border:"1px solid var(--bdr)",display:"flex",alignItems:"center",whiteSpace:"nowrap"}}>
          {filtered.length.toLocaleString()} / {logs.length.toLocaleString()}건
        </span>
      </div>

      {/* ══ 메인 영역 ══ */}
      <div style={{flex:1,display:"grid",gap:8,minHeight:0,
        gridTemplateColumns:showDetail&&selectedLog?"1fr 360px":"1fr"}}>

        {/* ─ 로그 목록 ─ */}
        <div ref={listRef}
          style={{background:"#080E1A",border:"1px solid var(--bdr)",borderRadius:10,
            overflowY:"auto",fontSize:11,lineHeight:1,
            fontFamily:"'Consolas','Courier New',Consolas,monospace"}}
          onScroll={e=>{
            const el=e.target;
            if(el.scrollHeight-el.scrollTop-el.clientHeight>60 && autoScroll) setAutoScroll(false);
          }}>
          {filtered.length===0 ? (
            <div style={{textAlign:"center",padding:"80px 0",color:"#3A4A5C",fontSize:12}}>
              <div style={{fontSize:40,marginBottom:10,opacity:.25}}>📋</div>
              {logs.length===0 ? "백엔드 연결 중... 잠시 후 로그가 표시됩니다" : "필터 조건에 맞는 로그 없음"}
            </div>
          ) : filtered.map((l,i)=>{
            const s = LEVEL[l.level]||LEVEL.info;
            const isSel = selectedLog?.seq===l.seq;
            return (
              <div key={l.seq||i} onClick={()=>setSelectedLog(isSel?null:l)}
                style={{display:"flex",alignItems:"flex-start",gap:0,padding:"2px 0",
                  cursor:"pointer",borderLeft:`3px solid ${isSel?s.color:"transparent"}`,
                  background:isSel?"rgba(255,255,255,.04)":"transparent",
                  borderBottom:"1px solid rgba(255,255,255,.02)"}}
                onMouseEnter={e=>!isSel&&(e.currentTarget.style.background="rgba(255,255,255,.025)")}
                onMouseLeave={e=>!isSel&&(e.currentTarget.style.background="transparent")}>
                {/* 시퀀스 */}
                <span style={{color:"#2D3748",fontSize:9,flexShrink:0,width:50,textAlign:"right",paddingRight:6,paddingTop:3,userSelect:"none"}}>
                  {l.seq}
                </span>
                {/* 시간 */}
                <span style={{color:"#4A5568",fontSize:10,flexShrink:0,width:86,paddingTop:2,paddingRight:4}}>
                  {l.ts?.slice(11)||""}
                </span>
                {/* 레벨 */}
                <span style={{width:56,flexShrink:0,paddingRight:6,paddingTop:1}}>
                  <LevelBadge level={l.level} small/>
                </span>
                {/* 태그 */}
                <span style={{color:"#4B5563",fontSize:9,flexShrink:0,width:64,paddingTop:3,
                  overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",paddingRight:4,fontWeight:600}}>
                  {l.tag}
                </span>
                {/* 로거:라인 */}
                <span style={{color:"#374151",fontSize:9,flexShrink:0,width:90,paddingTop:3,
                  overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",paddingRight:6}}>
                  {l.logger?.split(".").pop()}:{l.line}
                </span>
                {/* 메시지 */}
                <span style={{
                  color:l.level==="error"||l.level==="critical"?"#FCA5A5":
                        l.level==="warn"?"#FDE68A":
                        l.level==="debug"?"#374151":"#9CA3AF",
                  lineHeight:1.5,wordBreak:"break-all",paddingTop:1,paddingRight:8,flex:1}}>
                  <Highlight text={l.msg} kw={filterQ}/>
                </span>
              </div>
            );
          })}
        </div>

        {/* ─ 상세 패널 ─ */}
        {showDetail && selectedLog && (
          <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,
            overflow:"hidden",display:"flex",flexDirection:"column",minHeight:0}}>
            <div style={{padding:"9px 12px",background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",
              display:"flex",alignItems:"center",gap:8}}>
              <LevelBadge level={selectedLog.level}/>
              <span style={{fontSize:11,fontWeight:700,color:"var(--txt)",flex:1}}>
                #{selectedLog.seq} 상세
              </span>
              <button onClick={()=>setSelectedLog(null)}
                style={{background:"transparent",border:"none",cursor:"pointer",color:"var(--txt3)",fontSize:14}}>✕</button>
            </div>
            <div style={{padding:"12px",overflowY:"auto",flex:1}}>
              {/* 메타 그리드 */}
              <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:12}}>
                {[
                  {l:"시간",    v:selectedLog.ts},
                  {l:"시퀀스",  v:`#${selectedLog.seq}`},
                  {l:"레벨",    v:selectedLog.level?.toUpperCase()},
                  {l:"태그",    v:selectedLog.tag},
                  {l:"로거",    v:selectedLog.logger},
                  {l:"위치",    v:`${selectedLog.module}.${selectedLog.func}:${selectedLog.line}`},
                ].map(d=>(
                  <div key={d.l} style={{background:"var(--bg-card2)",borderRadius:5,padding:"6px 8px",border:"1px solid var(--bdr)"}}>
                    <div style={{fontSize:8,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:2}}>{d.l}</div>
                    <div style={{fontSize:11,color:"var(--txt)",fontWeight:500,wordBreak:"break-all"}}>{d.v||"—"}</div>
                  </div>
                ))}
              </div>
              {/* 메시지 */}
              <div style={{marginBottom:12}}>
                <div style={{fontSize:8,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:5}}>메시지</div>
                <div style={{background:"#080E1A",padding:"10px 12px",borderRadius:7,
                  border:"1px solid var(--bdr)",fontFamily:"Consolas,monospace",
                  fontSize:11,color:"#9CA3AF",whiteSpace:"pre-wrap",wordBreak:"break-all",
                  lineHeight:1.7,maxHeight:200,overflowY:"auto"}}>
                  {selectedLog.msg}
                </div>
              </div>
              {/* 복사 버튼 */}
              <button onClick={()=>navigator.clipboard?.writeText(
                `[${selectedLog.ts}] [${selectedLog.level?.toUpperCase()}] ${selectedLog.logger}:${selectedLog.line} - ${selectedLog.msg}`
              )} style={{width:"100%",padding:"6px",borderRadius:6,border:"1px solid var(--bdr)",
                background:"transparent",color:"var(--txt3)",fontSize:11,cursor:"pointer",marginBottom:12}}>
                📋 클립보드 복사
              </button>
              {/* 동일 로거 최근 로그 */}
              <div>
                <div style={{fontSize:8,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:5}}>
                  동일 로거 ({selectedLog.logger}) 최근 5건
                </div>
                {logs.filter(l=>l.logger===selectedLog.logger&&l.seq!==selectedLog.seq)
                  .slice(-5).reverse().map((l,i)=>{
                  const s=LEVEL[l.level]||LEVEL.info;
                  return (
                    <div key={i} onClick={()=>setSelectedLog(l)}
                      style={{padding:"4px 8px",borderRadius:4,marginBottom:3,cursor:"pointer",
                        background:"var(--bg-card2)",border:"1px solid var(--bdr)",
                        display:"flex",gap:6,alignItems:"flex-start"}}>
                      <span style={{fontSize:9,color:"#4A5568",flexShrink:0,paddingTop:1}}>{l.ts?.slice(11)}</span>
                      <LevelBadge level={l.level} small/>
                      <span style={{fontSize:10,color:"var(--txt3)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",flex:1}}>
                        {l.msg?.slice(0,60)}
                      </span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}
      </div>

      {/* ══ 상태 바 ══ */}
      <div style={{display:"flex",alignItems:"center",gap:12,flexShrink:0,
        padding:"4px 10px",background:"var(--bg-card2)",borderRadius:6,
        border:"1px solid var(--bdr)",fontSize:10,color:"var(--txt3)"}}>
        <span>표시 <strong style={{color:"var(--txt)"}}>{filtered.length.toLocaleString()}</strong></span>
        <span>전체 <strong style={{color:"var(--txt)"}}>{logs.length.toLocaleString()}</strong></span>
        <span>서버 레벨 <strong style={{color:LEVEL[minLevel]?.color||"var(--txt)"}}>{minLevel.toUpperCase()}</strong></span>
        {Object.entries(stats.tags||{}).slice(0,5).map(([t,c])=>(
          <span key={t} onClick={()=>setFilterTag(filterTag===t?"":t)}
            style={{cursor:"pointer",padding:"0 5px",borderRadius:3,background:"var(--bg-input)",border:"1px solid var(--bdr)"}}>
            {t}: {c}
          </span>
        ))}
        <span style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:8}}>
          {paused&&<span style={{color:"#FBBF24",fontWeight:700}}>⏸ 정지</span>}
          <span>{autoScroll?"↓ 자동":"↓ 고정"}</span>
          <span>max <select value={maxLines} onChange={e=>setMaxLines(Number(e.target.value))}
            style={{padding:"0 4px",background:"transparent",border:"none",color:"var(--txt3)",fontSize:10,cursor:"pointer"}}>
            {[1000,3000,5000].map(n=><option key={n} value={n}>{n}</option>)}
          </select></span>
        </span>
      </div>
    </div>
  );
}
