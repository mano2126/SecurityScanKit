// pages/PageDashboard.jsx
// 좌우 컬럼 간 자유 이동 드래그 앤 드롭
import { useEffect, useState, useRef, useCallback } from "react";
import { useLang } from "../i18n/LangContext";
import { Badge, RepBadge, RBar, Prog, Card, Spinner } from "../components/UI";
import { fetchDashboard } from "../hooks/useAPI";

const SEV = {
  critical: { dot:"#EF4444", text:"#F87171", bg:"#2D1515", bdr:"#5C2626" },
  high:     { dot:"#F97316", text:"#FB923C", bg:"#2D1E0F", bdr:"#5C3A1A" },
  medium:   { dot:"#EAB308", text:"#FBBF24", bg:"#2D2810", bdr:"#5C4F1A" },
  low:      { dot:"#22C55E", text:"#4ADE80", bg:"#122D1A", bdr:"#1F5C32" },
  info:     { dot:"#3B82F6", text:"#60A5FA", bg:"#111E30", bdr:"#1E3A5F" },
};
const SEV_LBL = { critical:"긴급", high:"고위험", medium:"중위험", low:"저위험" };

// ── 레이아웃 저장/복원 ─────────────────────────────────────────
const DEFAULT_LAYOUT = {
  left:  ["kpi", "asset-risk", "vuln-stats"],
  right: ["risk-gauge", "alerts", "repeat"],
};

function loadLayout() {
  try {
    const saved = localStorage.getItem("ssk_dash_layout");
    return saved ? JSON.parse(saved) : DEFAULT_LAYOUT;
  } catch { return DEFAULT_LAYOUT; }
}

function saveLayout(layout) {
  localStorage.setItem("ssk_dash_layout", JSON.stringify(layout));
}

// ── 드래그 가능 블록 ───────────────────────────────────────────
function Block({ id, title, dragState, onDragStart, onDragEnter, onDrop, children }) {
  const isDragging  = dragState.dragging === id;
  const isOverCol   = dragState.overBlock === id;

  return (
    <div
      draggable
      onDragStart={(e) => { e.dataTransfer.effectAllowed = "move"; onDragStart(id); }}
      onDragEnd={() => onDrop()}
      onDragEnter={(e) => { e.preventDefault(); onDragEnter(id); }}
      onDragOver={(e) => e.preventDefault()}
      style={{
        opacity: isDragging ? 0.3 : 1,
        transform: isOverCol && !isDragging ? "translateY(-2px)" : "none",
        transition: "opacity .15s, transform .12s",
      }}
    >
      <div style={{
        background:"var(--bg-card)",
        border:`1px solid ${isOverCol && !isDragging ? "var(--accent)" : "var(--bdr)"}`,
        borderRadius:10,
        overflow:"hidden",
        boxShadow:"var(--shadow)",
        transition:"border-color .15s",
      }}>
        {/* 헤더 = 드래그 핸들 */}
        <div
          style={{
            display:"flex", alignItems:"center", gap:8,
            padding:"10px 14px",
            borderBottom:"1px solid var(--bdr)",
            cursor:"grab",
            userSelect:"none",
            background:"var(--bg-card)",
          }}
        >
          <span style={{ fontSize:13, color:"var(--txt3)", letterSpacing:3, opacity:.5, flexShrink:0 }}>⠿</span>
          <span style={{ fontSize:13, fontWeight:600, color:"var(--txt2)", flex:1 }}>{title}</span>
          {isOverCol && !isDragging && (
            <span style={{ fontSize:13, color:"var(--accent-text)", opacity:.8 }}>여기에 놓기</span>
          )}
        </div>
        <div style={{ padding:"12px 14px" }}>{children}</div>
      </div>
    </div>
  );
}

// ── 컬럼 드롭 존 (빈 공간에 놓기) ────────────────────────────────
function ColDropZone({ col, dragState, onDragEnter, show }) {
  const isOver = dragState.overCol === col && dragState.overBlock === null;
  if (!show) return null;
  return (
    <div
      onDragEnter={(e) => { e.preventDefault(); onDragEnter(col); }}
      onDragOver={(e) => e.preventDefault()}
      style={{
        height: 48,
        border: `2px dashed ${isOver ? "var(--accent)" : "var(--bdr)"}`,
        borderRadius: 8,
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        fontSize: 11,
        color: isOver ? "var(--accent-text)" : "var(--txt3)",
        background: isOver ? "var(--bg-active)" : "transparent",
        transition: "all .15s",
        opacity: isOver ? 1 : .5,
      }}
    >
      {isOver ? "여기에 놓기" : "빈 영역에 드롭"}
    </div>
  );
}

export default function PageDashboard({ onNav, onCtrl, onNavWithFilter }) {
  const { t } = useLang();
  const [data,    setData]    = useState(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [layout,  setLayout]  = useState(loadLayout);

  // 드래그 상태
  const [dragState, setDragState] = useState({
    dragging:  null,
    overBlock: null,
    overCol:   null,
  });

  const dragStateRef = useRef(dragState);
  dragStateRef.current = dragState;

  const load = async () => {
    setLoading(true); setError(null);
    try { setData(await fetchDashboard()); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };

  const resetLayout = useCallback(() => {
    setLayout(DEFAULT_LAYOUT);
    saveLayout(DEFAULT_LAYOUT);
  }, []);

  useEffect(() => { load(); }, []);

  // 사이드바에 컨트롤 등록
  useEffect(() => {
    if (onCtrl) onCtrl({ refresh: load, reset: resetLayout });
    return () => { if (onCtrl) onCtrl(null); };
  }, [onCtrl, resetLayout]);

  // ── 드래그 핸들러 ─────────────────────────────────────────────
  const onDragStart = useCallback((id) => {
    setDragState({ dragging:id, overBlock:null, overCol:null });
  }, []);

  const onDragEnterBlock = useCallback((targetId) => {
    setDragState(prev => ({ ...prev, overBlock:targetId, overCol:null }));
  }, []);

  const onDragEnterCol = useCallback((col) => {
    setDragState(prev => ({ ...prev, overCol:col, overBlock:null }));
  }, []);

  const onDrop = useCallback(() => {
    const { dragging, overBlock, overCol } = dragStateRef.current;
    setDragState({ dragging:null, overBlock:null, overCol:null });

    if (!dragging) return;

    setLayout(prev => {
      const next = { left:[...prev.left], right:[...prev.right] };

      // 드래그 소스 컬럼에서 제거
      const srcCol = next.left.includes(dragging) ? "left" : "right";
      next[srcCol] = next[srcCol].filter(id => id !== dragging);

      if (overBlock) {
        // 특정 블록 위에 놓기 — 그 블록 앞에 삽입
        const dstCol = next.left.includes(overBlock) ? "left" : "right";
        const idx = next[dstCol].indexOf(overBlock);
        next[dstCol].splice(idx, 0, dragging);
      } else if (overCol) {
        // 컬럼 빈 공간에 놓기 — 맨 아래에 추가
        next[overCol].push(dragging);
      } else {
        // 아무 곳도 아닌 경우 원래 위치로 복원
        next[srcCol].push(dragging);
      }

      saveLayout(next);
      return next;
    });
  }, []);

  if (loading) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:300, gap:12, color:"var(--txt3)" }}>
      <Spinner /> 데이터 로딩 중...
    </div>
  );

  if (error) return (
    <div style={{ padding:"30px 22px" }}>
      <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:10, padding:"20px" }}>
        <div style={{ fontSize:13, fontWeight:600, color:"#F87171", marginBottom:6 }}>백엔드 연결 오류</div>
        <div style={{ fontSize:13, color:"var(--txt2)", marginBottom:12 }}>{error}</div>
        <div style={{ fontSize:13, color:"var(--txt3)", marginBottom:12, lineHeight:1.8 }}>
          CMD에서 백엔드를 시작하세요:<br/>
          <code style={{ color:"var(--accent-text)", background:"var(--bg-card2)", padding:"2px 6px", borderRadius:3 }}>
            cd backend → python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
          </code>
        </div>
        <button onClick={load} style={{ padding:"7px 16px", borderRadius:6, border:"1px solid var(--bdr2)", background:"var(--bg-hover)", color:"var(--txt)", fontSize:13, cursor:"pointer" }}>
          다시 연결
        </button>
      </div>
    </div>
  );

  const s       = data?.stats           || {};
  const assets  = data?.top_assets      || [];
  const alerts  = data?.recent_alerts   || [];
  const repeats = data?.repeat_findings || [];
  const avgRisk = Math.round(s.avg_risk_score || 0);
  const riskColor = avgRisk >= 70 ? "#EF4444" : avgRisk >= 50 ? "#F97316" : "#22C55E";

  // ── 블록 컨텐츠 ───────────────────────────────────────────────
  const blocks = {

    "kpi": {
      title: "종합 현황",
      content: (
        <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)", gap:8 }}>
          {[
            { lbl:"전체 자산",    val:s.total_assets||0,           color:"var(--txt)",  sub:`위험 ${s.risk_distribution?.critical||0}개`, page:"assets" },
            { lbl:"긴급 취약점",  val:s.critical||0,               color:"#F87171",     sub:"즉각 조치 필요",  page:"findings" },
            { lbl:"고위험",       val:s.high||0,                   color:"#FB923C",     sub:"빠른 조치 필요",  page:"findings" },
            { lbl:"반복 취약점",  val:s.repeat||0,                 color:"#FBBF24",     sub:"연속 미조치",     page:"findings", tab:"repeat" },
            { lbl:"신규(7일)",    val:s.new_this_week||0,          color:"var(--txt2)", sub:"이번 주 신규",    page:"findings" },
            { lbl:"컴플라이언스", val:`${s.compliance_score||0}%`, color:"#4ADE80",     sub:"규정 준수율",     page:"compliance" },
          ].map(k => (
            <div key={k.lbl} onClick={() => k.page && (k.tab && onNavWithFilter ? onNavWithFilter(k.page, k.tab==="repeat" ? {repeat:true} : k.tab) : onNav(k.page))}
              style={{ background:"var(--bg-card2)", borderRadius:7, padding:"11px",
                cursor:k.page?"pointer":"default", border:"1px solid var(--bdr)",
                transition:"all .15s" }}
              onMouseEnter={e=>{ if(k.page){ e.currentTarget.style.background="var(--bg-hover)"; e.currentTarget.style.borderColor="var(--bdr2)"; }}}
              onMouseLeave={e=>{ e.currentTarget.style.background="var(--bg-card2)"; e.currentTarget.style.borderColor="var(--bdr)"; }}>
              <div style={{ fontSize:13, fontWeight:600, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", marginBottom:7 }}>{k.lbl}</div>
              <div style={{ fontSize:22, fontWeight:700, lineHeight:1, color:k.color, marginBottom:3 }}>{k.val}</div>
              <div style={{ fontSize:13, color:"var(--txt3)" }}>{k.sub}</div>
            </div>
          ))}
        </div>
      ),
    },

    "asset-risk": {
      title: "자산 위험 현황",
      content: assets.length === 0 ? (
        <div style={{ textAlign:"center", padding:"20px 0", color:"var(--txt3)", fontSize:12 }}>
          등록된 자산이 없습니다
          <div style={{ marginTop:8 }}>
            <button onClick={() => onNav("upload")} style={{ padding:"5px 12px", borderRadius:5, border:"1px solid var(--bdr2)", background:"var(--bg-hover)", color:"var(--txt)", fontSize:13, cursor:"pointer" }}>+ 자산 등록</button>
          </div>
        </div>
      ) : (
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
            <thead>
              <tr>{["자산명","IP","위험도","점수","최종점검","상태"].map(h => (
                <th key={h} style={{ padding:"10px 12px", textAlign:"left", fontSize:13, fontWeight:600, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", borderBottom:"1px solid var(--bdr)", whiteSpace:"nowrap" }}>{h}</th>
              ))}</tr>
            </thead>
            <tbody>
              {assets.map(a => {
                const sev = a.risk_score>=70?"critical":a.risk_score>=50?"high":a.risk_score>=30?"medium":"low";
                const sc  = SEV[sev];
                const stMap = { completed:{l:"정상",c:"#4ADE80"}, scanning:{l:"점검중",c:"#60A5FA"}, pending:{l:"미점검",c:"#6B7280"} };
                const st = stMap[a.status]||stMap.pending;
                return (
                  <tr key={a.id}
                    onClick={() => onNavWithFilter
                      ? onNavWithFilter("findings", { assetIp: a.ip, assetName: a.name })
                      : onNav("findings")}
                    style={{ cursor:"pointer", transition:"background .1s" }}
                    onMouseEnter={e=>e.currentTarget.style.background="var(--bg-hover)"}
                    onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                    <td style={{ padding:"8px 8px", borderBottom:"1px solid var(--bdr)", color:"var(--txt)", fontWeight:500 }}>{a.name}</td>
                    <td style={{ padding:"8px 8px", borderBottom:"1px solid var(--bdr)" }}><code style={{ fontSize:13, color:"var(--accent-text)" }}>{a.ip}</code></td>
                    <td style={{ padding:"8px 8px", borderBottom:"1px solid var(--bdr)" }}>
                      <span style={{ padding:"2px 7px", borderRadius:3, fontSize:13, fontWeight:700, background:sc.bg, color:sc.text, border:`1px solid ${sc.bdr}` }}>{SEV_LBL[sev]}</span>
                    </td>
                    <td style={{ padding:"8px 8px", borderBottom:"1px solid var(--bdr)" }}>
                      <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                        <div style={{ width:38, height:4, borderRadius:2, background:"var(--bg-input)", overflow:"hidden" }}>
                          <div style={{ height:"100%", width:`${a.risk_score}%`, background:sc.dot, borderRadius:2 }}/>
                        </div>
                        <span style={{ fontSize:13, fontWeight:600, color:sc.text }}>{Math.round(a.risk_score)}</span>
                      </div>
                    </td>
                    <td style={{ padding:"8px 8px", borderBottom:"1px solid var(--bdr)", fontSize:13, color:"var(--txt3)" }}>{a.last_scan?.slice(0,10)||"미점검"}</td>
                    <td style={{ padding:"8px 8px", borderBottom:"1px solid var(--bdr)", fontSize:13, color:st.c }}>● {st.l}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ),
    },

    "vuln-stats": {
      title: "취약점 분류",
      content: (
        <div>
          {[
            { label:"긴급 (Critical)", val:s.critical||0, total:s.total||1, color:"#EF4444" },
            { label:"고위험 (High)",   val:s.high||0,     total:s.total||1, color:"#F97316" },
            { label:"중위험 (Medium)", val:s.medium||0,   total:s.total||1, color:"#EAB308" },
            { label:"저위험 (Low)",    val:s.low||0,      total:s.total||1, color:"#22C55E" },
          ].map(b => (
            <div key={b.label} style={{ marginBottom:11, cursor:"pointer" }}
              onClick={() => onNav("findings")}
              onMouseEnter={e=>e.currentTarget.style.opacity=".75"}
              onMouseLeave={e=>e.currentTarget.style.opacity="1"}>
              <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                <span style={{ fontSize:13, color:"var(--txt2)" }}>{b.label}</span>
                <span style={{ fontSize:13, fontWeight:600, color:b.color }}>{b.val}건 →</span>
              </div>
              <div style={{ height:4, borderRadius:2, background:"var(--bg-input)", overflow:"hidden" }}>
                <div style={{ height:"100%", width:`${b.total>0?(b.val/b.total)*100:0}%`, background:b.color, borderRadius:2, transition:"width .4s" }}/>
              </div>
            </div>
          ))}
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:8, marginTop:12, paddingTop:12, borderTop:"1px solid var(--bdr)" }}>
            {[
              { lbl:"전체 미조치", val:s.total||0,  c:"var(--txt)", page:"findings" },
              { lbl:"반복 취약점", val:s.repeat||0, c:"#FBBF24",    page:"findings", tab:"repeat" },
            ].map(x => (
              <div key={x.lbl}
                onClick={() => x.tab && onNavWithFilter ? onNavWithFilter(x.page, x.tab==="repeat" ? {repeat:true} : x.tab) : onNav(x.page)}
                style={{ background:"var(--bg-card2)", borderRadius:6, padding:"10px",
                  textAlign:"center", cursor:"pointer", border:"1px solid var(--bdr)",
                  transition:"all .15s" }}
                onMouseEnter={e=>{ e.currentTarget.style.background="var(--bg-hover)"; e.currentTarget.style.borderColor="var(--bdr2)"; }}
                onMouseLeave={e=>{ e.currentTarget.style.background="var(--bg-card2)"; e.currentTarget.style.borderColor="var(--bdr)"; }}>
                <div style={{ fontSize:20, fontWeight:700, color:x.c }}>{x.val}</div>
                <div style={{ fontSize:13, color:"var(--txt3)", marginTop:3 }}>{x.lbl} →</div>
              </div>
            ))}
          </div>
        </div>
      ),
    },

    "risk-gauge": {
      title: "위험 점수",
      content: (
        <div style={{ display:"flex", flexDirection:"column", alignItems:"center" }}>
          <div style={{ position:"relative", marginBottom:8 }}>
            <svg width="160" height="90" viewBox="0 0 160 90">
              <path d="M 20 80 A 60 60 0 0 1 140 80" fill="none" stroke="var(--bg-input)" strokeWidth="10" strokeLinecap="round"/>
              <path d="M 20 80 A 60 60 0 0 1 140 80" fill="none" stroke={riskColor} strokeWidth="10" strokeLinecap="round"
                strokeDasharray={`${(avgRisk/100)*188} 188`} opacity=".9"/>
              <text x="80" y="70" textAnchor="middle" fontSize="28" fontWeight="700" fill={riskColor}>{avgRisk}</text>
              <text x="80" y="84" textAnchor="middle" fontSize="10" fill="var(--txt3)">/ 100</text>
            </svg>
          </div>
          <div style={{ fontSize:13, fontWeight:600, color:riskColor, marginBottom:14 }}>
            {avgRisk>=70?"고위험":avgRisk>=50?"주의 필요":"양호"}
          </div>
          {[
            { l:"미조치 취약점", v:s.total||0,            unit:"건", max:50,  c:"#EF4444", page:"findings" },
            { l:"반복 취약점",   v:s.repeat||0,           unit:"건", max:10,  c:"#F97316", page:"findings", tab:"repeat" },
            { l:"컴플라이언스", v:s.compliance_score||0, unit:"%",  max:100, c:"#4ADE80", page:"compliance" },
          ].map(g => (
            <div key={g.l} style={{ width:"100%", marginBottom:8, cursor:"pointer" }}
              onClick={() => g.tab && onNavWithFilter ? onNavWithFilter(g.page, g.tab==="repeat" ? {repeat:true} : g.tab) : onNav(g.page)}
              onMouseEnter={e=>e.currentTarget.style.opacity=".75"}
              onMouseLeave={e=>e.currentTarget.style.opacity="1"}>
              <div style={{ display:"flex", justifyContent:"space-between", fontSize:13, color:"var(--txt3)", marginBottom:3 }}>
                <span>{g.l}</span>
                <span style={{ color:g.c, fontWeight:600 }}>{g.v}{g.unit} →</span>
              </div>
              <div style={{ height:4, borderRadius:2, background:"var(--bg-input)", overflow:"hidden" }}>
                <div style={{ height:"100%", width:`${Math.min(100,(g.v/g.max)*100)}%`, background:g.c, borderRadius:2 }}/>
              </div>
            </div>
          ))}
        </div>
      ),
    },

    "alerts": {
      title: `알람 (미읽음 ${alerts.filter(a=>!a.is_read).length}건)`,
      content: alerts.length === 0 ? (
        <div style={{ textAlign:"center", padding:"16px 0", color:"var(--txt3)", fontSize:12 }}>알람 없음 ✓</div>
      ) : (
        <div>
          {alerts.map((a,i) => {
            const sc = SEV[a.severity]||SEV.info;
            return (
              <div key={a.id} style={{ display:"flex", gap:10, padding:"8px 0", borderBottom:i<alerts.length-1?"1px solid var(--bdr)":"none", cursor:"pointer", opacity:a.is_read?.75:1 }} onClick={() => onNav("alerts")}>
                <div style={{ width:3, minHeight:28, borderRadius:2, background:sc.dot, flexShrink:0 }}/>
                <div style={{ flex:1, minWidth:0 }}>
                  <div style={{ fontSize:13, color:"var(--txt)", lineHeight:1.6, overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{a.title}</div>
                  <div style={{ fontSize:13, color:"var(--txt3)", marginTop:2, display:"flex", gap:6 }}>
                    <span style={{ color:sc.text }}>{a.severity}</span>
                    <span>· {a.created_at?.slice(11,16)}</span>
                    {!a.is_read && <span style={{ color:"var(--accent-text)", fontWeight:700 }}>NEW</span>}
                  </div>
                </div>
              </div>
            );
          })}
          <button onClick={() => onNav("alerts")} style={{ marginTop:10, width:"100%", padding:"6px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>
            전체 알람 →
          </button>
        </div>
      ),
    },

    "repeat": {
      title: `반복 취약점 (${repeats.length}건)`,
      content: repeats.length === 0 ? (
        <div style={{ textAlign:"center", padding:"16px 0", color:"var(--txt3)", fontSize:12 }}>반복 취약점 없음 ✓</div>
      ) : (
        <div>
          {repeats.slice(0,4).map((f,i) => {
            const sc = SEV[f.severity]||SEV.info;
            return (
              <div key={f.id} style={{ padding:"8px 0", borderBottom:i<Math.min(repeats.length,4)-1?"1px solid var(--bdr)":"none", cursor:"pointer" }} onClick={() => onNav("findings")}>
                <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:3 }}>
                  <span style={{ padding:"2px 6px", borderRadius:3, fontSize:13, fontWeight:700, background:sc.bg, color:sc.text, border:`1px solid ${sc.bdr}` }}>{SEV_LBL[f.severity]}</span>
                  <span style={{ padding:"1px 5px", borderRadius:3, fontSize:13, fontWeight:700, background:"#2E1065", color:"#C4B5FD", border:"1px solid #6B21A8" }}>↺ {f.repeat_count}회</span>
                </div>
                <div style={{ fontSize:13, color:"var(--txt)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{f.title}</div>
                <div style={{ fontSize:13, color:"var(--txt3)", marginTop:2 }}>
                  <code style={{ color:"var(--accent-text)" }}>{f.asset_ip}</code> · {f.first_seen?.slice(0,10)}
                </div>
              </div>
            );
          })}
        </div>
      ),
    },

  };

  const isDragging = !!dragState.dragging;

  return (
    <div style={{ padding:"14px 20px" }}>
      {/* 2컬럼 레이아웃 */}
      <div style={{ display:"grid", gridTemplateColumns:"1.4fr 1fr", gap:14, alignItems:"start" }}>
        {/* 왼쪽 */}
        <div
          style={{ display:"flex", flexDirection:"column", gap:12 }}
          onDragEnter={(e) => { e.preventDefault(); if(!e.currentTarget.contains(e.relatedTarget)) onDragEnterCol("left"); }}
          onDragOver={(e) => e.preventDefault()}
        >
          {layout.left.filter(id => blocks[id]).map(id => (
            <Block key={id} id={id} title={blocks[id].title}
              dragState={dragState}
              onDragStart={onDragStart}
              onDragEnter={onDragEnterBlock}
              onDrop={onDrop}
            >
              {blocks[id].content}
            </Block>
          ))}
          {/* 왼쪽 컬럼 드롭존 */}
          <ColDropZone col="left" dragState={dragState} onDragEnter={onDragEnterCol} show={isDragging} />
        </div>

        {/* 오른쪽 */}
        <div
          style={{ display:"flex", flexDirection:"column", gap:12 }}
          onDragEnter={(e) => { e.preventDefault(); if(!e.currentTarget.contains(e.relatedTarget)) onDragEnterCol("right"); }}
          onDragOver={(e) => e.preventDefault()}
        >
          {layout.right.filter(id => blocks[id]).map(id => (
            <Block key={id} id={id} title={blocks[id].title}
              dragState={dragState}
              onDragStart={onDragStart}
              onDragEnter={onDragEnterBlock}
              onDrop={onDrop}
            >
              {blocks[id].content}
            </Block>
          ))}
          {/* 오른쪽 컬럼 드롭존 */}
          <ColDropZone col="right" dragState={dragState} onDragEnter={onDragEnterCol} show={isDragging} />
        </div>
      </div>
    </div>
  );
}
