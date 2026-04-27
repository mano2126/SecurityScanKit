import { useState, useEffect, useCallback } from "react";
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ── 상태 정의 ────────────────────────────────────────────────────
const ACTION_STATUS = {
  notified:    { label:"통보됨",   color:"#60A5FA", bg:"rgba(96,165,250,.12)" },
  in_progress: { label:"조치중",   color:"#FBBF24", bg:"rgba(251,191,36,.12)" },
  completed:   { label:"조치완료", color:"#4ADE80", bg:"rgba(74,222,128,.12)" },
  overdue:     { label:"기한초과", color:"#F87171", bg:"rgba(248,113,113,.12)" },
  pending:     { label:"발송대기", color:"#94A3B8", bg:"rgba(148,163,184,.12)" },
};
const SEND_STATUS = {
  sent:    { label:"발송완료", color:"#4ADE80" },
  failed:  { label:"발송실패", color:"#F87171" },
  pending: { label:"대기",     color:"#94A3B8" },
};


// ── 담당자 목록 테이블 (페이징·정렬·다중선택·상세보기) ──────────
function MgrTable({ managerRows, selRows, toggleRow, toggleAll, emailMap, setEmailMap, selManager, onSelectManager, onPreview, previewLoading }) {
  const [sort,    setSort]    = useState({ key:"total", asc:false });
  const [page,    setPage]    = useState(1);
  const [search,  setSearch]  = useState("");
  const PAGE_SIZE = 10;

  const SEV_ORD = {"critical":0,"high":1,"medium":2,"low":3};
  const SC = {"critical":"#F87171","high":"#FB923C","medium":"#FBBF24","low":"#4ADE80"};
  const SL = {"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험"};

  const filtered = managerRows.filter(r =>
    !search || r.name.includes(search) || r.dept.includes(search)
  );

  const sorted = [...filtered].sort((a,b)=>{
    let vA, vB;
    if      (sort.key==="name")     { vA=a.name;      vB=b.name; }
    else if (sort.key==="dept")     { vA=a.dept;      vB=b.dept; }
    else if (sort.key==="total")    { vA=a.findings.length; vB=b.findings.length; }
    else if (sort.key==="critical") { vA=a.findings.filter(f=>f.severity==="critical").length; vB=b.findings.filter(f=>f.severity==="critical").length; }
    else if (sort.key==="high")     { vA=a.findings.filter(f=>f.severity==="high").length; vB=b.findings.filter(f=>f.severity==="high").length; }
    else if (sort.key==="assets")   { vA=a.assets.length; vB=b.assets.length; }
    else { vA=a[sort.key]; vB=b[sort.key]; }
    if (typeof vA==="number") return sort.asc ? vA-vB : vB-vA;
    return sort.asc ? String(vA).localeCompare(String(vB)) : String(vB).localeCompare(String(vA));
  });

  const totalPages = Math.ceil(sorted.length / PAGE_SIZE);
  const paged = sorted.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);
  const pagedNames = paged.map(r=>r.name);
  const allPageSel = pagedNames.length>0 && pagedNames.every(n=>selRows.has(n));
  const somePageSel = pagedNames.some(n=>selRows.has(n));

  const togglePage = () => {
    if (allPageSel) { const n=new Set(selRows); pagedNames.forEach(nm=>n.delete(nm)); /* parent */ pagedNames.forEach(nm=>toggleRow(nm)); }
    else pagedNames.forEach(nm=>{ if(!selRows.has(nm)) toggleRow(nm); });
  };

  const Th = ({k, children, w}) => (
    <th onClick={()=>{ setSort(p=>({key:k,asc:p.key===k?!p.asc:true})); setPage(1); }}
      style={{ padding:"8px 10px", textAlign:"left", fontSize:9, fontWeight:700, whiteSpace:"nowrap",
        color:sort.key===k?"var(--accent-text)":"var(--txt3)", textTransform:"uppercase",
        letterSpacing:".05em", background:"var(--bg-card2)", borderBottom:"1px solid var(--bdr)",
        cursor:"pointer", userSelect:"none", width:w||"auto" }}>
      {children}{sort.key===k ? (sort.asc?" ▲":" ▼") : " ⇅"}
    </th>
  );

  return (
    <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:10, overflow:"hidden" }}>
      {/* 툴바 */}
      <div style={{ padding:"10px 14px", background:"var(--bg-card2)", borderBottom:"1px solid var(--bdr)",
        display:"flex", alignItems:"center", gap:8, flexWrap:"wrap" }}>
        <span style={{ fontSize:12, fontWeight:700, color:"var(--txt)" }}>담당자별 미조치 취약점</span>
        <span style={{ fontSize:10, padding:"1px 6px", borderRadius:8, background:"var(--bg-input)",
          border:"1px solid var(--bdr)", color:"var(--txt3)" }}>
          {filtered.length}명 / 총 {managerRows.reduce((s,r)=>s+r.findings.length,0)}건
        </span>
        {selRows.size>0 && (
          <span style={{ fontSize:10, padding:"1px 8px", borderRadius:8, fontWeight:700,
            background:"rgba(37,99,235,.15)", color:"var(--accent-text)", border:"1px solid rgba(37,99,235,.3)" }}>
            {selRows.size}명 선택
          </span>
        )}
        <div style={{ position:"relative", marginLeft:"auto" }}>
          <span style={{ position:"absolute",left:7,top:"50%",transform:"translateY(-50%)",fontSize:11,color:"var(--txt3)",pointerEvents:"none" }}>⌕</span>
          <input value={search} onChange={e=>{setSearch(e.target.value);setPage(1);}}
            placeholder="이름·부서 검색"
            style={{ padding:"5px 8px 5px 22px", borderRadius:6, border:"1px solid var(--bdr)",
              background:"var(--bg-input)", color:"var(--txt)", fontSize:11, outline:"none", width:150 }}/>
          {search && <span onClick={()=>setSearch("")} style={{ position:"absolute",right:7,top:"50%",transform:"translateY(-50%)",cursor:"pointer",color:"var(--txt3)",fontSize:11 }}>✕</span>}
        </div>
      </div>

      {/* 테이블 */}
      <div style={{ overflowX:"auto" }}>
        <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
          <thead><tr>
            <th style={{ padding:"8px 10px", width:36, background:"var(--bg-card2)", borderBottom:"1px solid var(--bdr)" }}>
              <div onClick={()=>{ pagedNames.forEach(nm=>{ if(allPageSel){ if(selRows.has(nm)) toggleRow(nm); } else { if(!selRows.has(nm)) toggleRow(nm); } }); }}
                style={{ width:14,height:14,borderRadius:3,cursor:"pointer",
                  border:`2px solid ${allPageSel?"var(--accent)":somePageSel?"var(--accent)":"var(--bdr2)"}`,
                  background:allPageSel?"var(--accent)":somePageSel?"rgba(37,99,235,.3)":"transparent",
                  display:"flex",alignItems:"center",justifyContent:"center" }}>
                {allPageSel && <span style={{ color:"#fff",fontSize:8,fontWeight:700 }}>✓</span>}
                {!allPageSel && somePageSel && <span style={{ color:"var(--accent-text)",fontSize:7,fontWeight:700 }}>−</span>}
              </div>
            </th>
            <Th k="name"     w="100px">담당자</Th>
            <Th k="dept"     w="80px">부서</Th>
            <Th k="total"    w="55px">전체</Th>
            <Th k="critical" w="45px">긴급</Th>
            <Th k="high"     w="55px">고위험</Th>
            <Th k="assets"   w="50px">자산수</Th>
            <th style={{ padding:"8px 10px", fontSize:9, fontWeight:700, color:"var(--txt3)",
              textTransform:"uppercase", letterSpacing:".05em", background:"var(--bg-card2)",
              borderBottom:"1px solid var(--bdr)" }}>수신 이메일</th>
            <th style={{ padding:"8px 10px", width:60, background:"var(--bg-card2)", borderBottom:"1px solid var(--bdr)" }}></th>
          </tr></thead>
          <tbody>
            {paged.length===0 ? (
              <tr><td colSpan={8} style={{ textAlign:"center", padding:"40px", color:"var(--txt3)", fontSize:12 }}>
                미조치 취약점이 있는 담당자가 없습니다
              </td></tr>
            ) : paged.map((row,i)=>{
              const isSel  = selRows.has(row.name);
              const isAct  = selManager===row.name;
              const crit   = row.findings.filter(f=>f.severity==="critical").length;
              const high   = row.findings.filter(f=>f.severity==="high").length;
              const rColor = crit>0?"#F87171":high>0?"#FB923C":"#FBBF24";
              return (<>
                {/* ─ 담당자 행 ─ */}
                <tr key={row.name}
                  onClick={()=>onSelectManager(isAct?"":(row.name))}
                  style={{ borderBottom:"1px solid var(--bdr)", cursor:"pointer", transition:"background .1s",
                    background:isAct?"rgba(37,99,235,.06)":isSel?"rgba(37,99,235,.04)":i%2===0?"transparent":"var(--bg-card2)" }}
                  onMouseEnter={e=>{ if(!isAct) e.currentTarget.style.background="var(--bg-hover)"; }}
                  onMouseLeave={e=>{ if(!isAct) e.currentTarget.style.background=isAct?"rgba(37,99,235,.06)":isSel?"rgba(37,99,235,.04)":i%2===0?"transparent":"var(--bg-card2)"; }}>
                  <td style={{ padding:"8px 10px" }} onClick={e=>{e.stopPropagation();toggleRow(row.name);}}>
                    <div style={{ width:14,height:14,borderRadius:3,cursor:"pointer",
                      border:`2px solid ${isSel?"var(--accent)":"var(--bdr2)"}`,
                      background:isSel?"var(--accent)":"transparent",
                      display:"flex",alignItems:"center",justifyContent:"center" }}>
                      {isSel && <span style={{ color:"#fff",fontSize:8,fontWeight:700 }}>✓</span>}
                    </div>
                  </td>
                  <td style={{ padding:"8px 10px" }}>
                    <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                      <span style={{ fontWeight:700, color:isAct?"var(--accent-text)":"var(--txt)" }}>{row.name}</span>
                      <span style={{ fontSize:9, color:"var(--txt3)", transition:"transform .15s",
                        transform:isAct?"rotate(90deg)":"rotate(0)", display:"inline-block" }}>▶</span>
                    </div>
                  </td>
                  <td style={{ padding:"8px 10px", color:"var(--txt3)" }}>{row.dept||"—"}</td>
                  <td style={{ padding:"8px 10px", fontWeight:700, color:rColor }}>{row.findings.length}</td>
                  <td style={{ padding:"8px 10px", color:crit>0?"#F87171":"var(--txt3)", fontWeight:crit>0?700:400 }}>{crit||"—"}</td>
                  <td style={{ padding:"8px 10px", color:high>0?"#FB923C":"var(--txt3)", fontWeight:high>0?700:400 }}>{high||"—"}</td>
                  <td style={{ padding:"8px 10px", color:"var(--txt3)", textAlign:"center" }}>{row.assets.length}</td>
                  <td style={{ padding:"6px 10px" }} onClick={e=>e.stopPropagation()}>
                    <input value={emailMap[row.name]||""} onChange={e=>setEmailMap(p=>({...p,[row.name]:e.target.value}))}
                      placeholder="이메일"
                      style={{ width:"100%", minWidth:150, padding:"4px 7px", borderRadius:5,
                        border:`1px solid ${isSel&&!emailMap[row.name]?"rgba(248,113,113,.5)":"var(--bdr)"}`,
                        background:"var(--bg-input)", color:"var(--txt)", fontSize:11, outline:"none" }}/>
                  </td>
                  <td style={{ padding:"6px 8px" }} onClick={e=>e.stopPropagation()}>
                    <button
                      onClick={()=>onPreview && onPreview(row.name, row.dept, row.assets.map(a=>a.id))}
                      disabled={previewLoading}
                      title="발송 메일 미리보기"
                      style={{ padding:"4px 8px", borderRadius:5, whiteSpace:"nowrap",
                        border:"1px solid rgba(251,191,36,.4)", background:"rgba(251,191,36,.08)",
                        color:"#FBBF24", fontSize:10, fontWeight:600,
                        cursor:previewLoading?"wait":"pointer",
                        display:"flex", alignItems:"center", gap:3 }}>
                      👁 발송 메일 미리보기
                    </button>
                  </td>
                </tr>


              </>);
            })}
          </tbody>
        </table>
      </div>

      {/* 페이지네이션 */}
      <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between",
        padding:"8px 14px", borderTop:"1px solid var(--bdr)", background:"var(--bg-card2)" }}>
        <span style={{ fontSize:11, color:"var(--txt3)" }}>
          {filtered.length}명
          {selRows.size>0 && <span style={{ color:"var(--accent-text)", fontWeight:700, marginLeft:6 }}>/ {selRows.size}명 선택</span>}
        </span>
        {totalPages>1 && (
          <div style={{ display:"flex", gap:3 }}>
            {["«","‹",...Array.from({length:totalPages},(_,i)=>String(i+1)),"›","»"].map((lbl,idx)=>{
              const pg = lbl==="«"?1:lbl==="‹"?page-1:lbl==="›"?page+1:lbl==="»"?totalPages:Number(lbl);
              if (pg<1||pg>totalPages) return null;
              return (
                <button key={idx} onClick={()=>setPage(pg)}
                  style={{ padding:"3px 8px", borderRadius:4, fontSize:11, cursor:"pointer",
                    border:`1px solid ${pg===page?"var(--accent)":"var(--bdr)"}`,
                    background:pg===page?"var(--accent)":"transparent",
                    color:pg===page?"#fff":"var(--txt3)" }}>
                  {lbl}
                </button>
              );
            })}
          </div>
        )}
        <span style={{ fontSize:10, color:"var(--txt3)" }}>페이지당 {PAGE_SIZE}명</span>
      </div>
    </div>
  );
}

export default function PageNotify({ onNav }) {
  const [tab,      setTab]      = useState("send");   // send | history | settings
  const [assets,   setAssets]   = useState([]);
  const [findings, setFindings] = useState([]);
  const [history,  setHistory]  = useState([]);
  const [summary,  setSummary]  = useState({});
  const [loading,  setLoading]  = useState(false);
  const [msg,      setMsg]      = useState(null);

  // SMTP 설정 (로컬 저장)
  const [smtp, setSmtp] = useState(() => {
    try { return JSON.parse(localStorage.getItem("ssk_smtp_cfg")||"{}"); } catch { return {}; }
  });
  const [testResult, setTestResult] = useState(null);
  const [testing,    setTesting]    = useState(false);

  // ── 발신자 정보 (보내는 사람: 관리자/IT보안팀)
  const [senderName,  setSenderName]  = useState(() => localStorage.getItem("ssk_sender_name")||"IT보안팀");
  const [senderEmail, setSenderEmail] = useState(() => localStorage.getItem("ssk_sender_email")||"");
  const [dueDays,     setDueDays]     = useState(7);

  // ── 수신자 (담당자별 이메일 + 선택)
  const [emailMap,    setEmailMap]    = useState({});  // manager명 → 수신 이메일
  const [selRows,     setSelRows]     = useState(new Set()); // 선택된 수신자
  const [selManager,  setSelManager]  = useState("");  // 상세 보기용
  const [preview,     setPreview]     = useState(null);

  // ── 발송 상태
  const [sending,     setSending]     = useState(false); // 개별 발송 (미사용, 하위호환)
  const [bulkSending, setBulkSending] = useState(false);
  const [bulkResults, setBulkResults] = useState([]);

  // ── 기타 (하위호환용 — 실제 미사용)
  const [selEmail,    setSelEmail]    = useState("");
  const [selDept,     setSelDept]     = useState("");
  const [selAssets,   setSelAssets]   = useState([]);

  // 메일 미리보기 모달
  const [previewModal,     setPreviewModal]     = useState(null); // {manager, html, finding_count}
  const [previewLoading,   setPreviewLoading]   = useState(false);

  // 조치 완료 모달
  const [actionModal, setActionModal] = useState(null);
  const [actionNote,  setActionNote]  = useState("");

  const load = useCallback(async () => {
    try {
      const [a, f, h, s] = await Promise.all([
        fetch(`${API_BASE}/api/assets`).then(r=>r.json()),
        fetch(`${API_BASE}/api/findings?status=open&limit=500`).then(r=>r.json()),
        fetch(`${API_BASE}/api/notifications`).then(r=>r.json()),
        fetch(`${API_BASE}/api/notifications/summary`).then(r=>r.json()),
      ]);
      setAssets(Array.isArray(a)?a:a.items||[]);
      setFindings(Array.isArray(f)?f:f.items||[]);
      setHistory(Array.isArray(h)?h:[]);
      setSummary(s||{});
    } catch(e) { console.error(e); }
  }, []);

  useEffect(() => { load(); }, [load]);

  // 담당자별 취약점 집계
  const managerRows = (() => {
    const map = {};
    for (const a of assets) {
      if (!a.manager) continue;
      if (!map[a.manager]) map[a.manager] = { name:a.manager, dept:a.department||"", assets:[], findings:[] };
      map[a.manager].assets.push(a);
    }
    for (const f of findings) {
      const a = assets.find(x=>x.id===f.asset_id);
      if (a?.manager && map[a.manager]) map[a.manager].findings.push(f);
    }
    return Object.values(map).filter(m=>m.findings.length>0)
      .sort((a,b)=>{
        const cA = a.findings.filter(f=>f.severity==="critical").length;
        const cB = b.findings.filter(f=>f.severity==="critical").length;
        if (cB!==cA) return cB-cA;
        return b.findings.length-a.findings.length;
      });
  })();

  // 수신자 행 클릭 → 오른쪽 상세 표시 + 이메일 자동 로드
  const onSelectManager = (name) => {
    setSelManager(prev => prev===name ? "" : name);
    const row = managerRows.find(m=>m.name===name);
    setPreview(row?.findings||[]);

    // 이미 이메일이 입력돼 있으면 유지
    if (emailMap[name]) return;

    // 1순위: 자산의 manager 이메일 필드 (assets 테이블)
    const assetEmail = row?.assets?.find(a=>a.manager_email)?.manager_email;
    if (assetEmail) { setEmailMap(p=>({...p,[name]:assetEmail})); return; }

    // 2순위: 관리자 사용자 목록 (localStorage ssk_users)
    try {
      const sysUsers = JSON.parse(localStorage.getItem("ssk_users")||"[]");
      const found = sysUsers.find(u=>u.name===name || u.name?.trim()===name?.trim());
      if (found?.email) setEmailMap(p=>({...p,[name]:found.email}));
    } catch {}
  };

  // 수신자 체크박스 토글
  const toggleRow = (name) => {
    setSelRows(p=>{ const n=new Set(p); n.has(name)?n.delete(name):n.add(name); return n; });
  };
  const toggleAll = () => {
    if (selRows.size===managerRows.length) setSelRows(new Set());
    else setSelRows(new Set(managerRows.map(m=>m.name)));
  };

  // 일괄 발송 — 선택된 수신자에게 각자 취약점 메일 발송
  const onBulkSend = async () => {
    if (selRows.size===0) { setMsg({ok:false,text:"수신자를 선택하세요"}); return; }
    if (!smtp.host) { setMsg({ok:false,text:"SMTP 설정 탭에서 서버 정보를 입력하세요"}); return; }
    const missing = [...selRows].filter(m=>!emailMap[m]);
    const sendable = [...selRows].filter(m=>emailMap[m]);
    if (sendable.length===0) { setMsg({ok:false,text:`수신 이메일 미입력: ${missing.join(", ")}`}); return; }
    // 발신자 이메일 설정
    const smtpWithSender = { ...smtp, from: senderEmail||smtp.from||smtp.user };
    setBulkSending(true); setBulkResults([]); setMsg(null);
    const results = [];
    for (const mgrName of sendable) {
      const row = managerRows.find(m=>m.name===mgrName);
      if (!row) continue;
      try {
        const r = await fetch(`${API_BASE}/api/notifications/send`, {
          method:"POST", headers:{"Content-Type":"application/json"},
          body: JSON.stringify({
            manager: mgrName, email: emailMap[mgrName], department: row.dept,
            asset_ids: row.assets.map(a=>a.id), due_days: dueDays, smtp: smtpWithSender, sent_by: senderName||"IT보안팀"
          })
        }).then(r=>r.json());
        results.push({ manager:mgrName, ok:r.ok, error:r.error||"", count:r.finding_count||0 });
      } catch(e) {
        results.push({ manager:mgrName, ok:false, error:e.message, count:0 });
      }
    }
    setBulkResults(results);
    const ok = results.filter(r=>r.ok).length;
    setMsg({ok:ok>0, text:`${ok}/${results.length}명 발송 완료`});
    setBulkSending(false);
    await load();
    if (ok>0) setTimeout(()=>setTab("history"),1500);
  };

  // 메일 미리보기
  const onPreview = async (mgrName, dept, assetIds) => {
    setPreviewLoading(true);
    try {
      const r = await fetch(`${API_BASE}/api/notifications/preview`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ manager:mgrName, department:dept, asset_ids:assetIds, due_days:dueDays })
      }).then(r=>r.json());
      if (r.html) setPreviewModal({ manager:mgrName, html:r.html, finding_count:r.finding_count, critical_count:r.critical_count });
      else setMsg({ok:false, text:r.detail||"미리보기 생성 실패"});
    } catch(e) { setMsg({ok:false, text:e.message}); }
    setPreviewLoading(false);
  };

  // SMTP 저장
  const saveSmtp = () => {
    localStorage.setItem("ssk_smtp_cfg", JSON.stringify(smtp));
    setMsg({ok:true, text:"SMTP 설정이 저장되었습니다"});
    setTimeout(()=>setMsg(null),2000);
  };

  // SMTP 테스트
  const testSmtp = async () => {
    setTesting(true); setTestResult(null);
    try {
      const r = await fetch(`${API_BASE}/api/notifications/test-smtp`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify(smtp)
      }).then(r=>r.json());
      setTestResult(r);
    } catch(e) { setTestResult({ok:false,error:e.message}); }
    setTesting(false);
  };

  // 발송
  const onSend = async () => {
    if (!selManager) { setMsg({ok:false,text:"담당자를 선택하세요"}); return; }
    if (!selEmail)   { setMsg({ok:false,text:"수신 이메일을 입력하세요"}); return; }
    if (!smtp.host)  { setMsg({ok:false,text:"SMTP 설정을 먼저 입력하세요 (설정 탭)"}); return; }
    setSending(true); setMsg(null);
    try {
      const r = await fetch(`${API_BASE}/api/notifications/send`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({
          manager: selManager, email: selEmail, department: selDept,
          asset_ids: selAssets, due_days: dueDays, smtp: {...smtp, from: senderEmail||smtp.from||smtp.user}, sent_by: senderName||"IT보안팀"
        })
      }).then(r=>r.json());
      if (r.ok) {
        setMsg({ok:true, text:`✅ ${selManager} (${selEmail}) 에게 발송 완료 — 취약점 ${r.finding_count}건`});
        await load();
        setTab("history");
      } else {
        setMsg({ok:false, text:`❌ 발송 실패: ${r.error||r.detail||"알 수 없는 오류"}`});
      }
    } catch(e) { setMsg({ok:false,text:`❌ ${e.message}`}); }
    setSending(false);
  };

  // 조치 완료 처리
  const onActionComplete = async (notifId, status) => {
    try {
      await fetch(`${API_BASE}/api/notifications/${notifId}/action`, {
        method:"PATCH", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({action_status: status, action_note: actionNote, completed_by:"admin"})
      });
      setActionModal(null); setActionNote("");
      await load();
    } catch(e) { alert(e.message); }
  };

  // 삭제
  const onDelete = async (id) => {
    if (!window.confirm("이 통보 이력을 삭제하시겠습니까?")) return;
    await fetch(`${API_BASE}/api/notifications/${id}`, {method:"DELETE"});
    await load();
  };

  const IS = { width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
    background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" };

  const TABS = [
    { id:"send",     icon:"📤", label:"통보 발송" },
    { id:"history",  icon:"📋", label:"발송 이력 · 조치 현황" },
    { id:"settings", icon:"⚙",  label:"SMTP 설정" },
  ];

  return (
    <div style={{ padding:"18px 22px" }}>
      {/* 헤더 */}
      <div style={{ marginBottom:16,display:"flex",alignItems:"center",gap:12 }}>
        <div style={{ width:40,height:40,borderRadius:10,background:"rgba(37,99,235,.1)",border:"1px solid rgba(37,99,235,.2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20 }}>📨</div>
        <div>
          <div style={{ fontSize:16,fontWeight:700,color:"var(--txt)" }}>보안 조치 통보 센터</div>
          <div style={{ fontSize:11,color:"var(--txt3)" }}>담당자별 취약점 통보 발송 · 조치 이행 추적 · 완료 확인</div>
        </div>
      </div>

      {/* KPI */}
      <div style={{ display:"grid",gridTemplateColumns:"repeat(5,1fr)",gap:8,marginBottom:16 }}>
        {[
          {l:"전체 발송",  v:summary.total||0,     c:"var(--accent-text)"},
          {l:"통보됨",     v:summary.notified||0,   c:"#60A5FA"},
          {l:"조치중",     v:summary.in_progress||0,c:"#FBBF24"},
          {l:"완료",       v:summary.completed||0,  c:"#4ADE80"},
          {l:"기한초과",   v:summary.overdue||0,    c:"#F87171"},
        ].map(k=>(
          <div key={k.l} style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:8,padding:"10px 12px" }}>
            <div style={{ fontSize:9,color:"var(--txt3)",marginBottom:3 }}>{k.l}</div>
            <div style={{ fontSize:20,fontWeight:700,color:k.c }}>{k.v}</div>
          </div>
        ))}
      </div>

      {/* 탭 */}
      <div style={{ display:"flex",gap:0,background:"var(--bg-card2)",borderRadius:8,padding:3,border:"1px solid var(--bdr)",marginBottom:14,width:"fit-content" }}>
        {TABS.map(tb=>(
          <button key={tb.id} onClick={()=>setTab(tb.id)}
            style={{ padding:"7px 16px",borderRadius:6,border:"none",cursor:"pointer",fontSize:12,
              fontWeight:tab===tb.id?700:400,
              background:tab===tb.id?"var(--bg-active)":"transparent",
              color:tab===tb.id?"var(--accent-text)":"var(--txt3)",
              display:"flex",alignItems:"center",gap:5 }}>
            {tb.icon} {tb.label}
          </button>
        ))}
      </div>

      {/* 메시지 */}
      {msg && (
        <div style={{ marginBottom:12,padding:"9px 14px",borderRadius:7,
          background:msg.ok?"rgba(22,163,74,.08)":"rgba(220,38,38,.08)",
          border:`1px solid ${msg.ok?"rgba(22,163,74,.25)":"rgba(220,38,38,.25)"}`,
          fontSize:12,color:msg.ok?"#4ADE80":"#F87171",display:"flex",justifyContent:"space-between",alignItems:"center" }}>
          {msg.text}
          <button onClick={()=>setMsg(null)} style={{ background:"none",border:"none",cursor:"pointer",color:"inherit",fontSize:14 }}>✕</button>
        </div>
      )}

      {/* ══ 발송 탭 ══ */}
      {tab==="send" && (
        <div style={{ display:"grid", gridTemplateColumns:"380px 1fr", gap:14, alignItems:"start" }}>

          {/* ══ 왼쪽: 발신 설정 + 상세 ══ */}
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>

            {/* 발신자 정보 */}
            <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:10, padding:"14px 16px" }}>
              <div style={{ fontSize:11, fontWeight:700, color:"var(--txt)", marginBottom:10,
                paddingBottom:7, borderBottom:"1px solid var(--bdr)" }}>
                📤 통보 발송
              </div>
              <div style={{ display:"flex", flexDirection:"column", gap:8 }}>
                <div>
                  <label style={{ fontSize:9,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>발신자 이름</label>
                  <input value={senderName} onChange={e=>{ setSenderName(e.target.value); localStorage.setItem("ssk_sender_name",e.target.value); }}
                    placeholder="IT보안팀"
                    style={{ width:"100%",padding:"6px 9px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt)",fontSize:11,outline:"none" }}/>
                </div>
                <div>
                  <label style={{ fontSize:9,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>발신자 이메일</label>
                  <input value={senderEmail} onChange={e=>{ setSenderEmail(e.target.value); localStorage.setItem("ssk_sender_email",e.target.value); }}
                    placeholder="security@company.com"
                    style={{ width:"100%",padding:"6px 9px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt)",fontSize:11,outline:"none" }}/>
                  <div style={{ fontSize:9,color:"var(--txt3)",marginTop:2 }}>비어있으면 SMTP 계정으로 발송</div>
                </div>
                <div>
                  <label style={{ fontSize:9,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>조치 기한</label>
                  <div style={{ display:"flex", gap:4 }}>
                    {[3,7,14,30].map(d=>(
                      <button key={d} onClick={()=>setDueDays(d)}
                        style={{ flex:1, padding:"5px 0", borderRadius:5, fontSize:11, cursor:"pointer",
                          border:`1px solid ${dueDays===d?"var(--accent)":"var(--bdr)"}`,
                          background:dueDays===d?"var(--bg-active)":"transparent",
                          color:dueDays===d?"var(--accent-text)":"var(--txt3)", fontWeight:dueDays===d?700:400 }}>
                        {d}일
                      </button>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* 선택된 수신자 취약점 상세 */}
            {selManager && preview ? (
              <>
              <div style={{ background:"var(--bg-card)", border:"1px solid rgba(37,99,235,.25)", borderRadius:10, overflow:"hidden" }}>
                <div style={{ padding:"9px 14px", background:"rgba(37,99,235,.06)", borderBottom:"1px solid rgba(37,99,235,.15)" }}>
                  <div style={{ fontSize:11,fontWeight:700,color:"var(--accent-text)" }}>📋 {selManager}</div>
                  <div style={{ fontSize:9,color:"var(--txt3)",marginTop:1 }}>
                    {managerRows.find(m=>m.name===selManager)?.dept} · 미조치 {preview.length}건
                  </div>
                </div>
                {/* KPI 4개 */}
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",borderBottom:"1px solid var(--bdr)" }}>
                  {[
                    {l:"전체",   v:preview.length,                                    c:"var(--accent-text)",bg:"transparent"},
                    {l:"긴급",   v:preview.filter(f=>f.severity==="critical").length, c:"#F87171",bg:"rgba(248,113,113,.05)"},
                    {l:"고위험", v:preview.filter(f=>f.severity==="high").length,     c:"#FB923C",bg:"rgba(251,146,60,.05)"},
                    {l:"반복",   v:preview.filter(f=>(f.repeat_count||0)>0).length,   c:"#FBBF24",bg:"rgba(251,191,36,.05)"},
                  ].map((k,i)=>(
                    <div key={k.l} style={{ padding:"8px 0",textAlign:"center",background:k.bg,
                      borderRight:i<3?"1px solid var(--bdr)":"none" }}>
                      <div style={{ fontSize:18,fontWeight:700,color:k.c }}>{k.v}</div>
                      <div style={{ fontSize:9,color:"var(--txt3)",textTransform:"uppercase",marginTop:1 }}>{k.l}</div>
                    </div>
                  ))}
                </div>
                {/* 취약점 리스트 */}
                <div style={{ overflowY:"auto", maxHeight:260 }}>
                  <table style={{ width:"100%",borderCollapse:"collapse",fontSize:10 }}>
                    <thead><tr style={{ background:"var(--bg-card2)",position:"sticky",top:0 }}>
                      {["취약점명","심각도","자산","반복"].map(h=>(
                        <th key={h} style={{ padding:"5px 9px",fontSize:9,fontWeight:700,textAlign:"left",
                          color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".04em",
                          borderBottom:"1px solid var(--bdr)",whiteSpace:"nowrap" }}>{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {(()=>{
                        const ORD={"critical":0,"high":1,"medium":2,"low":3};
                        const SC={"critical":"#F87171","high":"#FB923C","medium":"#FBBF24","low":"#4ADE80"};
                        const SL={"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험"};
                        return [...preview].sort((a,b)=>(ORD[a.severity]||9)-(ORD[b.severity]||9)).map((f,i)=>(
                          <tr key={f.id} style={{ borderBottom:"1px solid var(--bdr)",
                            background:i%2===0?"transparent":"var(--bg-card2)" }}>
                            <td style={{ padding:"5px 9px",color:"var(--txt)",fontWeight:500,maxWidth:130 }}>
                              <div style={{ overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{f.title}</div>
                            </td>
                            <td style={{ padding:"5px 9px" }}>
                              <span style={{ fontSize:9,padding:"1px 5px",borderRadius:4,fontWeight:700,
                                color:SC[f.severity]||"#94A3B8",background:`${SC[f.severity]||"#94A3B8"}18` }}>
                                {SL[f.severity]||f.severity}
                              </span>
                            </td>
                            <td style={{ padding:"5px 9px",color:"var(--txt3)",whiteSpace:"nowrap",fontSize:10 }}>{f.asset_name||"—"}</td>
                            <td style={{ padding:"5px 9px",textAlign:"center",fontSize:10,
                              color:(f.repeat_count||0)>0?"#FB923C":"var(--txt3)",
                              fontWeight:(f.repeat_count||0)>0?700:400 }}>
                              {(f.repeat_count||0)>0?`${f.repeat_count}회`:"—"}
                            </td>
                          </tr>
                        ));
                      })()}
                    </tbody>
                  </table>
                </div>
              </div>

              </>
            ) : (
              <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,
                padding:"30px 16px",textAlign:"center",color:"var(--txt3)" }}>
                <div style={{ fontSize:28,marginBottom:6,opacity:.3 }}>👉</div>
                <div style={{ fontSize:11 }}>오른쪽에서 수신자를<br/>클릭하면 취약점이 표시됩니다</div>
              </div>
            )}

            {/* 일괄 발송 버튼 */}
            {selRows.size>0 && (
              <div style={{ background:"var(--bg-card)", border:"1px solid rgba(37,99,235,.25)", borderRadius:10, padding:"12px 14px" }}>
                <div style={{ fontSize:11, fontWeight:700, color:"var(--txt)", marginBottom:5 }}>
                  📮 발송 대상 ({selRows.size}명)
                </div>
                <div style={{ fontSize:10, color:"var(--txt3)", marginBottom:6, lineHeight:1.6 }}>
                  {[...selRows].join(", ")}
                </div>
                {[...selRows].some(m=>!emailMap[m]) && (
                  <div style={{ fontSize:10,color:"#F87171",marginBottom:6 }}>
                    ⚠ 수신 이메일 미입력: {[...selRows].filter(m=>!emailMap[m]).join(", ")}
                  </div>
                )}
                <button onClick={onBulkSend} disabled={bulkSending}
                  style={{ width:"100%",padding:"9px",borderRadius:7,fontWeight:700,fontSize:12,cursor:"pointer",
                    border:`1.5px solid ${bulkSending?"var(--bdr)":"var(--accent)"}`,
                    background:bulkSending?"var(--bg-card2)":"var(--bg-active)",
                    color:bulkSending?"var(--txt3)":"var(--accent-text)",
                    display:"flex",alignItems:"center",justifyContent:"center",gap:6 }}>
                  {bulkSending
                    ? <><span style={{ width:12,height:12,borderRadius:"50%",border:"2px solid var(--accent)",borderTopColor:"transparent",animation:"spin .8s linear infinite",display:"inline-block" }}/> 발송 중...</>
                    : `📤 ${selRows.size}명에게 일괄 발송`}
                </button>
                {bulkResults.length>0 && (
                  <div style={{ marginTop:8,display:"flex",flexDirection:"column",gap:3 }}>
                    {bulkResults.map(r=>(
                      <div key={r.manager} style={{ fontSize:10,padding:"3px 8px",borderRadius:4,
                        color:r.ok?"#4ADE80":"#F87171",
                        background:r.ok?"rgba(22,163,74,.08)":"rgba(220,38,38,.08)" }}>
                        {r.ok?`✓ ${r.manager} (${r.count}건 발송)`:`✗ ${r.manager}: ${r.error?.slice(0,30)}`}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>

          {/* ══ 오른쪽: 수신자 목록 (페이징·정렬·다중선택) ══ */}
          <MgrTable
            managerRows={managerRows}
            selRows={selRows}
            toggleRow={toggleRow}
            toggleAll={toggleAll}
            emailMap={emailMap}
            setEmailMap={setEmailMap}
            selManager={selManager}
            onSelectManager={onSelectManager}
            onPreview={onPreview}
            previewLoading={previewLoading}
          />
        </div>
      )}
      {/* ══ 이력 탭 ══ */}
      {tab==="history" && (
        <div>
          {history.length===0 ? (
            <div style={{ textAlign:"center",padding:"60px 0",color:"var(--txt3)" }}>
              <div style={{ fontSize:36,marginBottom:8,opacity:.3 }}>📭</div>
              <div style={{ fontSize:13 }}>발송 이력이 없습니다</div>
            </div>
          ) : (
            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,overflow:"hidden" }}>
              <table style={{ width:"100%",borderCollapse:"collapse",fontSize:11 }}>
                <thead><tr style={{ background:"var(--bg-card2)" }}>
                  {["담당자","부서","취약점","발송 상태","발송 일시","조치 상태","기한","액션"].map(h=>(
                    <th key={h} style={{ padding:"8px 10px",textAlign:"left",fontSize:9,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",borderBottom:"1px solid var(--bdr)" }}>{h}</th>
                  ))}
                </tr></thead>
                <tbody>
                  {history.map((n,i)=>{
                    const as = ACTION_STATUS[n.action_status]||ACTION_STATUS.notified;
                    const ss = SEND_STATUS[n.status]||SEND_STATUS.pending;
                    const overdue = n.action_due_date && new Date(n.action_due_date)<new Date() && n.action_status!=="completed";
                    return (
                      <tr key={n.id} style={{ borderBottom:"1px solid var(--bdr)",background:i%2===0?"transparent":"var(--bg-card2)" }}>
                        <td style={{ padding:"8px 10px",fontWeight:600,color:"var(--txt)" }}>
                          <div>{n.manager}</div>
                          <div style={{ fontSize:10,color:"var(--txt3)" }}>{n.manager_email}</div>
                        </td>
                        <td style={{ padding:"8px 10px",color:"var(--txt3)" }}>{n.department||"—"}</td>
                        <td style={{ padding:"8px 10px",textAlign:"center" }}>
                          <span style={{ fontWeight:700,color:n.critical_count>0?"#F87171":"var(--txt)" }}>{n.finding_count}건</span>
                          {n.critical_count>0 && <div style={{ fontSize:9,color:"#F87171" }}>긴급 {n.critical_count}건</div>}
                        </td>
                        <td style={{ padding:"8px 10px" }}>
                          <span style={{ fontSize:10,padding:"2px 8px",borderRadius:8,fontWeight:700,color:ss.color,
                            background:`${ss.color}15`,border:`1px solid ${ss.color}33` }}>{ss.label}</span>
                          {n.error_msg && <div style={{ fontSize:9,color:"#F87171",marginTop:2 }}>{n.error_msg.slice(0,40)}</div>}
                        </td>
                        <td style={{ padding:"8px 10px",color:"var(--txt3)",fontSize:10,whiteSpace:"nowrap" }}>
                          {n.sent_at ? new Date(n.sent_at).toLocaleString("ko-KR",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"}) : "—"}
                        </td>
                        <td style={{ padding:"8px 10px" }}>
                          <span style={{ fontSize:10,padding:"2px 8px",borderRadius:8,fontWeight:700,
                            color:overdue?"#F87171":as.color,
                            background:overdue?"rgba(248,113,113,.12)":as.bg,
                            border:`1px solid ${overdue?"rgba(248,113,113,.3)":as.color}33` }}>
                            {overdue ? "⚠ 기한초과" : as.label}
                          </span>
                          {n.action_note && <div style={{ fontSize:9,color:"var(--txt3)",marginTop:2 }}>{n.action_note.slice(0,30)}</div>}
                        </td>
                        <td style={{ padding:"8px 10px",color:overdue?"#F87171":"var(--txt3)",fontSize:10,whiteSpace:"nowrap" }}>
                          {n.action_due_date ? new Date(n.action_due_date).toLocaleDateString("ko-KR") : "—"}
                        </td>
                        <td style={{ padding:"8px 10px" }}>
                          <div style={{ display:"flex",gap:4,flexWrap:"wrap" }}>
                            {n.action_status!=="completed" && (
                              <button onClick={()=>{ setActionModal(n); setActionNote(n.action_note||""); }}
                                style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(74,222,128,.4)",background:"rgba(74,222,128,.1)",color:"#4ADE80",fontSize:10,fontWeight:600,cursor:"pointer" }}>
                                ✓ 조치완료
                              </button>
                            )}
                            {n.action_status==="notified" && (
                              <button onClick={()=>onActionComplete(n.id,"in_progress")}
                                style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(251,191,36,.4)",background:"rgba(251,191,36,.1)",color:"#FBBF24",fontSize:10,cursor:"pointer" }}>
                                조치중
                              </button>
                            )}
                            <button onClick={()=>onDelete(n.id)}
                              style={{ padding:"3px 7px",borderRadius:4,border:"1px solid rgba(220,38,38,.3)",background:"transparent",color:"#F87171",fontSize:10,cursor:"pointer" }}>
                              🗑
                            </button>
                          </div>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ══ SMTP 설정 탭 ══ */}
      {tab==="settings" && (
        <div style={{ display:"grid",gridTemplateColumns:"420px 1fr",gap:14 }}>
          <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"18px" }}>
            <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:14,paddingBottom:8,borderBottom:"1px solid var(--bdr)" }}>
              ⚙ SMTP 서버 설정 (Exchange/Office365)
            </div>
            <div style={{ display:"flex",flexDirection:"column",gap:9 }}>
              {[
                {k:"host",     l:"SMTP 서버 주소 *",  ph:"smtp.office365.com"},
                {k:"port",     l:"포트 *",            ph:"587"},
                {k:"user",     l:"계정 (이메일)",       ph:"security@company.com"},
                {k:"password", l:"비밀번호",            ph:"••••••••", type:"password"},
                {k:"from",     l:"발신자 표시명",        ph:"IT보안팀 <security@company.com>"},
              ].map(f=>(
                <div key={f.k}>
                  <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>{f.l}</label>
                  <input type={f.type||"text"} value={smtp[f.k]||""} onChange={e=>setSmtp(p=>({...p,[f.k]:e.target.value}))}
                    placeholder={f.ph} style={IS}/>
                </div>
              ))}
              <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                <input type="checkbox" id="tls_chk" checked={smtp.use_tls!==false}
                  onChange={e=>setSmtp(p=>({...p,use_tls:e.target.checked}))}/>
                <label htmlFor="tls_chk" style={{ fontSize:12,color:"var(--txt)",cursor:"pointer" }}>STARTTLS 사용 (권장)</label>
              </div>
              <div style={{ display:"flex",gap:6 }}>
                <button onClick={saveSmtp}
                  style={{ flex:1,padding:"8px",borderRadius:6,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:12,fontWeight:700,cursor:"pointer" }}>
                  저장
                </button>
                <button onClick={testSmtp} disabled={testing||!smtp.host}
                  style={{ flex:1,padding:"8px",borderRadius:6,border:"1px solid var(--bdr2)",background:"transparent",color:"var(--txt3)",fontSize:12,cursor:testing||!smtp.host?"not-allowed":"pointer" }}>
                  {testing ? "테스트 중..." : "🔌 연결 테스트"}
                </button>
              </div>
              {testResult && (
                <div style={{ padding:"8px 10px",borderRadius:6,fontSize:11,
                  background:testResult.ok?"rgba(22,163,74,.08)":"rgba(220,38,38,.08)",
                  color:testResult.ok?"#4ADE80":"#F87171",
                  border:`1px solid ${testResult.ok?"rgba(22,163,74,.25)":"rgba(220,38,38,.25)"}` }}>
                  {testResult.ok ? "✓ SMTP 연결 성공" : `✗ 연결 실패: ${testResult.error}`}
                </div>
              )}
            </div>
          </div>

          {/* 가이드 */}
          <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"18px" }}>
            <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:12 }}>📖 Exchange/Office365 설정 가이드</div>
            {[
              {title:"Office 365 설정",
               items:["SMTP 서버: smtp.office365.com","포트: 587 (STARTTLS)","계정: 발신용 메일 주소","Azure AD에서 SMTP Auth 허용 필요"]},
              {title:"Exchange 온프레미스",
               items:["SMTP 서버: 내부 Exchange 서버 IP/도메인","포트: 25 (내부) 또는 587","SMTP 릴레이 허용 설정 필요","인증 없이 릴레이 허용 가능 (내부망)"]},
              {title:"Gmail (테스트용)",
               items:["SMTP 서버: smtp.gmail.com","포트: 587 (STARTTLS)","2단계 인증 활성화 후 앱 비밀번호 사용","Google 계정 → 보안 → 앱 비밀번호"]},
            ].map(g=>(
              <div key={g.title} style={{ marginBottom:14,padding:"12px 14px",background:"var(--bg-card2)",borderRadius:8,border:"1px solid var(--bdr)" }}>
                <div style={{ fontSize:11,fontWeight:700,color:"var(--txt)",marginBottom:6 }}>{g.title}</div>
                {g.items.map((item,i)=>(
                  <div key={i} style={{ display:"flex",alignItems:"center",gap:6,fontSize:11,color:"var(--txt3)",marginBottom:3 }}>
                    <span style={{ width:4,height:4,borderRadius:"50%",background:"var(--accent)",flexShrink:0 }}/>
                    {item}
                  </div>
                ))}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ══ 메일 미리보기 모달 ══ */}
      {previewModal && (
        <div style={{ position:"fixed",inset:0,background:"rgba(0,0,0,.75)",zIndex:1000,
          display:"flex",alignItems:"flex-start",justifyContent:"center",padding:"20px",overflowY:"auto" }}>
          <div style={{ background:"#fff",borderRadius:12,width:"100%",maxWidth:760,
            boxShadow:"0 20px 60px rgba(0,0,0,.4)",overflow:"hidden" }}>
            {/* 모달 헤더 */}
            <div style={{ display:"flex",alignItems:"center",gap:12,padding:"14px 20px",
              background:"#0D1B2A",color:"#fff" }}>
              <div style={{ fontSize:20 }}>📧</div>
              <div style={{ flex:1 }}>
                <div style={{ fontSize:14,fontWeight:700 }}>발송 메일 미리보기 — {previewModal.manager}</div>
                <div style={{ fontSize:11,color:"rgba(255,255,255,.6)",marginTop:1 }}>
                  취약점 {previewModal.finding_count}건 · 긴급 {previewModal.critical_count}건 포함
                </div>
              </div>
              <div style={{ display:"flex",gap:8 }}>
                <button
                  onClick={()=>{
                    const row=managerRows.find(m=>m.name===previewModal.manager);
                    if(row&&emailMap[previewModal.manager]) {
                      setSelManager(previewModal.manager);
                      setSelEmail(emailMap[previewModal.manager]);
                      setSelDept(row.dept);
                      setSelAssets(row.assets.map(a=>a.id));
                      setPreviewModal(null);
                      onSend();
                    } else {
                      setMsg({ok:false,text:"먼저 수신 이메일을 입력하세요"});
                      setPreviewModal(null);
                    }
                  }}
                  style={{ padding:"7px 18px",borderRadius:7,border:"1px solid rgba(74,222,128,.5)",
                    background:"rgba(74,222,128,.15)",color:"#4ADE80",fontSize:12,fontWeight:700,cursor:"pointer" }}>
                  📤 이대로 발송
                </button>
                <button onClick={()=>setPreviewModal(null)}
                  style={{ padding:"7px 14px",borderRadius:7,border:"1px solid rgba(255,255,255,.2)",
                    background:"transparent",color:"rgba(255,255,255,.7)",fontSize:12,cursor:"pointer" }}>
                  닫기
                </button>
              </div>
            </div>
            {/* 미리보기 iframe 영역 */}
            <div style={{ height:"80vh",overflow:"auto",background:"#F5F5F5",padding:"16px" }}>
              <div style={{ maxWidth:700,margin:"0 auto",background:"#fff",borderRadius:8,
                boxShadow:"0 2px 12px rgba(0,0,0,.1)",overflow:"hidden" }}
                dangerouslySetInnerHTML={{__html:previewModal.html}}/>
            </div>
          </div>
        </div>
      )}

      {/* ══ 조치 완료 모달 ══ */}
      {actionModal && (
        <div style={{ position:"fixed",inset:0,background:"rgba(0,0,0,.6)",zIndex:1000,display:"flex",alignItems:"center",justifyContent:"center" }}>
          <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:12,padding:"24px",width:420,boxShadow:"0 20px 60px rgba(0,0,0,.3)" }}>
            <div style={{ fontSize:15,fontWeight:700,color:"var(--txt)",marginBottom:4 }}>✅ 조치 완료 확인</div>
            <div style={{ fontSize:12,color:"var(--txt3)",marginBottom:16 }}>
              <strong style={{ color:"var(--txt)" }}>{actionModal.manager}</strong> 담당자의 취약점 {actionModal.finding_count}건에 대한 조치 완료를 처리합니다.<br/>
              완료 처리 시 연관된 취약점이 자동으로 <strong style={{ color:"#4ADE80" }}>resolved</strong> 처리됩니다.
            </div>
            <div style={{ marginBottom:14 }}>
              <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:5 }}>조치 내용 메모 (선택)</label>
              <textarea value={actionNote} onChange={e=>setActionNote(e.target.value)}
                placeholder="조치한 내용을 간략히 입력하세요 (예: 패치 v2.1 적용, 포트 차단 완료)"
                style={{ ...IS,height:80,resize:"none",fontFamily:"inherit" }}/>
            </div>
            <div style={{ display:"flex",gap:8 }}>
              <button onClick={()=>onActionComplete(actionModal.id,"completed")}
                style={{ flex:2,padding:"10px",borderRadius:7,border:"1px solid rgba(74,222,128,.4)",background:"rgba(74,222,128,.1)",color:"#4ADE80",fontSize:13,fontWeight:700,cursor:"pointer" }}>
                ✅ 완료 처리
              </button>
              <button onClick={()=>setActionModal(null)}
                style={{ flex:1,padding:"10px",borderRadius:7,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
                취소
              </button>
            </div>
          </div>
        </div>
      )}

      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}
