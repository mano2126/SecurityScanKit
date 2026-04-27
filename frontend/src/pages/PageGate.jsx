// PageGate.jsx — 보안 점검 시스템 대문 페이지
import { useState, useEffect, useRef, useMemo } from "react";
import API_BASE from "../hooks/apiConfig.js";

function loadLocalUsers() {
  try { return JSON.parse(localStorage.getItem("ssk_users") || "[]"); } catch { return []; }
}

export default function PageGate({ onEnter }) {
  const [step,      setStep]     = useState("name");
  const [name,      setName]     = useState("");
  const [division,  setDivision] = useState("");
  const [dept,      setDept]     = useState("");
  const [divDirect, setDivDirect]= useState(false);
  const [deptDirect,setDeptDirect]=useState(false);
  const [foundUser, setFoundUser]= useState(null);
  const [error,     setError]    = useState("");
  const [saving,    setSaving]   = useState(false);
  const [blink,     setBlink]    = useState(true);
  const nameRef = useRef(null);

  useEffect(() => {
    const t = setInterval(() => setBlink(b => !b), 700);
    return () => clearInterval(t);
  }, []);

  useEffect(() => { nameRef.current?.focus(); }, []);

  // ── 사용자 목록: 백엔드 DB + localStorage 병합
  const [users, setUsers] = useState(loadLocalUsers);

  useEffect(() => {
    // 백엔드 DB에서 사용자 목록 로드 → localStorage와 병합
    fetch(`${API_BASE}/api/system-users`)
      .then(r => r.json())
      .then(dbUsers => {
        if (!Array.isArray(dbUsers)) return;
        const local = loadLocalUsers();
        // DB 사용자 우선, local에만 있는 사용자 추가
        const merged = [...dbUsers];
        local.forEach(lu => {
          if (!merged.find(u => u.name?.trim() === lu.name?.trim())) {
            merged.push(lu);
          }
        });
        setUsers(merged);
        // localStorage도 동기화
        localStorage.setItem("ssk_users", JSON.stringify(merged));
      })
      .catch(() => {
        // 백엔드 연결 실패 시 localStorage만 사용
        setUsers(loadLocalUsers());
      });
  }, []);

  // ── 본부: division 필드만, 부서: dept 필드만 group by
  const uniqDivs  = useMemo(() =>
    [...new Set(users.map(u => (u.division||"").trim()).filter(Boolean))].sort()
  , [users]);

  const uniqDepts = useMemo(() =>
    [...new Set(users.map(u => (u.dept||"").trim()).filter(Boolean))].sort()
  , [users]);

  // ── step1: 이름 입력
  const handleNameSubmit = () => {
    if (!name.trim()) { setError("이름을 입력하세요"); return; }
    setError("");

    const found = users.find(u => u.name?.trim() === name.trim());
    setFoundUser(found || null);

    if (found) {
      const divVal  = (found.division || "").trim();
      const deptVal = (found.dept || "").trim();
      setDivision(divVal);
      setDept(deptVal);
      // 기존 값이 목록에 없으면 직접입력 모드
      setDivDirect(!!divVal && !uniqDivs.includes(divVal));
      setDeptDirect(!!deptVal && !uniqDepts.includes(deptVal));
    } else {
      setDivision(""); setDept("");
      setDivDirect(false); setDeptDirect(false);
    }
    setStep("info");
  };

  // ── step2: 본부/부서 확인 후 로그인
  const handleInfoSubmit = () => {
    if (!dept.trim() && !division.trim()) { setError("부서를 선택하거나 입력하세요"); return; }
    setError("");
    setSaving(true);

    const finalDiv  = division.trim();
    const finalDept = dept.trim();

    const latest = loadLocalUsers();
    let updated;
    if (foundUser) {
      updated = latest.map(u =>
        u.name?.trim() === name.trim() ? { ...u, division: finalDiv, dept: finalDept } : u
      );
      if (!updated.find(u => u.name?.trim() === name.trim())) {
        updated.push({ id: Date.now(), name: name.trim(), division: finalDiv, dept: finalDept });
      }
    } else {
      updated = [...latest, {
        id: Date.now(), name: name.trim(),
        division: finalDiv, dept: finalDept,
        role: "user", createdAt: new Date().toISOString(),
      }];
    }
    localStorage.setItem("ssk_users", JSON.stringify(updated));
    setUsers(updated);

    const me = { name: name.trim(), division: finalDiv, dept: finalDept, loginAt: new Date().toISOString() };
    localStorage.setItem("ssk_current_user", JSON.stringify(me));

    // 백엔드 DB에도 저장 (비동기 — 실패해도 로그인은 진행)
    fetch(`${API_BASE}/api/system-users`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ name: name.trim(), division: finalDiv, dept: finalDept }),
    }).catch(() => {});

    setStep("done");
    setTimeout(() => onEnter({ user: me, goto: null }), 800); // App.jsx에서 자산 유무로 결정
  };

  const onKey = (e) => {
    if (e.key !== "Enter") return;
    if (step === "name") {
      if (name.trim()) handleNameSubmit();
    } else {
      handleInfoSubmit();
    }
  };

  const inputSt  = (v) => ({ width:"100%", padding:"10px 12px", borderRadius:6, boxSizing:"border-box",
    border:`1px solid ${v?"var(--accent)":"var(--bdr)"}`, background:"var(--bg-input)",
    color:"var(--txt)", fontSize:13, outline:"none", transition:"border-color .15s" });
  const selectSt = (v) => ({ ...inputSt(v), cursor:"pointer" });
  const labelSt  = { display:"block", fontSize:11, fontWeight:700, color:"var(--txt3)",
    textTransform:"uppercase", letterSpacing:".06em", marginBottom:6 };

  return (
    <div style={{ minHeight:"100vh", background:"var(--bg-base,#1A1D21)",
      display:"flex", alignItems:"center", justifyContent:"center",
      fontFamily:"'Malgun Gothic','Apple SD Gothic Neo',sans-serif", padding:20 }}>

      <div style={{ width:"100%", maxWidth:460, background:"var(--bg-card)",
        border:"1px solid var(--bdr)", borderRadius:12, overflow:"hidden",
        boxShadow:"0 4px 24px rgba(0,0,0,.2)" }}>

        {/* 헤더 */}
        <div style={{ background:"var(--bg-card2)", borderBottom:"2px solid var(--accent)",
          padding:"28px 32px 22px", textAlign:"center" }}>
          <div style={{ fontSize:36, marginBottom:10 }}>🛡</div>
          <div style={{ fontSize:18, fontWeight:700, color:"var(--txt)", marginBottom:4 }}>
            보안 취약점 점검 시스템
          </div>
          <div style={{ fontSize:11, color:"var(--txt3)", letterSpacing:".05em" }}>
            SecurityScanKit v1.0 · 금융보안원 가이드 준거
          </div>
          {/* 단계 표시 */}
          <div style={{ display:"flex", alignItems:"center", justifyContent:"center", gap:6, marginTop:14 }}>
            {[{s:"name",n:1,l:"이름"},{s:"info",n:2,l:"소속"},{s:"done",n:3,l:"시작"}].map((st,i,arr)=>{
              const done = ["name","info","done"].indexOf(step) > i;
              const cur  = step === st.s;
              return (
                <div key={st.s} style={{ display:"flex", alignItems:"center", gap:6 }}>
                  <div style={{ width:22, height:22, borderRadius:"50%",
                    display:"flex", alignItems:"center", justifyContent:"center",
                    fontSize:11, fontWeight:700,
                    background: cur?"var(--accent)": done?"rgba(59,130,246,.3)":"var(--bg-card)",
                    color: cur?"#fff": done?"var(--accent-text)":"var(--txt3)",
                    border:`1px solid ${cur?"var(--accent)":"var(--bdr)"}`
                  }}>{st.n}</div>
                  <span style={{ fontSize:11, color:cur?"var(--accent-text)":"var(--txt3)" }}>{st.l}</span>
                  {i < arr.length-1 && <div style={{ width:20, height:1, background:"var(--bdr2)" }}/>}
                </div>
              );
            })}
          </div>
        </div>

        {/* 폼 */}
        <div style={{ padding:"24px 32px 28px" }}>

          {/* ── step1: 이름 ── */}
          {step === "name" && (<>
            <div style={{ marginBottom:8, fontSize:13, color:"var(--txt3)", lineHeight:1.6 }}>
              이름을 입력해야 시스템에 접근할 수 있습니다.
              <span style={{ color:"#F87171", fontWeight:600, marginLeft:4 }}>*필수</span>
            </div>
            <div style={{ marginBottom:18 }}>
              <label style={labelSt}>이름 <span style={{ color:"#F87171" }}>*</span></label>
              <input ref={nameRef} type="text" value={name}
                onChange={e => { setName(e.target.value); setError(""); }}
                onKeyDown={onKey} placeholder="본인 이름을 입력하세요"
                style={inputSt(name)}/>
            </div>
            {error && <ErrBox msg={error}/>}
            <button
              onClick={handleNameSubmit}
              disabled={!name.trim()}
              style={{
                width:"100%", padding:"12px", borderRadius:7, fontSize:14,
                fontWeight:700, border:"none", transition:"all .3s",
                cursor: name.trim() ? "pointer" : "not-allowed",
                background: name.trim() ? "var(--accent)" : "var(--bdr2)",
                color: name.trim() ? "#fff" : "var(--txt3)",
                opacity: name.trim() ? (blink?1:0.85) : 0.45,
                boxShadow: name.trim() && blink ? "0 0 12px rgba(37,99,235,.4)" : "none",
              }}>
              {name.trim() ? "다음 →" : "이름을 입력하세요"}
            </button>
            <div style={{ marginTop:16, padding:"10px 14px",
              background:"var(--bg-card2)", borderRadius:6, border:"1px solid var(--bdr)" }}>
              <div style={{ fontSize:11, color:"var(--txt3)", lineHeight:1.7 }}>
                <div>• 처음 사용자는 <strong style={{color:"var(--txt)"}}>자산 등록</strong> 화면으로 이동합니다</div>
                <div>• 기존 사용자는 <strong style={{color:"var(--txt)"}}>점검 엔진</strong>으로 바로 이동합니다</div>
              </div>
            </div>
          </>)}

          {/* ── step2: 본부/부서 ── */}
          {step === "info" && (<>
            {/* 사용자 안내 배너 */}
            <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:18,
              padding:"10px 14px", borderRadius:8,
              background: foundUser?"rgba(74,222,128,.06)":"rgba(96,165,250,.06)",
              border:`1px solid ${foundUser?"rgba(74,222,128,.2)":"rgba(96,165,250,.2)"}` }}>
              <span style={{ fontSize:20 }}>{foundUser?"👤":"🆕"}</span>
              <div>
                <div style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>
                  {name}님{foundUser?", 반갑습니다!":" — 처음 오셨군요!"}
                </div>
                <div style={{ fontSize:11, color:"var(--txt3)", marginTop:2 }}>
                  {foundUser?"소속 정보를 확인하고 변경이 있으면 수정해 주세요.":"본부와 부서를 입력해 주세요."}
                </div>
              </div>
            </div>

            {/* 본부 — division group by, 없으면 직접입력 */}
            <div style={{ marginBottom:14 }}>
              <label style={labelSt}>본부 <span style={{color:"var(--txt3)",fontSize:10,fontWeight:400}}>(선택)</span></label>
              {!divDirect ? (
                <select value={division}
                  onChange={e => {
                    if (e.target.value === "__new__") { setDivDirect(true); setDivision(""); }
                    else setDivision(e.target.value);
                  }}
                  style={selectSt(division)}>
                  <option value="">— 본부 선택 (없으면 생략) —</option>
                  {uniqDivs.map(d => <option key={d} value={d}>{d}</option>)}
                  <option value="__new__">✏ 직접 입력</option>
                </select>
              ) : (
                <div style={{ display:"flex", gap:6 }}>
                  <input value={division} onChange={e => setDivision(e.target.value)}
                    onKeyDown={onKey} placeholder="새 본부명 입력"
                    style={{ ...inputSt(division), flex:1 }}/>
                  <button onClick={() => { setDivDirect(false); setDivision(""); }}
                    style={{ padding:"0 10px", borderRadius:6, border:"1px solid var(--bdr)",
                      background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer", whiteSpace:"nowrap" }}>
                    목록 선택
                  </button>
                </div>
              )}
            </div>

            {/* 부서 — dept group by, 없으면 직접입력 */}
            <div style={{ marginBottom:18 }}>
              <label style={labelSt}>부서 <span style={{ color:"#F87171" }}>*</span></label>
              {!deptDirect ? (
                <select value={dept}
                  onChange={e => {
                    if (e.target.value === "__new__") { setDeptDirect(true); setDept(""); }
                    else setDept(e.target.value);
                  }}
                  style={selectSt(dept)}>
                  <option value="">— 부서 선택 —</option>
                  {uniqDepts.map(d => <option key={d} value={d}>{d}</option>)}
                  <option value="__new__">✏ 직접 입력</option>
                </select>
              ) : (
                <div style={{ display:"flex", gap:6 }}>
                  <input value={dept} onChange={e => setDept(e.target.value)}
                    onKeyDown={onKey} placeholder="새 부서명 입력"
                    style={{ ...inputSt(dept), flex:1 }}/>
                  <button onClick={() => { setDeptDirect(false); setDept(""); }}
                    style={{ padding:"0 10px", borderRadius:6, border:"1px solid var(--bdr)",
                      background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer", whiteSpace:"nowrap" }}>
                    목록 선택
                  </button>
                </div>
              )}
            </div>

            {error && <ErrBox msg={error}/>}

            <div style={{ display:"flex", gap:8 }}>
              <button onClick={() => { setStep("name"); setError(""); }}
                style={{ padding:"11px 16px", borderRadius:7, border:"1px solid var(--bdr)",
                  background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>
                ← 뒤로
              </button>
              <button onClick={handleInfoSubmit} disabled={saving} style={{
                flex:1, padding:"12px", borderRadius:7, fontSize:14, fontWeight:700,
                cursor: saving?"wait":"pointer", border:"none",
                background: dept?"var(--accent)":"var(--bdr2)",
                color: dept?"#fff":"var(--txt3)",
                opacity: dept?(blink?1:0.8):0.5, transition:"all .3s",
                boxShadow: dept&&blink?"0 0 12px rgba(37,99,246,.4)":"none"
              }}>
                {saving?"저장 중...":"점검 시작 →"}
              </button>
            </div>
          </>)}

          {/* ── step3: 완료 ── */}
          {step === "done" && (
            <div style={{ textAlign:"center", padding:"20px 0" }}>
              <div style={{ fontSize:40, marginBottom:12 }}>✅</div>
              <div style={{ fontSize:15, fontWeight:700, color:"var(--txt)", marginBottom:4 }}>
                {name}님, 안녕하세요
              </div>
              <div style={{ fontSize:12, color:"var(--txt3)" }}>
                {[division, dept].filter(Boolean).join(" · ")} · 이동 중...
              </div>
            </div>
          )}
        </div>

        {/* 푸터 */}
        <div style={{ padding:"10px 32px", borderTop:"1px solid var(--bdr)",
          background:"var(--bg-card2)", textAlign:"center" }}>
          <div style={{ fontSize:11, color:"var(--txt3)" }}>
            문의: IT보안팀 내선 ·
            <span style={{ marginLeft:6, color:"var(--accent-text)", cursor:"pointer" }}
              onClick={() => onEnter({ user:null, goto:"dashboard" })}>
              관리자 바로가기
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}

function ErrBox({ msg }) {
  return (
    <div style={{ fontSize:12, color:"#F87171", marginBottom:12,
      padding:"6px 10px", background:"rgba(248,113,113,.08)",
      borderRadius:5, border:"1px solid rgba(248,113,113,.2)" }}>
      ⚠ {msg}
    </div>
  );
}
