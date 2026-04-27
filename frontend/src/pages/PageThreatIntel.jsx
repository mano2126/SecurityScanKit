/**
 * PageThreatIntel.jsx — 보안 점검 현황 & 엔진 신뢰도 센터
 * 패치 156: 전면 개편 — "점검 라이브러리 + 기관 반영 현황 + CISO 신뢰도 로드맵"
 */
import { useState, useMemo, useRef, useCallback, useEffect } from "react";
import AI_CACHE from "../config/aiAnalysisCache.json";


// ─── 검색어 하이라이트 헬퍼 ─────────────────────────────────────────────────
function Highlight({ text, q }) {
  if (!q || !text) return <>{text}</>;
  const idx = text.toLowerCase().indexOf(q.toLowerCase());
  if (idx === -1) return <>{text}</>;
  return (
    <>
      {text.slice(0, idx)}
      <mark style={{background:"rgba(251,191,36,.35)",color:"var(--txt)",
        borderRadius:2,padding:"0 1px"}}>{text.slice(idx, idx+q.length)}</mark>
      {text.slice(idx+q.length)}
    </>
  );
}

// ─── AI 상세 분석 팝업 ───────────────────────────────────────────────────────
function AiAnalysisModal({ item, onClose }) {
  const [loading,   setLoading]   = useState(true);
  const [sections,  setSections]  = useState(null);
  const [error,     setError]     = useState(null);
  const abortRef = useRef(null);

  useEffect(() => {
    if (!item) return;
    setLoading(true); setSections(null); setError(null);

    // ── 1순위: 로컬 캐시 파일 확인 (API 비용 없음) ──
    const cached = AI_CACHE[item.id];
    if (cached) {
      setSections(cached);
      setLoading(false);
      return;
    }

    // ── 2순위: 캐시 없으면 백엔드 API 호출 ──
    const ctrl = new AbortController();
    abortRef.current = ctrl;

    const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
    fetch(`${API_BASE}/api/ai-analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      signal: ctrl.signal,
      body: JSON.stringify({ item })
    })
    .then(r => r.json())
    .then(data => {
      if (data.error) { setError(data.error); return; }
      if (data.result) { setSections(data.result); return; }
      setError("응답 형식 오류");
    })
    .catch(e => { if (e.name !== "AbortError") setError(e.message); })
    .finally(() => setLoading(false));

    return () => ctrl.abort();
  }, [item]);

  if (!item) return null;

  const SEV = { critical:"#F87171", high:"#FB923C", medium:"#FBBF24", low:"#4ADE80" };
  const sevColor = SEV[item.severity] || "#94A3B8";
  const CAT_C = { "네트워크":"#60A5FA","SSL/TLS":"#A78BFA","웹 보안":"#34D399","네트워크 장비":"#F472B6","데이터베이스":"#FBBF24" };
  const catColor = CAT_C[item.category] || "#94A3B8";

  const SECTIONS = sections ? [
    { key:"attack",      icon:"🎯", title:"공격 시나리오",       color:"#F87171",  bg:"rgba(248,113,113,.06)",  border:"rgba(248,113,113,.2)"  },
    { key:"regulation",  icon:"🏛", title:"기관 규정 및 제재",   color:"#818CF8",  bg:"rgba(129,140,248,.06)",  border:"rgba(129,140,248,.2)"  },
    { key:"engine",      icon:"⚙", title:"엔진 탐지 방식",      color:"#60A5FA",  bg:"rgba(96,165,250,.06)",   border:"rgba(96,165,250,.2)"   },
    { key:"cases",       icon:"📰", title:"실제 침해 사례",      color:"#FB923C",  bg:"rgba(251,146,60,.06)",   border:"rgba(251,146,60,.2)"   },
    { key:"remediation", icon:"✅", title:"즉시 조치 가이드",    color:"#4ADE80",  bg:"rgba(74,222,128,.06)",   border:"rgba(74,222,128,.2)"   },
    { key:"ciso_note",   icon:"👔", title:"CISO 보고 핵심 메시지", color:"#FBBF24", bg:"rgba(251,191,36,.06)", border:"rgba(251,191,36,.2)"   },
  ] : [];

  return (
    <div style={{position:"fixed",inset:0,zIndex:9999,display:"flex",alignItems:"center",justifyContent:"center",
      background:"rgba(0,0,0,.65)",backdropFilter:"blur(4px)"}}
      onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div style={{width:"min(860px,96vw)",maxHeight:"90vh",display:"flex",flexDirection:"column",
        background:"var(--bg-card)",borderRadius:14,overflow:"hidden",
        border:`1px solid ${catColor}44`,boxShadow:`0 24px 60px rgba(0,0,0,.5),0 0 0 1px ${catColor}22`}}>

        {/* 헤더 */}
        <div style={{padding:"14px 18px",borderBottom:"1px solid var(--bdr)",
          background:`linear-gradient(135deg,${catColor}10,transparent)`,
          display:"flex",alignItems:"flex-start",gap:12,flexShrink:0}}>
          <div style={{flex:1,minWidth:0}}>
            <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:5,flexWrap:"wrap"}}>
              <span style={{fontSize:13,padding:"1px 7px",borderRadius:4,fontWeight:700,
                color:catColor,background:`${catColor}18`,border:`1px solid ${catColor}33`}}>
                {item.category}
              </span>
              <span style={{fontSize:13,padding:"1px 7px",borderRadius:4,fontWeight:700,
                color:sevColor,background:`${sevColor}18`,border:`1px solid ${sevColor}33`}}>
                {item.severity.toUpperCase()}
              </span>
              <code style={{fontSize:13,color:"var(--txt3)",background:"var(--bg-card2)",
                padding:"1px 6px",borderRadius:4,border:"1px solid var(--bdr)"}}>{item.id}</code>
            </div>
            <div style={{fontSize:15,fontWeight:700,color:"var(--txt)",lineHeight:1.6}}>
              🤖 AI 상세 분석 — {item.title}
            </div>
            <div style={{fontSize:13,color:"var(--txt3)",marginTop:4}}>{item.ref}</div>
          </div>
          <button onClick={onClose}
            style={{background:"transparent",border:"1px solid var(--bdr)",borderRadius:7,
              cursor:"pointer",color:"var(--txt3)",fontSize:16,padding:"4px 9px",flexShrink:0,
              lineHeight:1}}>✕</button>
        </div>

        {/* 본문 */}
        <div style={{flex:1,overflowY:"auto",padding:"16px 18px"}}>
          {loading && (
            <div style={{display:"flex",flexDirection:"column",alignItems:"center",
              justifyContent:"center",gap:14,padding:"50px 0"}}>
              <div style={{width:36,height:36,borderRadius:"50%",
                border:`3px solid ${catColor}`,borderTopColor:"transparent",
                animation:"spin .8s linear infinite"}}/>
              <div style={{fontSize:13,color:"var(--txt3)"}}>
                AI가 분석 중입니다... 금융보안원·금감원 기준으로 상세 분석 중
              </div>
            </div>
          )}
          {error && (
            <div style={{padding:"20px",background:"rgba(248,113,113,.08)",borderRadius:8,
              border:"1px solid rgba(248,113,113,.2)",color:"#F87171",fontSize:12}}>
              ⚠ 분석 오류: {error}
            </div>
          )}
          {sections && (
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10}}>
              {SECTIONS.map(s=>(
                <div key={s.key}
                  style={{background:s.bg,border:`1px solid ${s.border}`,
                    borderRadius:9,padding:"12px 14px",
                    gridColumn:s.key==="remediation"||s.key==="ciso_note"?"span 1":"span 1"}}>
                  <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:8}}>
                    <span style={{fontSize:16}}>{s.icon}</span>
                    <span style={{fontSize:13,fontWeight:700,color:s.color}}>{s.title}</span>
                  </div>
                  <div style={{fontSize:13,color:"var(--txt)",lineHeight:1.8,whiteSpace:"pre-wrap"}}>
                    {s.key==="remediation"
                      ? sections[s.key].split(/\n|\d+\.\s/).filter(Boolean).map((line,i)=>(
                          <div key={i} style={{display:"flex",gap:7,marginBottom:5}}>
                            <span style={{color:s.color,fontWeight:700,flexShrink:0,minWidth:16}}>{i+1}.</span>
                            <span>{line.trim()}</span>
                          </div>
                        ))
                      : sections[s.key]
                    }
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* 푸터 */}
        <div style={{padding:"10px 18px",borderTop:"1px solid var(--bdr)",
          background:"var(--bg-card2)",display:"flex",alignItems:"center",
          justifyContent:"space-between",flexShrink:0}}>
          <span style={{fontSize:13,color:"var(--txt3)",display:"flex",alignItems:"center",gap:6}}>
            {AI_CACHE[item.id]
              ? <><span style={{color:"#4ADE80",fontWeight:700}}>✅ 사전 분석 데이터</span> · API 미사용</>
              : <>🤖 Claude AI 실시간 분석</>
            }
            &nbsp;· 금융보안원·금감원·ISMS-P·OWASP 기준 참조
          </span>
          <button onClick={onClose}
            style={{padding:"5px 16px",borderRadius:7,border:"1px solid var(--bdr)",
              background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer"}}>
            닫기
          </button>
        </div>
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

// ─── 엔진에 실제 구현된 점검 항목 마스터 데이터 ─────────────────────────────
const CHECK_LIBRARY = [
  { id:"PORT-TELNET",   category:"네트워크",      engine:"port_scanner",    title:"Telnet 서비스 개방",                          severity:"critical", standard:"금융보안원", standard2:"ISMS-P",        ref:"금융보안원 네트워크 보안 가이드 N-01",                        addedDate:"2025-01-20", implemented:true,  improvable:true,  improveNote:"버전 식별 및 배너 그래빙 추가 가능",       description:"평문 통신 프로토콜 Telnet 포트(23) 개방 여부 탐지. 자격증명 스니핑 및 세션 하이재킹 가능" },
  { id:"PORT-FTP",      category:"네트워크",      engine:"port_scanner",    title:"FTP 서비스 개방",                              severity:"high",     standard:"금융보안원", standard2:"CIS Controls",  ref:"금융보안원 취약점 점검 가이드",                               addedDate:"2025-01-20", implemented:true,  improvable:true,  improveNote:"익명 FTP 로그인 시도 테스트 추가 가능",    description:"평문 전송 FTP(21) 포트 개방 및 익명 접근 허용 여부 점검" },
  { id:"PORT-SMB",      category:"네트워크",      engine:"port_scanner",    title:"SMB 포트 외부 노출 (EternalBlue)",             severity:"critical", standard:"금융보안원", standard2:"CISA",          ref:"MS17-010 EternalBlue 관련 금융권 긴급 권고",                  addedDate:"2025-01-20", implemented:true,  improvable:false, improveNote:"",                                        description:"SMB(445) 외부 노출 탐지 — WannaCry/NotPetya 랜섬웨어 주요 침투 경로" },
  { id:"PORT-RDP",      category:"네트워크",      engine:"port_scanner",    title:"RDP 원격 데스크탑 외부 노출",                  severity:"critical", standard:"금융보안원", standard2:"KISA",          ref:"금융보안원 원격 접속 보안 지침",                              addedDate:"2025-01-20", implemented:true,  improvable:true,  improveNote:"NLA 활성화 여부 및 버전 식별 추가 가능",   description:"RDP(3389) 외부 노출 탐지 — 브루트포스 및 BlueKeep(CVE-2019-0708) 공격 경로" },
  { id:"PORT-VNC",      category:"네트워크",      engine:"port_scanner",    title:"VNC 원격 접속 외부 노출",                      severity:"critical", standard:"금융보안원", standard2:null,            ref:"금융보안원 취약점 점검 가이드",                               addedDate:"2025-01-20", implemented:true,  improvable:true,  improveNote:"인증 없음(None) 모드 실제 테스트 추가 가능", description:"VNC(5900) 평문 원격 접속 및 취약한 인증 방식 사용 탐지" },
  { id:"PORT-REDIS",    category:"네트워크",      engine:"port_scanner",    title:"Redis 포트 외부 노출",                         severity:"critical", standard:"금융보안원", standard2:"KISA",          ref:"금융보안원 취약점 점검 가이드",                               addedDate:"2025-01-20", implemented:true,  improvable:false, improveNote:"",                                        description:"Redis(6379) 인증 없이 원격 접근 가능 여부 포트 레벨 탐지" },
  { id:"PORT-MONGO",    category:"네트워크",      engine:"port_scanner",    title:"MongoDB 포트 외부 노출",                       severity:"critical", standard:"금융보안원", standard2:null,            ref:"금융보안원 취약점 점검 가이드",                               addedDate:"2025-01-20", implemented:true,  improvable:false, improveNote:"",                                        description:"MongoDB(27017) 기본 설정 시 인증 없이 원격 접근 가능 포트 탐지" },
  { id:"PORT-21KINDS",  category:"네트워크",      engine:"port_scanner",    title:"위험 포트 21종 전수 점검",                     severity:"high",     standard:"금융보안원", standard2:"CIS Controls",  ref:"금융보안원 취약점 점검 가이드 — 포트 점검 목록",              addedDate:"2025-01-20", implemented:true,  improvable:false, improveNote:"",                                        description:"21·22·23·25·53·80·110·135·139·443·445·1433·1521·3306·3389·5432·5900·6379·8080·8443·27017 전수 점검" },
  { id:"SSL-TLS10",     category:"SSL/TLS",       engine:"ssl_scanner",     title:"TLS 1.0 취약 프로토콜 지원",                   severity:"high",     standard:"금융보안원", standard2:"NIST",          ref:"NIST SP 800-52 Rev.2 / 금융보안원 SSL/TLS 설정 가이드",      addedDate:"2025-03-05", implemented:true,  improvable:false, improveNote:"",                                        description:"BEAST, POODLE-TLS 공격에 취약한 TLS 1.0 활성화 여부 점검. 금융권 2024년 폐기 의무" },
  { id:"SSL-TLS11",     category:"SSL/TLS",       engine:"ssl_scanner",     title:"TLS 1.1 구버전 프로토콜 지원",                 severity:"medium",   standard:"금융보안원", standard2:"NIST",          ref:"NIST SP 800-52 Rev.2",                                       addedDate:"2025-03-05", implemented:true,  improvable:false, improveNote:"",                                        description:"TLS 1.2 이상으로 전환 권고 대상인 TLS 1.1 사용 탐지" },
  { id:"SSL-EXPIRED",   category:"SSL/TLS",       engine:"ssl_scanner",     title:"SSL 인증서 만료",                              severity:"critical", standard:"금감원",    standard2:"금융보안원",     ref:"금융회사 IT부문 검사매뉴얼 — 인증서 관리",                    addedDate:"2025-03-05", implemented:true,  improvable:false, improveNote:"",                                        description:"현재 날짜 기준 인증서 유효기간 초과 여부 실시간 점검" },
  { id:"SSL-EXPIRING",  category:"SSL/TLS",       engine:"ssl_scanner",     title:"SSL 인증서 만료 임박 (7일/30일/90일)",         severity:"high",     standard:"금융보안원", standard2:null,            ref:"인증서 관리 정책",                                            addedDate:"2025-03-05", implemented:true,  improvable:false, improveNote:"",                                        description:"7일 이내(critical), 30일 이내(high), 90일 이내(medium) 3단계 만료 예고 점검" },
  { id:"SSL-SELF",      category:"SSL/TLS",       engine:"ssl_scanner",     title:"자가서명(Self-signed) 인증서 사용",            severity:"high",     standard:"금융보안원", standard2:null,            ref:"금융보안원 SSL 인증서 관리 지침",                             addedDate:"2025-03-05", implemented:true,  improvable:false, improveNote:"",                                        description:"공인 CA 발급이 아닌 자가서명 인증서 사용 탐지 — 피싱 사이트 위장 위험" },
  { id:"SSL-CIPHER",    category:"SSL/TLS",       engine:"ssl_scanner",     title:"취약한 암호화 스위트 10종 탐지",               severity:"high",     standard:"금융보안원", standard2:"NIST",          ref:"NIST SP 800-52 Rev.2 — 취약 암호화 목록",                    addedDate:"2025-03-05", implemented:true,  improvable:false, improveNote:"",                                        description:"RC4·DES·3DES·NULL·EXPORT·익명DH/ECDH·MD5·SHA1 서명 등 10종 취약 암호 스위트 탐지" },
  { id:"WEB-HSTS",      category:"웹 보안",       engine:"web_scanner",     title:"HSTS 보안 헤더 미설정",                        severity:"high",     standard:"ISMS-P",    standard2:"OWASP",         ref:"ISMS-P 2.7.1 / OWASP Secure Headers Project",                addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"Strict-Transport-Security 헤더 부재 — HTTP 다운그레이드 공격(SSLstrip) 가능" },
  { id:"WEB-XFO",       category:"웹 보안",       engine:"web_scanner",     title:"클릭재킹 방어 헤더(X-Frame-Options) 미설정", severity:"medium",   standard:"ISMS-P",    standard2:"OWASP",         ref:"OWASP Testing Guide — Clickjacking",                         addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"X-Frame-Options 헤더 부재 — iframe 삽입을 통한 UI 조작 공격 가능" },
  { id:"WEB-MIME",      category:"웹 보안",       engine:"web_scanner",     title:"MIME 타입 스니핑 방어 헤더 미설정",           severity:"medium",   standard:"ISMS-P",    standard2:null,            ref:"OWASP Secure Headers Project",                               addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"X-Content-Type-Options: nosniff 부재 — 브라우저 MIME 타입 추론 공격 가능" },
  { id:"WEB-CSP",       category:"웹 보안",       engine:"web_scanner",     title:"CSP(콘텐츠 보안 정책) 미설정",               severity:"medium",   standard:"ISMS-P",    standard2:"OWASP",         ref:"OWASP A03:2021 Injection / ISMS-P 2.7",                      addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"Content-Security-Policy 헤더 부재 — XSS 공격 방어 정책 없음" },
  { id:"WEB-XSS",       category:"웹 보안",       engine:"web_scanner",     title:"XSS 필터링 헤더 미설정",                      severity:"low",      standard:"ISMS-P",    standard2:null,            ref:"OWASP Secure Headers",                                       addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"X-XSS-Protection 헤더 부재. 구형 브라우저 XSS 필터 미동작" },
  { id:"WEB-REDIRECT",  category:"웹 보안",       engine:"web_scanner",     title:"HTTP→HTTPS 강제 리다이렉트 미설정",           severity:"high",     standard:"금융보안원", standard2:"ISMS-P",        ref:"ISMS-P 2.7.1 — 전송 구간 암호화",                            addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"HTTP 접속 시 HTTPS로 자동 전환 미설정 — 중간자 공격(MITM) 가능" },
  { id:"WEB-PATH",      category:"웹 보안",       engine:"web_scanner",     title:"민감 경로 노출 18종 탐지",                    severity:"high",     standard:"OWASP",     standard2:"금융보안원",    ref:"OWASP A05:2021 Security Misconfiguration",                   addedDate:"2025-05-12", implemented:true,  improvable:true,  improveNote:"경로 목록 50개 이상으로 확대 가능",        description:"/admin·/.env·/.git/config·/web.config·/phpinfo.php·/actuator/env 등 18개 민감 경로 HTTP 200 응답 탐지" },
  { id:"WEB-INFO",      category:"웹 보안",       engine:"web_scanner",     title:"서버 정보 헤더 노출 (Server/X-Powered-By)",  severity:"low",      standard:"OWASP",     standard2:null,            ref:"OWASP Testing Guide — OTG-INFO-002",                         addedDate:"2025-05-12", implemented:true,  improvable:false, improveNote:"",                                        description:"Server·X-Powered-By·X-AspNet-Version·X-Generator 헤더를 통한 기술 스택 노출" },
  { id:"NET-SNMP",      category:"네트워크 장비",  engine:"network_scanner", title:"SNMP Community String 'public' 허용",        severity:"medium",   standard:"금융보안원", standard2:null,            ref:"금융보안원 네트워크 장비 보안 가이드",                        addedDate:"2025-08-01", implemented:true,  improvable:true,  improveNote:"SNMPv3 지원 여부 확인 로직 추가 가능",     description:"기본 SNMP Community String 'public' 응답 탐지 — 네트워크 구성 정보 무단 조회 가능" },
  { id:"NET-DEFCRED",   category:"네트워크 장비",  engine:"network_scanner", title:"기본 자격증명 허용 (admin/admin 등)",         severity:"critical", standard:"금융보안원", standard2:"OWASP",         ref:"OWASP Testing Guide — OTG-AUTHN-002",                        addedDate:"2025-08-01", implemented:true,  improvable:true,  improveNote:"기본 자격증명 목록 50종 이상으로 확대 가능", description:"admin/admin·admin/1234 등 기본 자격증명으로 웹 관리 인터페이스 로그인 시도" },
  { id:"NET-HTTP-MGMT", category:"네트워크 장비",  engine:"network_scanner", title:"HTTP 평문 관리 인터페이스 개방",              severity:"high",     standard:"금융보안원", standard2:"CIS Controls",  ref:"금융보안원 네트워크 보안 가이드 / CIS Controls v8",          addedDate:"2025-08-01", implemented:true,  improvable:false, improveNote:"",                                        description:"장비 관리 포털이 평문 HTTP(80)로 제공 — 자격증명 탈취 위험" },
  { id:"DB-EXT",        category:"데이터베이스",   engine:"db_scanner",      title:"DB 포트 외부망 직접 접근 가능 (5종)",        severity:"high",     standard:"금융보안원", standard2:"금감원",        ref:"금융보안원 DB 보안 가이드 / 금감원 IT검사 주요 지적 사항",   addedDate:"2025-11-10", implemented:true,  improvable:false, improveNote:"",                                        description:"MySQL·MSSQL·Oracle·PostgreSQL·MongoDB 외부망 직접 접근 가능 여부. 금감원 IT검사 최다 지적 항목" },
  { id:"DB-REDIS-NA",   category:"데이터베이스",   engine:"db_scanner",      title:"Redis 인증 없이 원격 접근",                  severity:"critical", standard:"금융보안원", standard2:"KISA",          ref:"CVE-2022-0543 / KISA 보안 공지",                             addedDate:"2025-11-10", implemented:true,  improvable:false, improveNote:"",                                        description:"Redis 기본 설정의 무인증 원격 접근 탐지 — 데이터 탈취 및 서버 장악 가능" },
  { id:"DB-MONGO-OPEN", category:"데이터베이스",   engine:"db_scanner",      title:"MongoDB 외부 접근 가능",                     severity:"critical", standard:"금융보안원", standard2:null,            ref:"MongoDB 보안 체크리스트",                                    addedDate:"2025-11-10", implemented:true,  improvable:false, improveNote:"",                                        description:"MongoDB(27017) 외부 접근 가능 및 인증 설정 미비 탐지" },
  { id:"DB-MSSQL",      category:"데이터베이스",   engine:"db_scanner",      title:"MSSQL 포트 외부 접근 가능",                  severity:"high",     standard:"금융보안원", standard2:null,            ref:"금융보안원 데이터베이스 보안 가이드",                         addedDate:"2025-11-10", implemented:true,  improvable:false, improveNote:"",                                        description:"MSSQL(1433) 외부망 노출 탐지" },
  { id:"DB-MYSQL-EOL",  category:"데이터베이스",   engine:"db_scanner",      title:"MySQL 지원 종료(EOL) 버전 사용",             severity:"high",     standard:"금융보안원", standard2:null,            ref:"MySQL 버전 지원 정책 / 금융보안원 SW 취약점 관리 가이드",    addedDate:"2025-11-10", implemented:true,  improvable:true,  improveNote:"Oracle·MSSQL·PostgreSQL EOL 버전 탐지 추가 가능", description:"보안 패치가 더 이상 제공되지 않는 MySQL EOL 버전 사용 탐지" },

  // ── 인젝션 공격 점검 (2026-04-16 추가) ──
  { id:"WEB-SQLI-BASIC", category:"웹 보안",   engine:"web_scanner", title:"SQL Injection 취약점 — 에러 기반 탐지",        severity:"critical", standard:"금융보안원", standard2:"OWASP",     ref:"OWASP A03:2021 Injection / 금융보안원 웹 취약점 점검 가이드 W-01",  addedDate:"2026-04-16", implemented:true,  improvable:true,  improveNote:"Blind SQLi(시간 기반·Boolean 기반) 탐지 추가 가능", description:"URL 파라미터·query string에 단순 따옴표(') 삽입 시 SQL query 에러 메시지 노출 여부 탐지. Query Injection 공격의 기본 탐지 방식. 에러 응답에 mysql_fetch·syntax error·ORA-· 등 DB 오류 시그니처 포함 여부 확인. 금융권 개인정보·계좌정보 탈취 주요 경로" },
  { id:"WEB-SQLI-OR",    category:"웹 보안",   engine:"web_scanner", title:"SQL Injection — OR 1=1 인증 우회 탐지",       severity:"critical", standard:"금융보안원", standard2:"OWASP",     ref:"OWASP A03:2021 / ISMS-P 2.7 / 금융감독원 전자금융감독규정",         addedDate:"2026-04-16", implemented:true,  improvable:true,  improveNote:"POST 방식 로그인 폼에 대한 SQLi 탐지 추가 가능",    description:"query 파라미터에 ' OR '1'='1 페이로드를 삽입해 WHERE 조건 항상 참 유도. SQL query 인젝션으로 인증 우회. 로그인·검색·조회 파라미터에 대해 인증 우회 가능 여부 탐지. 금감원 IT검사 시 필수 점검 항목" },
  { id:"WEB-SQLI-VER",   category:"웹 보안",   engine:"web_scanner", title:"SQL Injection — DB 버전 정보 추출 탐지",      severity:"critical", standard:"OWASP",     standard2:"ISMS-P",    ref:"OWASP A03:2021 / NIST SP 800-115",                                   addedDate:"2026-04-16", implemented:true,  improvable:true,  improveNote:"UNION 기반·시간지연 기반 탐지 추가 가능",           description:"SQL query에 @@version·version() 함수를 삽입해 DB 버전 정보 탈취 시도 탐지. query injection으로 DB 구조 정보 수집. DB 종류·버전 노출 시 취약점 특정 공격 가능" },
  { id:"WEB-XSS-REFLECT", category:"웹 보안",  engine:"web_scanner", title:"Reflected XSS (반사형 크로스사이트 스크립팅)", severity:"high",     standard:"금융보안원", standard2:"OWASP",     ref:"OWASP A03:2021 / 금융보안원 웹 취약점 점검 가이드 W-04",             addedDate:"2026-04-16", implemented:true,  improvable:true,  improveNote:"Stored XSS·DOM-based XSS 탐지 추가 가능",          description:"입력 파라미터를 HTML 인코딩 없이 응답에 그대로 반사하는지 탐지. 금융 서비스 세션 탈취·피싱 페이지 삽입·키로거 삽입에 악용" },
  { id:"WEB-CMDI-ID",    category:"웹 보안",   engine:"web_scanner", title:"Command Injection — OS 명령어 삽입 탐지",     severity:"critical", standard:"금융보안원", standard2:"OWASP",     ref:"OWASP A03:2021 / 금융보안원 웹 취약점 점검 가이드 W-06",             addedDate:"2026-04-16", implemented:true,  improvable:true,  improveNote:"시간 기반 Blind Command Injection 탐지 추가 가능",   description:";id, |whoami 등 OS 명령어 삽입 시 서버 응답에 uid=·root: 등 시스템 정보 포함 여부 탐지. 서버 완전 장악·내부망 횡이동 가능" },
  { id:"WEB-TRAV-LNX",   category:"웹 보안",   engine:"web_scanner", title:"Path Traversal — /etc/passwd 접근 탐지",      severity:"critical", standard:"금융보안원", standard2:"OWASP",     ref:"OWASP A01:2021 / 금융보안원 웹 취약점 점검 가이드 W-05",             addedDate:"2026-04-16", implemented:true,  improvable:false, improveNote:"",                                                  description:"/../../../etc/passwd 형태의 경로 탐색 공격으로 서버 시스템 파일 접근 시도 탐지. root:x: 시그니처 포함 여부 확인. 소스코드·설정파일·개인정보 파일 탈취 경로" },
  { id:"WEB-TRAV-WIN",   category:"웹 보안",   engine:"web_scanner", title:"Path Traversal — Windows 시스템 파일 접근",   severity:"critical", standard:"금융보안원", standard2:"OWASP",     ref:"OWASP A01:2021 / 금융보안원 웹 취약점 점검 가이드 W-05",             addedDate:"2026-04-16", implemented:true,  improvable:false, improveNote:"",                                                  description:"..\\..\\windows\\win.ini 경로 탐색으로 Windows 서버 시스템 파일 접근 시도 탐지. [extensions] 시그니처 포함 여부 확인" },
];

const STANDARDS_MAP = {
  "금융보안원":   { color:"#818CF8", bg:"rgba(129,140,248,.12)", border:"rgba(129,140,248,.25)", icon:"🏦", fullName:"금융보안원 보안 가이드",         totalRec:45,  url:"https://www.fsec.or.kr",       desc:"금융회사 대상 IT·보안 가이드라인 제공. 네트워크·DB·웹·단말 점검 기준 제시" },
  "금감원":       { color:"#F87171", bg:"rgba(248,113,113,.12)", border:"rgba(248,113,113,.25)", icon:"🏛", fullName:"금융감독원 IT 검사 지침",         totalRec:38,  url:"https://www.fss.or.kr",        desc:"금감원 IT 검사 시 주요 지적 항목 기준. 인증서·DB 접근·원격접속 중점 점검" },
  "ISMS-P":       { color:"#34D399", bg:"rgba(52,211,153,.12)",  border:"rgba(52,211,153,.25)",  icon:"📋", fullName:"ISMS-P 인증 기준",               totalRec:102, url:"https://isms.kisa.or.kr",      desc:"KISA 주관 정보보호 관리체계 인증 기준. 2.7 암호화·전송구간 보안 항목 연관" },
  "OWASP":        { color:"#FB923C", bg:"rgba(251,146,60,.12)",  border:"rgba(251,146,60,.25)",  icon:"🌐", fullName:"OWASP Top 10 2021",              totalRec:10,  url:"https://owasp.org/Top10",      desc:"웹 애플리케이션 10대 보안 위협. A01~A10 중 웹 점검 엔진에 반영" },
  "NIST":         { color:"#FBBF24", bg:"rgba(251,191,36,.12)",  border:"rgba(251,191,36,.25)",  icon:"🇺🇸", fullName:"NIST SP 800-52 Rev.2",          totalRec:28,  url:"https://csrc.nist.gov",        desc:"TLS 구현 가이드라인. 취약 프로토콜·암호 스위트 폐기 기준 및 권고 목록" },
  "KISA":         { color:"#60A5FA", bg:"rgba(96,165,250,.12)",  border:"rgba(96,165,250,.25)",  icon:"🇰🇷", fullName:"KISA 취약점 점검 가이드",        totalRec:55,  url:"https://www.kisa.or.kr",       desc:"한국인터넷진흥원 보안 취약점 점검 기준. Redis·MongoDB·원격접속 취약점 포함" },
  "CIS Controls": { color:"#A78BFA", bg:"rgba(167,139,250,.12)", border:"rgba(167,139,250,.25)", icon:"🛡", fullName:"CIS Controls v8",                totalRec:18,  url:"https://www.cisecurity.org",   desc:"인터넷 보안 센터 18개 핵심 보안 통제. 포트 관리·인증서 관리 항목 반영" },
  "CISA":         { color:"#F472B6", bg:"rgba(244,114,182,.12)", border:"rgba(244,114,182,.25)", icon:"⚠",  fullName:"CISA Known Exploited Vulnerabilities", totalRec:20, url:"https://www.cisa.gov/known-exploited-vulnerabilities-catalog", desc:"실제 공격에 악용된 취약점. SMB(EternalBlue)·RDP(BlueKeep) 관련 항목 반영" },
};

const UPDATES = [
  { date:"2026-04-16", count:9, category:"웹 보안", detail:"SQL Injection(에러기반·OR우회·버전추출) + Reflected XSS + Command Injection + Path Traversal(Linux/Windows) 7종 점검 엔진 추가 + 보안 점검 현황 센터 전면 개편 — OWASP A03·금융보안원 W-01~W-06 반영" },
  { date:"2025-11-10", count:5, category:"데이터베이스",   detail:"DB 외부 접근·Redis 무인증·MongoDB 오픈·MySQL EOL·MSSQL 외부 노출 5종 추가 — 금융보안원 DB 보안 가이드 반영" },
  { date:"2025-08-01", count:3, category:"네트워크 장비",  detail:"SNMP 기본 Community String·기본 자격증명·HTTP 관리 인터페이스 3종 추가 — 금융보안원 네트워크 장비 보안 가이드 반영" },
  { date:"2025-05-12", count:8, category:"웹 보안",        detail:"HSTS·XFO·CSP·MIME 보안 헤더 6종 + HTTP→HTTPS 리다이렉트 + 민감 경로 18종 탐지 추가 — ISMS-P 2.7 및 OWASP 반영" },
  { date:"2025-03-05", count:6, category:"SSL/TLS",        detail:"TLS 1.0/1.1 구버전·인증서 만료/임박/자가서명·취약 암호 스위트 10종 탐지 추가 — NIST SP 800-52 Rev.2 반영" },
  { date:"2025-01-20", count:8, category:"네트워크",       detail:"Telnet·FTP·SMB·RDP·VNC·Redis·MongoDB 위험 포트 7종 + 포트 21종 전수 점검 엔진 구축 — 금융보안원 취약점 점검 가이드 반영" },
];

const ROADMAP = [
  { phase:1, label:"즉시 적용 가능", period:"1~2개월", color:"#4ADE80", bg:"rgba(74,222,128,.08)", border:"rgba(74,222,128,.25)", items:[
    { title:"점검 항목 수 확대",      detail:"현재 30개 → 목표 60개. 기본 자격증명 목록 50종 확대, 민감 경로 50개, DB EOL 전 DB 확대" },
    { title:"취약점 근거 기관 표시",  detail:"각 취약점 결과 화면에 '금융보안원 가이드 N-01 위반' 등 기관 근거 명시 → 직원 신뢰도 즉각 향상" },
    { title:"조치 가이드 링크 제공",  detail:"취약점마다 금융보안원·KISA 공식 조치 가이드 PDF/URL 연결 → 담당자가 직접 근거 확인 가능" },
  ]},
  { phase:2, label:"단기 개발", period:"3~6개월", color:"#60A5FA", bg:"rgba(96,165,250,.08)", border:"rgba(96,165,250,.25)", items:[
    { title:"계정 정책 점검 추가",     detail:"비밀번호 복잡도·계정 잠금 정책·관리자 계정 분리·불필요 계정 존재 여부 — 금감원 최빈 IT검사 지적 항목" },
    { title:"OS·SW 패치 관리 점검",   detail:"OS·미들웨어 버전 식별 및 CVE 매핑. 취약 버전 사용 시 즉시 경보 — ISMS-P 2.9.1 대응" },
    { title:"로그 수집 설정 점검",    detail:"접근로그·이상행위 로그 활성화 여부 자동 점검 — ISMS-P 2.9.4 대응" },
    { title:"경영진 월간 리포트",     detail:"CIO·임원 전용 1페이지 요약 PDF 자동 생성 및 이메일 발송. 위에서 아래로 신뢰 전파 효과" },
  ]},
  { phase:3, label:"중기 고도화", period:"6~12개월", color:"#F472B6", bg:"rgba(244,114,182,.08)", border:"rgba(244,114,182,.25)", items:[
    { title:"AI 취약점 우선순위 분석", detail:"반복 취약점 패턴 분석·조치 우선순위 자동 제안·조치 효과 예측 — Claude API 연동" },
    { title:"금감원 검사 대비 사전 점검", detail:"금감원 IT검사 체크리스트 기반 자동 점검 리포트 생성 — 검사 D-30 알림 발송" },
    { title:"주간 자동 점검 + 비교 분석", detail:"주간/월간 자동 점검 후 이전 결과와 비교. 개선/악화 트렌드 시각화" },
    { title:"CVE 자동 매핑 연동",     detail:"NVD·KISA 신규 CVE → 우리 자산 영향 여부 자동 분석 및 알림" },
  ]},
];

const SEV_META = {
  critical:{ label:"긴급",   color:"#F87171", bg:"rgba(248,113,113,.15)", border:"rgba(248,113,113,.3)" },
  high:    { label:"고위험", color:"#FB923C", bg:"rgba(251,146,60,.15)",  border:"rgba(251,146,60,.3)" },
  medium:  { label:"중위험", color:"#FBBF24", bg:"rgba(251,191,36,.15)",  border:"rgba(251,191,36,.3)" },
  low:     { label:"저위험", color:"#4ADE80", bg:"rgba(74,222,128,.15)",  border:"rgba(74,222,128,.3)" },
  info:    { label:"정보",   color:"#94A3B8", bg:"rgba(148,163,184,.15)", border:"rgba(148,163,184,.3)" },
};
const CAT_COLOR = { "네트워크":"#60A5FA","SSL/TLS":"#A78BFA","웹 보안":"#34D399","네트워크 장비":"#F472B6","데이터베이스":"#FBBF24" };
const SevBadge = ({sev,small}) => { const m=SEV_META[sev]||SEV_META.info; return <span style={{fontSize:small?9:10,padding:small?"1px 5px":"2px 8px",borderRadius:5,fontWeight:700,color:m.color,background:m.bg,border:`1px solid ${m.border}`,whiteSpace:"nowrap"}}>{m.label}</span>; };
const StdBadge = ({std}) => { const m=STANDARDS_MAP[std]; if(!m) return null; return <span style={{fontSize:13,padding:"1px 6px",borderRadius:4,fontWeight:700,color:m.color,background:m.bg,border:`1px solid ${m.border}`,whiteSpace:"nowrap"}}>{m.icon} {std}</span>; };
const CatBadge = ({cat}) => <span style={{fontSize:13,padding:"1px 7px",borderRadius:10,fontWeight:600,color:CAT_COLOR[cat]||"#94A3B8",background:`${CAT_COLOR[cat]||"#94A3B8"}18`,border:`1px solid ${CAT_COLOR[cat]||"#94A3B8"}33`}}>{cat}</span>;
const TABS = [
  {id:"overview",  icon:"📊", label:"점검 현황 개요"},
  {id:"standards", icon:"🏛", label:"기관별 반영 현황"},
  {id:"roadmap",   icon:"🗺", label:"신뢰도 강화 로드맵"},
];

export default function PageThreatIntel() {
  const [tab,      setTab]     = useState("overview");
  const [selItem,  setSelItem] = useState(null);
  const [filter,   setFilter]  = useState({cat:"전체",sev:"전체",std:"전체",q:"",eng:"전체",imp:false});
  const [expanded, setExpanded]= useState(null);
  const [aiItem,    setAiItem]   = useState(null); // AI 분석 팝업 대상

  const stats = useMemo(()=>{
    const total=CHECK_LIBRARY.length;
    const byCategory={};const bySeverity={critical:0,high:0,medium:0,low:0,info:0};
    const improvable=CHECK_LIBRARY.filter(x=>x.improvable).length;
    CHECK_LIBRARY.forEach(c=>{ byCategory[c.category]=(byCategory[c.category]||0)+1; bySeverity[c.severity]=(bySeverity[c.severity]||0)+1; });
    return {total,byCategory,bySeverity,improvable};
  },[]);

  const standardStats = useMemo(()=>{
    const r={};
    Object.keys(STANDARDS_MAP).forEach(std=>{ r[std]={implemented:CHECK_LIBRARY.filter(c=>c.standard===std||c.standard2===std).length}; });
    return r;
  },[]);

  const filtered = useMemo(()=>CHECK_LIBRARY.filter(c=>{
    if(filter.cat!=="전체"&&c.category!==filter.cat) return false;
    if(filter.sev!=="전체"&&c.severity!==filter.sev) return false;
    if(filter.std!=="전체"&&c.standard!==filter.std&&c.standard2!==filter.std) return false;
    if(filter.eng&&filter.eng!=="전체"&&c.engine!==filter.eng) return false;
    if(filter.imp&&!c.improvable) return false;
    if(filter.q){
      const q=filter.q.toLowerCase();
      const hit = c.title.toLowerCase().includes(q)
        || c.description.toLowerCase().includes(q)
        || c.id.toLowerCase().includes(q)
        || c.ref.toLowerCase().includes(q)
        || c.engine.toLowerCase().includes(q)
        || c.category.toLowerCase().includes(q)
        || (c.standard||"").toLowerCase().includes(q)
        || (c.standard2||"").toLowerCase().includes(q)
        || (c.improveNote||"").toLowerCase().includes(q);
      if(!hit) return false;
    }
    return true;
  }),[filter]);

  const categories=["전체",...Object.keys(stats.byCategory)];
  const severities=["전체","critical","high","medium","low"];
  const standards=["전체",...Object.keys(STANDARDS_MAP)];

  return (
    <div style={{padding:"14px 18px",minHeight:"100%"}}>
      {/* AI 분석 팝업 */}
      {aiItem && <AiAnalysisModal item={aiItem} onClose={()=>setAiItem(null)}/>}
      {/* 헤더 */}
      <div style={{display:"flex",alignItems:"center",gap:12,marginBottom:14}}>
        <div style={{width:40,height:40,borderRadius:10,background:"rgba(129,140,248,.15)",border:"1px solid rgba(129,140,248,.3)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0}}>🔬</div>
        <div style={{flex:1}}>
          <div style={{fontSize:15,fontWeight:700,color:"var(--txt)"}}>보안 점검 현황 센터</div>
          <div style={{fontSize:13,color:"var(--txt3)",marginTop:1}}>금융보안원 · 금감원 · ISMS-P · OWASP · NIST · KISA · CIS Controls · CISA 기반 &nbsp;—&nbsp; 엔진 구현 점검 항목 <strong style={{color:"var(--accent-text)"}}>{stats.total}종</strong> 현행화</div>
        </div>
        <div style={{padding:"5px 12px",borderRadius:7,background:"rgba(74,222,128,.1)",border:"1px solid rgba(74,222,128,.25)",fontSize:13,color:"#4ADE80",fontWeight:600}}>✅ 최종 업데이트 {UPDATES[0].date}</div>
      </div>

      {/* 탭 */}
      <div style={{display:"flex",gap:3,background:"var(--bg-card2)",borderRadius:8,padding:3,border:"1px solid var(--bdr)",marginBottom:14,width:"fit-content"}}>
        {TABS.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)}
            style={{padding:"6px 16px",borderRadius:6,border:"none",cursor:"pointer",fontSize:13,fontWeight:tab===t.id?700:400,background:tab===t.id?"var(--bg-active)":"transparent",color:tab===t.id?"var(--accent-text)":"var(--txt3)",display:"flex",alignItems:"center",gap:5}}>
            {t.icon} {t.label}
          </button>
        ))}
      </div>

      {/* ── 탭1: 개요 ── */}
      {tab==="overview"&&(
        <div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(6,1fr)",gap:8,marginBottom:14}}>
            {[
              {label:"총 점검 항목",  value:stats.total,                          color:"var(--accent-text)", icon:"🔬", sub:"엔진 구현 완료"},
              {label:"긴급",          value:stats.bySeverity.critical,            color:"#F87171",            icon:"🔴", sub:"즉시 조치"},
              {label:"고위험",        value:stats.bySeverity.high,                color:"#FB923C",            icon:"🟠", sub:"24h 내 조치"},
              {label:"강화 가능",     value:stats.improvable,                     color:"#FBBF24",            icon:"⚡", sub:"추가 개선 가능"},
              {label:"반영 기관 수",  value:Object.keys(STANDARDS_MAP).length,    color:"#818CF8",            icon:"🏛", sub:"국내외 기준"},
              {label:"점검 영역",     value:Object.keys(stats.byCategory).length, color:"#34D399",            icon:"📂", sub:"카테고리"},
            ].map((k,i)=>(
              <div key={i} style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:9,padding:"10px 12px",borderTop:`3px solid ${k.color}33`}}>
                <div style={{display:"flex",alignItems:"center",gap:5,marginBottom:4}}><span style={{fontSize:14}}>{k.icon}</span><span style={{fontSize:13,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".04em"}}>{k.label}</span></div>
                <div style={{fontSize:22,fontWeight:700,color:k.color,lineHeight:1}}>{k.value}</div>
                <div style={{fontSize:13,color:"var(--txt3)",marginTop:3}}>{k.sub}</div>
              </div>
            ))}
          </div>

          <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:14}}>
            <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10}}>
              <div style={{padding:"10px 14px",borderBottom:"1px solid var(--bdr)",fontSize:13,fontWeight:700,color:"var(--txt)"}}>📂 카테고리별 점검 항목</div>
              <div style={{padding:"10px 14px",display:"flex",flexDirection:"column",gap:8}}>
                {Object.entries(stats.byCategory).map(([cat,cnt])=>{
                  const pct=Math.round((cnt/stats.total)*100);const color=CAT_COLOR[cat]||"#94A3B8";
                  return <div key={cat}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:3}}><CatBadge cat={cat}/><span style={{fontSize:13,fontWeight:600,color}}>{cnt}종</span></div><div style={{height:5,borderRadius:3,background:"var(--bg-card2)",overflow:"hidden"}}><div style={{height:"100%",width:`${pct}%`,borderRadius:3,background:`linear-gradient(90deg,${color}cc,${color})`,transition:"width .6s ease"}}/></div></div>;
                })}
              </div>
            </div>
            <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10}}>
              <div style={{padding:"10px 14px",borderBottom:"1px solid var(--bdr)",fontSize:13,fontWeight:700,color:"var(--txt)"}}>🎯 심각도 분포</div>
              <div style={{padding:"10px 14px",display:"flex",flexDirection:"column",gap:8}}>
                {["critical","high","medium","low"].map(sev=>{
                  const m=SEV_META[sev];const cnt=stats.bySeverity[sev];const pct=Math.round((cnt/stats.total)*100);
                  return <div key={sev}><div style={{display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:3}}><SevBadge sev={sev}/><span style={{fontSize:13,fontWeight:600,color:m.color}}>{cnt}종 ({pct}%)</span></div><div style={{height:5,borderRadius:3,background:"var(--bg-card2)",overflow:"hidden"}}><div style={{height:"100%",width:`${pct}%`,borderRadius:3,background:`linear-gradient(90deg,${m.color}88,${m.color})`,transition:"width .6s ease"}}/></div></div>;
                })}
              </div>
            </div>
          </div>

          <div style={{background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10}}>
            <div style={{padding:"10px 14px",borderBottom:"1px solid var(--bdr)",fontSize:13,fontWeight:700,color:"var(--txt)",display:"flex",alignItems:"center",gap:6}}>
              🗓 점검 항목 반영 이력 <span style={{marginLeft:"auto",fontSize:13,color:"var(--txt3)",fontWeight:400}}>2025.01~현재 총 {UPDATES.reduce((a,b)=>a+b.count,0)}종 추가</span>
            </div>
            <div style={{padding:"12px 14px",display:"flex",flexDirection:"column",gap:0}}>
              {UPDATES.map((u,i)=>{
                const color=CAT_COLOR[u.category]||"#94A3B8";
                return (
                  <div key={i} style={{display:"flex",gap:14,position:"relative",paddingBottom:i<UPDATES.length-1?16:0}}>
                    {i<UPDATES.length-1&&<div style={{position:"absolute",left:13,top:26,bottom:0,width:1,background:"var(--bdr)"}}/>}
                    <div style={{flexShrink:0,width:26,height:26,borderRadius:"50%",background:`${color}22`,border:`2px solid ${color}55`,display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,color,fontWeight:700,zIndex:1}}>+{u.count}</div>
                    <div style={{flex:1,paddingTop:3}}>
                      <div style={{display:"flex",alignItems:"center",gap:7,marginBottom:4}}>
                        <span style={{fontSize:13,fontWeight:700,color:"var(--txt)"}}>{u.date}</span>
                        <CatBadge cat={u.category}/>
                        <span style={{fontSize:13,padding:"1px 6px",borderRadius:4,fontWeight:700,background:"rgba(74,222,128,.12)",color:"#4ADE80",border:"1px solid rgba(74,222,128,.25)"}}>신규 {u.count}종 반영</span>
                      </div>
                      <div style={{fontSize:13,color:"var(--txt2)",lineHeight:1.6}}>{u.detail}</div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}

      {/* ── 탭2: 라이브러리 (테이블) ── */}
      {/* ── 탭3: 기관별 반영 현황 ── */}
      {tab==="standards"&&(
        <div>
          <div style={{background:"rgba(129,140,248,.06)",border:"1px solid rgba(129,140,248,.2)",borderRadius:10,padding:"12px 16px",marginBottom:14,display:"flex",alignItems:"flex-start",gap:12}}>
            <div style={{fontSize:24,flexShrink:0}}>🏛</div>
            <div>
              <div style={{fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:3}}>기관별 보안 권고 반영 현황</div>
              <div style={{fontSize:13,color:"var(--txt2)",lineHeight:1.7}}>금융보안원·금감원·ISMS-P·OWASP·NIST·KISA·CIS Controls·CISA 등 8개 기관의 보안 권고 사항을 점검 엔진에 반영한 현황입니다. <strong style={{color:"var(--txt)"}}>엔진 반영 항목 수</strong>는 실제 스캐너 코드에서 추출한 수치이며, 각 기관의 전체 권고 항목 대비 비율로 표시됩니다.</div>
            </div>
          </div>
          <div style={{display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:10}}>
            {Object.entries(STANDARDS_MAP).map(([std,meta])=>{
              const impl=standardStats[std]?.implemented||0;const total=meta.totalRec;const pct=Math.min(100,Math.round((impl/total)*100));
              const isOpen=expanded===std;const relatedItems=CHECK_LIBRARY.filter(c=>c.standard===std||c.standard2===std);
              return (
                <div key={std} style={{background:"var(--bg-card)",border:`1px solid ${isOpen?meta.border:"var(--bdr)"}`,borderRadius:10,overflow:"hidden",transition:"border-color .15s"}}>
                  <div onClick={()=>setExpanded(isOpen?null:std)} style={{padding:"12px 14px",cursor:"pointer"}}
                    onMouseEnter={e=>!isOpen&&(e.currentTarget.style.background="var(--bg-hover)")}
                    onMouseLeave={e=>!isOpen&&(e.currentTarget.style.background="transparent")}>
                    <div style={{display:"flex",alignItems:"center",gap:8,marginBottom:8}}>
                      <span style={{fontSize:20}}>{meta.icon}</span>
                      <div style={{flex:1}}><div style={{fontSize:13,fontWeight:700,color:"var(--txt)"}}>{meta.fullName}</div><div style={{fontSize:13,color:"var(--txt3)",marginTop:1}}>{meta.desc}</div></div>
                      <span style={{fontSize:13,color:"var(--txt3)"}}>{isOpen?"▲":"▼"}</span>
                    </div>
                    <div style={{display:"flex",alignItems:"center",gap:8}}>
                      <div style={{flex:1,height:7,borderRadius:4,background:"var(--bg-card2)",overflow:"hidden"}}><div style={{height:"100%",borderRadius:4,transition:"width .8s ease",width:`${pct}%`,background:`linear-gradient(90deg,${meta.color}88,${meta.color})`}}/></div>
                      <span style={{fontSize:13,fontWeight:700,color:meta.color,flexShrink:0}}>{impl}종 반영</span>
                    </div>
                    <div style={{display:"flex",justifyContent:"space-between",marginTop:4}}>
                      <span style={{fontSize:13,color:"var(--txt3)"}}>전체 권고 {total}종 중 {pct}% 반영</span>
                      <a href={meta.url} target="_blank" rel="noreferrer" onClick={e=>e.stopPropagation()} style={{fontSize:13,color:meta.color,textDecoration:"none"}}>🔗 기관 바로가기</a>
                    </div>
                  </div>
                  {isOpen&&(
                    <div style={{borderTop:"1px solid var(--bdr)",padding:"10px 14px"}}>
                      <div style={{fontSize:13,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".05em",marginBottom:8}}>엔진 반영 점검 항목 ({relatedItems.length}종)</div>
                      <div style={{display:"flex",flexDirection:"column",gap:5}}>
                        {relatedItems.map(item=>(
                          <div key={item.id} style={{display:"flex",alignItems:"center",gap:7,padding:"8px 11px",background:"var(--bg-card2)",borderRadius:6,border:"1px solid var(--bdr)"}}>
                            <SevBadge sev={item.severity} small/><CatBadge cat={item.category}/>
                            <span style={{flex:1,fontSize:13,color:"var(--txt)"}}>{item.title}</span>
                            <span style={{fontSize:13,color:"var(--txt3)"}}>{item.addedDate}</span>
                          </div>
                        ))}
                      </div>
                      <div style={{marginTop:10,padding:"10px 12px",background:"rgba(251,191,36,.06)",borderRadius:7,border:"1px solid rgba(251,191,36,.2)"}}>
                        <div style={{fontSize:13,color:"#FBBF24",fontWeight:600,marginBottom:2}}>⚠ {total-impl}종 미반영 (로드맵 탭 참조)</div>
                        <div style={{fontSize:13,color:"var(--txt3)"}}>계정 정책·패치 관리·로그 점검 등 추가 항목은 신뢰도 강화 로드맵에서 확인하세요</div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* ── 탭4: 신뢰도 로드맵 ── */}
      {tab==="roadmap"&&(
        <div>
          <div style={{background:"linear-gradient(135deg,rgba(129,140,248,.1),rgba(244,114,182,.06))",border:"1px solid rgba(129,140,248,.25)",borderRadius:12,padding:"16px 18px",marginBottom:16}}>
            <div style={{display:"flex",alignItems:"flex-start",gap:14}}>
              <div style={{fontSize:32,flexShrink:0}}>🎯</div>
              <div>
                <div style={{fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:6}}>CISO 관점 — 점검툴 신뢰도 제고 핵심 전략</div>
                <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:8}}>
                  {[
                    {icon:"📊",title:"수치로 증명",    detail:"직원들이 신뢰하는 것은 '점검했다'가 아닌 '몇 개를 어떤 기준으로 점검했다'입니다. 현재 30종 → 60종 확대하고 기관 근거를 화면에 표시하는 것만으로도 신뢰도가 크게 향상됩니다."},
                    {icon:"🏛",title:"기관 권위 활용",  detail:"금감원·금융보안원 기준을 명시하면 '우리가 만든 룰'이 아닌 '규제기관 기준'으로 인식됩니다. 특히 금감원 IT검사 지적사항 반영을 강조하면 현업 부서도 협조적으로 바뀝니다."},
                    {icon:"📈",title:"트렌드 가시화",   detail:"매월 '이번 달 새로 추가된 점검 항목 N종'을 이메일로 발송하면, 점검툴이 살아있는 시스템으로 인식됩니다. 정적인 툴은 신뢰를 잃습니다."},
                    {icon:"👔",title:"경영진 리포트",   detail:"CIO·임원진에게 1페이지 요약 리포트를 정기 제공하면 위에서 아래로 신뢰가 전파됩니다. 직원들은 경영진이 관심갖는 시스템을 자연스럽게 신뢰합니다."},
                  ].map(g=>(
                    <div key={g.title} style={{background:"var(--bg-card)",borderRadius:8,padding:"10px 12px",border:"1px solid var(--bdr)"}}>
                      <div style={{display:"flex",alignItems:"center",gap:6,marginBottom:5}}><span style={{fontSize:16}}>{g.icon}</span><span style={{fontSize:13,fontWeight:700,color:"var(--txt)"}}>{g.title}</span></div>
                      <div style={{fontSize:13,color:"var(--txt2)",lineHeight:1.7}}>{g.detail}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {ROADMAP.map(phase=>(
            <div key={phase.phase} style={{background:"var(--bg-card)",border:`1px solid ${phase.border}`,borderRadius:12,marginBottom:10,overflow:"hidden"}}>
              <div style={{padding:"12px 16px",background:phase.bg,borderBottom:`1px solid ${phase.border}`,display:"flex",alignItems:"center",gap:10}}>
                <div style={{width:28,height:28,borderRadius:"50%",background:phase.color,display:"flex",alignItems:"center",justifyContent:"center",fontSize:13,fontWeight:700,color:"#000",flexShrink:0}}>{phase.phase}</div>
                <div><div style={{fontSize:13,fontWeight:700,color:"var(--txt)"}}>Phase {phase.phase} — {phase.label}</div><div style={{fontSize:13,color:"var(--txt3)"}}>예상 기간: {phase.period}</div></div>
                <div style={{marginLeft:"auto",fontSize:13,fontWeight:600,color:phase.color}}>{phase.items.length}개 과제</div>
              </div>
              <div style={{padding:"10px 14px",display:"flex",flexDirection:"column",gap:8}}>
                {phase.items.map((item,i)=>(
                  <div key={i} style={{display:"flex",gap:10,padding:"9px 11px",background:"var(--bg-card2)",borderRadius:8,border:"1px solid var(--bdr)"}}>
                    <div style={{width:6,flexShrink:0,borderRadius:3,background:phase.color,alignSelf:"stretch"}}/>
                    <div><div style={{fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:3}}>{item.title}</div><div style={{fontSize:13,color:"var(--txt2)",lineHeight:1.6}}>{item.detail}</div></div>
                  </div>
                ))}
              </div>
            </div>
          ))}

          <div style={{background:"rgba(248,113,113,.05)",border:"1px solid rgba(248,113,113,.2)",borderRadius:10,padding:"14px 16px"}}>
            <div style={{fontSize:13,fontWeight:700,color:"#F87171",marginBottom:10,display:"flex",alignItems:"center",gap:6}}>🏛 금감원 IT 검사 — 현재 엔진 대응 현황</div>
            <div style={{display:"grid",gridTemplateColumns:"1fr 1fr",gap:6}}>
              {[
                {item:"외부망 DB 포트 차단 여부",   status:true,  note:"db_scanner 반영"},
                {item:"SSL 인증서 유효성 관리",     status:true,  note:"ssl_scanner 반영"},
                {item:"원격 접속(RDP/VNC) 통제",   status:true,  note:"port_scanner 반영"},
                {item:"SNMP 기본 설정 변경",        status:true,  note:"network_scanner 반영"},
                {item:"계정 비밀번호 정책 점검",    status:false, note:"→ Phase 2 개발 예정"},
                {item:"불필요 계정·권한 관리",      status:false, note:"→ Phase 2 개발 예정"},
                {item:"OS·SW 보안 패치 적용 현황",  status:false, note:"→ Phase 2 개발 예정"},
                {item:"접근 로그 수집·보관 여부",   status:false, note:"→ Phase 2 개발 예정"},
              ].map((c,i)=>(
                <div key={i} style={{display:"flex",alignItems:"center",gap:8,padding:"8px 11px",background:"var(--bg-card)",borderRadius:6,border:"1px solid var(--bdr)"}}>
                  <span style={{fontSize:14,flexShrink:0}}>{c.status?"✅":"⬜"}</span>
                  <div style={{flex:1}}><div style={{fontSize:13,color:"var(--txt)",fontWeight:c.status?600:400}}>{c.item}</div><div style={{fontSize:13,color:c.status?"#4ADE80":"var(--txt3)"}}>{c.note}</div></div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
