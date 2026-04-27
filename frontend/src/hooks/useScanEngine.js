// hooks/useScanEngine.js — 실제 백엔드 연동 + 데모 데이터 폴백

const API = "http://localhost:8000";

// ── 날짜 헬퍼: 하드코딩 금지 — 오늘 기준 상대 날짜 계산 ──────────
function daysAgo(n) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return d.toISOString().slice(0, 10);
}
function daysAgoHM(n, h=14, m=20) {
  const d = new Date();
  d.setDate(d.getDate() - n);
  return `${d.toISOString().slice(0,10)} ${String(h).padStart(2,"0")}:${String(m).padStart(2,"0")}`;
}
function daysLater(n) {
  const d = new Date();
  d.setDate(d.getDate() + n);
  return d.toISOString().slice(0, 10);
}

// ── 데모 데이터 ────────────────────────────────────────────────────
export const DEMO_ASSETS = [
  { id:"A001", name:"Prod Web-01",    type:"Web Server",  env:"Production",  ip:"192.168.1.100",   port:443, scanTypes:["port","web","ssl"],        dept:"IT운영팀", manager:"김보안",  priority:"critical", status:"completed", lastScan:daysAgo(2), riskScore:82 },
  { id:"A002", name:"Oracle-DB-01",   type:"DB Server",   env:"Production",  ip:"192.168.20.50",   port:1521, scanTypes:["port","db"],              dept:"DBA팀",    manager:"박DB",    priority:"critical", status:"completed", lastScan:daysAgo(2), riskScore:70 },
  { id:"A003", name:"Core-SW-01",     type:"Network",     env:"Production",  ip:"10.0.0.1",        port:22,  scanTypes:["port","network"],          dept:"네트워크팀", manager:"최망관", priority:"high",     status:"completed", lastScan:daysAgo(2), riskScore:56 },
  { id:"A004", name:"WAS-01",         type:"App Server",  env:"Production",  ip:"192.168.10.101",  port:8443, scanTypes:["port","web","ssl"],       dept:"IT운영팀", manager:"이관리",  priority:"high",     status:"scanning",  lastScan:daysAgo(2), riskScore:36 },
  { id:"A005", name:"Dev-Web-01",     type:"Web Server",  env:"Development", ip:"192.168.30.10",   port:80,  scanTypes:["web","ssl"],               dept:"개발팀",   manager:"정개발",  priority:"medium",   status:"pending",   lastScan:"-",          riskScore:15 },
  { id:"A006", name:"Mail-01",        type:"Mail Server", env:"Production",  ip:"192.168.50.10",   port:443, scanTypes:["port","ssl"],              dept:"IT운영팀", manager:"홍길동",  priority:"high",     status:"completed", lastScan:daysAgo(6), riskScore:44 },
  { id:"A007", name:"Backup-01",      type:"File Server", env:"Production",  ip:"192.168.60.10",   port:445, scanTypes:["port"],                    dept:"IT운영팀", manager:"홍길동",  priority:"medium",   status:"completed", lastScan:daysAgo(6), riskScore:28 },
  { id:"A008", name:"DR-Web-01",      type:"Web Server",  env:"DR",          ip:"10.100.1.100",    port:443, scanTypes:["port","web","ssl"],        dept:"IT운영팀", manager:"김보안",  priority:"medium",   status:"pending",   lastScan:"-",          riskScore:0  },
];

export const DEMO_FINDINGS = [
  { id:"PORT-00023",   title:"Telnet service exposed (port 23)",          titleKo:"Telnet 서비스 외부 노출 (포트 23)",          assetId:"A001", ip:"192.168.1.100",  sev:"crit",  cvss:9.8, repeat:3, firstSeen:daysAgo(183), status:"open",    desc:"평문 전송 방식으로 자격증명 노출 가능. 즉각적인 서비스 차단 필요.", rec:"Telnet 서비스 즉시 비활성화 후 SSH(포트 22)로 대체. 방화벽에서 포트 23 차단.", regulation:"전자금융감독규정 제17조, ISMS-P 2.10.1", scanType:"port" },
  { id:"DB-EXT-MYSQL", title:"MySQL 3306 externally accessible",          titleKo:"MySQL 3306 외부 접근 가능",                  assetId:"A001", ip:"192.168.1.100",  sev:"crit",  cvss:9.1, repeat:2, firstSeen:daysAgo(98), status:"open",    desc:"DB 포트가 방화벽 없이 외부에서 직접 접근 가능. 데이터 유출 및 SQL 공격 위험.", rec:"방화벽에서 3306 포트 차단. 허용된 내부 IP만 접근 가능하도록 ACL 설정.", regulation:"ISMS-P 2.6.1, 금융보안원 DB 보안 가이드", scanType:"db" },
  { id:"NET-TELNET-23",title:"Network device Telnet management",          titleKo:"네트워크 장비 Telnet 관리 인터페이스",         assetId:"A003", ip:"10.0.0.1",       sev:"crit",  cvss:9.0, repeat:0, firstSeen:daysAgo(2), status:"open",    desc:"네트워크 스위치의 Telnet 관리 포트 개방. 평문 통신으로 관리자 자격증명 스니핑 가능.", rec:"Telnet 비활성화, SSH v2로 전환. enable secret 설정 확인.", regulation:"금융보안원 네트워크 보안 가이드", scanType:"network" },
  { id:"PORT-03389",   title:"RDP port 3389 exposed",                     titleKo:"RDP 포트(3389) 외부 노출",                   assetId:"A001", ip:"192.168.1.100",  sev:"high",  cvss:8.8, repeat:0, firstSeen:daysAgo(2), status:"open",    desc:"원격 데스크탑 서비스 외부 노출. 브루트포스 및 BlueKeep 취약점 공격 경로.", rec:"RDP NLA(네트워크 수준 인증) 활성화. 포트 변경. VPN 뒤에 배치.", regulation:"전자금융감독규정 제14조", scanType:"port" },
  { id:"SSL-CERT-EXP", title:"SSL certificate expires in 24 days",        titleKo:"SSL 인증서 만료 24일 전",                    assetId:"A001", ip:"192.168.1.100",  sev:"high",  cvss:7.5, repeat:0, firstSeen:daysAgo(2), status:"urgent",  desc:`${daysLater(24)} SSL 인증서 만료 예정. 만료 시 서비스 장애 및 보안 경고 발생.", rec:"SSL 인증서 즉시 갱신. 자동 갱신 설정 검토 (Let's Encrypt 등).", regulation:"전자금융감독규정 제15조", scanType:"ssl" },
  { id:"NET-SNMP-PUB", title:"SNMP v1 community 'public' responding",     titleKo:"SNMP v1 기본 Community String 응답",         assetId:"A003", ip:"10.0.0.1",       sev:"med",   cvss:6.5, repeat:2, firstSeen:daysAgo(98), status:"open",    desc:"SNMP v1 기본 Community String 'public'으로 응답. 네트워크 토폴로지 정보 노출.", rec:"SNMPv3으로 업그레이드. 기본 Community String 변경. 불필요시 SNMP 비활성화.", regulation:"금융보안원 네트워크 장비 보안 가이드", scanType:"network" },
  { id:"WEB-HDR-HSTS", title:"Missing Strict-Transport-Security header",  titleKo:"HSTS 헤더 미설정",                           assetId:"A004", ip:"192.168.10.101", sev:"high",  cvss:7.4, repeat:2, firstSeen:daysAgo(98), status:"open",    desc:"HTTP Strict Transport Security 미설정으로 다운그레이드 공격 가능.", rec:"Strict-Transport-Security: max-age=31536000; includeSubDomains 설정.", regulation:"OWASP Top 10 A05, ISMS-P 2.7.1", scanType:"web" },
  { id:"WEB-HDR-CSP",  title:"Missing Content-Security-Policy header",    titleKo:"CSP 헤더 미설정",                            assetId:"A004", ip:"192.168.10.101", sev:"med",   cvss:6.1, repeat:0, firstSeen:daysAgo(2), status:"open",    desc:"CSP 미설정으로 XSS 공격 방어 정책 부재.", rec:"Content-Security-Policy 헤더 설정. default-src 'self' 이상으로 제한.", regulation:"OWASP Top 10 A03", scanType:"web" },
  { id:"SSL-TLS10",    title:"TLS 1.0 protocol supported",                titleKo:"TLS 1.0 프로토콜 지원",                     assetId:"A001", ip:"192.168.1.100",  sev:"high",  cvss:7.4, repeat:0, firstSeen:daysAgo(2), status:"open",    desc:"구버전 TLS 1.0 프로토콜 활성화. BEAST, POODLE 취약점 대상.", rec:"TLS 1.0/1.1 비활성화. TLS 1.2 이상만 허용.", regulation:"전자금융감독규정 제15조, ISMS-P 2.7.1", scanType:"ssl" },
  { id:"PORT-SMB445",  title:"SMB port 445 externally exposed",           titleKo:"SMB 포트(445) 외부 노출",                   assetId:"A007", ip:"192.168.60.10",  sev:"crit",  cvss:9.3, repeat:0, firstSeen:daysAgo(6), status:"open",    desc:"SMB 포트 외부 노출. EternalBlue(MS17-010) 등 랜섬웨어 침투 경로.", rec:"방화벽에서 445 포트 완전 차단. 최신 보안 패치 적용.", regulation:"전자금융감독규정 제17조", scanType:"port" },
  { id:"WEB-ADMIN",    title:"Admin interface exposed at /admin",          titleKo:"관리자 경로(/admin) 외부 노출",              assetId:"A006", ip:"192.168.50.10",  sev:"high",  cvss:8.1, repeat:0, firstSeen:daysAgo(6), status:"open",    desc:"HTTP 200 응답하는 관리자 인터페이스 발견. 무단 접근 시도 위험.", rec:"IP 기반 접근 제어 적용. VPN 뒤에 배치. 강력한 인증 설정.", regulation:"OWASP Top 10 A01", scanType:"web" },
];

export const DEMO_CVE = [
  { id:"CVE-2026-1337", cvss:9.8, sev:"crit",  product:"Apache 2.4.x",       desc:"원격 코드 실행 취약점. 인증 없이 임의 코드 실행 가능.", affectedAssets:["A001","A006"], status:"patch_now",  published:daysAgo(2), patch:"Apache 2.4.62 이상으로 업그레이드" },
  { id:"CVE-2026-0812", cvss:8.1, sev:"high",  product:"Cisco IOS 16.x",     desc:"원격 서비스 거부 및 권한 상승 취약점.",               affectedAssets:["A003"],         status:"in_review",  published:daysAgo(4), patch:"IOS 16.12.8 이상 업데이트" },
  { id:"CVE-2026-0571", cvss:7.5, sev:"high",  product:"OpenSSL 3.2.x",      desc:"TLS 핸드셰이크 처리 메모리 고갈 취약점.",             affectedAssets:["A001","A004","A006","A008"], status:"analysis",   published:daysAgo(5), patch:"OpenSSL 3.2.4 이상 업데이트" },
  { id:"CVE-2025-4521", cvss:7.2, sev:"high",  product:"MySQL 8.0.x",        desc:"원격 데이터 변조 취약점.",                            affectedAssets:[],               status:"clear",      published:daysAgo(27), patch:"MySQL 8.0.37 이상" },
  { id:"CVE-2025-3890", cvss:6.8, sev:"med",   product:"Windows Server 2022",desc:"권한 상승 취약점. 로컬 공격자 시스템 권한 획득.",       affectedAssets:["A001","A007"],  status:"pending",    published:daysAgo(32), patch:`${daysAgo(32).slice(0,7)} 월례 보안 업데이트` },
  { id:"CVE-2025-2291", cvss:5.9, sev:"med",   product:"nginx 1.24.x",       desc:"HTTP 요청 처리 오류로 서비스 거부 가능.",              affectedAssets:[],               status:"clear",      published:daysAgo(47), patch:"nginx 1.26.0 이상" },
];

export const DEMO_NEWS = [
  { id:1, source:"KrCERT",   sourceBg:"#450A0A", sourceColor:"#FCA5A5", tag:"CRITICAL",    title:"Apache HTTP Server 2.4.x 원격 코드 실행 취약점 긴급 패치 권고 (CVE-2026-1337)", meta:"CVSS 9.8 · 국내 약 2,300개 서버 영향 · ${daysAgo(2)} 14:20`, affected:true, url:"https://www.krcert.or.kr", date:daysAgo(2) },
  { id:2, source:"금융보안원", sourceBg:"#0C1A3A", sourceColor:"#93C5FD", tag:"REPORT",      title:"2026년 1분기 금융권 사이버 위협 동향 — AI 기반 공격 43% 증가", meta:"피싱·랜섬웨어 주요 벡터 · 금융기관 타깃 집중 · ${daysAgo(2)} 10:00`, url:"https://www.fsec.or.kr", date:daysAgo(2) },
  { id:3, source:"KISA",     sourceBg:"#052E16", sourceColor:"#86EFAC", tag:"ADVISORY",    title:"MS Exchange Server 제로데이 국내 금융기관 타깃 공격 확인", meta:"Exchange 2019/2016 영향 · 즉시 패치 권고 · ${daysAgo(3)} 16:30`, url:"https://www.kisa.or.kr", date:daysAgo(3) },
  { id:4, source:"CISA",     sourceBg:"#2E1065", sourceColor:"#D8B4FE", tag:"KEV UPDATE",  title:"Known Exploited Vulnerabilities 카탈로그 8건 신규 추가", meta:"Cisco IOS · VMware ESXi 포함 · 21일 내 패치 의무 · ${daysAgo(4)} 22:00`, url:"https://www.cisa.gov", date:daysAgo(4) },
  { id:5, source:"NVD",      sourceBg:"#1C1000", sourceColor:"#FCD34D", tag:"CVE",         title:"OpenSSL 3.2.x 서비스 거부 취약점 공개 (CVE-2026-0571)", meta:"CVSS 7.5 · TLS 핸드셰이크 메모리 고갈 · ${daysAgo(5)} 18:00`, url:"https://nvd.nist.gov", date:daysAgo(5) },
  { id:6, source:"KISA",     sourceBg:"#052E16", sourceColor:"#86EFAC", tag:"NOTICE",      title:"랜섬웨어 피해 예방을 위한 중요 인프라 보안 강화 권고", meta:"금융·의료·에너지 분야 특별 주의 · ${daysAgo(6)} 09:00`, url:"https://www.kisa.or.kr", date:daysAgo(6) },
  { id:7, source:"Bleeping", sourceBg:"#2C1A00", sourceColor:"#FED7AA", tag:"NEWS",        title:"LockBit 4.0 랜섬웨어, 아시아 금융기관 공격 캠페인 활발", meta:"한국 금융기관 4곳 피해 확인 · VPN 취약점 경로 · ${daysAgo(7)} 20:00`, url:"https://www.bleepingcomputer.com", date:daysAgo(7) },
  { id:8, source:"KrCERT",   sourceBg:"#450A0A", sourceColor:"#FCA5A5", tag:"PATCH",       title:"Windows 2026-04 정기 보안 업데이트 — 78개 취약점 패치", meta:"긴급 3개, 중요 45개 포함 · ${daysAgo(7)} 03:00`, url:"https://www.krcert.or.kr", date:daysAgo(7) },
];

export const DEMO_HISTORY = [
  { id:"SCAN-0414-001", target:"Prod Web-01",    ip:"192.168.1.100",  date:daysAgoHM(2,14,20), duration:"4m 32s", status:"completed", crit:3, high:4, med:2, low:1 },
  { id:"SCAN-0414-002", target:"Oracle-DB-01",  ip:"192.168.20.50",  date:daysAgoHM(2,13,10), duration:"2m 18s", status:"completed", crit:1, high:2, med:3, low:2 },
  { id:"SCAN-0410-001", target:"Mail-01",        ip:"192.168.50.10",  date:daysAgoHM(6,10,0), duration:"3m 45s", status:"completed", crit:0, high:2, med:4, low:3 },
  { id:"SCAN-0410-002", target:"Backup-01",      ip:"192.168.60.10",  date:daysAgoHM(6,9,30), duration:"1m 52s", status:"completed", crit:1, high:1, med:2, low:1 },
  { id:"SCAN-0108-001", target:"Prod Web-01",    ip:"192.168.1.100",  date:daysAgoHM(98,2,0), duration:"5m 10s", status:"completed", crit:2, high:5, med:3, low:2 },
];

// ── API 헬퍼 ──────────────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  try {
    const res = await fetch(`${API}${path}`, {
      headers: { "Content-Type": "application/json" },
      signal: AbortSignal.timeout(5000),
      ...opts,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } catch {
    return null;  // 백엔드 없으면 null → 데모 폴백
  }
}

export async function fetchAssets() {
  const data = await apiFetch("/api/assets");
  return data || DEMO_ASSETS;
}

export async function fetchFindings() {
  const data = await apiFetch("/api/findings");
  return data || DEMO_FINDINGS;
}

export async function fetchCVE() {
  const data = await apiFetch("/api/cve");
  return data || DEMO_CVE;
}

export async function fetchNews() {
  const data = await apiFetch("/api/news");
  return data || DEMO_NEWS;
}

export async function startScan(targets) {
  const data = await apiFetch("/api/scan/start", {
    method: "POST",
    body: JSON.stringify({ targets }),
  });
  return data;
}

export async function fetchScanStatus(jobId) {
  const data = await apiFetch(`/api/scan/status/${jobId}`);
  return data;
}
