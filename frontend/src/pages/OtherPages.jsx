// pages/OtherPages.jsx — 실제 백엔드 연동 (Findings/Alerts/Assets/Threat/CVE/Compliance/Reports/History/Upload)
import API_BASE from "../hooks/apiConfig.js";
import { OrgContext } from "../App.jsx";
import { SYSTEM_NAME_PRESETS, PC_ITEMS } from "../config/assetPresets.js";
import React, { useState, useEffect } from "react";
import { useLang } from "../i18n/LangContext";
import { Badge, RepBadge, RBar, Prog, Card, CardHd, Th, Td, CheckTd, Chip, Spinner, EmptyState, Pagination, DeleteConfirm, SearchBar, FilterSelect, TableActions, Btn, InfoTip } from "../components/UI";
import {
  fetchFindings, fetchFindingStats, fetchRepeatFindings, resolveFindings, deleteFindings,
  fetchAlerts, fetchAlertConfigs, updateAlertConfig, markAlertsRead,
  fetchAssets, createAsset, deleteAsset, updateAsset,
  fetchNews, triggerNewsFetch,
  fetchCVE,
  fetchCompliance,
  generateReport, fetchScanHistory,
  uploadAssets, fetchUploadHistory,
} from "../hooks/useAPI";

// ── 공통 로딩/에러 래퍼 ──────────────────────────────────────────
function PageWrap({ loading, error, onRetry, children }) {
  if (loading) return (
    <div style={{ display:"flex", alignItems:"center", justifyContent:"center", height:300, gap:12, color:"var(--txt3)" }}>
      <Spinner /> 로딩 중...
    </div>
  );
  if (error) return (
    <div style={{ padding:"30px 22px" }}>
      <div style={{ background:"#1C0A0A", border:"1px solid #7F1D1D", borderRadius:10, padding:"16px" }}>
        <div style={{ color:"#FCA5A5", fontWeight:600, marginBottom:6 }}>오류 발생</div>
        <div style={{ color:"#FDA4AF", fontSize:13, marginBottom:10 }}>{error}</div>
        <button onClick={onRetry} style={{ padding:"6px 14px", borderRadius:5, border:"1px solid #1E3A8A", background:"#0C1A3A", color:"#93C5FD", fontSize:13, cursor:"pointer" }}>다시 시도</button>
      </div>
    </div>
  );
  return children;
}

const SEV_MAP  = { critical:"crit", high:"high", medium:"med", low:"low" };
const SEV_LBL  = { critical:"긴급", high:"고위험", medium:"중위험", low:"저위험", info:"정보" };
const SEV_COL  = { critical:"#F87171", high:"#FB923C", medium:"#FDE047", low:"#4ADE80" };

// ═══════════════════════════════════════════════════════════════
// FINDINGS
// ═══════════════════════════════════════════════════════════════

// ════════════════════════════════════════════════════════════════
// 취약점 상세 패널 — 왼쪽: 현황 분석 / 오른쪽: 단계별 조치 가이드
// ════════════════════════════════════════════════════════════════

// 취약점 유형별 상세 가이드 데이터
const VULN_GUIDES = {

  // ═══ PORT-00022: SSH ═══════════════════════════════════════════
  "PORT-00022": {
    risk: "SSH 22번 포트 외부 노출 시 자동화 브루트포스 공격 대상이 됩니다. OpenSSH 구버전(8.8 이하)은 CVE-2023-38408 원격 코드 실행 취약점이 있습니다. 금융기관에서는 SSH를 VPN 경유로만 허용해야 합니다.",
    check: [
      { label:"SSH 버전 확인",
        cmd:"ssh -V",
        success:"OpenSSH_9.x 이상이면 ✅ 버전 안전",
        fail:"8.8 이하면 → STEP 1 업데이트 먼저 진행" },
      { label:"현재 접속 세션 확인 (비인가 세션 있으면 즉시 차단)",
        cmd:"who\nlast | head -10",
        success:"본인 세션만 보이면 ✅ 정상",
        fail:"모르는 IP 세션 있으면 → 즉시 kill -9 [PID] 후 비밀번호 변경" },
      { label:"로그인 실패 이력 (브루트포스 공격 여부)",
        cmd:"grep 'Failed password' /var/log/auth.log | tail -20",
        success:"실패 이력 없거나 소수이면 ✅ 정상",
        fail:"동일 IP에서 반복 실패 → Fail2Ban 적용 또는 해당 IP 방화벽 차단" },
      { label:"방화벽 차단 규칙 확인 (외부 차단 여부)",
        cmd:"netsh advfirewall firewall show rule name=Block_SSH_22",
        success:"규칙이 표시되면 ✅ 차단 적용됨",
        fail:"아무것도 안 나오면 → STEP 3 실행" },
    ],
    danger_versions: ["OpenSSH 8.8 이하", "OpenSSH 7.x 이하 (EOL)"],
    good_version: "OpenSSH 9.0 이상",
    steps: [
      { no:1, title:"SSH 버전 업데이트 (Linux)",
        cmd:"sudo apt-get update && sudo apt-get install -y openssh-server",
        note:"업데이트 후 서비스 재시작: sudo systemctl restart sshd" },
      { no:2, title:"SSH 보안 설정 강화 (설정 파일 수정 후 재시작 필수)",
        cmd:"# /etc/ssh/sshd_config 파일에 아래 내용 적용\nPermitRootLogin no\nPasswordAuthentication no\nMaxAuthTries 3\nLoginGraceTime 30\nAllowUsers [허용할계정명만]",
        note:"설정 저장 후 반드시 재시작: sudo systemctl restart sshd — 재시작 전 현재 세션 유지" },
      { no:3, title:"방화벽에서 외부 SSH 차단 (내부망만 허용)",
        cmd:"netsh advfirewall firewall add rule name=Block_SSH_22 dir=in action=block protocol=TCP localport=22",
        note:"⚠ 관리자 권한 CMD 필요. 재부팅 불필요, 즉시 적용. VPN 경유 접속만 허용 권장" },
      { no:4, title:"적용 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_SSH_22",
        note:"규칙이 표시되면 차단 성공. 표시 안 되면 STEP 3 관리자 CMD에서 재실행" },
    ]
  },

  // ═══ PORT-00445: SMB ═══════════════════════════════════════════
  "PORT-00445": {
    risk: "WannaCry·NotPetya 랜섬웨어의 주요 진입 경로입니다. EternalBlue(MS17-010) 취약점을 이용해 인증 없이 원격 코드 실행이 가능합니다. 445 포트가 외부에 열려있으면 자동 스캐너에 의해 수 분 내에 공격받을 수 있습니다.",
    check: [
      { label:"SMBv1 비활성화 확인 (False여야 ✅ 정상)",
        cmd:"Get-SmbServerConfiguration | Select EnableSMB1Protocol",
        success:"EnableSMB1Protocol: False 이면 ✅ 비활성화 완료",
        fail:"True 이면 → STEP 1 실행 후 재부팅 필수" },
      { label:"MS17-010 패치 확인",
        cmd:"Get-HotFix -Id KB4012212\nGet-HotFix -Id KB4012215",
        success:"패치 정보가 표시되면 ✅ 패치 적용됨",
        fail:"아무것도 안 나오면 → Windows Update에서 즉시 보안 업데이트 실행" },
      { label:"방화벽 차단 규칙 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_SMB_445",
        success:"규칙이 표시되면 ✅ 외부 차단 적용됨",
        fail:"아무것도 안 나오면 → STEP 3 실행" },
      { label:"외부에서 차단 확인 (다른 PC에서 실행)",
        cmd:"Test-NetConnection -ComputerName [서버IP] -Port 445",
        success:"TcpTestSucceeded: False 이면 ✅ 차단 성공",
        fail:"TcpTestSucceeded: True 이면 → 방화벽 규칙 재확인. netsh 말고 Windows Defender 방화벽 GUI에서도 적용 필요" },
    ],
    danger_versions: ["Windows 7/Server 2008 MS17-010 미패치", "SMBv1 활성화 상태"],
    good_version: "Windows 10/Server 2016 이상 + MS17-010 패치 + SMBv1 비활성화",
    steps: [
      { no:1, title:"SMBv1 비활성화 (관리자 PowerShell에서 실행, 재부팅 필요)",
        cmd:"Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force",
        note:"⚠ 관리자 PowerShell 필요. 실행 후 재부팅해야 완전히 적용됨. 재부팅 전 업무 영향 확인" },
      { no:2, title:"레지스트리 이중 비활성화 후 재부팅",
        cmd:"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name SMB1 -Value 0\nRestart-Computer -Force",
        note:"⚠ 관리자 PowerShell 필요. Restart-Computer 실행 시 즉시 재부팅됨 — 저장 중인 작업 먼저 닫을 것" },
      { no:3, title:"방화벽 외부 차단 (관리자 CMD에서 실행)",
        cmd:"netsh advfirewall firewall add rule name=Block_SMB_445 dir=in action=block protocol=TCP localport=445",
        note:"⚠ 관리자 CMD 필요. 재부팅 불필요, 즉시 적용" },
      { no:4, title:"적용 확인",
        cmd:"Get-SmbServerConfiguration | Select EnableSMB1Protocol\nnetsh advfirewall firewall show rule name=Block_SMB_445",
        note:"EnableSMB1Protocol: False + 규칙 표시 = 완료. 재부팅 후 False 확인 필수" },
    ]
  },

  // ═══ PORT-00135: RPC ═══════════════════════════════════════════
  "PORT-00135": {
    risk: "DCOM/RPC 원격 코드 실행 취약점 경로입니다. 내부망 횡이동(Lateral Movement)의 주요 경로이며, MS03-026 등 구버전 취약점 대상입니다. netstat에 LISTENING이 보이는 건 정상입니다 — RPC는 Windows 내부 서비스이므로 종료 불가. 외부 방화벽 차단만 하면 됩니다.",
    check: [
      { label:"방화벽 차단 규칙 확인 (이게 핵심)",
        cmd:"netsh advfirewall firewall show rule name=Block_RPC_135",
        success:"규칙 내용이 표시되면 ✅ 차단 완료. netstat에 LISTENING이 보여도 정상",
        fail:"아무것도 안 나오면 → STEP 1을 관리자 CMD에서 재실행" },
      { label:"외부 차단 확인 (다른 PC에서 실행 — 이게 최종 확인)",
        cmd:"Test-NetConnection -ComputerName [서버IP] -Port 135",
        success:"TcpTestSucceeded: False 이면 ✅ 외부 차단 성공",
        fail:"TcpTestSucceeded: True 이면 → Windows Defender 방화벽 고급 설정 GUI에서도 인바운드 규칙 추가 필요" },
      { label:"※ 이 결과는 정상입니다 — netstat LISTENING은 무시",
        cmd:"netstat -ano | findstr :135",
        success:"LISTENING 표시는 정상입니다. RPC 서비스는 Windows 내부적으로 필요하므로 종료 불가. 방화벽 차단만 하면 외부 접근이 막힘",
        fail:"" },
    ],
    danger_versions: ["Windows 미패치 상태 (MS03-026, MS03-039)"],
    good_version: "방화벽 인바운드 차단 + 최신 보안 패치 적용",
    steps: [
      { no:1, title:"방화벽 차단 (반드시 관리자 CMD에서 실행)",
        cmd:"netsh advfirewall firewall add rule name=Block_RPC_135 dir=in action=block protocol=TCP localport=135",
        note:"⚠ 관리자 CMD 필요 — 시작버튼 우클릭 → 명령 프롬프트(관리자). 재부팅 불필요, 즉시 적용" },
      { no:2, title:"즉시 확인 (같은 관리자 CMD에서)",
        cmd:"netsh advfirewall firewall show rule name=Block_RPC_135",
        note:"규칙 내용이 표시되면 성공. 표시 안 되면 STEP 1을 다시 실행 (관리자 CMD인지 확인)" },
      { no:3, title:"Windows 보안 패치 확인",
        cmd:"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10",
        note:"⚠ 관리자 PowerShell 필요. MS03-026 등 RPC 관련 패치 적용 여부 확인" },
    ]
  },

  // ═══ PORT-00139: NetBIOS ════════════════════════════════════════
  "PORT-00139": {
    risk: "NetBIOS over TCP/IP — SMB 공격 보조 경로이자 내부망 정보(컴퓨터명, 공유 폴더) 노출 경로입니다. 445 포트와 함께 차단해야 효과적입니다.",
    check: [
      { label:"방화벽 차단 규칙 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_NetBIOS_139",
        success:"규칙이 표시되면 ✅ 차단 완료",
        fail:"표시 안 되면 → STEP 1 실행" },
      { label:"NetBT 서비스 비활성화 확인 (Disabled여야 완전 차단)",
        cmd:"Get-Service -Name NetBT | Select Status, StartType",
        success:"StartType: Disabled 이면 ✅ 완전 비활성화 완료",
        fail:"StartType: Automatic 이면 → STEP 2 실행 후 재부팅 필요" },
      { label:"139 포트 확인 (STEP 2 완료 후 LISTENING이 사라져야 함)",
        cmd:"netstat -ano | findstr :139",
        success:"아무것도 안 나오면 ✅ 포트 완전히 닫힘",
        fail:"LISTENING이 아직 보이면 → 재부팅 미실시. Restart-Computer 실행" },
    ],
    danger_versions: ["NetBT 활성화 + 외부 노출 상태"],
    good_version: "방화벽 차단 + NetBT 비활성화 + 재부팅 완료",
    steps: [
      { no:1, title:"방화벽 차단 (관리자 CMD, 즉시 적용)",
        cmd:"netsh advfirewall firewall add rule name=Block_NetBIOS_139 dir=in action=block protocol=TCP localport=139",
        note:"⚠ 관리자 CMD 필요. 재부팅 불필요" },
      { no:2, title:"NetBT 서비스 비활성화 + 재부팅 (완전 차단)",
        cmd:"Set-Service -Name NetBT -StartupType Disabled\nStop-Service -Name NetBT -Force\nRestart-Computer -Force",
        note:"⚠ 관리자 PowerShell 필요. Restart-Computer 실행 시 즉시 재부팅됨 — 저장 중인 작업 먼저 닫을 것. 재부팅 후 139 포트 사라짐" },
      { no:3, title:"적용 확인 (재부팅 후)",
        cmd:"Get-Service -Name NetBT | Select Status, StartType\nnetstat -ano | findstr :139",
        note:"Status: Stopped, StartType: Disabled + 포트 없음 = 완료" },
    ]
  },

  // ═══ PORT-01433: MSSQL ══════════════════════════════════════════
  "PORT-01433": {
    risk: "MSSQL DB가 인터넷에 직접 노출됩니다. SA(시스템 관리자) 계정 브루트포스, 데이터 탈취, xp_cmdshell을 통한 OS 명령 실행이 가능합니다. 금감원 IT검사에서 DB 외부 노출은 즉시 시정 대상입니다.",
    check: [
      { label:"SA 계정 비활성화 확인 (is_disabled=1이어야 ✅)",
        cmd:"sqlcmd -Q \"SELECT name, is_disabled FROM sys.sql_logins WHERE name='sa'\"",
        success:"is_disabled: 1 이면 ✅ SA 비활성화 완료",
        fail:"is_disabled: 0 이면 → STEP 1 즉시 실행" },
      { label:"방화벽 차단 규칙 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_MSSQL_1433",
        success:"규칙이 표시되면 ✅ 외부 차단 완료",
        fail:"표시 안 되면 → STEP 2 실행" },
      { label:"xp_cmdshell 비활성화 확인 (0이어야 ✅)",
        cmd:"sqlcmd -Q \"SELECT value FROM sys.configurations WHERE name='xp_cmdshell'\"",
        success:"value: 0 이면 ✅ 비활성화 완료",
        fail:"value: 1 이면 → STEP 3 즉시 실행 (OS 명령 실행 취약점)" },
      { label:"외부 차단 확인 (다른 PC에서 실행)",
        cmd:"Test-NetConnection -ComputerName [서버IP] -Port 1433",
        success:"TcpTestSucceeded: False 이면 ✅ 외부 차단 성공",
        fail:"TcpTestSucceeded: True 이면 → 방화벽 규칙 재확인 및 STEP 2 재실행" },
    ],
    danger_versions: ["SQL Server 2014 이하 (지원 종료)", "SA 계정 활성화 상태", "xp_cmdshell 활성화 상태"],
    good_version: "SQL Server 2019/2022 + SA 비활성화 + 외부 차단",
    steps: [
      { no:1, title:"SA 계정 비활성화 (SSMS 또는 sqlcmd에서 실행)",
        cmd:"ALTER LOGIN sa DISABLE;\nGO",
        note:"SA 계정은 사용하지 않더라도 활성화 상태면 공격 대상. 비활성화 즉시 적용됨" },
      { no:2, title:"방화벽 1433 외부 차단 (관리자 CMD)",
        cmd:"netsh advfirewall firewall add rule name=Block_MSSQL_1433 dir=in action=block protocol=TCP localport=1433",
        note:"⚠ 관리자 CMD 필요. 재부팅 불필요, 즉시 적용. 앱 서버 IP만 허용하는 방식 권장" },
      { no:3, title:"xp_cmdshell 비활성화 (SSMS에서 실행)",
        cmd:"EXEC sp_configure 'show advanced options', 1;\nRECONFIGURE;\nEXEC sp_configure 'xp_cmdshell', 0;\nRECONFIGURE;\nGO",
        note:"OS 명령 실행 기능 완전 차단. 즉시 적용됨" },
      { no:4, title:"최소 권한 앱 계정 생성 (SA 대신 사용)",
        cmd:"CREATE LOGIN appuser WITH PASSWORD='AppStr0ng!Pass2024';\nUSE [데이터베이스명];\nCREATE USER appuser FOR LOGIN appuser;\nGRANT SELECT, INSERT, UPDATE, DELETE ON SCHEMA::dbo TO appuser;\nGO",
        note:"앱 연결은 반드시 최소 권한 계정만 사용. SA 계정으로 앱 연결 금지" },
    ]
  },

  // ═══ PORT-03306: MySQL ══════════════════════════════════════════
  "PORT-03306": {
    risk: "MySQL DB가 인터넷에 직접 노출됩니다. root 계정 원격 접속 허용 시 전체 DB 장악, 데이터 탈취 및 삭제가 가능합니다. 개인정보보호법 위반으로 최대 매출의 3% 과징금이 부과될 수 있습니다.",
    check: [
      { label:"root 원격 접속 차단 확인 (localhost만 나와야 ✅)",
        cmd:"mysql -u root -p -e \"SELECT user, host FROM mysql.user WHERE user='root';\"",
        success:"host에 'localhost' 또는 '127.0.0.1'만 있으면 ✅ 원격 차단 완료",
        fail:"host에 '%' 또는 외부 IP가 있으면 → STEP 1 즉시 실행" },
      { label:"bind-address 설정 확인 (127.0.0.1이어야 ✅)",
        cmd:"grep bind-address /etc/mysql/mysql.conf.d/mysqld.cnf",
        success:"bind-address = 127.0.0.1 이면 ✅ 외부 연결 원천 차단",
        fail:"없거나 0.0.0.0이면 → STEP 3 설정 후 재시작 필요" },
      { label:"방화벽 차단 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_MySQL_3306",
        success:"규칙이 표시되면 ✅ 차단 완료",
        fail:"표시 안 되면 → STEP 2 실행" },
      { label:"외부 차단 확인 (다른 PC에서)",
        cmd:"Test-NetConnection -ComputerName [서버IP] -Port 3306",
        success:"TcpTestSucceeded: False 이면 ✅ 외부 차단 성공",
        fail:"TcpTestSucceeded: True 이면 → bind-address 설정 + 방화벽 규칙 모두 적용 필요" },
    ],
    danger_versions: ["MySQL 5.7 이하 (2023년 지원 종료)", "root 원격 접속 허용 상태", "bind-address 미설정"],
    good_version: "MySQL 8.0.34 이상 + root 원격 차단 + bind-address=127.0.0.1",
    steps: [
      { no:1, title:"root 원격 접속 계정 삭제 (MySQL 내에서 실행)",
        cmd:"DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1');\nFLUSH PRIVILEGES;",
        note:"실행 즉시 적용됨. 현재 연결된 root 원격 세션도 다음 연결부터 차단됨" },
      { no:2, title:"방화벽 3306 외부 차단 (관리자 CMD)",
        cmd:"netsh advfirewall firewall add rule name=Block_MySQL_3306 dir=in action=block protocol=TCP localport=3306",
        note:"⚠ 관리자 CMD 필요. 재부팅 불필요, 즉시 적용" },
      { no:3, title:"bind-address 설정 (설정 파일 수정 후 재시작 필요)",
        cmd:"# /etc/mysql/mysql.conf.d/mysqld.cnf 파일 수정\n[mysqld]\nbind-address = 127.0.0.1\n\n# 수정 후 MySQL 재시작\nsudo systemctl restart mysql",
        note:"재시작 후 3306 포트가 외부에서 완전히 차단됨. 재시작 시 서비스 약 5~10초 중단" },
      { no:4, title:"앱 전용 최소 권한 계정 생성",
        cmd:"CREATE USER 'appuser'@'앱서버IP' IDENTIFIED BY 'Str0ng!Pass2024';\nGRANT SELECT, INSERT, UPDATE, DELETE ON 데이터베이스명.* TO 'appuser'@'앱서버IP';\nFLUSH PRIVILEGES;",
        note:"앱 서버 IP를 정확히 지정. root 계정으로 앱 연결 절대 금지" },
    ]
  },

  // ═══ PORT-03389: RDP ════════════════════════════════════════════
  "PORT-03389": {
    risk: "RDP(원격 데스크탑) 포트가 인터넷에 직접 노출됩니다. 자동화 브루트포스 도구가 수 분 내에 공격을 시도합니다. BlueKeep(CVE-2019-0708) 등 RDP 취약점은 인증 없이 원격 코드 실행이 가능합니다. 랜섬웨어 그룹의 최선호 초기 침투 경로입니다.",
    check: [
      { label:"방화벽 차단 규칙 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_RDP_3389",
        success:"규칙이 표시되면 ✅ 외부 차단 완료",
        fail:"표시 안 되면 → STEP 1 즉시 실행" },
      { label:"외부 차단 확인 (다른 PC에서 실행 — 최종 확인)",
        cmd:"Test-NetConnection -ComputerName [서버IP] -Port 3389",
        success:"TcpTestSucceeded: False 이면 ✅ 차단 성공",
        fail:"TcpTestSucceeded: True 이면 → Windows Defender 방화벽 고급 설정에서도 인바운드 3389 차단 규칙 추가" },
      { label:"NLA(네트워크 수준 인증) 활성화 확인",
        cmd:"Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication | Select UserAuthentication",
        success:"UserAuthentication: 1 이면 ✅ NLA 활성화 완료",
        fail:"0 이면 → STEP 3 실행" },
    ],
    danger_versions: ["Windows Server 2008/2012 BlueKeep 미패치", "NLA 비활성화 상태"],
    good_version: "외부 차단 + VPN 경유 + NLA 활성화 + MFA",
    steps: [
      { no:1, title:"방화벽 외부 RDP 차단 (관리자 CMD)",
        cmd:"netsh advfirewall firewall add rule name=Block_RDP_3389 dir=in action=block protocol=TCP localport=3389",
        note:"⚠ 관리자 CMD 필요. 재부팅 불필요, 즉시 적용. 원격 작업 중이면 차단 전 다른 접속 방법 확보 필수" },
      { no:2, title:"적용 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_RDP_3389",
        note:"규칙이 표시되면 완료. VPN 경유 접속만 허용하도록 네트워크 구성 변경 권장" },
      { no:3, title:"NLA(네트워크 수준 인증) 활성화",
        cmd:"Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1",
        note:"⚠ 관리자 PowerShell 필요. 즉시 적용됨. 이후 RDP 접속 시 Windows 인증 먼저 요구" },
      { no:4, title:"BlueKeep 패치 확인",
        cmd:"Get-HotFix -Id KB4499175\nGet-HotFix -Id KB4499180",
        note:"패치 정보가 표시되면 완료. 없으면 Windows Update에서 즉시 적용" },
    ]
  },

  // ═══ PORT-00023: Telnet ══════════════════════════════════════════
  "PORT-00023": {
    risk: "Telnet은 모든 통신이 평문(암호화 없음)으로 전송됩니다. 동일 네트워크 구간에서 패킷 스니핑으로 ID/비밀번호를 그대로 탈취할 수 있습니다. 금감원 검사에서 즉시 시정 대상이며, SSH로 교체해야 합니다.",
    check: [
      { label:"Telnet 서비스 상태 확인 (Stopped/Disabled여야 ✅)",
        cmd:"Get-Service -Name TlntSvr | Select Status, StartType",
        success:"Status: Stopped + StartType: Disabled 이면 ✅ 완전 비활성화",
        fail:"Status: Running 이면 → STEP 1 즉시 실행" },
      { label:"방화벽 차단 확인",
        cmd:"netsh advfirewall firewall show rule name=Block_Telnet_23",
        success:"규칙이 표시되면 ✅ 차단 완료",
        fail:"표시 안 되면 → STEP 2 실행" },
      { label:"23 포트 확인 (아무것도 없어야 ✅)",
        cmd:"netstat -ano | findstr :23",
        success:"아무것도 안 나오면 ✅ 포트 완전히 닫힘",
        fail:"LISTENING 있으면 → STEP 1로 서비스 중지 후 재확인" },
    ],
    danger_versions: ["Telnet 서비스 활성화 상태"],
    good_version: "Telnet 비활성화 + SSH 사용",
    steps: [
      { no:1, title:"Telnet 서비스 비활성화 (관리자 PowerShell)",
        cmd:"Stop-Service -Name TlntSvr -Force\nSet-Service -Name TlntSvr -StartupType Disabled",
        note:"⚠ 관리자 PowerShell 필요. 재부팅 불필요, 즉시 적용. 서비스 중지 후 23 포트 사라짐" },
      { no:2, title:"방화벽 차단 (이중 차단)",
        cmd:"netsh advfirewall firewall add rule name=Block_Telnet_23 dir=in action=block protocol=TCP localport=23",
        note:"⚠ 관리자 CMD 필요. 서비스 중지와 방화벽 차단 모두 적용 권장" },
      { no:3, title:"SSH 설치 및 활성화 (대체 수단)",
        cmd:"Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0\nStart-Service sshd\nSet-Service -Name sshd -StartupType Automatic",
        note:"⚠ 관리자 PowerShell 필요. OpenSSH 설치 후 22번 포트로 암호화 접속 가능" },
      { no:4, title:"적용 확인",
        cmd:"Get-Service -Name TlntSvr | Select Status\nnetstat -ano | findstr :23",
        note:"Stopped + 포트 없음 = 완료" },
    ]
  },

  // ═══ SSL-CONN-FAIL ═══════════════════════════════════════════════
  "SSL-CONN-FAIL": {
    risk: "SSL/TLS 연결 자체가 실패한 상태입니다. HTTPS가 동작하지 않거나 인증서 오류, 포트 미개방, TLS 구버전(1.0/1.1) 사용 등이 원인입니다. 암호화 통신이 불가하여 데이터가 평문으로 전송됩니다.",
    check: [
      { label:"443 포트 열림 확인 (LISTENING이 있어야 ✅)",
        cmd:"netstat -ano | findstr :443",
        success:"LISTENING이 표시되면 ✅ 포트 열려 있음",
        fail:"아무것도 안 나오면 → 웹 서버 서비스 중지 상태. IIS/Apache 서비스 재시작 필요" },
      { label:"SSL 인증서 유효성 확인",
        cmd:"openssl s_client -connect [호스트]:443 -brief 2>&1",
        success:"Certificate chain 및 만료일이 표시되면 ✅ 인증서 정상",
        fail:"SSL handshake 실패 또는 self signed 오류 → 인증서 교체 필요" },
      { label:"TLS 버전 확인 (1.2 이상이어야 ✅)",
        cmd:"openssl s_client -connect [호스트]:443 -tls1_2 2>&1 | findstr Protocol",
        success:"TLSv1.2 또는 TLSv1.3 표시되면 ✅ 안전한 버전 사용 중",
        fail:"연결 실패 또는 TLSv1.0/1.1이면 → 웹 서버 TLS 설정 변경 필요" },
    ],
    danger_versions: ["자체 서명 인증서", "만료된 인증서", "TLSv1.0/1.1 사용"],
    good_version: "TLS 1.2 이상 + 공인 CA 인증서 + 유효기간 내",
    steps: [
      { no:1, title:"HTTPS 서비스 상태 확인",
        cmd:"Get-Service -Name W3SVC | Select Status\nnetstat -ano | findstr :443",
        note:"IIS 서비스(W3SVC) 실행 중 + 443 포트 LISTENING = 정상 동작" },
      { no:2, title:"인증서 교체 (만료/자체서명인 경우)",
        cmd:"# IIS 관리자 → 서버 인증서 → 인증서 요청/갱신\n# 또는 Let's Encrypt: certbot --standalone -d [도메인명]",
        note:"공인 CA 인증서 구매 후 웹 서버에 바인딩. 교체 후 사이트 바인딩에서 새 인증서 선택" },
      { no:3, title:"TLS 1.0/1.1 비활성화 (레지스트리, 재부팅 필요)",
        cmd:"# TLS 1.0 비활성화\nNew-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Force\nSet-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server' -Name Enabled -Value 0\n# TLS 1.1 비활성화 (같은 방식으로 'TLS 1.1' 경로 사용)\nRestart-Computer -Force",
        note:"⚠ 재부팅 후 적용됨. 레거시 클라이언트 영향 확인 후 적용 권장" },
    ]
  },

  // ═══ SSL-CERT-EXPIRED ════════════════════════════════════════════
  "SSL-CERT-EXPIRED": {
    risk: "SSL 인증서가 만료됐습니다. 브라우저에 '연결이 안전하지 않습니다' 경고가 표시되고, 일부 클라이언트는 연결을 거부합니다. 금감원 검사에서 즉시 시정 대상이며, 서비스 신뢰도에 치명적입니다.",
    check: [
      { label:"인증서 만료일 확인",
        cmd:"openssl s_client -connect [호스트]:443 2>&1 | openssl x509 -noout -dates",
        success:"notAfter 날짜가 오늘 이후이면 ✅ 갱신 완료",
        fail:"notAfter 날짜가 오늘 이전이면 → STEP 1 즉시 실행" },
      { label:"새 인증서 설치 확인 (갱신 후)",
        cmd:"openssl s_client -connect [호스트]:443 2>&1 | openssl x509 -noout -issuer -subject",
        success:"발급기관과 만료일이 정상적으로 표시되면 ✅",
        fail:"자체 서명 인증서가 나오면 → 공인 CA 인증서로 교체 필요" },
    ],
    danger_versions: ["만료된 인증서 사용 중"],
    good_version: "유효기간 내 공인 CA 인증서 + 자동 갱신 설정",
    steps: [
      { no:1, title:"인증서 갱신 신청 (CA에서 신규 발급)",
        cmd:"# Let's Encrypt 무료 갱신:\ncertbot renew --force-renewal\n\n# 또는 기존 CA에서 갱신 후 서버에 설치",
        note:"갱신 후 웹 서버 재시작 필요: sudo systemctl restart apache2 (또는 nginx, iis)" },
      { no:2, title:"IIS 인증서 교체",
        cmd:"# IIS 관리자 → 사이트 → 바인딩 → https 선택 → 편집\n# SSL 인증서 드롭다운에서 새 인증서 선택 → 확인",
        note:"교체 즉시 적용됨. 브라우저에서 새로고침으로 인증서 변경 확인" },
      { no:3, title:"자동 갱신 설정 (재발생 방지)",
        cmd:"# Windows 작업 스케줄러에 갱신 작업 등록\n# 또는 certbot 자동 갱신: certbot renew --quiet (cron 등록)\n# 만료 30일 전 이메일 알림 설정 권장",
        note:"만료 90일·30일·7일 전 담당자 이메일 알림 자동화 강력 권장" },
    ]
  },

  // ═══ SSL-CERT-SELF-SIGNED ════════════════════════════════════════
  "SSL-CERT-SELF-SIGNED": {
    risk: "자체 서명(Self-Signed) 인증서를 사용 중입니다. 신뢰할 수 있는 CA의 검증을 받지 않아 브라우저 경고가 표시됩니다. 공격자가 동일한 자체 서명 인증서를 만들어 중간자 공격(MITM)에 활용할 수 있습니다. 금융 서비스에서는 공인 인증서 필수입니다.",
    check: [
      { label:"인증서 발급기관 확인 (공인 CA가 표시돼야 ✅)",
        cmd:"openssl s_client -connect [호스트]:443 2>&1 | openssl x509 -noout -issuer",
        success:"DigiCert, GlobalSign, Let's Encrypt 등 공인 CA가 표시되면 ✅ 교체 완료",
        fail:"issuer와 subject가 동일하거나 사설 CA이면 → STEP 1 실행" },
      { label:"인증서 상세 확인",
        cmd:"openssl s_client -connect [호스트]:443 2>&1 | openssl x509 -noout -text | findstr -i \"issuer subject\"",
        success:"Issuer와 Subject가 다른 공인 기관이면 ✅",
        fail:"Issuer = Subject 이면 자체 서명 인증서" },
    ],
    danger_versions: ["자체 서명 인증서 사용 중"],
    good_version: "공인 CA 발급 인증서 (DigiCert, GlobalSign, Let's Encrypt 등)",
    steps: [
      { no:1, title:"공인 인증서 발급 신청",
        cmd:"# 무료 인증서 (Let's Encrypt):\ncertbot --standalone -d [도메인명]\n\n# 또는 유료 공인 CA (DigiCert, GlobalSign 등) 에서 구매 신청",
        note:"도메인 소유 확인 후 발급. 보통 수 분 ~ 수 시간 소요" },
      { no:2, title:"IIS에 공인 인증서 설치 및 바인딩",
        cmd:"# IIS 관리자 → 서버 인증서 → 인증서 가져오기 → .pfx 파일 선택\n# 사이트 → 바인딩 → https → 새 인증서 선택 → 확인",
        note:"교체 즉시 적용됨. 브라우저 자물쇠 아이콘으로 공인 인증서 확인" },
      { no:3, title:"자동 갱신 설정",
        cmd:"# Let's Encrypt 자동 갱신 테스트:\ncertbot renew --dry-run",
        note:"자동 갱신이 정상 동작하면 이후 만료 걱정 불필요. dry-run 성공 확인 후 cron 등록" },
    ]
  },

  // ═══ WEB-HTTP-REDIRECT ════════════════════════════════════════════
  "WEB-HTTP-REDIRECT": {
    risk: "HTTP(80)로 접속 시 HTTPS(443)로 자동 리다이렉트되지 않습니다. 사용자가 평문 HTTP로 접속하면 ID/비밀번호 등 민감 정보가 암호화 없이 전송됩니다. SSLstrip 공격으로 HTTPS를 HTTP로 다운그레이드할 수 있습니다.",
    check: [
      { label:"HTTP 리다이렉트 확인 (301/302 응답과 https:// Location이 있어야 ✅)",
        cmd:"curl -I http://[호스트] 2>&1",
        success:"HTTP/1.1 301 또는 302 + Location: https:// 가 나오면 ✅ 리다이렉트 정상",
        fail:"200 OK가 나오거나 Location에 https가 없으면 → STEP 1 또는 STEP 2 실행" },
      { label:"HSTS 헤더 확인 (Strict-Transport-Security가 있어야 ✅)",
        cmd:"curl -I https://[호스트] 2>&1 | findstr Strict",
        success:"Strict-Transport-Security: max-age=... 가 나오면 ✅ HSTS 적용됨",
        fail:"아무것도 안 나오면 → STEP 3으로 HSTS 헤더 추가 권장" },
    ],
    danger_versions: ["HTTP 평문 접속 허용", "HSTS 미설정"],
    good_version: "HTTP→HTTPS 301 리다이렉트 + HSTS 헤더",
    steps: [
      { no:1, title:"IIS HTTP 리다이렉트 설정",
        cmd:"# IIS 관리자 → 사이트 선택 → HTTP 리디렉션(기능 뷰)\n# ☑ HTTP 요청을 다음으로 리디렉션\n# URL: https://[도메인명]\n# ☑ 요청을 이 대상으로만 리디렉션 체크\n# 상태 코드: 302 → 301(영구)로 변경 권장",
        note:"설정 저장 즉시 적용됨. IIS 재시작 불필요" },
      { no:2, title:"Apache 리다이렉트 설정 (설정 후 재시작 필요)",
        cmd:"# /etc/apache2/sites-enabled/000-default.conf 에 추가\n<VirtualHost *:80>\n    RewriteEngine On\n    RewriteRule ^ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n</VirtualHost>",
        note:"설정 저장 후 재시작: sudo systemctl restart apache2" },
      { no:3, title:"HSTS 헤더 추가 (브라우저 다운그레이드 방지)",
        cmd:"# IIS web.config에 추가:\n<system.webServer><httpProtocol><customHeaders>\n  <add name='Strict-Transport-Security' value='max-age=31536000; includeSubDomains' />\n</customHeaders></httpProtocol></system.webServer>",
        note:"HSTS 적용 후 1년간 브라우저가 자동으로 HTTPS 접속. max-age=31536000 = 1년" },
      { no:4, title:"적용 확인",
        cmd:"curl -I http://[호스트]",
        note:"301 Moved Permanently + Location: https:// 가 나오면 완료" },
    ]
  },

  // ═══ WEB-HEADER ═══════════════════════════════════════════════════
  "WEB-HEADER": {
    risk: "보안 헤더(HSTS, CSP, X-Frame-Options 등)가 누락됐습니다. 클릭재킹, XSS, MIME 스니핑 등의 공격에 취약합니다.",
    check: [
      { label:"보안 헤더 전체 확인",
        cmd:"curl -I https://[호스트] 2>&1",
        success:"Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options 모두 있으면 ✅",
        fail:"항목이 없으면 → STEP 1 실행" },
    ],
    danger_versions: ["보안 헤더 미설정"],
    good_version: "HSTS + X-Frame-Options + X-Content-Type-Options + CSP 전부 설정",
    steps: [
      { no:1, title:"IIS 보안 헤더 일괄 추가 (web.config)",
        cmd:"<system.webServer><httpProtocol><customHeaders>\n  <add name='X-Frame-Options' value='SAMEORIGIN' />\n  <add name='X-Content-Type-Options' value='nosniff' />\n  <add name='X-XSS-Protection' value='1; mode=block' />\n  <add name='Strict-Transport-Security' value='max-age=31536000; includeSubDomains' />\n  <add name='Referrer-Policy' value='strict-origin-when-cross-origin' />\n</customHeaders></httpProtocol></system.webServer>",
        note:"web.config 수정 즉시 적용됨. IIS 재시작 불필요" },
      { no:2, title:"적용 확인",
        cmd:"curl -I https://[호스트] 2>&1 | findstr -i \"frame content xss strict\"",
        note:"각 헤더가 표시되면 완료" },
    ]
  },

  // ═══ DEFAULT ═══════════════════════════════════════════════════════
  "DEFAULT": {
    risk: "보안 취약점으로 인한 시스템 침해 가능성이 있습니다. 취약점 ID와 설명을 참고하여 담당자와 조치 방안을 검토하세요.",
    check: [
      { label:"Windows 최신 패치 적용 여부 확인",
        cmd:"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 10",
        success:"최근 1개월 내 패치가 적용돼 있으면 ✅ 정상",
        fail:"패치 이력이 수개월 이상 없으면 → Windows Update 즉시 실행" },
      { label:"Linux 최신 패치 확인",
        cmd:"apt list --upgradable 2>/dev/null | head -20",
        success:"업그레이드 가능 항목이 없으면 ✅ 최신 상태",
        fail:"보안 패키지 업데이트 항목이 있으면 → STEP 1 실행" },
    ],
    danger_versions: ["최신 보안 패치 미적용 상태"],
    good_version: "최신 보안 패치 적용 완료",
    steps: [
      { no:1, title:"Windows 보안 업데이트",
        cmd:"# 시작 → 설정 → Windows 업데이트 → 업데이트 확인 및 설치\n# 또는 PowerShell(관리자):\nInstall-Module PSWindowsUpdate -Force\nGet-WindowsUpdate -Install -AcceptAll",
        note:"⚠ 재부팅이 필요할 수 있음. 업무 종료 후 적용 권장" },
      { no:2, title:"Linux 보안 업데이트",
        cmd:"sudo apt-get update\nsudo apt-get upgrade -y\nsudo apt-get dist-upgrade -y",
        note:"커널 업데이트 시 재부팅 필요: sudo reboot" },
      { no:3, title:"패치 적용 확인",
        cmd:"Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5",
        note:"오늘 날짜의 패치가 표시되면 완료" },
    ]
  }
};
function getGuide(finding) {
  if (!finding) return VULN_GUIDES.DEFAULT;
  const key = (finding.vuln_id||"").toUpperCase();
  // 정확한 ID 매칭
  if (VULN_GUIDES[key]) return VULN_GUIDES[key];
  // SSL 계열 — ID 접두어 매칭
  if (key.startsWith("SSL-CONN")) return VULN_GUIDES["SSL-CONN-FAIL"];
  if (key.startsWith("SSL-CERT-EXP")) return VULN_GUIDES["SSL-CERT-EXPIRED"];
  if (key.startsWith("SSL-CERT-SELF")) return VULN_GUIDES["SSL-CERT-SELF-SIGNED"];
  if (key.startsWith("SSL-")) return VULN_GUIDES["SSL-CONN-FAIL"];
  // WEB 계열
  if (key.startsWith("WEB-HTTP")) return VULN_GUIDES["WEB-HTTP-REDIRECT"];
  if (key.startsWith("WEB-")) return VULN_GUIDES["WEB-HTTP-REDIRECT"];
  // 제목 기반 매칭
  const t = (finding.title||"").toLowerCase();
  if (t.includes("ssl") || t.includes("tls") || t.includes("https") || t.includes("인증서")) return VULN_GUIDES["SSL-CONN-FAIL"];
  if (t.includes("ssh") || t.includes("22번"))                          return VULN_GUIDES["PORT-00022"];
  if (t.includes("smb") || t.includes("445") || t.includes("eternalblue")) return VULN_GUIDES["PORT-00445"];
  if (t.includes("rpc") || t.includes("135"))                           return VULN_GUIDES["PORT-00135"];
  if (t.includes("netbios") || t.includes("139"))                       return VULN_GUIDES["PORT-00139"];
  if (t.includes("mssql") || t.includes("1433"))                        return VULN_GUIDES["PORT-01433"];
  if (t.includes("mysql") || t.includes("3306"))                        return VULN_GUIDES["PORT-03306"];
  if (t.includes("rdp") || t.includes("3389") || t.includes("원격 데스크")) return VULN_GUIDES["PORT-03389"];
  if (t.includes("telnet") || t.includes("23번"))                       return VULN_GUIDES["PORT-00023"];
  if (t.includes("헤더") || t.includes("header") || t.includes("csp") || t.includes("hsts") || t.includes("x-frame")) return VULN_GUIDES["WEB-HEADER"];
  if (t.includes("리다이렉트") || t.includes("redirect") || t.includes("http접속")) return VULN_GUIDES["WEB-HTTP-REDIRECT"];
  // 커스텀 가이드: recommendation 필드 활용
  return {
    ...VULN_GUIDES.DEFAULT,
    risk: finding.description || VULN_GUIDES.DEFAULT.risk,
    steps: [
      ...VULN_GUIDES.DEFAULT.steps.slice(0,1),
      { no:2, title:"권고 조치 수행", cmd:finding.recommendation || "시스템 보안 정책에 따라 조치", note:"조치 후 재점검으로 해소 확인" },
    ]
  };
}

function FindingDetailPanel({ finding, onResolve, resolving }) {
  const guide  = getGuide(finding);
  const sColor = { critical:"#F87171", high:"#FB923C", medium:"#FBBF24", low:"#4ADE80", info:"#94A3B8" }[finding.severity] || "#94A3B8";
  const sLabel = { critical:"긴급", high:"고위험", medium:"중위험", low:"저위험", info:"정보" }[finding.severity] || finding.severity;

  const [copied, setCopied] = React.useState(null);
  const copy = (cmd, i) => {
    navigator.clipboard?.writeText((cmd||"").split("\\n").join(String.fromCharCode(10)));
    setCopied(i); setTimeout(()=>setCopied(null),1500);
  };

  return (
    <div style={{ display:"grid", gridTemplateColumns:"1fr 1.4fr",
      background:"var(--bg-card)", borderTop:`3px solid ${sColor}` }}>

      {/* ══ 왼쪽: 현황 ══ */}
      <div style={{ padding:"16px 18px", borderRight:"1px solid var(--bdr)" }}>

        {/* 기본정보 - 작게 */}
        <div style={{ display:"flex",flexWrap:"wrap",gap:6,marginBottom:14,
          padding:"10px 12px",background:"var(--bg-card2)",borderRadius:6,border:"1px solid var(--bdr)" }}>
          {[
            {l:"ID",  v:finding.vuln_id},
            {l:"심각도", v:<span style={{color:sColor,fontWeight:700}}>{sLabel}</span>},
            {l:"포트", v:finding.port||"—"},
            {l:"반복", v:finding.repeat_count>0?<span style={{color:"#FB923C",fontWeight:700}}>{finding.repeat_count}회</span>:"—"},
          ].map(d=>(
            <div key={d.l} style={{ minWidth:80 }}>
              <div style={{ fontSize:13,color:"var(--txt3)",textTransform:"uppercase",marginBottom:1 }}>{d.l}</div>
              <div style={{ fontSize:13,color:"var(--txt)" }}>{d.v}</div>
            </div>
          ))}
        </div>

        {/* 왜 위험한가 — 강조 */}
        <div style={{ marginBottom:14 }}>
          <div style={{ fontSize:13,fontWeight:700,color:sColor,marginBottom:6,
            display:"flex",alignItems:"center",gap:6 }}>
            <span>⚠</span> 왜 위험한가
          </div>
          <div style={{ fontSize:13,color:"var(--txt)",lineHeight:1.8,
            padding:"10px 12px",borderRadius:6,
            background:`${sColor}0D`,
            border:`1px solid ${sColor}30` }}>
            {guide.risk || finding.description || "—"}
          </div>
        </div>

        {/* 버전 현황 */}
        {(guide.good_version || guide.danger_versions?.length > 0) && (
          <div style={{ marginBottom:10 }}>
            <div style={{ fontSize:13,fontWeight:700,color:"var(--txt3)",marginBottom:5 }}>📦 버전 현황</div>
            {guide.danger_versions?.map((v,i)=>(
              <div key={i} style={{ fontSize:13,color:"#F87171",padding:"2px 8px",
                background:"rgba(248,113,113,.05)",borderRadius:4,marginBottom:3 }}>❌ {v}</div>
            ))}
            {guide.good_version && (
              <div style={{ fontSize:13,color:"#4ADE80",padding:"2px 8px",
                background:"rgba(74,222,128,.05)",borderRadius:4 }}>✅ 권장: {guide.good_version}</div>
            )}
          </div>
        )}

        {finding.regulation && (
          <div style={{ fontSize:13,color:"var(--txt3)",padding:"7px 10px",
            background:"var(--bg-card2)",borderRadius:4,border:"1px solid var(--bdr)" }}>
            📋 {finding.regulation}
          </div>
        )}
      </div>

      {/* ══ 오른쪽: 조치 절차 ══ */}
      <div style={{ padding:"16px 18px" }}>

        {/* 조치방법 헤더 — 강조 */}
        <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:10,
          display:"flex",alignItems:"center",gap:6,
          padding:"10px 14px",
          background:"rgba(74,222,128,.07)",
          border:"1px solid rgba(74,222,128,.2)",borderRadius:6 }}>
          <span>🔧</span>
          <span>이렇게 따라하면 위험이 제거됩니다</span>
        </div>

        {/* 단계별 절차 */}
        <div style={{ display:"flex",flexDirection:"column",gap:10,marginBottom:12 }}>
          {guide.steps?.map((step,i)=>(
            <div key={i} style={{ border:"1px solid var(--bdr)",borderRadius:6,overflow:"hidden" }}>
              {/* 단계 헤더 */}
              <div style={{ display:"flex",alignItems:"center",gap:8,
                padding:"9px 12px",background:"var(--bg-card2)",
                borderBottom:"1px solid var(--bdr)" }}>
                <div style={{ width:20,height:20,borderRadius:"50%",
                  background:"var(--accent)",color:"#fff",
                  display:"flex",alignItems:"center",justifyContent:"center",
                  fontSize:13,fontWeight:700,flexShrink:0 }}>{step.no}</div>
                <span style={{ fontSize:13,fontWeight:700,color:"var(--txt)" }}>{step.title}</span>
              </div>
              {/* 명령어 */}
              <div style={{ position:"relative",background:"#0A0F1A" }}>
                <button onClick={()=>copy(step.cmd||"",i)}
                  style={{ position:"absolute",top:5,right:5,padding:"2px 8px",borderRadius:3,
                    border:"1px solid rgba(255,255,255,.15)",background:"rgba(255,255,255,.06)",
                    color:"rgba(255,255,255,.5)",fontSize:13,cursor:"pointer",zIndex:1 }}>
                  {copied===i?"✓ 복사됨":"📋 복사"}
                </button>
                <pre style={{ margin:0,padding:"10px 40px 10px 12px",fontSize:13,
                  color:"#7DD3FC",lineHeight:1.7,fontFamily:"Consolas,monospace",
                  overflowX:"auto",whiteSpace:"pre-wrap",wordBreak:"break-all" }}>
                  {(step.cmd||"").split("\n").join(String.fromCharCode(10))}
                </pre>
              </div>
              {/* 노트 */}
              {step.note && (
                <div style={{ padding:"5px 10px",fontSize:13,lineHeight:1.65,
                  display:"flex",gap:5,
                  color: step.note.includes("관리자 권한") ? "#FBBF24" : "var(--txt3)",
                  background: step.note.includes("관리자 권한") ? "rgba(251,191,36,.06)" : "var(--bg-card2)",
                  borderTop:"1px solid var(--bdr)" }}>
                  <span style={{flexShrink:0}}>
                    {step.note.includes("관리자 권한") ? "🔐" : "💡"}
                  </span>
                  <span style={{fontWeight:step.note.includes("관리자 권한")?600:400}}>
                    {step.note}
                  </span>
                </div>
              )}
            </div>
          ))}
        </div>

        {/* 조치완료 버튼 or 조치 정보 */}
        {finding.status === "resolved" ? (
          <div style={{ padding:"12px 14px",borderRadius:7,
            background:"rgba(74,222,128,.07)",border:"1px solid rgba(74,222,128,.25)" }}>
            <div style={{ display:"flex",alignItems:"center",gap:6,marginBottom:8 }}>
              <span style={{fontSize:16}}>✅</span>
              <span style={{fontSize:13,fontWeight:700,color:"#4ADE80"}}>조치 완료</span>
            </div>
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:6 }}>
              <div style={{ background:"var(--bg-card2)",borderRadius:5,padding:"7px 10px",
                border:"1px solid var(--bdr)" }}>
                <div style={{fontSize:10,color:"var(--txt3)",marginBottom:2,textTransform:"uppercase"}}>조치자</div>
                <div style={{fontSize:12,color:"var(--txt)",fontWeight:600}}>
                  {finding.resolved_by || "—"}
                </div>
              </div>
              <div style={{ background:"var(--bg-card2)",borderRadius:5,padding:"7px 10px",
                border:"1px solid var(--bdr)" }}>
                <div style={{fontSize:10,color:"var(--txt3)",marginBottom:2,textTransform:"uppercase"}}>조치일시</div>
                <div style={{fontSize:12,color:"var(--txt)",fontWeight:600}}>
                  {finding.resolved_at ? finding.resolved_at.slice(0,16).replace("T"," ") : "—"}
                </div>
              </div>
              {finding.resolution_note && (
                <div style={{ gridColumn:"1/-1",background:"var(--bg-card2)",borderRadius:5,
                  padding:"7px 10px",border:"1px solid var(--bdr)" }}>
                  <div style={{fontSize:10,color:"var(--txt3)",marginBottom:2,textTransform:"uppercase"}}>조치 내용</div>
                  <div style={{fontSize:12,color:"var(--txt)",lineHeight:1.6}}>
                    {finding.resolution_note}
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : (
          <button onClick={()=>onResolve(finding.id)} disabled={resolving===finding.id}
            style={{ width:"100%",padding:"9px",borderRadius:6,
              border:"1px solid rgba(74,222,128,.4)",
              background:"rgba(74,222,128,.08)",color:"#4ADE80",
              fontSize:13,fontWeight:700,cursor:"pointer" }}>
            {resolving===finding.id ? "처리 중..." : "✅ 위험 조치 완료 처리"}
          </button>
        )}
      </div>
    </div>
  );
}


// ── 조치방법 새창 오픈 ───────────────────────────────────────────
function openRemediation(finding) {
  const guide = getGuide(finding);
  const sColor = {critical:"#F87171",high:"#FB923C",medium:"#FBBF24",low:"#4ADE80",info:"#94A3B8"}[finding.severity]||"#94A3B8";
  const sLabel = {critical:"긴급",high:"고위험",medium:"중위험",low:"저위험",info:"정보"}[finding.severity]||finding.severity;

  const stepsHtml = (guide.steps||[]).map((step,i) => {
    const cmdLines = (step.cmd||"").split("\\n").join("\n").split("\n").map(l=>`<span>${l}</span>`).join("\n");
    const isAdmin  = (step.note||"").includes("관리자 권한");
    return `
      <div class="step">
        <div class="step-header">
          <div class="step-num">${step.no}</div>
          <span>${step.title}</span>
        </div>
        <div class="cmd-block">
          <button class="copy-btn" onclick="navigator.clipboard?.writeText(this.nextElementSibling.innerText)">📋 복사</button>
          <pre>${cmdLines}</pre>
        </div>
        ${step.note ? `<div class="step-note ${isAdmin?"admin":""}">${isAdmin?"🔐":"💡"} ${step.note}</div>` : ""}
      </div>`;
  }).join("");

  // 결과 확인 명령 섹션
  const checkHtml = (guide.check||[]).length > 0 ? `
    <div class="check-section">
      <div class="check-header">🔍 조치 후 결과 확인 — 이렇게 나와야 성공입니다</div>
      ${(guide.check||[]).map(c => {
        const cmdLines = (c.cmd||"").split("\\n").join("\n").split("\n").map(l=>`<span>${l}</span>`).join("\n");
        return `
        <div class="check-item">
          <div class="check-label">${c.label}</div>
          <div class="cmd-block">
            <button class="copy-btn" onclick="navigator.clipboard?.writeText(this.nextElementSibling.innerText)">📋 복사</button>
            <pre>${cmdLines}</pre>
          </div>
          ${c.success ? `<div class="check-success">✅ 성공: ${c.success}</div>` : ""}
          ${c.fail ? `<div class="check-fail">❌ 아직 나오면: ${c.fail}</div>` : ""}
        </div>`;
      }).join("")}
    </div>` : "";

  const dangerHtml = (guide.danger_versions||[]).map(v=>`<div class="ver-bad">❌ ${v}</div>`).join("");
  const goodHtml   = guide.good_version ? `<div class="ver-good">✅ 권장: ${guide.good_version}</div>` : "";

  const html = `<!DOCTYPE html>
<html lang="ko">
<head>
<meta charset="UTF-8">
<title>조치 가이드 — ${finding.title||finding.vuln_id}</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:'Malgun Gothic','Apple SD Gothic Neo',sans-serif;background:#f8f9fb;color:#1e293b;font-size:13px;line-height:1.6}
  .header{background:#1e293b;color:#fff;padding:18px 24px;display:flex;align-items:center;gap:12;border-bottom:3px solid ${sColor}}
  .header-icon{font-size:22px}
  .header-title{font-size:16px;font-weight:700}
  .header-sub{font-size:11px;color:#94a3b8;margin-top:2px}
  .sev-badge{padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;background:${sColor}22;color:${sColor};border:1px solid ${sColor}44}
  .body{display:grid;grid-template-columns:1fr 1.4fr;gap:0;height:calc(100vh - 68px)}
  .left{padding:20px;border-right:1px solid #e2e8f0;overflow-y:auto;background:#fff}
  .right{padding:20px;overflow-y:auto;background:#f8f9fb}
  .section-title{font-size:12px;font-weight:700;color:#64748b;text-transform:uppercase;letter-spacing:.06em;margin-bottom:8px;margin-top:16px}
  .section-title:first-child{margin-top:0}
  .info-grid{display:grid;grid-template-columns:1fr 1fr;gap:6px;margin-bottom:14px}
  .info-item{background:#f1f5f9;border-radius:6px;padding:8px 10px;border:1px solid #e2e8f0}
  .info-label{font-size:9px;color:#94a3b8;text-transform:uppercase;margin-bottom:2px}
  .info-val{font-size:12px;font-weight:500;color:#1e293b}
  .risk-box{background:${sColor}0D;border:1px solid ${sColor}30;border-radius:7px;padding:12px 14px;font-size:12px;line-height:1.8;color:#1e293b;margin-bottom:12px}
  .ver-bad{font-size:11px;color:#ef4444;background:#fef2f2;border-radius:4px;padding:3px 8px;margin-bottom:3px}
  .ver-good{font-size:11px;color:#16a34a;background:#f0fdf4;border-radius:4px;padding:3px 8px}
  .guide-header{background:#f0fdf4;border:1px solid #86efac;border-radius:7px;padding:10px 14px;font-size:13px;font-weight:700;color:#15803d;margin-bottom:12px;display:flex;align-items:center;gap:6px}
  .step{border:1px solid #e2e8f0;border-radius:7px;overflow:hidden;margin-bottom:10px;background:#fff}
  .step-header{display:flex;align-items:center;gap:8px;padding:8px 12px;background:#f8f9fb;border-bottom:1px solid #e2e8f0}
  .step-num{width:22px;height:22px;border-radius:50%;background:#2563eb;color:#fff;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:700;flex-shrink:0}
  .step-header span{font-size:12px;font-weight:700;color:#1e293b}
  .cmd-block{position:relative;background:#0a0f1a}
  .copy-btn{position:absolute;top:6px;right:6px;padding:2px 8px;border-radius:3px;border:1px solid rgba(255,255,255,.2);background:rgba(255,255,255,.08);color:rgba(255,255,255,.6);font-size:10px;cursor:pointer;z-index:1}
  .copy-btn:hover{background:rgba(255,255,255,.15)}
  pre{padding:10px 40px 10px 14px;font-size:11px;color:#7dd3fc;line-height:1.8;font-family:Consolas,monospace;white-space:pre-wrap;word-break:break-all;margin:0}
  .step-note{padding:6px 12px;font-size:11px;line-height:1.5;background:#f8f9fb;border-top:1px solid #e2e8f0;color:#64748b}
  .step-note.admin{color:#d97706;background:#fffbeb;font-weight:600}
  .reg{font-size:10px;color:#64748b;background:#f1f5f9;border-radius:4px;padding:5px 8px;border:1px solid #e2e8f0;margin-top:8px}
  .check-section{margin-top:20px;border:1px solid #6366f1;border-radius:8px;overflow:hidden}
  .check-header{background:#eef2ff;border-bottom:1px solid #c7d2fe;padding:10px 14px;font-size:12px;font-weight:700;color:#4338ca;display:flex;align-items:center;gap:6px}
  .check-item{border-bottom:1px solid #e2e8f0;background:#fff}
  .check-item:last-child{border-bottom:none}
  .check-label{padding:7px 12px 4px;font-size:11px;font-weight:600;color:#374151;background:#f8faff}
  .check-success{padding:5px 12px 6px;font-size:11px;color:#15803d;background:#f0fdf4;border-top:1px solid #bbf7d0;line-height:1.5}
  .check-fail{padding:5px 12px 6px;font-size:11px;color:#b91c1c;background:#fef2f2;border-top:1px solid #fecaca;line-height:1.5;font-weight:600}
  @media print{.copy-btn{display:none}}
</style>
</head>
<body>
<div class="header">
  <div class="header-icon">🛡</div>
  <div style="flex:1">
    <div class="header-title">${finding.title||finding.vuln_id}</div>
    <div class="header-sub">${finding.vuln_id} · ${finding.asset_name||""} · ${finding.asset_ip||""}</div>
  </div>
  <span class="sev-badge">${sLabel}</span>
</div>
<div class="body">
  <div class="left">
    <div class="section-title">기본 정보</div>
    <div class="info-grid">
      <div class="info-item"><div class="info-label">취약점 ID</div><div class="info-val">${finding.vuln_id}</div></div>
      <div class="info-item"><div class="info-label">심각도</div><div class="info-val" style="color:${sColor};font-weight:700">${sLabel}</div></div>
      <div class="info-item"><div class="info-label">포트</div><div class="info-val">${finding.port||"—"}</div></div>
      <div class="info-item"><div class="info-label">반복횟수</div><div class="info-val">${finding.repeat_count>0?finding.repeat_count+"회":"—"}</div></div>
    </div>
    <div class="section-title">⚠ 왜 위험한가</div>
    <div class="risk-box">${guide.risk||finding.description||"—"}</div>
    ${dangerHtml||goodHtml ? `<div class="section-title">📦 버전 현황</div>${dangerHtml}${goodHtml}` : ""}
    ${finding.regulation ? `<div class="reg">📋 규정 연관: ${finding.regulation}</div>` : ""}
  </div>
  <div class="right">
    <div class="guide-header">🔧 이렇게 따라하면 위험이 제거됩니다</div>
    ${stepsHtml}
    ${checkHtml}
  </div>
</div>
</body></html>`;

  const w = window.open("","_blank","width=1100,height=780,resizable=yes,scrollbars=yes");
  if (w) { w.document.write(html); w.document.close(); }
}

export function PageFindings({ onNav, initFilter, onFilterUsed }) {
  const [findings, setFindings] = useState([]);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState(null);
  const [search,   setSearch]   = useState("");
  const [sevF,     setSevF]     = useState("");
  const [statusF,  setStatusF]  = useState("open");
  const [repeatF,  setRepeatF]  = useState(false); // 반복 취약점만 필터
  const [sort,     setSort]     = useState({ key:"cvss_score", asc:false });
  const [page,     setPage]     = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const [selected, setSelected] = useState(new Set());
  const [expanded, setExpanded] = useState(null);
  const [resolving,setResolving]= useState(null);
  // 이력에서 넘어온 필터
  const [drillFilter, setDrillFilter] = useState(null); // { assetIp, assetName }

  const load = async () => {
    setLoading(true); setError(null);
    try { setFindings(await fetchFindings()); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  // 이력 드릴다운 필터 적용
  useEffect(() => {
    if (initFilter) {
      setDrillFilter(initFilter);
      setSearch(initFilter.assetIp || "");
      setStatusF(initFilter.repeat ? "" : "");
      setSevF("");
      if (initFilter.repeat) setRepeatF(true);
      setPage(1);
      if (onFilterUsed) onFilterUsed();
    }
  }, [initFilter]);

  const SEV_ORDER = { critical:4, high:3, medium:2, low:1, info:0 };
  const SEV_LBL   = { critical:"긴급", high:"고위험", medium:"중위험", low:"저위험", info:"정보" };
  const SEV_MAP   = { critical:"crit", high:"high", medium:"med", low:"low" };

  const currentJobId = drillFilter?.jobId || null;

  const filtered = findings.filter(f => {
    const ms  = !search  || f.title?.toLowerCase().includes(search.toLowerCase()) || f.asset_ip?.includes(search) || f.vuln_id?.includes(search);
    const mse = !sevF    || f.severity === sevF;
    const mst = !statusF || f.status   === statusF;
    const mrp = !repeatF || (f.repeat_count > 0);
    return ms && mse && mst && mrp;
  }).sort((a,b) => {
    // 이번 점검 항목 최상단
    const aNew = currentJobId && a.scan_job_id === currentJobId ? 1 : 0;
    const bNew = currentJobId && b.scan_job_id === currentJobId ? 1 : 0;
    if (aNew !== bNew) return bNew - aNew;
    // 그 다음 기존 정렬
    let v1=a[sort.key], v2=b[sort.key];
    if (sort.key==="severity") { v1=SEV_ORDER[v1]??0; v2=SEV_ORDER[v2]??0; }
    const r = typeof v1==="number" ? v1-v2 : String(v1??"").localeCompare(String(v2??""));
    return sort.asc?r:-r;
  });

  // 이번 점검 / 이전 점검 그룹 분리
  const thisJobFindings  = currentJobId ? filtered.filter(f=>f.scan_job_id===currentJobId) : [];
  const otherFindings    = currentJobId ? filtered.filter(f=>f.scan_job_id!==currentJobId) : filtered;
  const groupMode        = currentJobId && thisJobFindings.length > 0;

  const paged = filtered.slice((page-1)*pageSize, page*pageSize);
  const onSort = k => setSort(p=>({key:k,asc:p.key===k?!p.asc:true}));
  const toggleSel = id => setSelected(p=>{const n=new Set(p);n.has(id)?n.delete(id):n.add(id);return n;});

  const onResolve = async (id) => {
    const by = prompt("조치자 이름:"); if(!by) return;
    const note = prompt("조치 내용:") || "";
    setResolving(id);
    try { await resolveFindings(id, by, note); load(); }
    catch(e) { alert("오류: "+e.message); }
    finally { setResolving(null); }
  };

  const counts = {
    all:findings.length, critical:findings.filter(f=>f.severity==="critical").length,
    high:findings.filter(f=>f.severity==="high").length,
    medium:findings.filter(f=>f.severity==="medium").length,
    open:findings.filter(f=>f.status==="open").length,
  };

  return (
    <div style={{ padding:"20px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>

        {/* KPI 요약 */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10, marginBottom:14 }}>
          {[
            {lbl:"전체",    val:counts.all,      c:"var(--txt)",  f:""},
            {lbl:"긴급",    val:counts.critical, c:"#F87171",     f:"critical"},
            {lbl:"고위험",  val:counts.high,     c:"#FB923C",     f:"high"},
            {lbl:"중위험",  val:counts.medium,   c:"#FBBF24",     f:"medium"},
            {lbl:"미조치",  val:counts.open,     c:"#60A5FA",     f:"__open"},
          ].map(k=>(
            <div key={k.lbl} onClick={()=>{if(k.f==="__open"){setStatusF("open");setSevF("");}else{setSevF(k.f);setStatusF("");}setPage(1);}}
              style={{ background:"var(--bg-card)", border:`1px solid ${(sevF===k.f||(!sevF&&!k.f&&statusF==="open"&&k.f==="__open"))?"var(--accent)":"var(--bdr)"}`, borderRadius:9, padding:"12px 14px", cursor:"pointer" }}>
              <div style={{ fontSize:13, color:"var(--txt3)", fontWeight:600, textTransform:"uppercase", marginBottom:6 }}>{k.lbl}</div>
              <div style={{ fontSize:24, fontWeight:700, color:k.c }}>{k.val}</div>
            </div>
          ))}
        </div>

        <Card>
          {/* 이력에서 넘어온 경우 — 필터 배너 */}
          {drillFilter && (
            <div style={{ display:"flex", alignItems:"center", gap:10, padding:"9px 14px", marginBottom:10,
              background:"rgba(37,99,235,.08)", border:"1px solid rgba(37,99,235,.25)", borderRadius:8 }}>
              <span style={{ fontSize:14 }}>🔍</span>
              <div style={{ flex:1 }}>
                <span style={{ fontSize:13, fontWeight:600, color:"var(--accent-text)" }}>점검 이력에서 이동 </span>
                <span style={{ fontSize:13, color:"var(--txt)" }}>— </span>
                <span style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>{drillFilter.assetName}</span>
                <code style={{ fontSize:13, color:"var(--accent-text)", background:"var(--bg-card2)", padding:"1px 6px", borderRadius:3, marginLeft:6, border:"1px solid var(--bdr)" }}>{drillFilter.assetIp}</code>
                <span style={{ fontSize:13, color:"var(--txt3)", marginLeft:8 }}>의 전체 취약점을 표시 중입니다</span>
              </div>
              <button onClick={()=>{ setDrillFilter(null); setSearch(""); setStatusF("open"); }}
                style={{ padding:"4px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>
                ✕ 필터 해제
              </button>
              {onNav && (
                <button onClick={()=>onNav("history")}
                  style={{ padding:"4px 10px", borderRadius:5, border:"1px solid rgba(37,99,235,.3)", background:"rgba(37,99,235,.1)", color:"#60A5FA", fontSize:13, cursor:"pointer" }}>
                  ← 이력으로
                </button>
              )}
            </div>
          )}

          <SearchBar value={search} onChange={v=>{setSearch(v);setPage(1);}} placeholder="취약점명 / IP / vuln_id 검색...">
            <FilterSelect value={sevF}    onChange={v=>{setSevF(v);setPage(1);}}
              options={[{value:"critical",label:"긴급"},{value:"high",label:"고위험"},{value:"medium",label:"중위험"},{value:"low",label:"저위험"}]}
              placeholder="전체 심각도"/>
            <FilterSelect value={statusF} onChange={v=>{setStatusF(v);setPage(1);}}
              options={[{value:"open",label:"미조치"},{value:"resolved",label:"조치완료"}]}
              placeholder="전체 상태"/>
            <button onClick={()=>{ setRepeatF(p=>!p); setPage(1); }}
              style={{ padding:"5px 11px", borderRadius:6, fontSize:12, cursor:"pointer",
                fontWeight:repeatF?700:400, border:`1px solid ${repeatF?"#C084FC":"var(--bdr)"}`,
                background:repeatF?"rgba(192,132,252,.12)":"transparent",
                color:repeatF?"#C084FC":"var(--txt3)", whiteSpace:"nowrap", transition:"all .15s" }}>
              ↺ 반복만
            </button>
            <Btn variant="ghost" onClick={load}>↻</Btn>
          </SearchBar>

          <TableActions selected={selected.size} total={paged.length}
            onSelectAll={()=>setSelected(new Set(paged.map(f=>f.id)))}
            onDeselectAll={()=>setSelected(new Set())}
            onDelete={async()=>{if(window.confirm(`선택한 ${selected.size}건을 삭제하시겠습니까?\n삭제 후 복구할 수 없습니다.`)){try{await deleteFindings([...selected]);setSelected(new Set());load();}catch(e){alert("삭제 실패: "+e.message);}}}}>
            <span style={{ fontSize:13, color:"var(--txt3)" }}>{filtered.length}건 표시 중</span>
          </TableActions>

          {paged.length===0 ? (
            <EmptyState icon="🛡" title="취약점 없음" desc="보안 점검을 실행하면 취약점이 여기에 표시됩니다"/>
          ) : (
            <div>
            {groupMode && (
              <div style={{ marginBottom:6,padding:"7px 12px",
                background:"rgba(37,99,235,.07)",border:"1px solid rgba(37,99,235,.2)",
                borderRadius:6,display:"flex",alignItems:"center",gap:8 }}>
                <span style={{ width:8,height:8,borderRadius:"50%",
                  background:"var(--accent)",display:"inline-block",
                  boxShadow:"0 0 6px var(--accent)" }}/>
                <span style={{ fontSize:13,fontWeight:700,color:"var(--accent-text)" }}>
                  🆕 이번 점검 결과 — {thisJobFindings.length}건
                </span>
                <span style={{ fontSize:13,color:"var(--txt3)",marginLeft:"auto" }}>
                  {drillFilter?.assetName||""} · 방금 전
                </span>
              </div>
            )}
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
                <thead><tr style={{ background:"var(--bg-card2)" }}>
                  <th style={{ width:36, borderBottom:"2px solid var(--bdr)" }}/>
                  <Th sortKey="vuln_id"      sortState={sort} onSort={onSort}>ID</Th>
                  <Th sortKey="title"        sortState={sort} onSort={onSort}>취약점명</Th>
                  <Th sortKey="asset_name"   sortState={sort} onSort={onSort}>자산명</Th>
                  <Th sortKey="asset_ip"     sortState={sort} onSort={onSort}>IP</Th>
                  <Th sortKey="severity"     sortState={sort} onSort={onSort}>심각도</Th>
                  <Th sortKey="cvss_score"   sortState={sort} onSort={onSort}>CVSS</Th>
                  <Th sortKey="repeat_count" sortState={sort} onSort={onSort}>반복</Th>
                  <Th sortKey="first_seen"   sortState={sort} onSort={onSort}>최초발견</Th>
                  <Th sortKey="status"       sortState={sort} onSort={onSort}>상태</Th>
                  <Th>조치</Th>
                </tr></thead>
                <tbody>
                  {paged.map((f, fi) => {
                    const sel = selected.has(f.id);
                    const exp = expanded===f.id;
                    const isNewJob = groupMode && f.scan_job_id===currentJobId;
                    const isFirstOther = groupMode && !isNewJob &&
                      (fi===0 || paged[fi-1].scan_job_id===currentJobId);
                    return [
                    isFirstOther ? (
                      <tr key={f.id+"-sep"}>
                        <td colSpan={11} style={{ padding:"6px 10px 4px",
                          background:"var(--bg-card2)",borderTop:"2px solid var(--bdr)" }}>
                          <span style={{ fontSize:13,fontWeight:600,color:"var(--txt3)" }}>
                            📁 이전 점검 이력 — {otherFindings.length}건
                          </span>
                        </td>
                      </tr>
                    ) : null,
                      <tr key={f.id} onClick={()=>toggleSel(f.id)}
                        style={{ cursor:"pointer",
                          background:sel?"var(--bg-active)":exp?"var(--bg-hover)":isNewJob?"rgba(37,99,235,.03)":"transparent",
                          borderLeft: isNewJob ? "3px solid rgba(37,99,235,.4)" : "3px solid transparent",
                          transition:"background .1s" }}>
                        <CheckTd checked={sel} onChange={()=>toggleSel(f.id)}/>
                        <Td style={{ whiteSpace:"nowrap" }}>
                          <code style={{ fontSize:13, color:"var(--txt3)" }}>{f.vuln_id}</code>
                        </Td>
                        <Td style={{ maxWidth:220 }}>
                          <div style={{ display:"flex", alignItems:"center", gap:5 }}>
                            <span style={{ overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap", fontWeight:500, flex:1 }} title={f.title}>{f.title}</span>
                            <span onClick={e=>{e.stopPropagation(); openRemediation(f);}}
                              title="조치 가이드 보기"
                              style={{ cursor:"pointer", color:"var(--accent-text)",
                                fontSize:11, fontWeight:500, flexShrink:0,
                                padding:"2px 7px", borderRadius:10,
                                background:"rgba(96,165,250,.10)",
                                border:"1px solid rgba(96,165,250,.25)",
                                whiteSpace:"nowrap", letterSpacing:".01em",
                                transition:"all .15s" }}
                              onMouseEnter={e=>e.currentTarget.style.background="rgba(96,165,250,.2)"}
                              onMouseLeave={e=>e.currentTarget.style.background="rgba(96,165,250,.10)"}>
                              가이드 ↗
                            </span>
                          </div>
                        </Td>
                        <Td style={{ maxWidth:130, whiteSpace:"nowrap", overflow:"hidden", textOverflow:"ellipsis" }}>
                          <span style={{ fontSize:13, color:"var(--txt2)" }} title={f.asset_name}>{f.asset_name||"—"}</span>
                        </Td>
                        <Td style={{ whiteSpace:"nowrap" }}>
                          <code style={{ fontSize:13, color:"var(--accent-text)", background:"var(--bg-card2)", padding:"2px 5px", borderRadius:3 }}>{f.asset_ip}</code>
                        </Td>
                        <Td><Badge type={SEV_MAP[f.severity]||"info"}>{SEV_LBL[f.severity]||f.severity}</Badge></Td>
                        <Td><span style={{ fontWeight:700, color:f.cvss_score>=9?"#F87171":f.cvss_score>=7?"#FB923C":"#FBBF24" }}>{f.cvss_score}</span></Td>
                        <Td>{f.repeat_count>0?<RepBadge n={f.repeat_count}/>:<span style={{ color:"var(--txt3)" }}>—</span>}</Td>
                        <Td><span style={{ fontSize:13, color:"var(--txt3)" }}>{f.first_seen?.slice(0,10)}</span></Td>
                        <Td>
                          <div style={{display:"inline-flex",alignItems:"center",gap:5,
                            padding:"3px 8px",borderRadius:20,
                            background: f.status==="resolved"?"rgba(74,222,128,.08)":"rgba(248,113,113,.08)",
                            border: `1px solid ${f.status==="resolved"?"rgba(74,222,128,.2)":"rgba(248,113,113,.2)"}`}}>
                            <span style={{width:6,height:6,borderRadius:"50%",flexShrink:0,
                              background: f.status==="resolved"?"#4ADE80":"#F87171",
                              boxShadow: f.status==="resolved"?"0 0 4px #4ADE8088":"0 0 4px #F8717188"}}/>
                            <span style={{fontSize:11,fontWeight:600,
                              color: f.status==="resolved"?"#4ADE80":"#F87171",
                              letterSpacing:".02em"}}>
                              {f.status==="resolved"?"완료":"미조치"}
                            </span>
                          </div>
                        </Td>
                        <Td>
                          {f.status==="resolved" ? (
                            /* 조치자 이름 — 클릭 시 상세 툴팁 */
                            <div style={{position:"relative",display:"inline-block"}}>
                              <span
                                onClick={e=>{
                                  e.stopPropagation();
                                  const el = e.currentTarget.nextSibling;
                                  el.style.display = el.style.display==="block"?"none":"block";
                                }}
                                style={{cursor:"pointer",fontSize:12,color:"var(--txt2)",
                                  fontWeight:500,borderBottom:"1px dashed var(--bdr2)",
                                  paddingBottom:1}}>
                                {f.resolved_by||"—"}
                              </span>
                              {/* 툴팁 팝업 */}
                              <div style={{display:"none",position:"absolute",
                                bottom:"calc(100% + 6px)",left:"50%",
                                transform:"translateX(-50%)",
                                zIndex:999,width:220,
                                background:"var(--bg-card)",
                                border:"1px solid var(--bdr2)",
                                borderRadius:8,padding:"10px 12px",
                                boxShadow:"0 8px 24px rgba(0,0,0,.35)"}}>
                                {/* 말풍선 꼬리 */}
                                <div style={{position:"absolute",bottom:-6,left:"50%",
                                  transform:"translateX(-50%)",
                                  width:10,height:6,overflow:"hidden"}}>
                                  <div style={{width:10,height:10,background:"var(--bg-card)",
                                    border:"1px solid var(--bdr2)",
                                    transform:"rotate(45deg)",transformOrigin:"top left",
                                    marginTop:3,marginLeft:1}}/>
                                </div>
                                <div style={{fontSize:11,color:"var(--txt3)",marginBottom:6,
                                  fontWeight:700,textTransform:"uppercase",letterSpacing:".05em"}}>
                                  조치 정보
                                </div>
                                <div style={{display:"grid",gap:5}}>
                                  <div>
                                    <div style={{fontSize:10,color:"var(--txt3)"}}>조치자</div>
                                    <div style={{fontSize:12,color:"var(--txt)",fontWeight:600}}>
                                      {f.resolved_by||"—"}
                                    </div>
                                  </div>
                                  <div>
                                    <div style={{fontSize:10,color:"var(--txt3)"}}>조치일시</div>
                                    <div style={{fontSize:12,color:"var(--txt)"}}>
                                      {f.resolved_at?f.resolved_at.slice(0,16).replace("T"," "):"—"}
                                    </div>
                                  </div>
                                  {f.resolution_note&&(
                                    <div>
                                      <div style={{fontSize:10,color:"var(--txt3)"}}>조치내용</div>
                                      <div style={{fontSize:12,color:"var(--txt)",lineHeight:1.5}}>
                                        {f.resolution_note}
                                      </div>
                                    </div>
                                  )}
                                </div>
                              </div>
                            </div>
                          ) : (
                            <button
                              onClick={e=>{e.stopPropagation();onResolve(f.id);}}
                              disabled={resolving===f.id}
                              style={{padding:"3px 10px",borderRadius:10,cursor:"pointer",
                                border:"1px solid rgba(74,222,128,.3)",
                                background:"rgba(74,222,128,.06)",
                                color:"#4ADE80",fontSize:11,fontWeight:600,
                                letterSpacing:".02em",transition:"all .15s"}}
                              onMouseEnter={e=>e.currentTarget.style.background="rgba(74,222,128,.14)"}
                              onMouseLeave={e=>e.currentTarget.style.background="rgba(74,222,128,.06)"}>
                              {resolving===f.id?"처리중":"조치"}
                            </button>
                          )}
                        </Td>
                      </tr>,
                      exp && (
                        <tr key={f.id+"-exp"}>
                          <td colSpan={11} style={{ padding:0, borderBottom:"2px solid var(--accent)" }}>
                            <FindingDetailPanel finding={f} onResolve={onResolve} resolving={resolving}/>
                          </td>
                        </tr>
                      )
                    ].filter(Boolean);
                  })}
                </tbody>
              </table>
            </div>
            </div>
          )}
          <Pagination total={filtered.length} page={page} pageSize={pageSize}
            onPage={setPage} onPageSize={n=>{setPageSize(n);setPage(1);}}/>
        </Card>
      </PageWrap>
    </div>
  );
}


export function PageAlerts({ onNav, initTab, onTabUsed }) {
  const [alerts,  setAlerts]  = useState([]);
  const [configs, setConfigs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [tab,      setTab]     = useState("all");
  const [sort,     setSort]    = useState({ key:"created_at", asc:false });
  const [page,     setPage]    = useState(1);
  const [pageSize, setPageSize]= useState(15);
  const [selected, setSelected]= useState(new Set());

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [a, c] = await Promise.all([fetchAlerts(), fetchAlertConfigs()]);
      setAlerts(a); setConfigs(c);
    } catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  // 외부에서 탭 지정 (대시보드 → 반복취약점 등)
  useEffect(() => {
    if (initTab) { setTab(initTab); setPage(1); if(onTabUsed) onTabUsed(); }
  }, [initTab]);

  const onMarkRead  = async (ids) => { try { await markAlertsRead(ids); load(); } catch(e) {} };
  const onMarkAll   = () => onMarkRead(alerts.filter(a=>!a.is_read).map(a=>a.id));
  const onToggleCfg = async (cfg) => { try { await updateAlertConfig(cfg.alert_type, { is_active: !cfg.is_active }); load(); } catch(e) {} };

  const SEV_DOT   = { critical:"#EF4444", high:"#F97316", medium:"#EAB308", low:"#22C55E", info:"#3B82F6" };
  const SEV_LABEL = { critical:"긴급", high:"고위험", medium:"중위험", low:"저위험", info:"정보" };
  const TYPE_ICON = { repeat_vuln:"↺", critical_vuln:"🚨", high_vuln:"⚠", ssl_expiry:"🔒", cve_match:"🛡", scan_fail:"❌", kev_new:"🇺🇸" };
  const TYPE_LABEL= { repeat_vuln:"반복 취약점", critical_vuln:"긴급 취약점", high_vuln:"고위험 취약점", ssl_expiry:"SSL 만료", cve_match:"CVE 매칭", scan_fail:"점검 실패", kev_new:"CISA KEV" };

  const unreadCount = alerts.filter(a=>!a.is_read).length;
  const critCount   = alerts.filter(a=>a.severity==="critical").length;
  const repeatCount = alerts.filter(a=>a.alert_type==="repeat_vuln").length;

  const filtered = alerts.filter(a => {
    if (tab==="unread")   return !a.is_read;
    if (tab==="critical") return a.severity==="critical";
    if (tab==="repeat")   return a.alert_type==="repeat_vuln";
    return true;
  }).sort((a,b) => {
    const v1=a[sort.key]??""; const v2=b[sort.key]??"";
    const r = String(v1).localeCompare(String(v2));
    return sort.asc ? r : -r;
  });

  const paged = filtered.slice((page-1)*pageSize, page*pageSize);
  const totalPages = Math.ceil(filtered.length / pageSize);
  const allChecked = paged.length>0 && paged.every(a=>selected.has(a.id));
  const someChecked = paged.some(a=>selected.has(a.id));
  const toggleOne = id => setSelected(p=>{ const n=new Set(p); n.has(id)?n.delete(id):n.add(id); return n; });
  const toggleAll = () => setSelected(p=>{
    const n=new Set(p);
    if(allChecked) paged.forEach(a=>n.delete(a.id));
    else paged.forEach(a=>n.add(a.id));
    return n;
  });
  const onSort = k => setSort(p=>({key:k,asc:p.key===k?!p.asc:true}));
  const SortIcon = ({k}) => sort.key===k ? (sort.asc?"▲":"▼") : "";
  const markSelected = () => onMarkRead([...selected]);
  const clearSel = () => setSelected(new Set());

  const timeAgo = iso => {
    if (!iso) return "";
    const diff = (Date.now() - new Date(iso)) / 1000;
    if (diff < 60)   return "방금 전";
    if (diff < 3600) return `${Math.floor(diff/60)}분 전`;
    if (diff < 86400)return `${Math.floor(diff/3600)}시간 전`;
    return `${Math.floor(diff/86400)}일 전`;
  };

  const TABS = [
    { id:"all",      label:"전체",       count:alerts.length },
    { id:"unread",   label:"미읽음",     count:unreadCount,   color:"#F87171" },
    { id:"critical", label:"긴급",       count:critCount,     color:"#F87171" },
    { id:"repeat",   label:"반복 취약점",count:repeatCount,   color:"#C084FC" },
  ];

  return (
    <div style={{ padding:"20px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>

        {/* KPI */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:10, marginBottom:16 }}>
          {[
            { icon:"🔔", lbl:"전체 알람",  val:alerts.length,           c:"var(--txt)", tab:"all" },
            { icon:"📬", lbl:"미읽음",     val:unreadCount,              c:"#F87171",    tab:"unread" },
            { icon:"🚨", lbl:"긴급",       val:critCount,                c:"#F87171",    tab:"critical" },
            { icon:"↺",  lbl:"반복 취약점",val:repeatCount,              c:"#C084FC",    tab:"repeat" },
            { icon:"✅", lbl:"읽음 처리",  val:alerts.length-unreadCount,c:"#4ADE80",    tab:"all" },
          ].map(k=>(
            <div key={k.lbl}
              onClick={()=>{ setTab(k.tab); setPage(1); }}
              style={{ background:"var(--bg-card)", border:`1px solid ${tab===k.tab?"var(--accent)":"var(--bdr)"}`,
                borderRadius:10, padding:"12px 14px", cursor:"pointer", transition:"all .15s" }}
              onMouseEnter={e=>{ e.currentTarget.style.background="var(--bg-hover)"; }}
              onMouseLeave={e=>{ e.currentTarget.style.background="var(--bg-card)"; }}>
              <div style={{ display:"flex", gap:6, alignItems:"center", marginBottom:6 }}>
                <span style={{ fontSize:15 }}>{k.icon}</span>
                <span style={{ fontSize:13, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".06em", fontWeight:600 }}>{k.lbl}</span>
              </div>
              <div style={{ fontSize:24, fontWeight:700, color:k.c }}>{k.val}</div>
            </div>
          ))}
        </div>

        <div style={{ display:"grid", gridTemplateColumns:"1fr 300px", gap:14 }}>

          {/* 알람 목록 */}
          <Card>
            {/* 탭 + 액션 */}
            <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:12 }}>
              <div style={{ display:"flex", gap:0, background:"var(--bg-card2)", borderRadius:8, padding:3, border:"1px solid var(--bdr)" }}>
                {TABS.map(tb=>(
                  <button key={tb.id} onClick={()=>{setTab(tb.id);setPage(1);}}
                    style={{ padding:"5px 11px", borderRadius:6, border:"none", cursor:"pointer", fontSize:13, fontWeight:tab===tb.id?700:400,
                      background:tab===tb.id?"var(--bg-active)":"transparent",
                      color:tab===tb.id?"var(--accent-text)":"var(--txt3)", display:"flex", alignItems:"center", gap:4, transition:"all .15s" }}>
                    {tb.label}
                    {tb.count>0 && <span style={{ padding:"0 5px", borderRadius:8, fontSize:13, fontWeight:700,
                      background:tab===tb.id?`${tb.color||"var(--accent)"}22`:"var(--bdr)",
                      color:tb.color||"var(--accent-text)" }}>{tb.count}</span>}
                  </button>
                ))}
              </div>
              <div style={{ display:"flex", gap:6 }}>
                {unreadCount>0 && (
                  <button onClick={onMarkAll}
                    style={{ padding:"5px 12px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>
                    전체 읽음
                  </button>
                )}
                <button onClick={load} style={{ padding:"5px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>↻</button>
              </div>
            </div>

            {/* 툴바: 선택 액션 + 페이지당 행 수 */}
            <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:8,
              padding:"6px 8px",background:"var(--bg-card2)",borderRadius:7,
              border:"1px solid var(--bdr)" }}>
              {/* 전체 체크 */}
              <div onClick={toggleAll}
                style={{ width:15,height:15,borderRadius:3,flexShrink:0,cursor:"pointer",
                  border:`2px solid ${someChecked?"var(--accent)":"var(--bdr2)"}`,
                  background:allChecked?"var(--accent)":someChecked?"rgba(37,99,235,.25)":"transparent",
                  display:"flex",alignItems:"center",justifyContent:"center" }}>
                {allChecked&&<span style={{color:"#fff",fontSize:9,fontWeight:700}}>✓</span>}
                {!allChecked&&someChecked&&<span style={{color:"var(--accent-text)",fontSize:8,fontWeight:700}}>−</span>}
              </div>
              {selected.size>0 ? (<>
                <span style={{fontSize:12,color:"var(--accent-text)",fontWeight:500}}>{selected.size}건 선택</span>
                <button onClick={markSelected}
                  style={{padding:"3px 10px",borderRadius:5,border:"1px solid rgba(96,165,250,.3)",
                    background:"rgba(96,165,250,.08)",color:"#60A5FA",fontSize:12,cursor:"pointer"}}>
                  읽음 처리
                </button>
                <button onClick={clearSel}
                  style={{padding:"3px 8px",borderRadius:5,border:"1px solid var(--bdr)",
                    background:"transparent",color:"var(--txt3)",fontSize:12,cursor:"pointer"}}>
                  해제
                </button>
              </>) : (
                <span style={{fontSize:12,color:"var(--txt3)"}}>{filtered.length}건</span>
              )}
              <div style={{marginLeft:"auto",display:"flex",alignItems:"center",gap:6}}>
                <span style={{fontSize:11,color:"var(--txt3)"}}>페이지당</span>
                <select value={pageSize} onChange={e=>{setPageSize(Number(e.target.value));setPage(1);}}
                  style={{padding:"3px 6px",borderRadius:5,border:"1px solid var(--bdr)",
                    background:"var(--bg-input)",color:"var(--txt)",fontSize:12,cursor:"pointer"}}>
                  {[10,15,20,30,50].map(n=><option key={n} value={n}>{n}행</option>)}
                </select>
              </div>
            </div>

            {paged.length===0 ? (
              <div style={{ textAlign:"center", padding:"40px 0", color:"var(--txt3)", fontSize:12 }}>
                <div style={{ fontSize:36, marginBottom:12, opacity:.4 }}>🔕</div>
                {tab==="all" ? "알람이 없습니다" : "해당하는 알람이 없습니다"}
              </div>
            ) : (
              <div>
                {/* 테이블 헤더 */}
                <div style={{ display:"grid",
                  gridTemplateColumns:"32px 7px 80px 100px 1fr 70px 60px 60px",
                  gap:8, padding:"6px 8px",
                  background:"var(--bg-card2)", borderRadius:"6px 6px 0 0",
                  borderBottom:"2px solid var(--bdr)", alignItems:"center" }}>
                  <div/>
                  <div/>
                  <div onClick={()=>onSort("severity")}
                    style={{fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
                      cursor:"pointer",userSelect:"none",letterSpacing:".05em"}}>
                    심각도 {sort.key==="severity"?<SortIcon k="severity"/>:""}
                  </div>
                  <div onClick={()=>onSort("alert_type")}
                    style={{fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
                      cursor:"pointer",userSelect:"none",letterSpacing:".05em"}}>
                    유형 {sort.key==="alert_type"?<SortIcon k="alert_type"/>:""}
                  </div>
                  <div onClick={()=>onSort("title")}
                    style={{fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
                      cursor:"pointer",userSelect:"none",letterSpacing:".05em"}}>
                    내용 {sort.key==="title"?<SortIcon k="title"/>:""}
                  </div>
                  <div onClick={()=>onSort("created_at")}
                    style={{fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
                      cursor:"pointer",userSelect:"none",letterSpacing:".05em",textAlign:"right"}}>
                    시간 {sort.key==="created_at"?<SortIcon k="created_at"/>:""}
                  </div>
                  <div style={{fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
                    letterSpacing:".05em",textAlign:"center"}}>상태</div>
                  <div style={{fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
                    letterSpacing:".05em",textAlign:"center"}}>액션</div>
                </div>

                {/* 행 */}
                {paged.map((a,i)=>{
                  const dot  = SEV_DOT[a.severity]||"#94A3B8";
                  const isSel= selected.has(a.id);
                  return (
                    <div key={a.id}
                      style={{ display:"grid",
                        gridTemplateColumns:"32px 7px 80px 100px 1fr 70px 60px 60px",
                        gap:8, padding:"7px 8px", alignItems:"center",
                        borderBottom:"1px solid var(--bdr)",
                        background:isSel?"rgba(37,99,235,.06)":a.is_read?"transparent":"rgba(37,99,235,.03)",
                        opacity:a.is_read?0.75:1,
                        transition:"background .1s",cursor:"pointer" }}
                      onMouseEnter={e=>!isSel&&(e.currentTarget.style.background="var(--bg-hover)")}
                      onMouseLeave={e=>!isSel&&(e.currentTarget.style.background=
                        a.is_read?"transparent":"rgba(37,99,235,.03)")}>
                      {/* 체크박스 */}
                      <div onClick={e=>{e.stopPropagation();toggleOne(a.id);}}
                        style={{width:15,height:15,borderRadius:3,cursor:"pointer",
                          border:`1.5px solid ${isSel?"var(--accent)":"var(--bdr2)"}`,
                          background:isSel?"var(--accent)":"transparent",
                          display:"flex",alignItems:"center",justifyContent:"center",
                          margin:"0 auto"}}>
                        {isSel&&<span style={{color:"#fff",fontSize:9,fontWeight:700}}>✓</span>}
                      </div>
                      {/* 심각도 dot */}
                      <div style={{width:7,height:7,borderRadius:"50%",background:dot,
                        boxShadow:!a.is_read?`0 0 5px ${dot}`:"none"}}/>
                      {/* 심각도 */}
                      <span style={{fontSize:11,padding:"2px 6px",borderRadius:10,fontWeight:600,
                        color:dot,background:`${dot}14`,border:`1px solid ${dot}30`,
                        whiteSpace:"nowrap",letterSpacing:".01em"}}>
                        {SEV_LABEL[a.severity]||a.severity}
                      </span>
                      {/* 유형 */}
                      <span style={{fontSize:11,color:"var(--txt3)",whiteSpace:"nowrap",
                        overflow:"hidden",textOverflow:"ellipsis"}}>
                        {TYPE_ICON[a.alert_type]||"📋"} {TYPE_LABEL[a.alert_type]||a.alert_type}
                      </span>
                      {/* 제목 + 메시지 */}
                      <div style={{minWidth:0}}>
                        <div style={{fontSize:12,fontWeight:a.is_read?400:600,color:"var(--txt)",
                          overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",
                          display:"flex",alignItems:"center",gap:5}}>
                          {!a.is_read&&<span style={{width:5,height:5,borderRadius:"50%",
                            background:"var(--accent)",flexShrink:0,display:"inline-block"}}/>}
                          {a.title}
                        </div>
                        <div style={{fontSize:11,color:"var(--txt3)",
                          overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap",
                          marginTop:1}}>{a.message}</div>
                      </div>
                      {/* 시간 */}
                      <span style={{fontSize:11,color:"var(--txt3)",textAlign:"right",
                        whiteSpace:"nowrap"}}>{timeAgo(a.created_at)}</span>
                      {/* 상태 */}
                      <div style={{textAlign:"center"}}>
                        {!a.is_read
                          ? <span style={{fontSize:10,fontWeight:700,color:"#60A5FA",
                              background:"rgba(37,99,235,.1)",padding:"2px 6px",
                              borderRadius:8,border:"1px solid rgba(37,99,235,.2)"}}>NEW</span>
                          : <span style={{fontSize:10,color:"var(--txt3)"}}>읽음</span>
                        }
                      </div>
                      {/* 액션 */}
                      <div style={{textAlign:"center"}}>
                        {!a.is_read
                          ? <button onClick={e=>{e.stopPropagation();onMarkRead([a.id]);}}
                              style={{padding:"2px 8px",borderRadius:8,border:"1px solid var(--bdr)",
                                background:"transparent",color:"var(--txt3)",fontSize:11,cursor:"pointer"}}>
                              읽음
                            </button>
                          : a.alert_type?.includes("vuln") && (
                              <span onClick={e=>{e.stopPropagation();onNav("findings");}}
                                style={{fontSize:11,color:"var(--accent-text)",cursor:"pointer",
                                  padding:"2px 6px",borderRadius:8,
                                  background:"rgba(96,165,250,.08)",
                                  border:"1px solid rgba(96,165,250,.2)"}}>
                                결과 ↗
                              </span>
                            )
                        }
                      </div>
                    </div>
                  );
                })}

                {/* 페이지네이션 */}
                <div style={{display:"flex",alignItems:"center",justifyContent:"space-between",
                  padding:"8px 8px 4px",borderTop:"1px solid var(--bdr)"}}>
                  <span style={{fontSize:12,color:"var(--txt3)"}}>
                    {filtered.length}건 중 {(page-1)*pageSize+1}–{Math.min(page*pageSize,filtered.length)}
                  </span>
                  {totalPages>1&&(
                    <div style={{display:"flex",gap:3}}>
                      {["«","‹",...Array.from({length:Math.min(totalPages,7)},(_,i)=>{
                        if(totalPages<=7) return String(i+1);
                        if(page<=4) return i<5?String(i+1):i===5?"…":String(totalPages);
                        if(page>=totalPages-3) return i===0?"1":i===1?"…":String(totalPages-4+i);
                        return i===0?"1":i===1?"…":i===5?"…":i===6?String(totalPages):String(page-2+i);
                      }),"›","»"].map((lbl,i)=>{
                        const pg=lbl==="«"?1:lbl==="‹"?page-1:lbl==="›"?page+1:lbl==="»"?totalPages:lbl==="…"?null:Number(lbl);
                        if(lbl==="…") return <span key={i} style={{padding:"0 4px",color:"var(--txt3)",fontSize:12}}>…</span>;
                        if(!pg||pg<1||pg>totalPages) return null;
                        return (
                          <button key={i} onClick={()=>setPage(pg)}
                            style={{width:26,height:26,borderRadius:5,fontSize:12,cursor:"pointer",
                              border:`1px solid ${pg===page?"var(--accent)":"var(--bdr)"}`,
                              background:pg===page?"var(--accent)":"transparent",
                              color:pg===page?"#fff":"var(--txt3)"}}>
                            {lbl}
                          </button>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>
            )}
          </Card>

          {/* 오른쪽: 알람 규칙 설정 */}
          <div style={{ display:"flex", flexDirection:"column", gap:10 }}>
            <Card>
              <CardHd title="알람 규칙" right={<span style={{ fontSize:13, color:"var(--txt3)" }}>{configs.filter(c=>c.is_active).length}/{configs.length} 활성</span>}/>
              {configs.length===0 ? (
                <div style={{ fontSize:13, color:"var(--txt3)", textAlign:"center", padding:"16px 0" }}>
                  설정에서 알람 규칙을 구성하세요
                </div>
              ) : configs.map((cfg,i)=>(
                <div key={cfg.id} style={{ display:"flex", alignItems:"center", gap:8, padding:"8px 0", borderBottom:i<configs.length-1?"1px solid var(--bdr)":"none" }}>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:13, fontWeight:500, color:"var(--txt)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{cfg.label||cfg.alert_type}</div>
                    <div style={{ fontSize:13, color:"var(--txt3)", marginTop:1 }}>{cfg.channels||"미설정"}</div>
                  </div>
                  <div onClick={()=>onToggleCfg(cfg)}
                    style={{ width:34,height:18,borderRadius:9,cursor:"pointer",flexShrink:0,transition:"background .2s",
                      background:cfg.is_active?"var(--accent)":"var(--bdr2)",position:"relative" }}>
                    <div style={{ width:12,height:12,borderRadius:"50%",background:"#fff",position:"absolute",top:3,left:cfg.is_active?19:3,transition:"left .2s" }}/>
                  </div>
                </div>
              ))}
            </Card>

            {/* 반복 취약점 경고 */}
            {repeatCount>0 && (
              <div style={{ background:"rgba(192,132,252,.08)", border:"1px solid rgba(192,132,252,.3)", borderRadius:9, padding:"12px 14px" }}>
                <div style={{ fontSize:13, fontWeight:700, color:"#C084FC", marginBottom:6 }}>⚠ 반복 취약점 경고</div>
                <div style={{ fontSize:13, color:"var(--txt2)", lineHeight:1.7 }}>
                  {repeatCount}개 취약점이 반복 발견됐습니다.<br/>
                  ISMS-P 심사 및 금융감독원 검사 시 지적사항이 될 수 있습니다.
                </div>
                {onNav && (
                  <button onClick={()=>onNav("findings")} style={{ marginTop:8, padding:"5px 12px", borderRadius:5, border:"1px solid rgba(192,132,252,.4)", background:"rgba(192,132,252,.12)", color:"#C084FC", fontSize:13, cursor:"pointer" }}>
                    반복 취약점 보기 →
                  </button>
                )}
              </div>
            )}
          </div>
        </div>
      </PageWrap>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// ASSETS
// ═══════════════════════════════════════════════════════════════
export function PageAssets({ onNav, onScanNav, currentUser }) {
  const ENVS = ["Production","Staging","Development","DR","테스트","QA","Training"];
  const [assets,  setAssets]  = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [search,  setSearch]  = useState("");
  const [envF,    setEnvF]    = useState("");
  const [typeF,   setTypeF]   = useState("");
  const [sort,    setSort]    = useState({ key:"risk_score", asc:false });
  const [page,    setPage]    = useState(1);
  const [pageSize,setPageSize]= useState(20);
  const [selected,setSelected]= useState(new Set());
  const [delConfirm,setDelConfirm] = useState(false);
  const [editModal, setEditModal]  = useState(null);  // 수정할 자산 객체
  const [editForm,  setEditForm]   = useState({});
  const [editSaving,setEditSaving] = useState(false);
  const [editMsg,   setEditMsg]    = useState(null);
  const { divs: orgDivs, depts: orgDepts } = React.useContext(OrgContext);
  const dbDivs  = orgDivs;
  const dbDepts = orgDepts;

  const openEdit = (a, e) => {
    e.stopPropagation();
    setEditForm({
      name:        a.name        || "",
      ip:          a.ip          || "",
      asset_type:  a.asset_type  || "",
      environment: a.environment || "Production",
      division:    a.division    || "",
      department:  a.department  || "",
      manager:     a.manager     || "",
      priority:    a.priority    || "medium",
      note:        a.note        || "",
      scan_types:  a.scan_types  || "port,web,ssl",
      http_port:   a.http_port   || 80,
      https_port:  a.https_port  || 443,
      db_type:     a.db_type     || "",
      db_port:     a.db_port     || "",
    });
    setEditModal(a);
    setEditMsg(null);
  };

  const saveEdit = async () => {
    if (!editForm.name.trim()) { setEditMsg({ok:false,text:"시스템명을 입력하세요"}); return; }
    if (!editForm.ip.trim())   { setEditMsg({ok:false,text:"IP 주소를 입력하세요"}); return; }
    setEditSaving(true);
    try {
      await updateAsset(editModal.id, {
        ...editForm,
        http_port:  Number(editForm.http_port)  || 80,
        https_port: Number(editForm.https_port) || 443,
        db_port:    editForm.db_port ? Number(editForm.db_port) : null,
        db_type:    editForm.db_type || null,
      });
      setEditMsg({ok:true,text:"✅ 수정 완료"});
      await load();
      setTimeout(()=>setEditModal(null),800);
    } catch(e) {
      setEditMsg({ok:false,text:"❌ " + e.message});
    }
    setEditSaving(false);
  };

  const load = async () => {
    setLoading(true); setError(null);
    try { setAssets(await fetchAssets()); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const envs  = [...new Set(assets.map(a=>a.environment).filter(Boolean))];
  const types = [...new Set(assets.map(a=>a.asset_type).filter(Boolean))];

  const filtered = assets.filter(a => {
    const ms = !search || a.name?.toLowerCase().includes(search.toLowerCase()) || a.ip?.includes(search) || a.manager?.includes(search);
    const me = !envF  || a.environment === envF;
    const mt = !typeF || a.asset_type  === typeF;
    return ms && me && mt;
  }).sort((a,b) => {
    const v1 = a[sort.key] ?? ""; const v2 = b[sort.key] ?? "";
    const r  = typeof v1==="number" ? v1-v2 : String(v1).localeCompare(String(v2));
    return sort.asc ? r : -r;
  });

  const totalPages = Math.ceil(filtered.length / pageSize);

  // ── 그룹 분리 ─────────────────────────────────────────────
  const me   = currentUser?.name       || "";
  const myDept = currentUser?.dept || currentUser?.department || "";
  const myAssets   = me     ? filtered.filter(a => a.manager === me) : [];
  const deptAssets = myDept ? filtered.filter(a => a.department === myDept && a.manager !== me) : [];
  const otherAssets = filtered.filter(a =>
    (me ? a.manager !== me : true) && (myDept ? a.department !== myDept : true)
  );
  const groupMode = me || myDept;
  const displayList = groupMode
    ? [...myAssets, ...deptAssets, ...otherAssets]
    : filtered;
  const paged = displayList.slice((page-1)*pageSize, page*pageSize);

  const onSort = k => setSort(p => ({ key:k, asc:p.key===k?!p.asc:true }));
  const onPage = p => { setPage(p); setSelected(new Set()); };

  const toggleSel = id => setSelected(p => { const n=new Set(p); n.has(id)?n.delete(id):n.add(id); return n; });
  const selAll    = () => setSelected(new Set(paged.map(a=>a.id)));
  const deselAll  = () => setSelected(new Set());

  const doDelete = async () => {
    for (const id of selected) {
      try { await deleteAsset(id); } catch(e) {}
    }
    setSelected(new Set()); setDelConfirm(false); load();
  };

  const SEV_COLOR = { crit:"#F87171", high:"#FB923C", med:"#FBBF24", low:"#4ADE80" };

  return (
    <div style={{ padding:"20px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>
        <Card>
          <div style={{ display:"flex", alignItems:"center", gap:10, marginBottom:12 }}>
            <button onClick={() => onNav("upload")}
              style={{ padding:"7px 16px", borderRadius:6, border:"none",
                background:"var(--accent)", color:"#fff", fontSize:13,
                fontWeight:700, cursor:"pointer", whiteSpace:"nowrap",
                display:"flex", alignItems:"center", gap:5 }}>
              ➕ 자산 등록
            </button>
            <span style={{ fontSize:13, fontWeight:600, color:"var(--txt2)" }}>
              전체 {assets.length}개
            </span>
          </div>

          <SearchBar value={search} onChange={v=>{setSearch(v);setPage(1);}} placeholder="시스템명 / IP / 담당자 검색...">
            <FilterSelect value={envF}  onChange={v=>{setEnvF(v);setPage(1);}}  options={ENVS} placeholder="전체 환경"/>
            <FilterSelect value={typeF} onChange={v=>{setTypeF(v);setPage(1);}} options={types} placeholder="전체 유형"/>
            <Btn variant="ghost" onClick={load}>↻</Btn>
          </SearchBar>

          {delConfirm && (
            <DeleteConfirm count={selected.size} onConfirm={doDelete} onCancel={()=>setDelConfirm(false)}/>
          )}
          <TableActions selected={selected.size} total={paged.length}
            onSelectAll={selAll} onDeselectAll={deselAll}
            onDelete={()=>setDelConfirm(true)}>
            <span style={{ fontSize:13, color:"var(--txt3)" }}>
              {filtered.length !== assets.length && `${filtered.length}건 필터됨`}
            </span>
          </TableActions>

          {paged.length === 0 ? (
            <EmptyState icon="🖥" title={assets.length===0?"등록된 자산 없음":"검색 결과 없음"}
              desc={assets.length===0?"자산을 먼저 등록하세요":"검색 조건을 변경해 보세요"}
              action={assets.length===0 ? <Btn variant="primary" onClick={()=>onNav("upload")}>➕ 자산 등록</Btn> : null}/>
          ) : (
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:12,
                tableLayout:"fixed" }}>
                <colgroup>
                  <col style={{width:28}}/>
                  <col style={{width:"18%"}}/>
                  <col style={{width:106}}/>
                  <col style={{width:54}}/>
                  <col style={{width:74}}/>
                  <col style={{width:"9%"}}/>
                  <col style={{width:"7%"}}/>
                  <col style={{width:66}}/>
                  <col style={{width:84}}/>
                  <col style={{width:54}}/>
                  <col style={{width:100}}/>
                  <col style={{width:44}}/>
                  <col style={{width:40}}/>
                </colgroup>
                <thead>
                  <tr style={{ background:"var(--bg-card2)" }}>
                    <th style={{ width:36, borderBottom:"2px solid var(--bdr)" }}/>
                    <Th sortKey="name"        sortState={sort} onSort={onSort}>시스템명</Th>
                    <Th sortKey="ip"          sortState={sort} onSort={onSort}>IP 주소</Th>
                    <Th sortKey="asset_type"  sortState={sort} onSort={onSort}>유형</Th>
                    <Th sortKey="environment" sortState={sort} onSort={onSort}>환경</Th>
                    <Th sortKey="department"  sortState={sort} onSort={onSort}>담당부서</Th>
                    <Th sortKey="manager"     sortState={sort} onSort={onSort}>담당자</Th>
                    <Th sortKey="risk_score"  sortState={sort} onSort={onSort}>위험점수</Th>
                    <Th sortKey="last_scan"   sortState={sort} onSort={onSort}>최종점검</Th>
                    <Th>상태</Th>
                    <Th>점검유형</Th>
                    <Th></Th>
                    <Th></Th>
                  </tr>
                </thead>
                <tbody>
                  {paged.map((a, ai) => {
                    const sev = a.risk_score>=70?"crit":a.risk_score>=50?"high":a.risk_score>=30?"med":"low";
                    const rc  = SEV_COLOR[sev];
                    const stMap = { completed:"online", scanning:"scan", pending:"off" };
                    const stLbl = { completed:"정상", scanning:"점검중", pending:"미점검" };
                    const sel  = selected.has(a.id);
                    const isMyAsset   = !!(me     && a.manager    === me);
                    const isDeptAsset = !!(myDept && a.department === myDept && !isMyAsset);
                    const isOther     = !isMyAsset && !isDeptAsset;
                    const prevA = ai > 0 ? paged[ai-1] : null;
                    const prevIsMy   = !!(prevA && me     && prevA.manager    === me);
                    const prevIsDept = !!(prevA && myDept && prevA.department === myDept && !(me && prevA.manager===me));
                    const showMyHeader    = groupMode && isMyAsset   && (ai===0 || !prevIsMy);
                    const showDeptHeader  = groupMode && isDeptAsset && (ai===0 || prevIsMy || (!prevIsDept && !prevIsMy));
                    const showOtherHeader = groupMode && isOther     && (ai===0 || prevIsMy || prevIsDept);
                    return (
                      <React.Fragment key={a.id}>
                        {showMyHeader && (
                          <tr>
                            <td colSpan={13} style={{ padding:"10px 14px 6px",
                              background:"rgba(37,99,235,.06)",
                              borderTop: ai>0 ? "2px solid rgba(37,99,235,.2)" : "none",
                              borderBottom:"1px solid rgba(37,99,235,.15)" }}>
                              <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                                <span style={{ width:8,height:8,borderRadius:"50%",background:"var(--accent)",
                                  display:"inline-block",boxShadow:"0 0 6px var(--accent)",flexShrink:0 }}/>
                                <span style={{ fontSize:13,fontWeight:700,color:"var(--accent-text)" }}>👤 내 담당 자산</span>
                                <span style={{ fontSize:13,color:"var(--txt3)" }}>— {me} · {myAssets.length}개</span>
                              </div>
                            </td>
                          </tr>
                        )}
                        {showDeptHeader && (
                          <tr>
                            <td colSpan={13} style={{ padding:"10px 14px 6px",
                              background:"rgba(251,191,36,.04)",
                              borderTop:"2px solid rgba(251,191,36,.15)",
                              borderBottom:"1px solid rgba(251,191,36,.1)" }}>
                              <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                                <span style={{ width:8,height:8,borderRadius:"50%",background:"#FBBF24",
                                  display:"inline-block",flexShrink:0 }}/>
                                <span style={{ fontSize:13,fontWeight:700,color:"#FBBF24" }}>🏢 {myDept} 자산</span>
                                <span style={{ fontSize:13,color:"var(--txt3)" }}>— {deptAssets.length}개</span>
                              </div>
                            </td>
                          </tr>
                        )}
                        {showOtherHeader && (
                          <tr>
                            <td colSpan={13} style={{ padding:"10px 14px 6px",
                              background:"var(--bg-card2)",
                              borderTop:"2px solid var(--bdr)",
                              borderBottom:"1px solid var(--bdr)" }}>
                              <div style={{ display:"flex",alignItems:"center",gap:8 }}>
                                <span style={{ width:8,height:8,borderRadius:"50%",background:"var(--txt3)",
                                  display:"inline-block",flexShrink:0 }}/>
                                <span style={{ fontSize:13,fontWeight:600,color:"var(--txt3)" }}>📋 전체 자산</span>
                                <span style={{ fontSize:13,color:"var(--txt3)" }}>— {otherAssets.length}개</span>
                              </div>
                            </td>
                          </tr>
                        )}
                        <tr onClick={()=>toggleSel(a.id)}
                          style={{ cursor:"pointer", transition:"background .1s",
                            background: sel ? "var(--bg-active)"
                              : isMyAsset   ? "rgba(37,99,235,.025)"
                              : isDeptAsset ? "rgba(251,191,36,.02)"
                              : "transparent",
                            borderLeft: isMyAsset   ? "3px solid rgba(37,99,235,.4)"
                                      : isDeptAsset ? "3px solid rgba(251,191,36,.35)"
                                      : "3px solid transparent",
                          }}>
                          <CheckTd checked={sel} onChange={()=>toggleSel(a.id)}/>
                          <Td>
                            <div style={{ fontWeight:600, color:"var(--txt)", fontSize:12,
                              overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}
                              title={a.name}>{a.name}</div>
                            {a.priority==="critical" && <Badge type="crit">긴급</Badge>}
                          </Td>
                          <Td><code style={{ fontSize:11, color:"var(--accent-text)", background:"var(--bg-card2)", padding:"2px 5px", borderRadius:3, whiteSpace:"nowrap" }}>{a.ip}</code></Td>
                          <Td><span style={{ fontSize:12, color:"var(--txt2)" }}>{a.asset_type||"—"}</span></Td>
                          <Td>
                            <Badge type={a.environment==="Production"?"crit":a.environment==="DR"?"warn":a.environment==="Staging"?"high":"info"}>
                              {a.environment||"—"}
                            </Badge>
                          </Td>
                          <Td><span style={{ fontSize:13, color:"var(--txt2)" }}>{a.department||"—"}</span></Td>
                          <Td><span style={{ fontSize:13, color:"var(--txt2)" }}>{a.manager||"—"}</span></Td>
                          <Td>
                            <div style={{ display:"flex", alignItems:"center", gap:6 }}>
                              <div style={{ width:48 }}><RBar pct={a.risk_score} color={rc}/></div>
                              <span style={{ fontSize:13, fontWeight:700, color:rc, minWidth:20 }}>{Math.round(a.risk_score)}</span>
                            </div>
                          </Td>
                          <Td><span style={{ fontSize:11, color:"var(--txt3)", whiteSpace:"nowrap" }}>{a.last_scan ? a.last_scan.slice(0,16).replace("T"," ") : "미점검"}</span></Td>
                          <Td><Chip type={stMap[a.status]||"off"} label={stLbl[a.status]||"미점검"}/></Td>
                          <Td>
                            {(a.status==="pending"||!a.status) && onScanNav && (
                              <button onClick={e=>{e.stopPropagation(); onScanNav(a.id);}}
                                title="점검 실행"
                                style={{ padding:"3px 7px", borderRadius:4,
                                  border:"1px solid rgba(37,99,235,.35)",
                                  background:"rgba(37,99,235,.08)",
                                  color:"#60A5FA", fontSize:11, fontWeight:600,
                                  cursor:"pointer", whiteSpace:"nowrap" }}>
                                점검
                              </button>
                            )}
                          </Td>
                          <Td>
                            <div style={{ display:"flex", gap:1, flexWrap:"nowrap",
                              overflow:"hidden", alignItems:"center" }}>
                              {(a.scan_types||"").split(",").filter(Boolean).map(t=>{
                                const SHORT={port:"P",web:"W",ssl:"S",db:"DB",network:"N"};
                                const FULL={port:"PORT",web:"WEB",ssl:"SSL",db:"DB",network:"NET"};
                                const COLOR={port:"#60A5FA",web:"#34D399",ssl:"#A78BFA",db:"#FBBF24",network:"#F472B6"};
                                return (
                                  <span key={t} title={FULL[t]||t.toUpperCase()}
                                    style={{ padding:"1px 4px", borderRadius:3,
                                    fontSize:9, fontWeight:700, fontFamily:"monospace",
                                    background:`${COLOR[t]||"#94A3B8"}15`,
                                    color:COLOR[t]||"var(--txt3)",
                                    border:`1px solid ${COLOR[t]||"#94A3B8"}35`,
                                    whiteSpace:"nowrap", flexShrink:0 }}>
                                    {FULL[t]||t.toUpperCase()}
                                  </span>
                                );
                              })}
                            </div>
                          </Td>
                          <Td>
                            <button onClick={e=>openEdit(a,e)}
                              title="수정"
                              style={{ padding:"3px 7px", borderRadius:4,
                                border:"1px solid rgba(251,191,36,.35)",
                                background:"rgba(251,191,36,.08)",
                                color:"#FBBF24", fontSize:11, fontWeight:600,
                                cursor:"pointer", whiteSpace:"nowrap" }}>
                              수정
                            </button>
                          </Td>
                        </tr>
                      </React.Fragment>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          <Pagination total={filtered.length} page={page} pageSize={pageSize}
            onPage={onPage} onPageSize={n=>{setPageSize(n);setPage(1);}}/>
        </Card>
      </PageWrap>

      {/* ══ 자산 수정 모달 ══ */}
      {editModal && (
        <div style={{ position:"fixed",inset:0,background:"rgba(0,0,0,.65)",zIndex:1000,
          display:"flex",alignItems:"center",justifyContent:"center",padding:20 }}
          onClick={e=>e.target===e.currentTarget&&setEditModal(null)}>
          <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:12,
            padding:24,maxWidth:660,width:"100%",maxHeight:"92vh",overflowY:"auto",
            boxShadow:"0 20px 60px rgba(0,0,0,.4)" }}>

            {/* 헤더 */}
            <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:16 }}>
              <div>
                <div style={{ fontSize:14,fontWeight:700,color:"var(--txt)" }}>✏ 자산 수정</div>
                <div style={{ fontSize:11,color:"var(--txt3)",marginTop:2 }}>{editModal.name} · {editModal.ip}</div>
              </div>
              <button onClick={()=>setEditModal(null)}
                style={{ background:"transparent",border:"none",cursor:"pointer",color:"var(--txt3)",fontSize:20 }}>✕</button>
            </div>

            {editMsg && (
              <div style={{ marginBottom:12,padding:"8px 12px",borderRadius:6,fontSize:12,
                background:editMsg.ok?"rgba(22,163,74,.08)":"rgba(220,38,38,.08)",
                color:editMsg.ok?"#4ADE80":"#F87171",
                border:`1px solid ${editMsg.ok?"rgba(22,163,74,.25)":"rgba(220,38,38,.25)"}`}}>
                {editMsg.text}
              </div>
            )}

            {/* ── 기본 정보 ── */}
            <div style={{ fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
              letterSpacing:".06em",marginBottom:8,paddingBottom:4,borderBottom:"1px solid var(--bdr)" }}>
              기본 정보
            </div>
            {/* 1행: 담당자 | 시스템명 | IP */}
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1.6fr 1.2fr",gap:10,marginBottom:10 }}>
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>담당자</label>
                <input value={editForm.manager||""} onChange={e=>setEditForm(p=>({...p,manager:e.target.value}))}
                  placeholder="홍길동"
                  style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                    background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
              </div>
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>시스템명 *</label>
                <input value={editForm.name||""} onChange={e=>setEditForm(p=>({...p,name:e.target.value}))}
                  placeholder="운영 웹서버"
                  style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                    background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
              </div>
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>IP 주소 *</label>
                <input value={editForm.ip||""} onChange={e=>setEditForm(p=>({...p,ip:e.target.value}))}
                  placeholder="192.168.1.100"
                  style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                    background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
              </div>
            </div>
            {/* 2행: 담당 본부 | 담당 부서 | 자산 유형 | 운영 환경 */}
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:10,marginBottom:14 }}>
              {/* 담당 본부 */}
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>담당 본부</label>
                {dbDivs.length > 0 ? (
                  <select value={editForm.division||""}
                    onChange={e=>setEditForm(p=>({...p,division:e.target.value}))}
                    style={{ width:"100%",padding:"7px 6px",borderRadius:6,border:"1px solid var(--bdr)",
                      background:"var(--bg-input)",color:editForm.division?"var(--txt)":"var(--txt3)",
                      fontSize:11,cursor:"pointer",outline:"none" }}>
                    <option value="">-- 선택 --</option>
                    {dbDivs.map(d=><option key={d} value={d}>{d}</option>)}
                  </select>
                ) : (
                  <input value={editForm.division||""} onChange={e=>setEditForm(p=>({...p,division:e.target.value}))}
                    placeholder="IT본부"
                    style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                      background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
                )}
              </div>
              {/* 담당 부서 */}
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>담당 부서</label>
                {dbDepts.length > 0 ? (
                  <select value={editForm.department||""}
                    onChange={e=>setEditForm(p=>({...p,department:e.target.value}))}
                    style={{ width:"100%",padding:"7px 6px",borderRadius:6,border:"1px solid var(--bdr)",
                      background:"var(--bg-input)",color:editForm.department?"var(--txt)":"var(--txt3)",
                      fontSize:11,cursor:"pointer",outline:"none" }}>
                    <option value="">-- 선택 --</option>
                    {dbDepts.map(d=><option key={d} value={d}>{d}</option>)}
                  </select>
                ) : (
                  <input value={editForm.department||""} onChange={e=>setEditForm(p=>({...p,department:e.target.value}))}
                    placeholder="IT운영팀"
                    style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                      background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
                )}
              </div>
              {/* 자산 유형 */}
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>자산 유형</label>
                <select value={editForm.asset_type||""} onChange={e=>setEditForm(p=>({...p,asset_type:e.target.value}))}
                  style={{ width:"100%",padding:"7px 6px",borderRadius:6,border:"1px solid var(--bdr)",
                    background:"var(--bg-input)",color:"var(--txt)",fontSize:11,cursor:"pointer",outline:"none" }}>
                  <option value="">-- 선택 --</option>
                  {["웹서버","WAS","DB서버","파일서버","네트워크장비","보안장비","PC","기타"].map(t=>(
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              {/* 운영 환경 */}
              <div>
                <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>운영 환경</label>
                <select value={editForm.environment||"Production"} onChange={e=>setEditForm(p=>({...p,environment:e.target.value}))}
                  style={{ width:"100%",padding:"7px 6px",borderRadius:6,border:"1px solid var(--bdr)",
                    background:"var(--bg-input)",color:"var(--txt)",fontSize:11,cursor:"pointer",outline:"none" }}>
                  {["Production","Staging","Development","DR","테스트","QA","Training"].map(t=>(
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
            </div>

            {/* ── 포트 / DB 설정 ── */}
            <div style={{ fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
              letterSpacing:".06em",marginBottom:8,paddingBottom:4,borderBottom:"1px solid var(--bdr)" }}>
              포트 / DB 설정
            </div>
            <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr 1fr 1fr",gap:10,marginBottom:14 }}>
              {[
                {k:"http_port",  l:"HTTP 포트",  ph:"80",   type:"number"},
                {k:"https_port", l:"HTTPS 포트", ph:"443",  type:"number"},
                {k:"db_type",    l:"DB 유형",    ph:"없음"},
                {k:"db_port",    l:"DB 포트",    ph:"3306", type:"number"},
              ].map(f=>(
                <div key={f.k}>
                  <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>{f.l}</label>
                  <input type={f.type||"text"} value={editForm[f.k]||""}
                    onChange={e=>setEditForm(p=>({...p,[f.k]:e.target.value}))}
                    placeholder={f.ph}
                    style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                      background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none" }}/>
                </div>
              ))}
            </div>

            {/* ── 점검 유형 ── */}
            <div style={{ fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
              letterSpacing:".06em",marginBottom:8,paddingBottom:4,borderBottom:"1px solid var(--bdr)" }}>
              점검 유형
            </div>
            <div style={{ display:"flex",gap:6,flexWrap:"wrap",marginBottom:14 }}>
              {[
                {id:"port",    label:"포트 스캔",   group:"서버/PC"},
                {id:"web",     label:"웹 취약점",   group:"서버/PC"},
                {id:"ssl",     label:"SSL/TLS",      group:"서버/PC"},
                {id:"db",      label:"DB 보안",      group:"DB"},
                {id:"network", label:"네트워크",     group:"Network"},
              ].map(t=>{
                const active = (editForm.scan_types||"").split(",").includes(t.id);
                const groupColor = t.group==="서버/PC"?"#60A5FA":t.group==="DB"?"#FBBF24":"#F472B6";
                return (
                  <div key={t.id} onClick={()=>{
                    const arr = (editForm.scan_types||"").split(",").filter(Boolean);
                    const next = active ? arr.filter(x=>x!==t.id) : [...arr,t.id];
                    setEditForm(p=>({...p,scan_types:next.join(",")}));
                  }} style={{ padding:"5px 12px",borderRadius:6,cursor:"pointer",fontSize:12,
                    fontWeight:active?700:400,transition:"all .15s",
                    border:`1px solid ${active?groupColor:"var(--bdr)"}`,
                    background:active?`${groupColor}18`:"transparent",
                    color:active?groupColor:"var(--txt3)" }}>
                    <span style={{ fontSize:10,color:active?groupColor:"var(--txt3)",marginRight:4,opacity:.7 }}>{t.group}</span>
                    {t.label}
                  </div>
                );
              })}
            </div>

            {/* ── 중요도 ── */}
            <div style={{ fontSize:10,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",
              letterSpacing:".06em",marginBottom:8,paddingBottom:4,borderBottom:"1px solid var(--bdr)" }}>
              중요도
            </div>
            <div style={{ display:"flex",gap:6,marginBottom:14 }}>
              {[
                {id:"critical",label:"긴급",  color:"#F87171"},
                {id:"high",    label:"고위험",color:"#FB923C"},
                {id:"medium",  label:"중간",  color:"#FBBF24"},
                {id:"low",     label:"낮음",  color:"#4ADE80"},
              ].map(p=>{
                const on = editForm.priority===p.id;
                return (
                  <div key={p.id} onClick={()=>setEditForm(f=>({...f,priority:p.id}))}
                    style={{ flex:1,padding:"7px 0",textAlign:"center",borderRadius:6,cursor:"pointer",
                      fontSize:12,fontWeight:on?700:400,transition:"all .15s",
                      border:`1px solid ${on?p.color:"var(--bdr)"}`,
                      background:on?`${p.color}18`:"transparent",
                      color:on?p.color:"var(--txt3)" }}>
                    {p.label}
                  </div>
                );
              })}
            </div>

            {/* ── 메모 ── */}
            <div style={{ marginBottom:16 }}>
              <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:700,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:4 }}>메모</label>
              <textarea value={editForm.note||""} onChange={e=>setEditForm(p=>({...p,note:e.target.value}))}
                placeholder="자산에 대한 추가 메모"
                rows={2}
                style={{ width:"100%",padding:"7px 9px",borderRadius:6,border:"1px solid var(--bdr)",
                  background:"var(--bg-input)",color:"var(--txt)",fontSize:12,outline:"none",
                  resize:"vertical",fontFamily:"inherit" }}/>
            </div>

            {/* ── 저장 / 취소 ── */}
            <div style={{ display:"flex",gap:8 }}>
              <button onClick={saveEdit} disabled={editSaving}
                style={{ flex:1,padding:"10px 0",borderRadius:7,border:"none",fontSize:13,fontWeight:700,
                  cursor:editSaving?"not-allowed":"pointer",
                  background:editSaving?"var(--bdr2)":"var(--accent)",color:"#fff",
                  display:"flex",alignItems:"center",justifyContent:"center",gap:6 }}>
                {editSaving ? "저장 중..." : "✅ 저장"}
              </button>
              <button onClick={()=>setEditModal(null)}
                style={{ padding:"10px 24px",borderRadius:7,border:"1px solid var(--bdr)",fontSize:13,
                  background:"transparent",color:"var(--txt3)",cursor:"pointer" }}>
                취소
              </button>
            </div>

          </div>
        </div>
      )}
    </div>
  );
}


// ═══════════════════════════════════════════════════════════════
// THREAT INTEL
// ═══════════════════════════════════════════════════════════════
export function PageThreat() {
  const [news,    setNews]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [source,  setSource]  = useState("all");
  const [fetching,setFetching]= useState(false);

  const load = async (s = source) => {
    setLoading(true); setError(null);
    try { setNews(await fetchNews(s === "all" ? "" : s)); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const onFetch = async () => {
    setFetching(true);
    try { await triggerNewsFetch(); await new Promise(r=>setTimeout(r,1500)); load(); }
    catch(e) {}
    finally { setFetching(false); }
  };

  const sources = ["all","KrCERT","금융보안원","KISA","CISA","NVD"];
  const sourceBg = { KrCERT:"#450A0A", "금융보안원":"#0C1A3A", KISA:"#052E16", CISA:"#2E1065", NVD:"#1C1000", Bleeping:"#2C1A00" };
  const sourceFg = { KrCERT:"#FCA5A5", "금융보안원":"#93C5FD", KISA:"#86EFAC", CISA:"#D8B4FE", NVD:"#FCD34D", Bleeping:"#FED7AA" };

  return (
    <div style={{ padding:"20px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>
        <Card>
          <CardHd title={
            <span style={{ display:"flex", alignItems:"center", gap:8 }}>
              보안 위협 인텔리전스
              <span style={{ fontSize:13, fontWeight:400, color:"var(--txt3)", background:"var(--bg-card2)", padding:"2px 8px", borderRadius:4, border:"1px solid var(--bdr)" }}>
                KrCERT · KISA · 금융보안원 · CISA · NVD 등 주요 기관의 실시간 위협 정보 피드
              </span>
            </span>
          } right={
            <div style={{ display:"flex", gap:6 }}>
              <Badge type="info">{news.length}건</Badge>
              <button onClick={onFetch} disabled={fetching} style={{ padding:"4px 12px", borderRadius:5, border:"1px solid var(--accent)", background:"var(--bg-active)", color:"var(--accent-text)", fontSize:13, fontWeight:600, cursor:"pointer" }}>
                {fetching ? "수집 중..." : "🔄 뉴스 수집"}
              </button>
            </div>
          }/>
          <div style={{ display:"flex", gap:6, marginBottom:14, flexWrap:"wrap" }}>
            {sources.map(s => (
              <button key={s} onClick={() => { setSource(s); load(s); }} style={{
                padding:"4px 10px", borderRadius:5, fontSize:13, cursor:"pointer",
                border:`1px solid ${source===s?"var(--accent)":"var(--bdr)"}`,
                background:source===s?"var(--bg-active)":"transparent",
                color:source===s?"var(--accent-text)":"var(--txt3)",
                fontWeight:source===s?600:400,
              }}>{s === "all" ? "전체" : s}</button>
            ))}
          </div>

          {news.length === 0 ? (
            <div style={{ textAlign:"center", padding:"40px 0", color:"var(--txt3)", fontSize:12 }}>
              뉴스가 없습니다. "뉴스 수집" 버튼을 눌러주세요.
            </div>
          ) : news.map((item,i) => (
            <div key={item.id} style={{ padding:"12px 0", borderBottom:i<news.length-1?"1px solid var(--bdr)":"none" }}>
              <div style={{ display:"flex", alignItems:"center", gap:6, marginBottom:5, flexWrap:"wrap" }}>
                <span style={{ padding:"2px 7px", borderRadius:3, fontSize:13, fontWeight:700, background:sourceBg[item.source]||"#0C1A3A", color:sourceFg[item.source]||"#93C5FD" }}>
                  {item.source} · {item.source_tag}
                </span>
                {item.affects_assets && <span style={{ fontSize:13, color:"#F87171", fontWeight:600 }}>● 자산 영향 확인됨</span>}
                <span style={{ marginLeft:"auto", fontSize:13, color:"var(--txt3)" }}>{item.published_at?.slice(0,10)}</span>
              </div>
              <div style={{ fontSize:13, color:"var(--txt)", lineHeight:1.65, marginBottom:4, fontWeight:500 }}>{item.title}</div>
              {item.summary && <div style={{ fontSize:13, color:"var(--txt3)", lineHeight:1.5 }}>{item.summary}</div>}
              {item.url && (
                <a href={item.url} target="_blank" rel="noreferrer" style={{ fontSize:13, color:"var(--accent-text)", textDecoration:"none", marginTop:4, display:"inline-block" }}>
                  원문 보기 →
                </a>
              )}
            </div>
          ))}
        </Card>
      </PageWrap>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// CVE
// ═══════════════════════════════════════════════════════════════
export function PageCVE() {
  const [cves,    setCves]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [expanded,setExpanded]= useState(null);
  const [days,    setDays]    = useState(30);

  const load = async (d = days) => {
    setLoading(true); setError(null);
    try { setCves(await fetchCVE(d)); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  return (
    <div style={{ padding:"20px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>
        <div style={{ display:"grid", gridTemplateColumns:"repeat(4,1fr)", gap:10, marginBottom:16 }}>
          {[
            {lbl:"전체 모니터링",  val:cves.length,                                          c:"var(--accent-text)"},
            {lbl:"자산 영향",      val:cves.filter(c=>c.affected_count>0).length,           c:"#F87171"},
            {lbl:"즉시 패치 필요", val:cves.filter(c=>c.affected_count>0&&c.cvss_score>=9).length, c:"#FB923C"},
            {lbl:"CISA KEV",      val:cves.filter(c=>c.is_kev).length,                     c:"#C084FC"},
          ].map(k => (
            <div key={k.lbl} style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:10, padding:"14px 16px" }}>
              <div style={{ fontSize:13, color:"var(--txt3)", fontWeight:600, textTransform:"uppercase", marginBottom:8, display:"flex", alignItems:"center", gap:4 }}>
                {k.lbl}
                {k.tip && <InfoTip text={k.tip}/>}
              </div>
              <div style={{ fontSize:26, fontWeight:700, color:k.c }}>{k.val}</div>
            </div>
          ))}
        </div>

        <Card>
          <CardHd title={
            <span style={{ display:"flex", alignItems:"center", gap:8 }}>
              CVE 취약점 모니터
              <span style={{ fontSize:13, fontWeight:400, color:"var(--txt3)", background:"var(--bg-card2)", padding:"2px 8px", borderRadius:4, border:"1px solid var(--bdr)" }}>
                CVE(Common Vulnerabilities and Exposures) — 전세계 공개 취약점 데이터베이스. CVSS 점수가 높을수록 위험
              </span>
            </span>
          } right={
            <div style={{ display:"flex", gap:6, alignItems:"center" }}>
              <select value={days} onChange={e=>{setDays(Number(e.target.value));load(Number(e.target.value));}}
                style={{ padding:"4px 8px", borderRadius:5, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:13, cursor:"pointer" }}>
                <option value={7}>최근 7일</option>
                <option value={30}>최근 30일</option>
                <option value={90}>최근 90일</option>
              </select>
              <button onClick={()=>load(days)} style={{ padding:"4px 10px", borderRadius:5, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>↻</button>
            </div>
          }/>

          {cves.length === 0 ? (
            <div style={{ textAlign:"center", padding:"40px 0", color:"var(--txt3)", fontSize:12 }}>등록된 CVE가 없습니다</div>
          ) : cves.map((c,i) => {
            const sev = c.cvss_score>=9?"crit":c.cvss_score>=7?"high":c.cvss_score>=4?"med":"low";
            return (
              <div key={c.id} style={{ borderBottom:i<cves.length-1?"1px solid var(--bdr)":"none" }}>
                <div style={{ display:"flex", alignItems:"center", gap:10, padding:"12px 0", cursor:"pointer" }} onClick={()=>setExpanded(expanded===c.id?null:c.id)}>
                  <code style={{ fontSize:13, color:SEV_COL[SEV_MAP[sev]]||"#93C5FD", width:130, flexShrink:0 }}>{c.id}</code>
                  <Badge type={sev}>{c.cvss_score}</Badge>
                  <div style={{ flex:1 }}>
                    <div style={{ fontSize:13, fontWeight:500, color:"var(--txt)" }}>{c.affected_products || c.id}</div>
                    <div style={{ fontSize:13, color:"var(--txt3)" }}>{c.description?.slice(0,80)}...</div>
                  </div>
                  <div style={{ display:"flex", gap:6, alignItems:"center" }}>
                    {c.affected_count > 0 ? <Badge type={sev}>{c.affected_count}개 자산</Badge> : <Badge type="ok">영향없음</Badge>}
                    {c.is_kev && <Badge type="purple">KEV</Badge>}
                    <span style={{ fontSize:13, color:"var(--txt3)" }}>{expanded===c.id?"▲":"▼"}</span>
                  </div>
                </div>
                {expanded === c.id && (
                  <div style={{ padding:"0 0 14px 140px", display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                    <div>
                      <div style={{ fontSize:13, color:"var(--txt3)", marginBottom:5, fontWeight:600 }}>상세 설명</div>
                      <div style={{ fontSize:13, color:"var(--txt)", lineHeight:1.6 }}>{c.description}</div>
                      <div style={{ fontSize:13, color:"var(--txt3)", marginTop:8 }}>공개일: {c.published_date?.slice(0,10)}</div>
                    </div>
                    <div>
                      <div style={{ fontSize:13, color:"var(--txt3)", marginBottom:5, fontWeight:600 }}>패치 방법</div>
                      <div style={{ fontSize:13, color:"#86EFAC", background:"#052E16", border:"1px solid #14532D", borderRadius:6, padding:"10px 12px", lineHeight:1.6 }}>
                        {c.patch_info || "패치 정보 없음"}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </Card>
      </PageWrap>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// COMPLIANCE
// ═══════════════════════════════════════════════════════════════
export function PageCompliance({ onNav }) {
  const [data,    setData]    = useState([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState(null);
  const [active,  setActive]  = useState(null);
  const [expandedIssue, setExpandedIssue] = useState(null);

  const load = async () => {
    setLoading(true); setError(null);
    try { setData(await fetchCompliance()); }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const STD_META = {
    "ISMS-P":          { icon:"🏛", agency:"KISA / 과학기술정보통신부", desc:"정보보호 및 개인정보보호 관리체계 인증", color:"#60A5FA", tag:"국내 필수",
      items:["접근통제","암호화","보안패치","네트워크보안","취약점관리"] },
    "전자금융감독규정": { icon:"🏦", agency:"금융감독원",               desc:"전자금융거래 보안 및 안전성 확보 규정", color:"#F87171", tag:"금융 필수",
      items:["정보보호체계","전자적침해","DB보안","망분리","취약점점검"] },
    "금융보안원 가이드":{ icon:"🔐", agency:"금융보안원",               desc:"금융권 IT·보안 종합 가이드라인",       color:"#FB923C", tag:"금융 권고",
      items:["서버보안","DB보안","네트워크","웹서비스","취약점관리"] },
    "PCI-DSS":         { icon:"💳", agency:"PCI SSC (국제)",            desc:"카드 결제 데이터 보안 표준",           color:"#C084FC", tag:"카드사 필수",
      items:["방화벽","암호화","접근통제","취약점관리","모니터링"] },
    "ISO 27001":       { icon:"🌐", agency:"ISO/IEC (국제)",            desc:"정보보안 경영시스템 국제 표준",         color:"#4ADE80", tag:"국제 표준",
      items:["위험평가","보안정책","물리보안","접근통제","사고대응"] },
    "NIST CSF":        { icon:"🇺🇸", agency:"NIST (미국)",              desc:"사이버보안 프레임워크",                color:"#FBBF24", tag:"참고 표준",
      items:["식별","보호","탐지","대응","복구"] },
  };

  // 미준수 항목 가이드 매핑 (취약점 유형 → 가이드)
  const ISSUE_GUIDE = {
    "포트":    { label:"위험 포트 외부 노출", guide:"PORT-00022", page:"findings" },
    "SSL":     { label:"SSL/TLS 취약점",      guide:"SSL-CONN-FAIL", page:"findings" },
    "웹":      { label:"웹 보안 헤더 미설정", guide:"WEB-HTTP-REDIRECT", page:"findings" },
    "DB":      { label:"DB 외부 노출",         guide:"PORT-01433", page:"findings" },
    "네트워크":{ label:"네트워크 취약점",       guide:"PORT-00135", page:"findings" },
    "인증서":  { label:"인증서 취약점",         guide:"SSL-CERT-EXPIRED", page:"findings" },
  };

  const totalScore   = data.length ? Math.round(data.reduce((s,d)=>s+d.score,0)/data.length) : 0;
  const criticalStds = data.filter(d=>d.score<70).length;
  const warningStds  = data.filter(d=>d.score>=70&&d.score<85).length;
  const safeStds     = data.filter(d=>d.score>=85).length;
  const totalIssues  = data.reduce((s,d)=>s+(d.issues||0),0);

  const selected = active ? data.find(d=>d.standard===active) : null;
  const selMeta  = active ? STD_META[active] : null;

  const scoreColor = s => s>=90?"#22C55E":s>=80?"#3B82F6":s>=70?"#F97316":"#EF4444";
  const scoreLabel = s => s>=90?"최우수":s>=80?"양호":s>=70?"주의":"즉시조치";

  return (
    <div style={{ padding:"16px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>

        {/* ── 헤더 ── */}
        <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:14 }}>
          <div>
            <div style={{ fontSize:15, fontWeight:700, color:"var(--txt)" }}>컴플라이언스 현황</div>
            <div style={{ fontSize:11, color:"var(--txt3)", marginTop:2 }}>
              금융보안원 · 금감원 · ISMS-P · PCI-DSS · ISO 27001 · NIST CSF 기반 자동 산출
            </div>
          </div>
          <button onClick={load}
            style={{ padding:"6px 12px", borderRadius:6, border:"1px solid var(--bdr)",
              background:"transparent", color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>
            ↻ 갱신
          </button>
        </div>

        {/* ── KPI ── */}
        <div style={{ display:"grid", gridTemplateColumns:"repeat(5,1fr)", gap:8, marginBottom:16 }}>
          {[
            { label:"종합 준수율", val:`${totalScore}%`, color:scoreColor(totalScore), icon:"📊",
              sub:scoreLabel(totalScore) },
            { label:"전체 미준수", val:`${totalIssues}건`, color:totalIssues>0?"#F87171":"#4ADE80", icon:"⚠",
              sub:"즉시 조치 필요" },
            { label:"규정 준수",   val:`${safeStds}개`,  color:"#4ADE80", icon:"✅", sub:"85% 이상" },
            { label:"주의",        val:`${warningStds}개`, color:"#F97316", icon:"🟠", sub:"70~85%" },
            { label:"즉시 조치",   val:`${criticalStds}개`, color:"#F87171", icon:"🚨", sub:"70% 미만" },
          ].map(k=>(
            <div key={k.label}
              style={{ background:"var(--bg-card)", border:`1px solid ${k.color}22`,
                borderRadius:10, padding:"12px 14px", cursor:"default" }}>
              <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:6 }}>
                <span style={{ fontSize:14 }}>{k.icon}</span>
                <span style={{ fontSize:10, color:"var(--txt3)", fontWeight:700,
                  textTransform:"uppercase", letterSpacing:".05em" }}>{k.label}</span>
              </div>
              <div style={{ fontSize:22, fontWeight:700, color:k.color, lineHeight:1 }}>{k.val}</div>
              <div style={{ fontSize:11, color:"var(--txt3)", marginTop:3 }}>{k.sub}</div>
            </div>
          ))}
        </div>

        {/* ── 메인: 규정 목록(왼) + 미준수 상세(오) ── */}
        <div style={{ display:"grid", gridTemplateColumns:"380px 1fr", gap:14, marginBottom:14 }}>

          {/* 왼쪽: 규정 카드 목록 */}
          <div style={{ display:"flex", flexDirection:"column", gap:6 }}>
            {data.length===0 && !loading && (
              <div style={{ textAlign:"center", padding:"40px 0", color:"var(--txt3)", fontSize:12 }}>
                <div style={{ fontSize:32, marginBottom:8, opacity:.3 }}>📋</div>
                점검 결과가 없습니다. 먼저 보안 점검을 실행하세요.
              </div>
            )}
            {data.map(d => {
              const meta = STD_META[d.standard]||{};
              const c    = scoreColor(d.score);
              const isOn = active===d.standard;
              const circ = 2*Math.PI*20;
              const dash = circ*(1-d.score/100);
              return (
                <div key={d.standard}
                  onClick={()=>setActive(isOn?null:d.standard)}
                  style={{ display:"flex", alignItems:"center", gap:10, padding:"10px 12px",
                    borderRadius:8, cursor:"pointer", transition:"all .15s",
                    background:isOn?"var(--bg-active)":"var(--bg-card)",
                    border:`1px solid ${isOn?"var(--accent)":d.issues>0?"rgba(248,113,113,.2)":"var(--bdr)"}`,
                    borderLeft:`3px solid ${c}` }}
                  onMouseEnter={e=>!isOn&&(e.currentTarget.style.background="var(--bg-hover)")}
                  onMouseLeave={e=>!isOn&&(e.currentTarget.style.background="var(--bg-card)")}>

                  {/* 스코어 링 */}
                  <div style={{ position:"relative", flexShrink:0, width:48, height:48 }}>
                    <svg width={48} height={48} style={{ transform:"rotate(-90deg)" }}>
                      <circle cx={24} cy={24} r={20} fill="none" stroke="var(--bdr)" strokeWidth={4}/>
                      <circle cx={24} cy={24} r={20} fill="none" stroke={c} strokeWidth={4}
                        strokeDasharray={circ} strokeDashoffset={dash} strokeLinecap="round"/>
                    </svg>
                    <div style={{ position:"absolute", top:0, left:0, width:48, height:48,
                      display:"flex", alignItems:"center", justifyContent:"center" }}>
                      <span style={{ fontSize:11, fontWeight:700, color:c }}>{d.score}</span>
                    </div>
                  </div>

                  {/* 규정 정보 */}
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ display:"flex", alignItems:"center", gap:5, marginBottom:2 }}>
                      <span style={{ fontSize:13 }}>{meta.icon||"📋"}</span>
                      <span style={{ fontSize:12, fontWeight:700, color:"var(--txt)",
                        overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>
                        {d.standard}
                      </span>
                      <span style={{ fontSize:9, padding:"1px 5px", borderRadius:3,
                        background:`${meta.color||"#94A3B8"}18`, color:meta.color||"#94A3B8",
                        border:`1px solid ${meta.color||"#94A3B8"}30`,
                        fontWeight:700, flexShrink:0, whiteSpace:"nowrap" }}>
                        {meta.tag||""}
                      </span>
                    </div>
                    <div style={{ fontSize:10, color:"var(--txt3)", marginBottom:4 }}>{meta.agency}</div>
                    <div style={{ height:3, borderRadius:2, background:"var(--bdr)", overflow:"hidden" }}>
                      <div style={{ height:"100%", width:`${d.score}%`, background:c,
                        borderRadius:2, transition:"width .8s ease" }}/>
                    </div>
                  </div>

                  {/* 미준수 배지 */}
                  <div style={{ flexShrink:0, textAlign:"right" }}>
                    {d.issues>0 ? (
                      <div style={{ display:"inline-flex", alignItems:"center", gap:4,
                        padding:"3px 8px", borderRadius:20,
                        background:"rgba(248,113,113,.1)", border:"1px solid rgba(248,113,113,.25)" }}>
                        <span style={{ width:5, height:5, borderRadius:"50%",
                          background:"#F87171", flexShrink:0 }}/>
                        <span style={{ fontSize:11, fontWeight:700, color:"#F87171" }}>
                          {d.issues}건
                        </span>
                      </div>
                    ) : (
                      <div style={{ display:"inline-flex", alignItems:"center", gap:4,
                        padding:"3px 8px", borderRadius:20,
                        background:"rgba(74,222,128,.08)", border:"1px solid rgba(74,222,128,.2)" }}>
                        <span style={{ fontSize:11, fontWeight:600, color:"#4ADE80" }}>✓ 준수</span>
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
          </div>

          {/* 오른쪽: 미준수 항목 상세 */}
          <div>
            {selected && selMeta ? (
              <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)",
                borderRadius:10, overflow:"hidden", height:"100%" }}>

                {/* 규정 헤더 */}
                <div style={{ padding:"14px 16px", borderBottom:"1px solid var(--bdr)",
                  background:"var(--bg-card2)",
                  borderTop:`3px solid ${scoreColor(selected.score)}` }}>
                  <div style={{ display:"flex", alignItems:"center", gap:10 }}>
                    <span style={{ fontSize:20 }}>{selMeta.icon}</span>
                    <div style={{ flex:1 }}>
                      <div style={{ fontSize:13, fontWeight:700, color:"var(--txt)" }}>
                        {selected.standard}
                      </div>
                      <div style={{ fontSize:11, color:"var(--txt3)", marginTop:1 }}>
                        {selMeta.agency} · {selMeta.desc}
                      </div>
                    </div>
                    {/* 스코어 */}
                    <div style={{ textAlign:"center", flexShrink:0 }}>
                      <div style={{ fontSize:24, fontWeight:700,
                        color:scoreColor(selected.score) }}>{selected.score}%</div>
                      <div style={{ fontSize:10, color:scoreColor(selected.score),
                        fontWeight:600 }}>{scoreLabel(selected.score)}</div>
                    </div>
                  </div>
                  {/* 준수율 바 */}
                  <div style={{ marginTop:10 }}>
                    <div style={{ height:6, borderRadius:3, background:"var(--bdr)", overflow:"hidden" }}>
                      <div style={{ height:"100%", width:`${selected.score}%`,
                        borderRadius:3, transition:"width .8s",
                        background:scoreColor(selected.score) }}/>
                    </div>
                    <div style={{ display:"flex", justifyContent:"space-between",
                      marginTop:3, fontSize:10, color:"var(--txt3)" }}>
                      <span>0%</span>
                      <span style={{color:"#EF4444"}}>70% 즉시조치</span>
                      <span style={{color:"#F97316"}}>85% 주의</span>
                      <span style={{color:"#22C55E"}}>90%+ 최우수</span>
                    </div>
                  </div>
                </div>

                {/* 통계 3칸 */}
                <div style={{ display:"grid", gridTemplateColumns:"repeat(3,1fr)",
                  borderBottom:"1px solid var(--bdr)" }}>
                  {[
                    { l:"통제 항목", v:selected.total_items||"—", c:"var(--txt)", icon:"📋" },
                    { l:"관련 취약점", v:selected.related_vulns||0, c:"#FB923C", icon:"🛡" },
                    { l:"미준수 항목", v:selected.issues||0,
                      c:selected.issues>0?"#F87171":"#4ADE80", icon:"⚠" },
                  ].map((s,i)=>(
                    <div key={s.l} style={{ padding:"10px 14px", textAlign:"center",
                      borderRight:i<2?"1px solid var(--bdr)":"none" }}>
                      <div style={{ fontSize:10, color:"var(--txt3)", textTransform:"uppercase",
                        letterSpacing:".05em", marginBottom:4 }}>{s.l}</div>
                      <div style={{ fontSize:20, fontWeight:700, color:s.c }}>{s.v}</div>
                    </div>
                  ))}
                </div>

                {/* 미준수 항목 목록 — 가이드 링크 포함 */}
                <div style={{ padding:"12px 14px", overflowY:"auto", maxHeight:280 }}>
                  <div style={{ fontSize:11, fontWeight:700, color:"var(--txt3)",
                    textTransform:"uppercase", letterSpacing:".05em", marginBottom:8 }}>
                    미준수 항목 및 조치 가이드
                  </div>

                  {selected.issues>0 ? (
                    <div style={{ display:"flex", flexDirection:"column", gap:4 }}>
                      {/* 관련 취약점 유형별 표시 */}
                      {(selMeta.items||[]).map((item,i) => {
                        const guideKey = Object.keys(ISSUE_GUIDE).find(k=>item.includes(k));
                        const guide = guideKey ? ISSUE_GUIDE[guideKey] : null;
                        const hasIssue = i < selected.issues;
                        return (
                          <div key={item}
                            style={{ display:"flex", alignItems:"center", gap:8,
                              padding:"8px 10px", borderRadius:6,
                              background:hasIssue?"rgba(248,113,113,.05)":"var(--bg-card2)",
                              border:`1px solid ${hasIssue?"rgba(248,113,113,.15)":"var(--bdr)"}`,
                              transition:"all .15s" }}>
                            {/* 상태 */}
                            <div style={{ width:20, height:20, borderRadius:"50%",
                              flexShrink:0, display:"flex", alignItems:"center",
                              justifyContent:"center",
                              background:hasIssue?"rgba(248,113,113,.15)":"rgba(74,222,128,.12)",
                              border:`1px solid ${hasIssue?"rgba(248,113,113,.3)":"rgba(74,222,128,.3)"}` }}>
                              <span style={{ fontSize:10 }}>{hasIssue?"✕":"✓"}</span>
                            </div>
                            {/* 항목명 */}
                            <div style={{ flex:1, minWidth:0 }}>
                              <span style={{ fontSize:12, fontWeight:hasIssue?600:400,
                                color:hasIssue?"var(--txt)":"var(--txt3)" }}>
                                {item}
                              </span>
                              {hasIssue && (
                                <div style={{ fontSize:10, color:"#F87171", marginTop:1 }}>
                                  관련 취약점 발견 — 즉시 조치 필요
                                </div>
                              )}
                            </div>
                            {/* 가이드 + 취약점 보기 */}
                            {hasIssue && (
                              <div style={{ display:"flex", gap:4, flexShrink:0 }}>
                                <span onClick={()=>onNav&&onNav("findings")}
                                  style={{ fontSize:11, padding:"2px 7px", borderRadius:8,
                                    background:"rgba(248,113,113,.1)",
                                    border:"1px solid rgba(248,113,113,.2)",
                                    color:"#F87171", cursor:"pointer", whiteSpace:"nowrap" }}>
                                  취약점 ↗
                                </span>
                                {guide && (
                                  <span onClick={()=>onNav&&onNav("findings")}
                                    style={{ fontSize:11, padding:"2px 7px", borderRadius:8,
                                      background:"rgba(96,165,250,.08)",
                                      border:"1px solid rgba(96,165,250,.2)",
                                      color:"var(--accent-text)", cursor:"pointer", whiteSpace:"nowrap" }}>
                                    가이드 ↗
                                  </span>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  ) : (
                    <div style={{ textAlign:"center", padding:"20px 0",
                      color:"#4ADE80", fontSize:12 }}>
                      <div style={{ fontSize:24, marginBottom:6 }}>✅</div>
                      모든 항목이 준수 상태입니다
                    </div>
                  )}
                </div>

                {/* 하단 액션 */}
                <div style={{ padding:"10px 14px", borderTop:"1px solid var(--bdr)",
                  background:"var(--bg-card2)", display:"flex", gap:8 }}>
                  <button onClick={()=>onNav&&onNav("findings")}
                    style={{ flex:1, padding:"7px", borderRadius:6,
                      border:"1px solid var(--accent)", background:"var(--bg-active)",
                      color:"var(--accent-text)", fontSize:12, fontWeight:600, cursor:"pointer" }}>
                    🛡 관련 취약점 전체 보기
                  </button>
                  <button onClick={()=>onNav&&onNav("reports")}
                    style={{ flex:1, padding:"7px", borderRadius:6,
                      border:"1px solid var(--bdr)", background:"transparent",
                      color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>
                    📄 규정 보고서 생성
                  </button>
                </div>
              </div>
            ) : (
              /* 선택 전 — 전체 요약 */
              <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)",
                borderRadius:10, padding:"16px" }}>
                <div style={{ fontSize:11, fontWeight:700, color:"var(--txt3)",
                  textTransform:"uppercase", letterSpacing:".06em", marginBottom:12 }}>
                  전체 준수 현황
                </div>
                {data.map(d=>{
                  const c = scoreColor(d.score);
                  const m = STD_META[d.standard]||{};
                  return (
                    <div key={d.standard}
                      onClick={()=>setActive(d.standard)}
                      style={{ display:"flex", alignItems:"center", gap:8,
                        marginBottom:8, cursor:"pointer", padding:"6px 8px",
                        borderRadius:6, transition:"background .1s" }}
                      onMouseEnter={e=>e.currentTarget.style.background="var(--bg-hover)"}
                      onMouseLeave={e=>e.currentTarget.style.background="transparent"}>
                      <span style={{ fontSize:14, flexShrink:0 }}>{m.icon||"📋"}</span>
                      <span style={{ fontSize:12, color:"var(--txt2)", width:120, flexShrink:0 }}>
                        {d.standard}
                      </span>
                      <div style={{ flex:1, height:5, borderRadius:2,
                        background:"var(--bdr)", overflow:"hidden" }}>
                        <div style={{ height:"100%", width:`${d.score}%`,
                          background:c, borderRadius:2 }}/>
                      </div>
                      <span style={{ fontSize:12, fontWeight:700, color:c,
                        minWidth:36, textAlign:"right" }}>{d.score}%</span>
                      {d.issues>0 && (
                        <span style={{ fontSize:10, padding:"1px 6px", borderRadius:8,
                          background:"rgba(248,113,113,.1)", color:"#F87171",
                          border:"1px solid rgba(248,113,113,.2)", flexShrink:0 }}>
                          {d.issues}건
                        </span>
                      )}
                    </div>
                  );
                })}
                {data.length===0 && (
                  <div style={{ textAlign:"center", padding:"30px 0",
                    color:"var(--txt3)", fontSize:12 }}>
                    <div style={{ fontSize:28, marginBottom:8, opacity:.3 }}>📊</div>
                    규정을 클릭하면 미준수 항목을 확인할 수 있습니다
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* 하단 안내 */}
        <div style={{ padding:"8px 14px", background:"var(--bg-card2)",
          border:"1px solid var(--bdr)", borderRadius:7,
          fontSize:11, color:"var(--txt3)", lineHeight:1.7 }}>
          💡 준수율은 각 규정과 연관된 취약점(포트·웹·SSL·DB·네트워크)의 긴급·고위험 발생 건수 기반으로 자동 산출됩니다.
          취약점을 조치하면 준수율이 향상됩니다.
        </div>

      </PageWrap>
    </div>
  );
}


export function PageHistory({ onNav, onNavWithFilter, currentUser }) {
  const [history,      setHistory]      = useState([]);
  const [loading,      setLoading]      = useState(true);
  const [error,        setError]        = useState(null);
  const [registeredIPs, setRegisteredIPs] = useState(new Set()); // 등록된 자산 IP
  const [regMsg,       setRegMsg]       = useState(null); // 자산 등록 결과 메시지
  const [search,  setSearch]  = useState("");
  const [statusF, setStatusF] = useState("");
  const [sort,    setSort]    = useState({ key:"created_at", asc:false });
  const [page,    setPage]    = useState(1);
  const [pageSize,setPageSize]= useState(20);
  const [selected,setSelected]= useState(new Set());
  const [delConfirm,setDelConfirm] = useState(false);
  const [delMsg,    setDelMsg]     = useState(null);
  const [editModal, setEditModal]  = useState(null);  // 수정할 자산 객체
  const [editForm,  setEditForm]   = useState({});
  const [editSaving,setEditSaving] = useState(false);
  const [editMsg,   setEditMsg]    = useState(null);
  const { divs: orgDivs, depts: orgDepts } = React.useContext(OrgContext);
  const dbDivs  = orgDivs;
  const dbDepts = orgDepts;

  const openEdit = (a, e) => {
    e.stopPropagation();
    setEditForm({
      name:        a.name        || "",
      ip:          a.ip          || "",
      asset_type:  a.asset_type  || "",
      environment: a.environment || "Production",
      division:    a.division    || "",
      department:  a.department  || "",
      manager:     a.manager     || "",
      priority:    a.priority    || "medium",
      note:        a.note        || "",
      scan_types:  a.scan_types  || "port,web,ssl",
      http_port:   a.http_port   || 80,
      https_port:  a.https_port  || 443,
      db_type:     a.db_type     || "",
      db_port:     a.db_port     || "",
    });
    setEditModal(a);
    setEditMsg(null);
  };

  const saveEdit = async () => {
    if (!editForm.name.trim()) { setEditMsg({ok:false,text:"시스템명을 입력하세요"}); return; }
    if (!editForm.ip.trim())   { setEditMsg({ok:false,text:"IP 주소를 입력하세요"}); return; }
    setEditSaving(true);
    try {
      await updateAsset(editModal.id, {
        ...editForm,
        http_port:  Number(editForm.http_port)  || 80,
        https_port: Number(editForm.https_port) || 443,
        db_port:    editForm.db_port ? Number(editForm.db_port) : null,
        db_type:    editForm.db_type || null,
      });
      setEditMsg({ok:true,text:"✅ 수정 완료"});
      await load();
      setTimeout(()=>setEditModal(null),800);
    } catch(e) {
      setEditMsg({ok:false,text:"❌ " + e.message});
    }
    setEditSaving(false);
  };

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [hist, assets] = await Promise.all([
        fetchScanHistory(),
        fetchAssets().catch(()=>[]),
      ]);
      setHistory(Array.isArray(hist) ? hist : []);
      setRegisteredIPs(new Set((Array.isArray(assets)?assets:[]).map(a=>a.ip)));
    }
    catch(e) { setError(e.message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const deleteSelected = async () => {
    if (selected.size === 0) return;
    if (!window.confirm(`선택한 점검 이력 ${selected.size}건을 삭제하시겠습니까?`)) return;
    try {
      const r = await fetch(`${API_BASE}/api/scan/history`, {
        method:"DELETE", headers:{"Content-Type":"application/json"},
        body: JSON.stringify({ids:[...selected]})
      }).then(r=>r.json());
      setDelMsg({ok:true, text:`${r.deleted}건 삭제 완료`});
      setSelected(new Set());
      await load();
    } catch(e) { setDelMsg({ok:false, text:"삭제 실패: "+e.message}); }
    setTimeout(()=>setDelMsg(null), 3000);
  };

  const deleteAll = async () => {
    if (!window.confirm(`점검 이력 전체 ${history.length}건을 모두 삭제하시겠습니까?
이 작업은 되돌릴 수 없습니다.`)) return;
    try {
      const r = await fetch(`${API_BASE}/api/scan/history/all`, {method:"DELETE"}).then(r=>r.json());
      setDelMsg({ok:true, text:`전체 ${r.deleted}건 삭제 완료`});
      setSelected(new Set());
      await load();
    } catch(e) { setDelMsg({ok:false, text:"삭제 실패: "+e.message}); }
    setTimeout(()=>setDelMsg(null), 3000);
  };

  const toggleAll = () => {
    if (selected.size === paged.length) setSelected(new Set());
    else setSelected(new Set(paged.map(h=>h.id)));
  };
  const toggle = (id) => setSelected(p=>{ const n=new Set(p); n.has(id)?n.delete(id):n.add(id); return n; });

  const filtered = history.filter(h => {
    const ms = !search || h.asset_name?.toLowerCase().includes(search.toLowerCase()) || h.asset_ip?.includes(search);
    const mst = !statusF || h.status === statusF;
    return ms && mst;
  }).sort((a,b) => {
    const v1=a[sort.key]??""; const v2=b[sort.key]??"";
    const r=typeof v1==="number"?v1-v2:String(v1).localeCompare(String(v2));
    return sort.asc?r:-r;
  });

  const paged = filtered.slice((page-1)*pageSize, page*pageSize);
  const onSort = k => setSort(p=>({key:k,asc:p.key===k?!p.asc:true}));

  return (
    <div style={{ padding:"20px 22px" }}>
      <PageWrap loading={loading} error={error} onRetry={load}>
        <Card>
          <CardHd title={`점검 이력 — ${history.length}건`} right={
            <div style={{display:"flex",gap:6,alignItems:"center"}}>
              {selected.size>0&&(
                <>
                  <span style={{fontSize:13,color:"var(--accent-text)",fontWeight:600}}>{selected.size}건 선택</span>
                  <Btn variant="danger" onClick={deleteSelected}>🗑 선택 삭제</Btn>
                </>
              )}
              <Btn variant="ghost" onClick={deleteAll} style={{color:"#F87171"}}>🗑 전체 삭제</Btn>
              <Btn variant="ghost" onClick={load}>↻ 새로고침</Btn>
            </div>
          }/>
          {delMsg&&(
            <div style={{margin:"0 0 8px",padding:"7px 12px",borderRadius:6,fontSize:13,fontWeight:600,
              color:delMsg.ok?"#4ADE80":"#F87171",
              background:delMsg.ok?"rgba(74,222,128,.08)":"rgba(248,113,113,.08)",
              border:`1px solid ${delMsg.ok?"rgba(74,222,128,.2)":"rgba(248,113,113,.2)"}`}}>
              {delMsg.ok?"✅":"❌"} {delMsg.text}
            </div>
          )}
          {regMsg && (
            <div style={{ margin:"0 0 8px", padding:"7px 12px", borderRadius:6, fontSize:13, fontWeight:600,
              color:regMsg.ok?"#4ADE80":"#F87171",
              background:regMsg.ok?"rgba(74,222,128,.08)":"rgba(248,113,113,.08)",
              border:`1px solid ${regMsg.ok?"rgba(74,222,128,.2)":"rgba(248,113,113,.2)"}`}}>
              {regMsg.text}
            </div>
          )}
          <SearchBar value={search} onChange={v=>{setSearch(v);setPage(1);}} placeholder="자산명 / IP 검색...">
            <FilterSelect value={statusF} onChange={v=>{setStatusF(v);setPage(1);}}
              options={[{value:"completed",label:"완료"},{value:"failed",label:"실패"},{value:"running",label:"진행중"}]}
              placeholder="전체 상태"/>
          </SearchBar>

          {paged.length === 0 ? (
            <EmptyState icon="📜" title="점검 이력 없음" desc="보안 점검을 실행하면 이력이 쌓입니다"/>
          ) : (
            <div style={{ overflowX:"auto" }}>
              <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
                <thead><tr style={{ background:"var(--bg-card2)" }}>
                  <th style={{padding:"10px 12px",width:36,background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)"}}>
                    <div onClick={toggleAll}
                      style={{width:14,height:14,borderRadius:3,cursor:"pointer",
                        border:`2px solid ${selected.size===paged.length&&paged.length>0?"var(--accent)":"var(--bdr2)"}`,
                        background:selected.size===paged.length&&paged.length>0?"var(--accent)":selected.size>0?"rgba(37,99,235,.3)":"transparent",
                        display:"flex",alignItems:"center",justifyContent:"center"}}>
                      {selected.size===paged.length&&paged.length>0&&<span style={{color:"#fff",fontSize:12,fontWeight:700}}>✓</span>}
                      {selected.size>0&&selected.size<paged.length&&<span style={{color:"var(--accent-text)",fontSize:10,fontWeight:700}}>−</span>}
                    </div>
                  </th>
                  <Th sortKey="asset_name"  sortState={sort} onSort={onSort}>자산명</Th>
                  <Th sortKey="asset_ip"    sortState={sort} onSort={onSort}>IP</Th>
                  <Th>점검 유형</Th>
                  <Th sortKey="created_at"  sortState={sort} onSort={onSort}>시작 시각</Th>
                  <Th sortKey="duration_sec" sortState={sort} onSort={onSort}>소요시간</Th>
                  <Th sortKey="crit_count"  sortState={sort} onSort={onSort}>긴급</Th>
                  <Th sortKey="high_count"  sortState={sort} onSort={onSort}>고위험</Th>
                  <Th sortKey="med_count"   sortState={sort} onSort={onSort}>중위험</Th>
                  <Th sortKey="status"      sortState={sort} onSort={onSort}>상태</Th>
                </tr></thead>
                <tbody>
                  {paged.map(h => {
                    const canDrill = h.status==="completed" && (h.crit_count||h.high_count||h.med_count||0) > 0;
                    const isMe = currentUser && h.asset_manager && h.asset_manager === currentUser.name;
                    const isRegistered = registeredIPs.has(h.asset_ip);
                    const onClick = () => {
                      if (!onNav) return;
                      if (onNavWithFilter) onNavWithFilter({ assetIp: h.asset_ip, assetName: h.asset_name, jobId: h.id });
                      onNav("findings");
                    };
                    return (
                      <tr key={h.id}
                        onClick={onClick}
                        title={canDrill ? `${h.asset_name} 취약점 결과 보기` : ""}
                        style={{cursor:onNav?"pointer":"default",transition:"background .1s",
                          background:selected.has(h.id)?"rgba(37,99,235,.06)":isMe?"rgba(37,99,235,.04)":"",
                          borderLeft: isMe ? "3px solid var(--accent)" : "3px solid transparent",
                        }}
                        onMouseEnter={e=>!selected.has(h.id)&&(e.currentTarget.style.background="var(--bg-hover)")}
                        onMouseLeave={e=>!selected.has(h.id)&&(e.currentTarget.style.background=isMe?"rgba(37,99,235,.04)":"")}>
                        <td style={{padding:"10px 12px"}} onClick={e=>{e.stopPropagation();toggle(h.id);}}>
                          <div style={{width:14,height:14,borderRadius:3,cursor:"pointer",
                            border:`2px solid ${selected.has(h.id)?"var(--accent)":"var(--bdr2)"}`,
                            background:selected.has(h.id)?"var(--accent)":"transparent",
                            display:"flex",alignItems:"center",justifyContent:"center"}}>
                            {selected.has(h.id)&&<span style={{color:"#fff",fontSize:12,fontWeight:700}}>✓</span>}
                          </div>
                        </td>
                        <Td>
                          <div style={{ display:"flex", alignItems:"center", gap:6, flexWrap:"wrap" }}>
                            <span style={{ fontWeight:700, color: isMe ? "var(--accent-text)" : "var(--txt)" }}>{h.asset_name}</span>
                            {isMe && <span style={{ fontSize:13, padding:"1px 5px", borderRadius:3, background:"rgba(37,99,235,.15)", color:"#60A5FA", border:"1px solid rgba(37,99,235,.3)" }}>나</span>}
                            {!isRegistered && (
                              <button
                                onClick={async e => {
                                  e.stopPropagation();
                                  try {
                                    await createAsset({
                                      name: h.asset_name, ip: h.asset_ip,
                                      asset_type: "PC", environment: "Production",
                                      manager: h.asset_manager || "",
                                      scan_types: h.scan_types || "port,web,ssl",
                                      http_port: 80, https_port: 443,
                                      priority: "medium",
                                    });
                                    setRegisteredIPs(p => new Set([...p, h.asset_ip]));
                                    setRegMsg({ ok:true, text:`✅ ${h.asset_name} 자산 등록 완료` });
                                    setTimeout(()=>setRegMsg(null), 3000);
                                  } catch(err) {
                                    setRegMsg({ ok:false, text:`❌ 등록 실패: ${err.message}` });
                                  }
                                }}
                                style={{ padding:"2px 8px", borderRadius:4, fontSize:11, fontWeight:600,
                                  border:"1px solid rgba(220,38,38,.4)",
                                  background:"rgba(220,38,38,.08)", color:"#DC2626",
                                  cursor:"pointer", whiteSpace:"nowrap", flexShrink:0 }}>
                                + 자산 등록
                              </button>
                            )}
                            {canDrill && (
                              <span title="취약점 결과 보기"
                                style={{ fontSize:11, padding:"2px 7px", borderRadius:10,
                                  background:"rgba(96,165,250,.08)", color:"var(--accent-text)",
                                  border:"1px solid rgba(96,165,250,.2)", flexShrink:0,
                                  letterSpacing:".01em", fontWeight:500, cursor:"pointer",
                                  transition:"all .15s" }}
                                onMouseEnter={e=>e.currentTarget.style.background="rgba(96,165,250,.18)"}
                                onMouseLeave={e=>e.currentTarget.style.background="rgba(96,165,250,.08)"}>
                                결과 ↗
                              </span>
                            )}
                          </div>
                        </Td>
                        <Td><code style={{ fontSize:13, color:"var(--accent-text)", background:"var(--bg-card2)", padding:"2px 6px", borderRadius:3 }}>{h.asset_ip}</code></Td>
                        <Td><span style={{ fontSize:13, color:"var(--txt3)" }}>{h.scan_types}</span></Td>
                        <Td><span style={{ fontSize:12, color:"var(--txt3)", whiteSpace:"nowrap" }}>{h.created_at?.slice(0,16).replace('T',' ') || '—'}</span></Td>
                        <Td><span style={{ fontSize:11 }}>{h.duration_sec?`${Math.round(h.duration_sec)}초`:"—"}</span></Td>
                        <Td><span style={{ fontWeight:700, color:"#F87171" }}>{h.crit_count||0}</span></Td>
                        <Td><span style={{ fontWeight:700, color:"#FB923C" }}>{h.high_count||0}</span></Td>
                        <Td><span style={{ fontWeight:700, color:"#FBBF24" }}>{h.med_count||0}</span></Td>
                        <Td>
                          <Badge type={h.status==="completed"?"ok":h.status==="failed"?"crit":"info"}>
                            {h.status==="completed"?"완료":h.status==="failed"?"실패":"진행중"}
                          </Badge>
                        </Td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          <Pagination total={filtered.length} page={page} pageSize={pageSize}
            onPage={setPage} onPageSize={n=>{setPageSize(n);setPage(1);}}/>
        </Card>
      </PageWrap>
    </div>
  );
}


// ── 자산등록 상수 ─────────────────────────────────────────────────
const ASSET_TYPES   = ["웹서버","WAS","DB서버","파일서버","네트워크장비","보안장비","PC","기타"];

// SYSTEM_NAME_PRESETS — frontend/src/config/assetPresets.js 에서 관리
// 설정 화면에서 변경 시 localStorage("ssk_asset_presets") 우선 사용
function useAssetPresets() {
  const [presets, setPresets] = useState(() => {
    try {
      const saved = localStorage.getItem("ssk_asset_presets");
      return saved ? JSON.parse(saved) : SYSTEM_NAME_PRESETS;
    } catch { return SYSTEM_NAME_PRESETS; }
  });
  // storage 이벤트로 다른 탭에서 변경 시 자동 반영
  useEffect(() => {
    const handler = () => {
      try {
        const saved = localStorage.getItem("ssk_asset_presets");
        if (saved) setPresets(JSON.parse(saved));
      } catch {}
    };
    window.addEventListener("storage", handler);
    return () => window.removeEventListener("storage", handler);
  }, []);
  const pcItems = presets.filter(g=>g.pcGroup).flatMap(g=>g.items);
  return { presets, pcItems };
}
const ENVIRONMENTS  = ["Production","Staging","Development","DR","테스트","QA","Training"];
const PRIORITIES    = [
  {id:"critical", label:"긴급",   color:"#F87171"},
  {id:"high",     label:"고위험", color:"#FB923C"},
  {id:"medium",   label:"중간",   color:"#FBBF24"},
  {id:"low",      label:"낮음",   color:"#4ADE80"},
];
const SCAN_TYPE_OPTIONS = [
  {id:"port",    label:"포트 스캔"},
  {id:"web",     label:"웹 취약점"},
  {id:"ssl",     label:"SSL/TLS"},
  {id:"db",      label:"DB 보안"},
  {id:"network", label:"네트워크"},
];

// ── 자산등록 전용 입력 컴포넌트 ──────────────────────────────────
function Inp({ label, value, onChange, type="text", placeholder="", required=false, hint="" }) {
  return (
    <div style={{ marginBottom:12 }}>
      <label style={{ display:"block", fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:4, textTransform:"uppercase", letterSpacing:".05em" }}>
        {label}{required && <span style={{ color:"#F87171" }}> *</span>}
      </label>
      <input type={type} value={value} onChange={e=>onChange(e.target.value)} placeholder={placeholder}
        style={{ width:"100%", padding:"10px 12px", borderRadius:6, border:`1px solid ${value?"var(--accent)":"var(--bdr)"}`, background:"var(--bg-input)", color:"var(--txt)", fontSize:13, outline:"none", transition:"border-color .15s" }}/>
      {hint && <div style={{ fontSize:13, color:"var(--txt3)", marginTop:3 }}>{hint}</div>}
    </div>
  );
}

function Sel({ label, value, onChange, options, required=false, placeholder="", noEmpty=false }) {
  return (
    <div style={{ marginBottom:12 }}>
      <label style={{ display:"block", fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:4, textTransform:"uppercase", letterSpacing:".05em" }}>
        {label}{required && <span style={{ color:"#F87171" }}> *</span>}
      </label>
      <select value={value} onChange={e=>onChange(e.target.value)}
        style={{ width:"100%", padding:"10px 12px", borderRadius:6,
          border:`1px solid ${!value&&!noEmpty?"var(--accent)":"var(--bdr)"}`,
          background:"var(--bg-input)",
          color:value?"var(--txt)":"var(--txt3)",
          fontSize:13, cursor:"pointer", outline:"none" }}>
        {!noEmpty && <option value="">— {placeholder||label} 선택 —</option>}
        {options.map(o => (
          <option key={typeof o==="string"?o:o.id} value={typeof o==="string"?o:o.id}>
            {typeof o==="string"?o:o.label}
          </option>
        ))}
      </select>
    </div>
  );
}

export function PageUpload({ onNav }) {
  const { presets: dynPresets, pcItems: dynPcItems } = useAssetPresets();
  const [tab, setTab] = useState("single"); // "single" | "excel"

  // ── 단계별 가이드 상태 ──
  // guideStep: form 값 기반으로 자동 계산 (수동 setState 불필요)
  const [savedOk,   setSavedOk]   = useState(false); // 등록 완료 후 점검 버튼
  const [guideStep, setGuideStep] = useState(0); // 수동 override용 (완료 후 리셋)

  // ── 공통 본부/부서 Context 사용 ──
  const { divs: _orgDivs, depts: _orgDepts } = React.useContext(OrgContext);
  const dbDepts = _orgDepts;
  const dbDivs  = _orgDivs;

  // ── 개별 등록 상태 ──
  // 로컬 IP 가져오기 (WebRTC 활용)
  const getLocalIP = () => new Promise((resolve) => {
    try {
      const pc = new RTCPeerConnection({ iceServers: [] });
      pc.createDataChannel("");
      pc.createOffer()
        .then(o => pc.setLocalDescription(o))
        .catch(() => resolve(null));
      const timer = setTimeout(() => { pc.close(); resolve(null); }, 2000);
      pc.onicecandidate = (e) => {
        if (!e || !e.candidate) return;
        const m = e.candidate.candidate.match(
          /([0-9]{1,3}(\.[0-9]{1,3}){3})/
        );
        if (m) {
          const ip = m[1];
          // 로컬 IP 필터 — 사설망 대역만
          if (ip.startsWith("192.168.") || ip.startsWith("10.") ||
              ip.startsWith("172.") || ip.startsWith("169.254.")) {
            clearTimeout(timer);
            pc.close();
            resolve(ip);
          }
        }
      };
    } catch { resolve(null); }
  });

  const handleGetIP = async (setFn) => {
    setIpLoading(true);
    // 1차: WebRTC로 시도
    const rtcIp = await getLocalIP();
    if (rtcIp) { setIpLoading(false); setIpFailed(false); setFn("ip", rtcIp); return; }

    // 2차: 백엔드 API 방식 — API_BASE 사용 (다른 PC에서도 동작)
    try {
      const r = await fetch(`${API_BASE}/api/my-ip`);
      const d = await r.json();
      if (d.candidates && d.candidates.length > 1) {
        // 여러 IP가 있으면 선택
        const chosen = window.prompt(
          "PC에서 감지된 IP 주소 목록입니다.\n사용할 IP를 선택하거나 직접 입력하세요:\n\n" +
          d.candidates.map((ip,i) => `${i+1}. ${ip}`).join("\n"),
          d.ip || d.candidates[0]
        );
        if (chosen) setFn("ip", chosen.trim());
      } else if (d.ip) {
        setFn("ip", d.ip);
      } else {
        alert("IP를 자동으로 가져올 수 없습니다.\nCMD에서 ipconfig 명령어로 IPv4 주소를 확인 후 직접 입력해 주세요.");
      }
    } catch {
      setIpFailed(true);
    } finally {
      setIpLoading(false);
    }
  };

    const [ipLoading, setIpLoading] = useState(false);
  const [ipFailed,  setIpFailed]  = useState(false); // IP 자동감지 실패

    const EMPTY = (() => {
    const me = (() => { try { return JSON.parse(localStorage.getItem("ssk_current_user")||"null"); } catch { return null; } })();
    return { name:"", ip:"", asset_type:"", environment:"Production",
      department: me?.department || "",
      manager:    me?.name       || "",
      priority:"medium", note:"",
      scan_types:["port","web","ssl"], http_port:"80", https_port:"443",
      db_type:"", db_port:"" };
  })();
  const [form,     setForm]     = useState(EMPTY);
  const [saving,   setSaving]   = useState(false);
  const [saveMsg,  setSaveMsg]  = useState(null); // {ok, text}
  const [errors,   setErrors]   = useState({});

  // ── Excel 업로드 상태 ──
  const [dragOver,   setDragOver]   = useState(false);
  const [uploading,  setUploading]  = useState(false);
  const [uploadMsg,  setUploadMsg]  = useState(null);
  const [uploader,   setUploader]   = useState("");
  const [history,    setHistory]    = useState([]);

  const loadHistory = async () => {
    try { setHistory(await fetchUploadHistory()); } catch(e) {}
  };
  useEffect(() => { loadHistory(); }, []);

  // guideStep 전용 핸들러 — setF와 완전히 분리
  // guideStep을 form 상태 기반으로 자동 계산
  useEffect(() => {
    if (savedOk) return; // 완료 후엔 건드리지 않음
    const step =
      !form.name                           ? 0 :
      !form.ip                             ? 1 :
      !form.asset_type                     ? 2 :
      !form.department                     ? 3 :
                                             4 ;
    setGuideStep(step);
  }, [form.name, form.ip, form.asset_type, form.department, savedOk]);

  const setF = (k,v) => {
    setForm(p => ({...p,[k]:v}));
    // guideStep은 위 useEffect가 자동 계산 — 여기선 form만 업데이트
  };

  // 점검유형 토글
  const toggleScanType = (id) => {
    setForm(p => ({
      ...p,
      scan_types: p.scan_types.includes(id)
        ? p.scan_types.filter(x=>x!==id)
        : [...p.scan_types, id]
    }));
  };

  // 유효성 검사
  const validate = () => {
    const e = {};
    if (!form.name.trim())       e.name = "시스템명을 입력하세요";
    if (!form.ip.trim())         e.ip   = "IP 주소를 입력하세요";
    if (!/^[\d.]+$/.test(form.ip.trim()) && form.ip.trim() !== "")
                                  e.ip   = "올바른 IP 형식이 아닙니다 (예: 192.168.1.1)";
    if (form.scan_types.length===0) e.scan_types = "점검 유형을 하나 이상 선택하세요";
    setErrors(e);
    return Object.keys(e).length === 0;
  };

  // 개별 등록 제출
  const onSave = async () => {
    if (!validate()) return;
    setSaving(true); setSaveMsg(null);
    try {
      await createAsset({
        ...form,
        scan_types: form.scan_types.join(","),
        http_port:  Number(form.http_port)  || 80,
        https_port: Number(form.https_port) || 443,
        db_port:    form.db_port ? Number(form.db_port) : null,
        db_type:    form.db_type || null,
      });
      setSaveMsg({ ok:true, text:`✅ "${form.name}" (${form.ip}) 등록 완료` });
      setSavedOk(true);
      setForm(EMPTY);
      setGuideStep(5);
    } catch(e) {
      setSaveMsg({ ok:false, text:"❌ " + e.message });
    }
    setSaving(false);
  };

  // Excel 업로드
  const doUpload = async (file) => {
    if (!file) return;
    if (!file.name.match(/\.xlsx?$/i)) {
      setUploadMsg({ ok:false, text:"❌ .xlsx 파일만 업로드 가능합니다" }); return;
    }
    setUploading(true); setUploadMsg(null);
    try {
      const r = await uploadAssets(file, uploader || "admin");
      setUploadMsg({ ok:true, text:`✅ ${r.message}` });
      loadHistory();
    } catch(e) {
      setUploadMsg({ ok:false, text:"❌ " + e.message });
    }
    setUploading(false);
  };

  // Excel 양식 다운로드
  const downloadTemplate = () => {
    const headers = ["시스템명*","IP주소*","자산유형","환경","부서","담당자","중요도","점검유형","HTTP포트","HTTPS포트","DB유형","DB포트","메모"];
    const sample  = ["운영 웹서버","192.168.1.100","웹서버","Production","IT운영팀","홍길동","critical","port,web,ssl","80","443","","","주요 운영서버"];
    const csvContent = [headers, sample].map(r => r.join(",")).join("\n");
    const blob = new Blob(["\uFEFF"+csvContent], { type:"text/csv;charset=utf-8;" });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = "자산등록_양식.csv"; a.click();
    URL.revokeObjectURL(url);
  };

  // ── 탭 버튼 ──────────────────────────────────────────────────
  const Tab = ({ id, icon, label }) => (
    <button onClick={()=>setTab(id)}
      style={{ flex:1, padding:"10px 0", border:"none", cursor:"pointer", fontSize:13, fontWeight:tab===id?700:500,
        background:tab===id?"var(--bg-card)":"var(--bg-card2)",
        color:tab===id?"var(--accent-text)":"var(--txt3)",
        borderBottom:tab===id?"2px solid var(--accent)":"2px solid transparent",
        transition:"all .15s" }}>
      {icon} {label}
    </button>
  );

  return (
    <div style={{ padding:"20px 22px" }}>
      <style>{`
        @keyframes guideText { 0%,100%{opacity:.3} 50%{opacity:.8} }
        @keyframes guideRingDown {
          0%,100%{ box-shadow:0 0 0 0 rgba(220,38,38,.6); transform:translateY(0); }
          50%    { box-shadow:0 0 0 7px rgba(220,38,38,0); transform:translateY(2px); }
        }
        @keyframes guideRingRight {
          0%,100%{ box-shadow:0 0 0 0 rgba(220,38,38,.6); transform:translateX(0); }
          50%    { box-shadow:0 0 0 7px rgba(220,38,38,0); transform:translateX(2px); }
        }
        @keyframes guidePulse  { 0%,100%{opacity:.3} 50%{opacity:1} }
        @keyframes guideBounce { 0%,100%{transform:translateY(0)} 50%{transform:translateY(4px)} }
      `}</style>

      {/* 탭 헤더 — 좌우 분리 레이아웃 */}
      <div style={{ display:"flex", gap:12, marginBottom:14, alignItems:"stretch" }}>

        {/* 왼쪽: 개별 자산 등록 버튼 (기본, 눈에 잘 띄게) */}
        <button onClick={()=>setTab("single")}
          style={{ display:"flex", alignItems:"center", gap:8,
            padding:"10px 20px", borderRadius:8, cursor:"pointer",
            fontSize:13, fontWeight:700, border:"none", transition:"all .15s",
            background: tab==="single" ? "var(--accent)" : "var(--bg-card)",
            color: tab==="single" ? "#fff" : "var(--txt2)",
            borderBottom: tab==="single" ? "none" : "1px solid var(--bdr)",
            boxShadow: tab==="single" ? "0 2px 8px rgba(37,99,235,.3)" : "none" }}>
          <span style={{fontSize:16}}>✏️</span>
          개별 자산 등록
        </button>

        <button onClick={()=>setTab("excel")}
          style={{ display:"flex", alignItems:"center", gap:8,
            padding:"10px 20px", borderRadius:8, cursor:"pointer",
            fontSize:13, fontWeight:600, border:"1px solid var(--bdr)",
            transition:"all .15s",
            background: tab==="excel" ? "var(--bg-active)" : "var(--bg-card2)",
            color: tab==="excel" ? "var(--accent-text)" : "var(--txt3)" }}>
          <span style={{fontSize:16}}>📊</span>
          Excel 일괄 등록
        </button>

        {/* 오른쪽 여백 — Excel 탭 선택 시 설명 표시 */}
        {tab==="excel" && (
          <div style={{ marginLeft:"auto", display:"flex", alignItems:"center",
            fontSize:12, color:"var(--txt3)", gap:6 }}>
            <span>📥</span> Excel 파일을 드래그하거나 클릭해서 업로드
          </div>
        )}
      </div>

      {/* ── 개별 등록 탭 ── */}
      {tab==="single" && (
        <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:"0 0 10px 10px", padding:"20px 22px" }}>
          {saveMsg && (
            <div style={{ marginBottom:16, padding:"10px 14px", borderRadius:7,
              background:saveMsg.ok?"#052E16":"#1C0A0A",
              border:`1px solid ${saveMsg.ok?"#14532D":"#7F1D1D"}`,
              fontSize:13, color:saveMsg.ok?"#4ADE80":"#FCA5A5",
              display:"flex", alignItems:"center", justifyContent:"space-between" }}>
              <span>{saveMsg.text}</span>
              <button onClick={()=>setSaveMsg(null)} style={{ background:"transparent", border:"none", color:"inherit", cursor:"pointer", fontSize:16 }}>✕</button>
            </div>
          )}

          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:24 }}>

            {/* 왼쪽: 기본 정보 */}
            <div>
              <div style={{ fontSize:13, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", marginBottom:14, paddingBottom:6, borderBottom:"1px solid var(--bdr)" }}>기본 정보</div>

              {/* 시스템명 셀렉트 + 기타 직접 입력 */}
              <div style={{ marginBottom:12 }}>
                <label style={{ display:"flex", alignItems:"center", gap:6, fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:6, textTransform:"uppercase", letterSpacing:".05em" }}>
                  시스템명 <span style={{ color:"#F87171" }}>*</span>
                  {guideStep===0 && (
                    <span style={{ display:"inline-flex", alignItems:"center", gap:7, marginLeft:8 }}>
                      <span style={{ fontSize:11, fontWeight:500, color:"#DC2626",
                        animation:"guideText 1.5s ease-in-out infinite" }}>먼저 선택하세요</span>
                      <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center",
                        width:24, height:24, borderRadius:"50%",
                        background:"#DC2626", color:"#fff",
                        fontSize:13, fontWeight:700, lineHeight:1,
                        animation:"guideRingDown 1.2s ease-out infinite", flexShrink:0 }}>↓</span>
                    </span>
                  )}
                </label>
                <select value={dynPresets.flatMap(g=>g.items).includes(form.name)||form.name===""?form.name:"기타 (직접 입력)"}
                  onChange={e=>{
                    const val = e.target.value;
                    if (val==="기타 (직접 입력)") {
                      setF("name","__custom__");
                    } else {
                      // PC/단말기 그룹 선택 시 담당자 이름 자동 앞에 붙임
                      const pcItems = dynPcItems;
                      if (pcItems.includes(val) && form.manager?.trim()) {
                        setF("name", `${form.manager.trim()}_${val}`);
                      } else {
                        setF("name", val);
                      }
                    }
                  }}
                  style={{ width:"100%", padding:"10px 12px", borderRadius:7, border:`1px solid ${errors.name?"#F87171":"var(--bdr)"}`,
                    background:"var(--bg-input)", color:"var(--txt)", fontSize:13, marginBottom:6 }}>
                  <option value="">— 시스템 유형 선택 —</option>
                  {dynPresets.map(g=>(
                    <optgroup key={g.group} label={g.group}>
                      {g.items.map(item=><option key={item} value={item}>{item}</option>)}
                    </optgroup>
                  ))}
                </select>
                {(form.name===""||form.name==="__custom__"||!dynPresets.flatMap(g=>g.items).includes(form.name))&&form.name!=='' && (
                  <input value={form.name==="__custom__"?"":form.name}
                    onChange={e=>setF("name",e.target.value)}
                    placeholder="시스템명을 직접 입력하세요"
                    style={{ width:"100%", padding:"10px 12px", borderRadius:7, border:"1px solid var(--accent)",
                      background:"var(--bg-input)", color:"var(--txt)", fontSize:13, outline:"none" }}/>
                )}
                {form.name==="__custom__" && (
                  <input value=""
                    onChange={e=>setF("name",e.target.value)}
                    placeholder="시스템명을 직접 입력하세요"
                    autoFocus
                    style={{ width:"100%", padding:"10px 12px", borderRadius:7, border:"1px solid var(--accent)",
                      background:"var(--bg-input)", color:"var(--txt)", fontSize:13, outline:"none" }}/>
                )}
                {errors.name && <div style={{ fontSize:13, color:"#F87171", marginTop:4 }}>{errors.name}</div>}
              </div>

              <div style={{ marginBottom:12 }}>
                <label style={{ display:"block", fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:6, textTransform:"uppercase", letterSpacing:".05em" }}>
                  IP 주소 <span style={{ color:"#F87171" }}>*</span>
                </label>
                <div style={{ display:"flex", gap:6 }}>
                  <input value={form.ip} onChange={e=>setF("ip",e.target.value)}
                    placeholder="예: 192.168.1.100"
                    style={{ flex:1, padding:"10px 12px", borderRadius:7,
                      border:`1px solid ${errors.ip?"#F87171":"var(--bdr)"}`,
                      background:"var(--bg-input)", color:"var(--txt)", fontSize:13, outline:"none" }}/>
                  <div style={{ position:"relative" }}>
                    {guideStep===1 && (
                      <div style={{ position:"absolute", top:"-34px", left:"50%",
                        transform:"translateX(-50%)", pointerEvents:"none",
                        display:"flex", flexDirection:"column", alignItems:"center", gap:3 }}>
                        <span style={{ fontSize:10, fontWeight:500, color:"#DC2626",
                          whiteSpace:"nowrap", animation:"guideText 1.5s ease-in-out infinite" }}>클릭</span>
                        <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center",
                          width:24, height:24, borderRadius:"50%",
                          background:"#DC2626", color:"#fff",
                          fontSize:13, fontWeight:700, lineHeight:1,
                          animation:"guideRingDown 1.2s ease-out infinite" }}>↓</span>
                      </div>
                    )}
                    <button type="button" onClick={()=>handleGetIP(setF)}
                      disabled={ipLoading}
                      style={{ padding:"10px 14px", borderRadius:7,
                        border:"1px solid var(--accent)",
                        background: ipLoading ? "var(--bg-card2)" : "var(--bg-active)",
                        color: ipLoading ? "var(--txt3)" : "var(--accent-text)",
                        fontSize:13, cursor: ipLoading ? "wait" : "pointer",
                        whiteSpace:"nowrap", fontWeight:600,
                        display:"flex", alignItems:"center", gap:5,
                        transition:"all .2s" }}>
                      {ipLoading
                        ? <><span style={{ display:"inline-block", animation:"spin 1s linear infinite" }}>⟳</span> 감지 중...</>
                        : <>📡 내 IP</>}
                    </button>
                  </div>
                </div>
                <div style={{ display:"flex", alignItems:"center", gap:6, marginTop:4 }}>
                  {guideStep===1 && ipFailed && (
                    <span style={{ display:"inline-flex", alignItems:"center", gap:7 }}>
                      <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center",
                        width:24, height:24, borderRadius:"50%",
                        background:"#DC2626", color:"#fff",
                        fontSize:13, fontWeight:700, lineHeight:1,
                        animation:"guideRingRight 1.2s ease-out infinite", flexShrink:0 }}>→</span>
                      <span style={{ fontSize:11, fontWeight:500, color:"#DC2626",
                        animation:"guideText 1.5s ease-in-out infinite" }}>직접 입력하세요</span>
                    </span>
                  )}
                  {!(guideStep===1 && ipFailed) && (
                    <span style={{ fontSize:12, color:"var(--txt3)" }}>
                      버튼으로 자동 입력 또는 직접 입력 (예: 192.168.1.100)
                    </span>
                  )}
                </div>
                {errors.ip && <div style={{ fontSize:13, color:"#F87171", marginTop:2 }}>{errors.ip}</div>}
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                <div>
                  <div style={{ marginBottom:12 }}>
                    <label style={{ display:"flex", alignItems:"center", gap:6, fontSize:13, fontWeight:600,
                      color:"var(--txt3)", marginBottom:4, textTransform:"uppercase", letterSpacing:".05em" }}>
                      자산 유형
                      {guideStep===2 && (
                        <span style={{ display:"inline-flex", alignItems:"center", gap:5, marginLeft:4 }}>
                          <span style={{ fontSize:10, fontWeight:500, color:"#DC2626",
                            animation:"guideText 1.5s ease-in-out infinite" }}>선택하세요</span>
                          <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center",
                            width:20, height:20, borderRadius:"50%",
                            background:"#DC2626", color:"#fff",
                            fontSize:11, fontWeight:700, lineHeight:1,
                            animation:"guideRingDown 1.2s ease-out infinite" }}>↓</span>
                        </span>
                      )}
                    </label>
                    <select value={form.asset_type} onChange={e=>setF("asset_type",e.target.value)}
                      style={{ width:"100%", padding:"10px 12px", borderRadius:6,
                        border:"1px solid var(--bdr)",
                        background:"var(--bg-input)",
                        color:form.asset_type?"var(--txt)":"var(--txt3)",
                        fontSize:13, cursor:"pointer", outline:"none" }}>
                      <option value="">— 자산 유형 선택 —</option>
                      {ASSET_TYPES.map(o=><option key={o} value={o}>{o}</option>)}
                    </select>
                  </div>
                </div>
                <div>
                  <Sel label="운영 환경" value={form.environment||"Production"} onChange={v=>setF("environment",v)} options={ENVIRONMENTS} noEmpty={true}/>
                  {guideStep>=2 && guideStep<5 && (
                    <div style={{ fontSize:11, color:"var(--txt3)", marginTop:3, opacity:.6 }}>
                      선택 가능 (옵션)
                    </div>
                  )}
                </div>
              </div>

              <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
                <div style={{ marginBottom:0 }}>
                  <label style={{ display:"flex",alignItems:"center",gap:6,fontSize:13,fontWeight:600,color:"var(--txt3)",marginBottom:4,textTransform:"uppercase",letterSpacing:".05em" }}>
                    담당 부서
                    {guideStep===3 && (
                      <span style={{ display:"inline-flex", alignItems:"center", gap:7, marginLeft:6 }}>
                        <span style={{ fontSize:10, fontWeight:500, color:"#DC2626",
                          animation:"guideText 1.5s ease-in-out infinite" }}>다음 선택</span>
                        <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center",
                          width:22, height:22, borderRadius:"50%",
                          background:"#DC2626", color:"#fff",
                          fontSize:12, fontWeight:700, lineHeight:1,
                          animation:"guideRingDown 1.2s ease-out infinite" }}>↓</span>
                      </span>
                    )}
                  </label>
                  {dbDepts.length > 0 ? (
                    <select value={form.department} onChange={e=>setF("department",e.target.value)}
                      style={{ width:"100%",padding:"10px 12px",borderRadius:7,
                        border:"1px solid var(--bdr)",background:"var(--bg-input)",
                        color:form.department?"var(--txt)":"var(--txt3)",fontSize:13,
                        cursor:"pointer",outline:"none" }}>
                      <option value="">-- 부서 선택 --</option>
                      {dbDepts.map(d=><option key={d} value={d}>{d}</option>)}
                    </select>
                  ) : (
                    <input value={form.department} onChange={e=>setF("department",e.target.value)}
                      placeholder="IT운영팀"
                      style={{ width:"100%",padding:"10px 12px",borderRadius:7,
                        border:"1px solid var(--bdr)",background:"var(--bg-input)",
                        color:"var(--txt)",fontSize:13,outline:"none" }}/>
                  )}
                </div>
                {/* 담당자 입력 + 사용자 자동완성 */}
                <div style={{ position:"relative" }}>
                  <label style={{ display:"block",fontSize:13,fontWeight:600,color:"var(--txt3)",marginBottom:4,textTransform:"uppercase",letterSpacing:".05em" }}>담당자</label>
                  <input
                    value={form.manager}
                    onChange={e=>{
                      const v=e.target.value;
                      setF("manager", v);
                      const pcItems = dynPcItems;
                      const pcSuffix = pcItems.find(p=>form.name?.endsWith(p)||form.name===p);
                      if (pcSuffix && v.trim()) setF("name",`${v.trim()}_${pcSuffix}`);
                      // 이메일/부서 자동완성 — ssk_users 조회
                      if (v.length>=1) {
                        try {
                          const su=JSON.parse(localStorage.getItem("ssk_users")||"[]");
                          const found=su.find(u=>u.name===v||u.name?.startsWith(v));
                          if (found) {
                            // 자동완성은 값만 채우고 guideStep은 건드리지 않음
                            if (!form.department && found.dept)
                              setForm(p=>({...p, department: found.dept}));
                          }
                        } catch {}
                      }
                    }}
                    list="manager_datalist"
                    placeholder="홍길동"
                    style={{ width:"100%",padding:"10px 12px",borderRadius:7,border:"1px solid var(--bdr)",
                      background:"var(--bg-input)",color:"var(--txt)",fontSize:13,outline:"none" }}
                  />
                  <datalist id="manager_datalist">
                    {(() => {
                      try {
                        const su=JSON.parse(localStorage.getItem("ssk_users")||"[]");
                        return su.map((u,i)=><option key={`user-${i}`} value={u.name}>{u.name} ({u.dept||u.division||""})</option>);
                      } catch { return null; }
                    })()}
                  </datalist>
                </div>
              </div>

              <div style={{ marginBottom:12 }}>
                <label style={{ display:"block", fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:8, textTransform:"uppercase", letterSpacing:".05em" }}>중요도</label>
                <div style={{ display:"flex", gap:6 }}>
                  {PRIORITIES.map(p => (
                    <div key={p.id} onClick={()=>setF("priority",p.id)}
                      style={{ flex:1, padding:"7px 0", textAlign:"center", borderRadius:6, cursor:"pointer", fontSize:13, fontWeight:600,
                        border:`1px solid ${form.priority===p.id?p.color:"var(--bdr)"}`,
                        background:form.priority===p.id?`${p.color}18`:"transparent",
                        color:form.priority===p.id?p.color:"var(--txt3)", transition:"all .15s" }}>
                      {p.label}
                    </div>
                  ))}
                </div>
              </div>

              <Inp label="메모" value={form.note} onChange={v=>setF("note",v)} placeholder="특이사항 또는 참고사항"/>
            </div>

            {/* 오른쪽: 점검 설정 */}
            <div>
              <div style={{ fontSize:13, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".07em", marginBottom:14, paddingBottom:6, borderBottom:"1px solid var(--bdr)" }}>점검 설정</div>

              <div style={{ marginBottom:14 }}>
                <label style={{ display:"block", fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:8, textTransform:"uppercase", letterSpacing:".05em" }}>
                  점검 유형 <span style={{ color:"#F87171" }}>*</span>
                </label>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:6 }}>
                  {SCAN_TYPE_OPTIONS.map(s => {
                    const on = form.scan_types.includes(s.id);
                    return (
                      <div key={s.id} onClick={()=>toggleScanType(s.id)}
                        style={{ display:"flex", alignItems:"center", gap:8, padding:"10px 12px", borderRadius:6, cursor:"pointer",
                          border:`1px solid ${on?"var(--accent)":"var(--bdr)"}`,
                          background:on?"var(--bg-active)":"transparent", transition:"all .15s" }}>
                        <div style={{ width:14, height:14, borderRadius:3, border:`2px solid ${on?"var(--accent)":"var(--bdr2)"}`,
                          background:on?"var(--accent)":"transparent", display:"flex", alignItems:"center", justifyContent:"center", flexShrink:0 }}>
                          {on && <span style={{ color:"#fff", fontSize:13, lineHeight:1 }}>✓</span>}
                        </div>
                        <span style={{ fontSize:13, color:on?"var(--accent-text)":"var(--txt2)" }}>{s.label}</span>
                      </div>
                    );
                  })}
                </div>
                {errors.scan_types && <div style={{ fontSize:13, color:"#F87171", marginTop:6 }}>{errors.scan_types}</div>}
              </div>

              <div style={{ background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:8, padding:"14px", marginBottom:14 }}>
                <div style={{ fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:10 }}>포트 설정</div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                  <Inp label="HTTP 포트" value={form.http_port} onChange={v=>setF("http_port",v)} type="number" placeholder="80"/>
                  <Inp label="HTTPS 포트" value={form.https_port} onChange={v=>setF("https_port",v)} type="number" placeholder="443"/>
                </div>
              </div>

              <div style={{ background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:8, padding:"14px" }}>
                <div style={{ fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:10 }}>DB 설정 (선택)</div>
                <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:10 }}>
                  <div style={{ marginBottom:0 }}>
                    <label style={{ display:"block", fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:4 }}>DB 유형</label>
                    <select value={form.db_type} onChange={e=>setF("db_type",e.target.value)}
                      style={{ width:"100%", padding:"10px 12px", borderRadius:6, border:"1px solid var(--bdr)", background:"var(--bg-input)", color:"var(--txt)", fontSize:13, cursor:"pointer", outline:"none" }}>
                      <option value="">없음</option>
                      {["Oracle","MySQL","MSSQL","PostgreSQL","MariaDB","MongoDB"].map(db=>(
                        <option key={db} value={db}>{db}</option>
                      ))}
                    </select>
                  </div>
                  <Inp label="DB 포트" value={form.db_port} onChange={v=>setF("db_port",v)} type="number"
                    placeholder={form.db_type==="Oracle"?"1521":form.db_type==="MySQL"?"3306":form.db_type==="MSSQL"?"1433":"5432"}/>
                </div>
              </div>
            </div>
          </div>

          {/* 등록 버튼 — 그리드 밖, 왼쪽 정렬 */}
          <div style={{ display:"flex", flexDirection:"row", justifyContent:"flex-start",
            alignItems:"center", gap:10, marginTop:20, paddingTop:16,
            borderTop:"2px solid var(--bdr)", width:"100%", clear:"both",
            position:"relative" }}>
            {guideStep===4 && (
              <div style={{ position:"absolute", top:"-36px", left:0,
                display:"flex", alignItems:"center", gap:7 }}>
                <span style={{ fontSize:11, fontWeight:500, color:"#DC2626",
                  animation:"guideText 1.5s ease-in-out infinite" }}>등록 버튼을 클릭하세요</span>
                <span style={{ display:"inline-flex", alignItems:"center", justifyContent:"center",
                  width:26, height:26, borderRadius:"50%",
                  background:"#DC2626", color:"#fff",
                  fontSize:14, fontWeight:700, lineHeight:1,
                  animation:"guideRingDown 1.2s ease-out infinite", flexShrink:0 }}>↓</span>
              </div>
            )}
            <button onClick={onSave} disabled={saving}
              style={{ padding:"10px 32px", borderRadius:7, border:"none",
                background:saving?"var(--bdr2)":"var(--accent)", color:"#fff",
                fontSize:14, fontWeight:700, cursor:saving?"not-allowed":"pointer",
                display:"flex", alignItems:"center", gap:8,
                boxShadow:saving?"none":"0 2px 8px rgba(37,99,235,.3)" }}>
              {saving ? <><Spinner/> 등록 중...</> : "✚ 자산 등록"}
            </button>
            <button onClick={()=>setForm(EMPTY)}
              style={{ padding:"10px 20px", borderRadius:7, border:"1px solid var(--bdr)",
                background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>
              초기화
            </button>
          </div>

          {/* ── 등록 완료 후 점검 유도 버튼 ── */}
          {savedOk && (
            <div style={{ marginTop:20, textAlign:"center",
              padding:"24px", background:"rgba(220,38,38,.04)",
              border:"1px solid rgba(220,38,38,.2)", borderRadius:12 }}>
              <div style={{ fontSize:16, fontWeight:700, color:"var(--txt)", marginBottom:6 }}>
                🎉 자산이 등록됐습니다!
              </div>
              <div style={{ fontSize:13, color:"var(--txt3)", marginBottom:16 }}>
                이제 보안 점검을 시작할 수 있습니다
              </div>
              <button onClick={()=>onNav("scan")}
                style={{ padding:"13px 40px", borderRadius:10,
                  border:"2px solid #DC2626",
                  background:"rgba(220,38,38,.08)", color:"#DC2626",
                  fontSize:15, fontWeight:700, cursor:"pointer",
                  animation:"guideRingDown 1.2s ease-out infinite" }}>
                🔍 점검하러 가기
              </button>
              <div style={{ marginTop:10 }}>
                <button onClick={()=>{setSavedOk(false);setGuideStep(0);}}
                  style={{ background:"transparent", border:"none",
                    color:"var(--txt3)", fontSize:12, cursor:"pointer" }}>
                  또 다른 자산 등록하기
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* ── Excel 일괄 등록 탭 ── */}
      {tab==="excel" && (
        <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:"0 0 10px 10px", padding:"20px 22px" }}>
          <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:20 }}>

            {/* 왼쪽: 업로드 */}
            <div>
              <div style={{ marginBottom:14 }}>
                <Inp label="업로드자" value={uploader} onChange={setUploader} placeholder="이름 입력 (기록용)"/>
              </div>

              {/* 드래그 앤 드롭 영역 */}
              <div
                onDragOver={e=>{e.preventDefault();setDragOver(true);}}
                onDragLeave={()=>setDragOver(false)}
                onDrop={e=>{e.preventDefault();setDragOver(false);doUpload(e.dataTransfer.files[0]);}}
                onClick={()=>document.getElementById("xl-input").click()}
                style={{ border:`2px dashed ${dragOver?"var(--accent)":"var(--bdr2)"}`, borderRadius:10, padding:"32px 20px", textAlign:"center", cursor:"pointer",
                  background:dragOver?"var(--bg-active)":"var(--bg-card2)", transition:"all .15s", marginBottom:12 }}>
                <div style={{ fontSize:40, marginBottom:10 }}>📤</div>
                <div style={{ fontSize:14, fontWeight:600, color:"var(--txt)", marginBottom:5 }}>
                  Excel 파일을 드래그하거나 클릭하여 선택
                </div>
                <div style={{ fontSize:13, color:"var(--txt3)" }}>.xlsx / .xls · 최대 10MB</div>
                <input id="xl-input" type="file" accept=".xlsx,.xls" style={{ display:"none" }}
                  onChange={e=>doUpload(e.target.files[0])}/>
              </div>

              {uploading && (
                <div style={{ padding:"10px 14px", background:"var(--bg-card2)", borderRadius:6, fontSize:13, color:"var(--txt3)", display:"flex", alignItems:"center", gap:8, marginBottom:10 }}>
                  <Spinner/> 업로드 처리 중...
                </div>
              )}
              {uploadMsg && (
                <div style={{ padding:"10px 14px", borderRadius:6, fontSize:13, marginBottom:10,
                  background:uploadMsg.ok?"#052E16":"#1C0A0A",
                  border:`1px solid ${uploadMsg.ok?"#14532D":"#7F1D1D"}`,
                  color:uploadMsg.ok?"#4ADE80":"#FCA5A5" }}>
                  {uploadMsg.text}
                </div>
              )}

              <button onClick={downloadTemplate}
                style={{ width:"100%", padding:"10px", borderRadius:7, border:"1px solid var(--accent)", background:"var(--bg-active)", color:"var(--accent-text)", fontSize:13, fontWeight:600, cursor:"pointer" }}>
                ⬇ 등록 양식 다운로드 (CSV)
              </button>

              {/* 양식 컬럼 안내 */}
              <div style={{ marginTop:16, background:"var(--bg-card2)", border:"1px solid var(--bdr)", borderRadius:8, padding:"12px 14px" }}>
                <div style={{ fontSize:13, fontWeight:600, color:"var(--txt3)", marginBottom:8, textTransform:"uppercase", letterSpacing:".05em" }}>양식 컬럼 안내</div>
                {[
                  {col:"시스템명*",  desc:"자산 이름 (필수)"},
                  {col:"IP주소*",    desc:"IPv4 주소 (필수)"},
                  {col:"자산유형",   desc:"웹서버 / WAS / DB서버 등"},
                  {col:"환경",       desc:"Production / Staging / DR"},
                  {col:"부서",       desc:"담당 부서명"},
                  {col:"담당자",     desc:"담당자 이름"},
                  {col:"중요도",     desc:"critical / high / medium / low"},
                  {col:"점검유형",   desc:"port,web,ssl (쉼표 구분)"},
                  {col:"HTTP포트",   desc:"기본값: 80"},
                  {col:"HTTPS포트",  desc:"기본값: 443"},
                ].map(c => (
                  <div key={c.col} style={{ display:"flex", gap:10, padding:"4px 0", borderBottom:"1px solid var(--bdr)", fontSize:11 }}>
                    <span style={{ fontWeight:600, color:"var(--accent-text)", minWidth:90, flexShrink:0 }}>{c.col}</span>
                    <span style={{ color:"var(--txt3)" }}>{c.desc}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* 오른쪽: 업로드 이력 */}
            <div>
              <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between", marginBottom:12 }}>
                <span style={{ fontSize:13, fontWeight:600, color:"var(--txt)" }}>업로드 이력</span>
                <button onClick={loadHistory} style={{ padding:"3px 9px", borderRadius:4, border:"1px solid var(--bdr)", background:"transparent", color:"var(--txt3)", fontSize:13, cursor:"pointer" }}>↻ 새로고침</button>
              </div>
              {history.length===0 ? (
                <div style={{ textAlign:"center", padding:"40px 0", color:"var(--txt3)", fontSize:12 }}>업로드 이력이 없습니다</div>
              ) : history.map((h,i) => (
                <div key={h.id} style={{ display:"flex", alignItems:"center", gap:10, padding:"11px 0", borderBottom:i<history.length-1?"1px solid var(--bdr)":"none" }}>
                  <div style={{ width:36, height:36, borderRadius:8, background:"var(--bg-active)", display:"flex", alignItems:"center", justifyContent:"center", fontSize:18, flexShrink:0 }}>📊</div>
                  <div style={{ flex:1, minWidth:0 }}>
                    <div style={{ fontSize:13, fontWeight:500, color:"var(--txt)", overflow:"hidden", textOverflow:"ellipsis", whiteSpace:"nowrap" }}>{h.filename}</div>
                    <div style={{ fontSize:13, color:"var(--txt3)", marginTop:2 }}>
                      {h.asset_count}개 자산 등록 · {h.uploaded_by} · {h.created_at?.slice(0,16).replace('T',' ')}
                    </div>
                  </div>
                  <span style={{ padding:"3px 8px", borderRadius:10, fontSize:13, fontWeight:600,
                    background:h.status==="active"?"#052E16":"var(--bg-card2)",
                    color:h.status==="active"?"#4ADE80":"var(--txt3)",
                    border:`1px solid ${h.status==="active"?"#14532D":"var(--bdr)"}` }}>
                    {h.status==="active"?"활성":"아카이브"}
                  </span>
                </div>
              ))}
              <div style={{ marginTop:12, padding:"10px 12px", background:"var(--bg-card2)", borderRadius:6, fontSize:13, color:"var(--txt3)", lineHeight:1.6 }}>
                📋 업로드 이력은 감사 목적으로 90일간 보관됩니다.<br/>
                * 표시된 항목은 필수 입력 컬럼입니다.
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// 관리자 페이지
// ═══════════════════════════════════════════════════════════════


// ── 사용자 목록 테이블 컴포넌트 ──────────────────────────────────
function UserListTable({ users, depts, saveUsers, ROLE_LABELS, ROLE_COLORS, iStyle, API_BASE }) {
  const [search,     setSearch]     = useState("");
  const [filterDept, setFilterDept] = useState("");
  const [filterRole, setFilterRole] = useState("");
  const [sort,       setSort]       = useState({ key:"name", asc:true });
  const [page,       setPage]       = useState(1);
  const [editId,     setEditId]     = useState(null);
  const [editData,   setEditData]   = useState({});
  const [selected,   setSelected]   = useState(new Set());
  const [bulkRole,   setBulkRole]   = useState("");
  const [bulkDept,   setBulkDept]   = useState("");
  const PAGE_SIZE = 15;

  const filtered = users.filter(u => {
    const ms = !search || u.name?.includes(search) || u.email?.includes(search)
               || u.dept?.includes(search) || u.phone?.includes(search) || u.title?.includes(search);
    const md = !filterDept || u.dept===filterDept;
    const mr = !filterRole || u.role===filterRole;
    return ms && md && mr;
  }).sort((a,b)=>{
    const v1=a[sort.key]||"", v2=b[sort.key]||"";
    return sort.asc ? String(v1).localeCompare(String(v2)) : String(v2).localeCompare(String(v1));
  });

  const totalPages = Math.ceil(filtered.length/PAGE_SIZE);
  const paged = filtered.slice((page-1)*PAGE_SIZE, page*PAGE_SIZE);
  const pagedIds = paged.map(u=>u.id);
  const allPageChecked = pagedIds.length>0 && pagedIds.every(id=>selected.has(id));
  const somePageChecked = pagedIds.some(id=>selected.has(id));

  const toggleOne  = (id) => setSelected(p=>{ const n=new Set(p); n.has(id)?n.delete(id):n.add(id); return n; });
  const togglePage = () => {
    if (allPageChecked) setSelected(p=>{ const n=new Set(p); pagedIds.forEach(id=>n.delete(id)); return n; });
    else               setSelected(p=>{ const n=new Set(p); pagedIds.forEach(id=>n.add(id)); return n; });
  };
  const toggleAll  = () => {
    if (selected.size===filtered.length) setSelected(new Set());
    else setSelected(new Set(filtered.map(u=>u.id)));
  };
  const clearSel   = () => setSelected(new Set());

  // 일괄 액션
  const bulkDelete = () => {
    if (!window.confirm(`선택한 ${selected.size}명을 삭제하시겠습니까?`)) return;
    saveUsers(users.filter(u=>!selected.has(u.id)));
    clearSel();
  };
  const bulkChangeRole = () => {
    if (!bulkRole) return;
    saveUsers(users.map(u=>selected.has(u.id)?{...u,role:bulkRole}:u));
    clearSel(); setBulkRole("");
  };
  const bulkChangeDept = () => {
    if (!bulkDept) return;
    saveUsers(users.map(u=>selected.has(u.id)?{...u,dept:bulkDept}:u));
    clearSel(); setBulkDept("");
  };

  const Th = ({k,children,w}) => (
    <th onClick={()=>{ setSort(p=>({key:k,asc:p.key===k?!p.asc:true})); setPage(1); }}
      style={{ padding:"10px 12px",textAlign:"left",fontSize:13,fontWeight:700,
        color:sort.key===k?"var(--accent-text)":"var(--txt3)",textTransform:"uppercase",
        letterSpacing:".06em",background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",
        cursor:"pointer",userSelect:"none",whiteSpace:"nowrap",width:w||"auto" }}>
      {children} <span style={{ fontSize:12,opacity:sort.key===k?1:.3 }}>{sort.key===k?(sort.asc?"▲":"▼"):"⇅"}</span>
    </th>
  );

  const ChkBox = ({ checked, partial, onClick }) => (
    <div onClick={e=>{e.stopPropagation();onClick();}}
      style={{ width:14,height:14,borderRadius:3,flexShrink:0,cursor:"pointer",
        border:`2px solid ${checked||partial?"var(--accent)":"var(--bdr2)"}`,
        background:checked?"var(--accent)":partial?"rgba(37,99,235,.3)":"transparent",
        display:"flex",alignItems:"center",justifyContent:"center",transition:"all .1s" }}>
      {checked  && <span style={{ color:"#fff",fontSize:12,fontWeight:700,lineHeight:1 }}>✓</span>}
      {!checked && partial && <span style={{ color:"var(--accent-text)",fontSize:10,fontWeight:700,lineHeight:1 }}>−</span>}
    </div>
  );

  const startEdit = (u) => { setEditId(u.id); setEditData({...u}); };
  const { reload: reloadOrg } = React.useContext(OrgContext);
  const saveEdit  = async () => {
    const updated = users.map(u=>u.id===editId?{...u,...editData}:u);
    saveUsers(updated);
    // 새 본부/부서면 DB에도 추가
    if (editData.division?.trim()) {
      await fetch(`${API_BASE}/api/divisions`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:editData.division.trim()})}).catch(()=>{});
    }
    if (editData.dept?.trim()) {
      await fetch(`${API_BASE}/api/departments`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({name:editData.dept.trim()})}).catch(()=>{});
    }
    // 백엔드 사용자도 업데이트
    try {
      await fetch(`${API_BASE}/api/system-users/${editId}`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({...editData})}).catch(()=>{});
    } catch {}
    reloadOrg(); // 전체 드롭다운 즉시 갱신
    setEditId(null);
  };
  const delUser   = async (id) => {
    if(!window.confirm("삭제하시겠습니까?")) return;
    // DB 삭제
    try {
      await fetch(`${API_BASE}/api/system-users/${id}`,{method:"DELETE"});
    } catch {}
    saveUsers(users.filter(u=>u.id!==id));
  };
  const [adminDivs,  setAdminDivs]  = React.useState([]);
  const [adminDepts, setAdminDepts] = React.useState([]);

  React.useEffect(() => {
    Promise.all([
      fetch(`${API_BASE}/api/divisions`).then(r=>r.json()).catch(()=>[]),
      fetch(`${API_BASE}/api/departments`).then(r=>r.json()).catch(()=>[]),
    ]).then(([divRes, deptRes]) => {
      const fromUsers_divs  = [...new Set(users.map(u=>u.division).filter(Boolean))];
      const fromUsers_depts = [...new Set(users.map(u=>u.dept).filter(Boolean))];
      const dbDivNames  = Array.isArray(divRes)  ? divRes.map(d=>d.name)  : [];
      const dbDeptNames = Array.isArray(deptRes) ? deptRes.map(d=>d.name) : [];
      setAdminDivs([...new Set([...dbDivNames,  ...fromUsers_divs])].sort());
      setAdminDepts([...new Set([...dbDeptNames, ...fromUsers_depts])].sort());
    });
  }, [users]);

  const uniqDepts = adminDepts;
  const uniqDivs  = adminDivs;

  return (
    <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,overflow:"hidden" }}>

      {/* 툴바 */}
      <div style={{ padding:"10px 14px",borderBottom:"1px solid var(--bdr)",background:"var(--bg-card2)",display:"flex",alignItems:"center",gap:8,flexWrap:"wrap" }}>
        <span style={{ fontSize:13,fontWeight:700,color:"var(--txt)" }}>사용자 목록</span>
        <span style={{ fontSize:13,color:"var(--txt3)",padding:"1px 7px",borderRadius:8,background:"var(--bg-input)",border:"1px solid var(--bdr)" }}>
          {filtered.length}/{users.length}명
        </span>
        <div style={{ position:"relative",flex:1,minWidth:160 }}>
          <span style={{ position:"absolute",left:8,top:"50%",transform:"translateY(-50%)",fontSize:13,color:"var(--txt3)",pointerEvents:"none" }}>⌕</span>
          <input value={search} onChange={e=>{setSearch(e.target.value);setPage(1);}}
            placeholder="이름 / 이메일 / 부서 / 직책 검색"
            style={{ width:"100%",padding:"5px 8px 5px 24px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt)",fontSize:13,outline:"none" }}/>
          {search && <span onClick={()=>{setSearch("");setPage(1);}} style={{ position:"absolute",right:7,top:"50%",transform:"translateY(-50%)",color:"var(--txt3)",cursor:"pointer",fontSize:11 }}>✕</span>}
        </div>
        <select value={filterDept} onChange={e=>{setFilterDept(e.target.value);setPage(1);}}
          style={{ padding:"7px 10px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:filterDept?"var(--accent-text)":"var(--txt3)",fontSize:13,cursor:"pointer" }}>
          <option value="">전체 부서</option>
          {uniqDepts.map(d=><option key={d} value={d}>{d}</option>)}
        </select>
        <select value={filterRole} onChange={e=>{setFilterRole(e.target.value);setPage(1);}}
          style={{ padding:"7px 10px",borderRadius:6,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:filterRole?"var(--accent-text)":"var(--txt3)",fontSize:13,cursor:"pointer" }}>
          <option value="">전체 역할</option>
          {Object.entries(ROLE_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
        </select>
      </div>

      {/* 일괄 액션 바 — 선택 시 표시 */}
      {selected.size>0 && (
        <div style={{ padding:"8px 14px",borderBottom:"1px solid var(--bdr)",background:"rgba(37,99,235,.06)",
          display:"flex",alignItems:"center",gap:10,flexWrap:"wrap" }}>
          <span style={{ fontSize:13,fontWeight:700,color:"var(--accent-text)",minWidth:80 }}>
            {selected.size}명 선택됨
          </span>
          {/* 역할 일괄 변경 */}
          <div style={{ display:"flex",gap:4,alignItems:"center" }}>
            <select value={bulkRole} onChange={e=>setBulkRole(e.target.value)}
              style={{ padding:"4px 7px",borderRadius:5,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
              <option value="">역할 변경...</option>
              {Object.entries(ROLE_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
            </select>
            <button onClick={bulkChangeRole} disabled={!bulkRole}
              style={{ padding:"4px 10px",borderRadius:5,border:`1px solid ${bulkRole?"var(--accent)":"var(--bdr)"}`,
                background:bulkRole?"var(--bg-active)":"transparent",
                color:bulkRole?"var(--accent-text)":"var(--txt3)",fontSize:13,cursor:bulkRole?"pointer":"not-allowed" }}>
              적용
            </button>
          </div>
          {/* 부서 일괄 변경 */}
          <div style={{ display:"flex",gap:4,alignItems:"center" }}>
            <select value={bulkDept} onChange={e=>setBulkDept(e.target.value)}
              style={{ padding:"4px 7px",borderRadius:5,border:"1px solid var(--bdr)",background:"var(--bg-input)",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
              <option value="">부서 변경...</option>
              {uniqDepts.map(d=><option key={d} value={d}>{d}</option>)}
            </select>
            <button onClick={bulkChangeDept} disabled={!bulkDept}
              style={{ padding:"4px 10px",borderRadius:5,border:`1px solid ${bulkDept?"var(--accent)":"var(--bdr)"}`,
                background:bulkDept?"var(--bg-active)":"transparent",
                color:bulkDept?"var(--accent-text)":"var(--txt3)",fontSize:13,cursor:bulkDept?"pointer":"not-allowed" }}>
              적용
            </button>
          </div>
          <div style={{ marginLeft:"auto",display:"flex",gap:6 }}>
            <button onClick={toggleAll}
              style={{ padding:"4px 10px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
              {selected.size===filtered.length ? "전체 해제" : `전체 선택 (${filtered.length}명)`}
            </button>
            <button onClick={bulkDelete}
              style={{ padding:"4px 12px",borderRadius:5,border:"1px solid rgba(220,38,38,.4)",background:"rgba(220,38,38,.08)",color:"#F87171",fontSize:13,fontWeight:700,cursor:"pointer" }}>
              🗑 선택 삭제
            </button>
            <button onClick={clearSel}
              style={{ padding:"4px 10px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
              ✕ 해제
            </button>
          </div>
        </div>
      )}

      {/* 테이블 */}
      {filtered.length===0 ? (
        <div style={{ textAlign:"center",padding:"40px 0",color:"var(--txt3)",fontSize:12 }}>
          {users.length===0 ? "등록된 사용자가 없습니다" : "검색 결과가 없습니다"}
        </div>
      ) : (
        <div style={{ overflowX:"auto" }}>
          <table style={{ width:"100%",borderCollapse:"collapse",fontSize:11 }}>
            <thead><tr>
              {/* 전체 체크박스 헤더 */}
              <th style={{ padding:"10px 12px",background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",width:36 }}>
                <ChkBox checked={allPageChecked} partial={somePageChecked&&!allPageChecked} onClick={togglePage}/>
              </th>
              <Th k="name"      w="100px">이름</Th>
              <Th k="division"  w="90px">본부</Th>
              <Th k="dept"      w="100px">부서</Th>
              <Th k="role"      w="70px">역할</Th>
              <Th k="title"     w="70px">직책</Th>
              <Th k="email"     w="150px">이메일</Th>
              <Th k="phone"     w="100px">전화번호</Th>
              <Th k="createdAt" w="80px">등록일</Th>
              <th style={{ padding:"10px 12px",fontSize:13,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",width:"80px" }}>액션</th>
            </tr></thead>
            <tbody>
              {paged.map((u,i)=>{
                const isEdit    = editId===u.id;
                const isSel     = selected.has(u.id);
                const rc        = ROLE_COLORS[u.role]||"#94A3B8";
                return (
                  <tr key={u.id}
                    style={{ borderBottom:"1px solid var(--bdr)",
                      background:isEdit?"var(--bg-active)":isSel?"rgba(37,99,235,.05)":i%2===0?"transparent":"var(--bg-card2)",
                      transition:"background .1s" }}>
                    {/* 체크박스 셀 */}
                    <td style={{ padding:"9px 12px" }}>
                      <ChkBox checked={isSel} partial={false} onClick={()=>toggleOne(u.id)}/>
                    </td>
                    {isEdit ? (
                      <>
                        <td style={{ padding:"7px 10px" }}><input value={editData.name||""} onChange={e=>setEditData(p=>({...p,name:e.target.value}))} style={{ ...iStyle("n"),padding:"4px 7px",fontSize:11 }}/></td>
                        <td style={{ padding:"7px 10px" }}>
                          {/* 본부 — ssk_users group by 셀렉트 + 직접입력 */}
                          <div style={{ display:"flex",gap:3 }}>
                            <select value={editData.division||""}
                              onChange={e=>{ if(e.target.value==="__direct__") return; setEditData(p=>({...p,division:e.target.value})); }}
                              style={{ ...iStyle("n"),padding:"4px 6px",fontSize:11,flex:1 }}>
                              <option value="">— 본부 선택 —</option>
                              {uniqDivs.map(d=><option key={d} value={d}>{d}</option>)}
                              <option value="__direct__">✏ 직접 입력</option>
                            </select>
                            {(!editData.division || !uniqDivs.includes(editData.division)) && (
                              <input value={editData.division||""}
                                onChange={e=>setEditData(p=>({...p,division:e.target.value}))}
                                placeholder="새 본부명"
                                style={{ ...iStyle("n"),padding:"4px 7px",fontSize:11,width:80 }}/>
                            )}
                          </div>
                        </td>
                        <td style={{ padding:"7px 10px" }}>
                          {/* 부서 — ssk_users group by 셀렉트 + 직접입력 */}
                          <div style={{ display:"flex",gap:3 }}>
                            <select value={editData.dept||""}
                              onChange={e=>{ if(e.target.value==="__direct__") return; setEditData(p=>({...p,dept:e.target.value})); }}
                              style={{ ...iStyle("d"),padding:"4px 6px",fontSize:11,flex:1 }}>
                              <option value="">— 부서 선택 —</option>
                              {uniqDepts.map(d=><option key={d} value={d}>{d}</option>)}
                              <option value="__direct__">✏ 직접 입력</option>
                            </select>
                            {(!editData.dept || !uniqDepts.includes(editData.dept)) && (
                              <input value={editData.dept||""}
                                onChange={e=>setEditData(p=>({...p,dept:e.target.value}))}
                                placeholder="새 부서명"
                                style={{ ...iStyle("d"),padding:"4px 7px",fontSize:11,width:80 }}/>
                            )}
                          </div>
                        </td>
                        <td style={{ padding:"7px 10px" }}>
                          <select value={editData.role||"user"} onChange={e=>setEditData(p=>({...p,role:e.target.value}))} style={{ ...iStyle("r"),padding:"4px 6px",fontSize:11 }}>
                            {Object.entries(ROLE_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
                          </select>
                        </td>
                        <td style={{ padding:"7px 10px" }}><input value={editData.title||""} onChange={e=>setEditData(p=>({...p,title:e.target.value}))} style={{ ...iStyle("t"),padding:"4px 7px",fontSize:11 }}/></td>
                        <td style={{ padding:"7px 10px" }}><input value={editData.email||""} onChange={e=>setEditData(p=>({...p,email:e.target.value}))} style={{ ...iStyle("e"),padding:"4px 7px",fontSize:11 }}/></td>
                        <td style={{ padding:"7px 10px" }}><input value={editData.phone||""} onChange={e=>setEditData(p=>({...p,phone:e.target.value}))} style={{ ...iStyle("p"),padding:"4px 7px",fontSize:11 }}/></td>
                        <td style={{ padding:"7px 10px",color:"var(--txt3)",fontSize:10 }}>{u.createdAt?.slice(0,10)||"—"}</td>
                        <td style={{ padding:"7px 10px" }}>
                          <div style={{ display:"flex",gap:4 }}>
                            <button onClick={saveEdit} style={{ padding:"3px 8px",borderRadius:4,border:"1px solid rgba(22,163,74,.4)",background:"rgba(22,163,74,.1)",color:"#4ADE80",fontSize:13,fontWeight:700,cursor:"pointer" }}>저장</button>
                            <button onClick={()=>setEditId(null)} style={{ padding:"3px 7px",borderRadius:4,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>취소</button>
                          </div>
                        </td>
                      </>
                    ) : (
                      <>
                        <td style={{ padding:"9px 12px",fontWeight:600,color:"var(--txt)" }}>{u.name}</td>
                        <td style={{ padding:"9px 12px",color:"var(--txt2)" }}>{u.division||"—"}</td>
                        <td style={{ padding:"9px 12px",color:"var(--txt2)" }}>{u.dept||"—"}</td>
                        <td style={{ padding:"9px 12px" }}>
                          <span style={{ padding:"2px 7px",borderRadius:8,fontSize:13,fontWeight:700,
                            background:`${rc}18`,color:rc,border:`1px solid ${rc}30` }}>
                            {ROLE_LABELS[u.role]||u.role}
                          </span>
                        </td>
                        <td style={{ padding:"9px 12px",color:"var(--txt3)" }}>{u.title||"—"}</td>
                        <td style={{ padding:"9px 12px",color:"var(--txt3)" }}>{u.email||"—"}</td>
                        <td style={{ padding:"9px 12px",color:"var(--txt3)" }}>{u.phone||"—"}</td>
                        <td style={{ padding:"9px 12px",color:"var(--txt3)",fontSize:13,whiteSpace:"nowrap" }}>{u.createdAt?.slice(0,10)||"—"}</td>
                        <td style={{ padding:"9px 12px" }}>
                          <div style={{ display:"flex",gap:4 }}>
                            <button onClick={()=>startEdit(u)} style={{ padding:"3px 8px",borderRadius:4,border:"1px solid var(--bdr2)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>수정</button>
                            <button onClick={()=>delUser(u.id)} style={{ padding:"3px 7px",borderRadius:4,border:"1px solid rgba(220,38,38,.3)",background:"transparent",color:"#F87171",fontSize:13,cursor:"pointer" }}>삭제</button>
                          </div>
                        </td>
                      </>
                    )}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* 하단: 페이지네이션 + 선택 요약 */}
      <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",padding:"8px 14px",borderTop:"1px solid var(--bdr)",background:"var(--bg-card2)" }}>
        <span style={{ fontSize:13,color:"var(--txt3)" }}>
          {filtered.length}명
          {selected.size>0 && <span style={{ color:"var(--accent-text)",fontWeight:700,marginLeft:6 }}>/ {selected.size}명 선택</span>}
        </span>
        {totalPages>1 && (
          <div style={{ display:"flex",gap:3 }}>
            {["«","‹",...Array.from({length:totalPages},(_,i)=>String(i+1)),"›","»"].map((lbl,i)=>{
              const pg = lbl==="«"?1:lbl==="‹"?page-1:lbl==="›"?page+1:lbl==="»"?totalPages:Number(lbl);
              if (pg<1||pg>totalPages) return null;
              return (
                <button key={i} onClick={()=>setPage(pg)}
                  style={{ padding:"3px 8px",borderRadius:4,border:`1px solid ${pg===page?"var(--accent)":"var(--bdr)"}`,
                    background:pg===page?"var(--accent)":"transparent",color:pg===page?"#fff":"var(--txt3)",fontSize:13,cursor:"pointer" }}>
                  {lbl}
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
// ── 시스템 설정 인라인 컴포넌트 ─────────────────────────────────
function SystemSettings({ API_BASE }) {
  const [open,      setOpen]      = useState(null); // 현재 열린 항목 id
  const [scanCfg,   setScanCfg]   = useState(() => {
    try { return JSON.parse(localStorage.getItem("ssk_scan_cfg")||"{}"); } catch { return {}; }
  });
  const [alertCfg,  setAlertCfg]  = useState(() => {
    try { return JSON.parse(localStorage.getItem("ssk_alert_cfg")||"{}"); } catch { return {}; }
  });
  const [dbStats,   setDbStats]   = useState(null);
  const [dbFile,    setDbFile]    = useState(null);
  const [visitors,  setVisitors]  = useState(null);
  const [orgs,      setOrgs]      = useState(() => {
    try { return JSON.parse(localStorage.getItem("ssk_orgs")||"null"); } catch { return null; }
  });
  const [checklist, setChecklist] = useState(() => {
    try { return JSON.parse(localStorage.getItem("ssk_checklist")||"null"); } catch { return null; }
  });
  const [saved,     setSaved]     = useState({});

  const showSaved = (id) => {
    setSaved(p=>({...p,[id]:true}));
    setTimeout(()=>setSaved(p=>({...p,[id]:false})),2000);
  };

  const loadDb = async () => {
    try {
      const [s,f] = await Promise.all([
        fetch(`${API_BASE}/api/admin/db/stats`).then(r=>r.json()),
        fetch(`${API_BASE}/api/admin/db/fileinfo`).then(r=>r.json()),
      ]);
      setDbStats(s); setDbFile(f);
    } catch {}
  };

  const loadVisitors = async () => {
    try {
      const v = await fetch(`${API_BASE}/api/admin/visitors`).then(r=>r.json());
      setVisitors(v);
    } catch {}
  };

  const toggle = (id) => {
    const next = open===id ? null : id;
    setOpen(next);
    if (next==="db")       loadDb();
    if (next==="visitors") loadVisitors();
  };

  // 입력 스타일
  const IS = { width:"100%",padding:"8px 11px",borderRadius:6,border:"1px solid var(--bdr)",
    background:"var(--bg-input)",color:"var(--txt)",fontSize:13,outline:"none" };
  const LB = { fontSize:13,fontWeight:600,color:"var(--txt3)",textTransform:"uppercase",
    letterSpacing:".05em",display:"block",marginBottom:4 };

  const ITEMS = [
    { id:"scan",      icon:"🔍", title:"점검 엔진",      badge:null,        desc:"타임아웃 · nmap · AI 분석" },
    { id:"alerts",    icon:"🔔", title:"알람 설정",       badge:"미설정",    desc:"이메일 · Slack · 알람 규칙" },
    { id:"orgs",      icon:"🌐", title:"정보보호 기관",   badge:null,        desc:"KrCERT · KISA · CISA · NVD" },
    { id:"checklist", icon:"📋", title:"일일 점검 항목",  badge:null,        desc:"매일/매주/매월/분기별 점검" },
    { id:"db",        icon:"🗄",  title:"데이터베이스",    badge:"LIVE",      desc:"파일 현황 · 테이블 통계" },
    { id:"visitors",  icon:"👥", title:"접속자 현황",     badge:"LIVE",      desc:"실시간 접속 · API 로그" },
  ];

  const BADGE_COLOR = { "LIVE":"rgba(22,163,74,.15)", "미설정":"rgba(234,179,8,.15)" };
  const BADGE_TEXT  = { "LIVE":"#4ADE80", "미설정":"#FBBF24" };

  return (
    <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,overflow:"hidden" }}>
      {ITEMS.map((item,i) => {
        const isOpen = open === item.id;
        return (
          <div key={item.id} style={{ borderBottom: i<ITEMS.length-1?"1px solid var(--bdr)":"none" }}>
            {/* ── 헤더 행 ── */}
            <div onClick={()=>toggle(item.id)}
              style={{ display:"flex",alignItems:"center",gap:12,padding:"11px 16px",cursor:"pointer",
                background:isOpen?"var(--bg-active)":"transparent",transition:"background .12s",
                borderLeft:`3px solid ${isOpen?"var(--accent)":"transparent"}` }}>
              <span style={{ fontSize:16,flexShrink:0 }}>{item.icon}</span>
              <span style={{ fontSize:13,fontWeight:isOpen?700:500,color:isOpen?"var(--accent-text)":"var(--txt)",flex:1 }}>
                {item.title}
              </span>
              <span style={{ fontSize:13,color:"var(--txt3)" }}>{item.desc}</span>
              {item.badge && (
                <span style={{ fontSize:13,padding:"1px 6px",borderRadius:8,fontWeight:700,
                  background:BADGE_COLOR[item.badge]||"var(--bg-card2)",
                  color:BADGE_TEXT[item.badge]||"var(--txt3)" }}>
                  {item.badge}
                </span>
              )}
              {saved[item.id] && <span style={{ fontSize:13,color:"#4ADE80",fontWeight:700 }}>✓ 저장됨</span>}
              <span style={{ fontSize:13,color:"var(--txt3)",transition:"transform .2s",
                transform:isOpen?"rotate(180deg)":"rotate(0)",display:"inline-block" }}>▾</span>
            </div>

            {/* ── 인라인 패널 ── */}
            {isOpen && (
              <div style={{ padding:"16px 20px",background:"var(--bg-card2)",borderTop:"1px solid var(--bdr)" }}>

                {/* 점검 엔진 */}
                {item.id==="scan" && (
                  <div>
                    <div style={{ display:"grid",gridTemplateColumns:"repeat(3,1fr)",gap:10,marginBottom:12 }}>
                      {[
                        {k:"timeout",    l:"타임아웃 (초)",     ph:"10",  type:"number"},
                        {k:"concurrent", l:"동시 점검 수",      ph:"5",   type:"number"},
                        {k:"nmap",       l:"nmap 경로",         ph:"/usr/bin/nmap", type:"text"},
                        {k:"sslWarnDays",l:"SSL 경고 일수",     ph:"30",  type:"number"},
                        {k:"repeatThreshold",l:"반복 임계값",   ph:"3",   type:"number"},
                        {k:"reportDir",  l:"리포트 저장 경로",  ph:"./reports", type:"text"},
                      ].map(f=>(
                        <div key={f.k}>
                          <label style={LB}>{f.l}</label>
                          <input type={f.type} value={scanCfg[f.k]||""} placeholder={f.ph}
                            onChange={e=>setScanCfg(p=>({...p,[f.k]:e.target.value}))}
                            style={IS}/>
                        </div>
                      ))}
                    </div>
                    <div style={{ display:"flex",alignItems:"center",gap:8,marginBottom:12 }}>
                      <input type="checkbox" id="ai_chk" checked={!!scanCfg.aiEnabled}
                        onChange={e=>setScanCfg(p=>({...p,aiEnabled:e.target.checked}))}/>
                      <label htmlFor="ai_chk" style={{ fontSize:13,color:"var(--txt)",cursor:"pointer" }}>AI 취약점 분석 활성화</label>
                    </div>
                    <button onClick={()=>{ localStorage.setItem("ssk_scan_cfg",JSON.stringify(scanCfg)); showSaved("scan"); }}
                      style={{ padding:"7px 20px",borderRadius:6,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:13,fontWeight:700,cursor:"pointer" }}>
                      저장
                    </button>
                  </div>
                )}

                {/* 알람 설정 */}
                {item.id==="alerts" && (
                  <div>
                    <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:10,lineHeight:1.7 }}>
                      상세 알람 규칙(7종) 및 채널 설정은 <strong style={{ color:"var(--txt2)" }}>설정 → 알람 설정</strong>에서 관리합니다.
                    </div>
                    <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:10,marginBottom:12 }}>
                      {[
                        {k:"email_smtp",   l:"SMTP 서버",      ph:"smtp.gmail.com"},
                        {k:"email_port",   l:"포트",           ph:"587"},
                        {k:"email_from",   l:"발신 주소",      ph:"security@company.com"},
                        {k:"email_to",     l:"수신 주소",      ph:"ciso@company.com"},
                        {k:"slack_webhook",l:"Slack Webhook", ph:"https://hooks.slack.com/..."},
                        {k:"teams_webhook",l:"Teams Webhook", ph:"https://outlook.office.com/..."},
                      ].map(f=>(
                        <div key={f.k}>
                          <label style={LB}>{f.l}</label>
                          <input value={alertCfg[f.k]||""} placeholder={f.ph}
                            onChange={e=>setAlertCfg(p=>({...p,[f.k]:e.target.value}))}
                            style={IS}/>
                        </div>
                      ))}
                    </div>
                    <button onClick={()=>{ localStorage.setItem("ssk_alert_cfg",JSON.stringify(alertCfg)); showSaved("alerts"); }}
                      style={{ padding:"7px 20px",borderRadius:6,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:13,fontWeight:700,cursor:"pointer" }}>
                      저장
                    </button>
                  </div>
                )}

                {/* 정보보호 기관 */}
                {item.id==="orgs" && (
                  <div>
                    <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:10 }}>
                      등록된 정보보호 기관 목록입니다. 상세 편집은 <strong style={{ color:"var(--txt2)" }}>설정 → 참조 기관</strong>에서 합니다.
                    </div>
                    {(orgs||[{name:"KrCERT/CC",country:"🇰🇷",type:"취약점"},{name:"KISA 보호나라",country:"🇰🇷",type:"정책"},
                      {name:"금융보안원",country:"🇰🇷",type:"금융"},{name:"CISA KEV",country:"🇺🇸",type:"KEV"},
                      {name:"NVD (NIST)",country:"🇺🇸",type:"CVE DB"},{name:"MITRE ATT&CK",country:"🇺🇸",type:"프레임워크"},
                    ]).map((org,i)=>(
                      <div key={i} style={{ display:"flex",alignItems:"center",gap:10,padding:"9px 12px",borderRadius:6,
                        background:i%2===0?"transparent":"var(--bg-card)",marginBottom:2 }}>
                        <span style={{ fontSize:14 }}>{org.country}</span>
                        <span style={{ fontSize:13,fontWeight:500,color:"var(--txt)",flex:1 }}>{org.name}</span>
                        <span style={{ fontSize:13,padding:"1px 6px",borderRadius:8,background:"var(--bg-card2)",color:"var(--txt3)",border:"1px solid var(--bdr)" }}>{org.type}</span>
                      </div>
                    ))}
                  </div>
                )}

                {/* 일일 점검 항목 */}
                {item.id==="checklist" && (
                  <div>
                    {(checklist||[
                      {time:"매일 08:00",task:"KrCERT 긴급 보안 공지 확인",priority:"critical",auto:true},
                      {time:"매일 08:00",task:"CISA KEV 신규 등재 취약점 확인",priority:"critical",auto:true},
                      {time:"매일 09:00",task:"NVD CVSS 9.0+ 신규 CVE 확인",priority:"high",auto:true},
                      {time:"매주 월요일",task:"금융보안원 주간 위협 동향 검토",priority:"medium",auto:false},
                      {time:"매월 1일",task:"SSL 인증서 30일 내 만료 자산 확인",priority:"high",auto:true},
                    ]).map((item2,i)=>{
                      const PC={"critical":"#F87171","high":"#FB923C","medium":"#FBBF24","low":"#4ADE80"};
                      return (
                        <div key={i} style={{ display:"flex",alignItems:"center",gap:10,padding:"9px 12px",borderRadius:6,
                          background:i%2===0?"transparent":"var(--bg-card)",marginBottom:2 }}>
                          <span style={{ width:5,height:5,borderRadius:"50%",background:PC[item2.priority]||"#94A3B8",flexShrink:0 }}/>
                          <span style={{ fontSize:13,color:"var(--txt3)",minWidth:80,flexShrink:0 }}>{item2.time}</span>
                          <span style={{ fontSize:13,color:"var(--txt)",flex:1 }}>{item2.task}</span>
                          <span style={{ fontSize:13,padding:"1px 5px",borderRadius:4,
                            background:item2.auto?"rgba(22,163,74,.15)":"var(--bg-card2)",
                            color:item2.auto?"#4ADE80":"var(--txt3)" }}>
                            {item2.auto?"자동":"수동"}
                          </span>
                        </div>
                      );
                    })}
                  </div>
                )}

                {/* 데이터베이스 */}
                {item.id==="db" && (
                  <div>
                    {!dbStats ? (
                      <div style={{ textAlign:"center",padding:"16px",color:"var(--txt3)",fontSize:11 }}>불러오는 중...</div>
                    ) : (
                      <div>
                        {dbFile && (
                          <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:12 }}>
                            {[
                              {l:"DB 경로",  v:dbFile.path?.split(/[\/]/).pop()||"—"},
                              {l:"파일 크기",v:dbFile.size_human||"—"},
                              {l:"수정일",   v:dbFile.modified_at?.slice(0,10)||"—"},
                              {l:"접근일",   v:dbFile.accessed_at?.slice(0,10)||"—"},
                            ].map(d=>(
                              <div key={d.l} style={{ background:"var(--bg-card)",borderRadius:6,padding:"10px 12px",border:"1px solid var(--bdr)" }}>
                                <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:3 }}>{d.l}</div>
                                <div style={{ fontSize:13,fontWeight:600,color:"var(--txt)",overflow:"hidden",textOverflow:"ellipsis",whiteSpace:"nowrap" }}>{d.v}</div>
                              </div>
                            ))}
                          </div>
                        )}
                        <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:6 }}>
                          {Object.entries(dbStats).filter(([k])=>!k.startsWith("_")).map(([k,v])=>(
                            <div key={k} style={{ background:"var(--bg-card)",borderRadius:6,padding:"9px 12px",border:"1px solid var(--bdr)" }}>
                              <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:2,textTransform:"uppercase",letterSpacing:".04em" }}>{k}</div>
                              <div style={{ fontSize:16,fontWeight:700,color:"var(--accent-text)" }}>{v?.toLocaleString?.()??v}</div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* 접속자 현황 */}
                {item.id==="visitors" && (
                  <div>
                    {!visitors ? (
                      <div style={{ textAlign:"center",padding:"16px",color:"var(--txt3)",fontSize:11 }}>불러오는 중...</div>
                    ) : (
                      <div>
                        <div style={{ display:"grid",gridTemplateColumns:"repeat(4,1fr)",gap:8,marginBottom:12 }}>
                          {[
                            {l:"고유 접속자",v:visitors.total_unique_ips||0,c:"var(--accent-text)"},
                            {l:"총 API 요청",v:visitors.total_requests||0,c:"#FBBF24"},
                            {l:"현재 접속중",v:visitors.active_sessions?.filter(s=>s.is_active).length||0,c:"#4ADE80"},
                            {l:"오류 응답",  v:(visitors.recent_logs||[]).filter(l=>l.status>=400).length,c:"#F87171"},
                          ].map(k=>(
                            <div key={k.l} style={{ background:"var(--bg-card)",borderRadius:6,padding:"10px 12px",border:"1px solid var(--bdr)" }}>
                              <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:3 }}>{k.l}</div>
                              <div style={{ fontSize:18,fontWeight:700,color:k.c }}>{k.v}</div>
                            </div>
                          ))}
                        </div>
                        {/* 최근 접속자 목록 */}
                        {(visitors.active_sessions||[]).slice(0,5).map((s,i)=>(
                          <div key={i} style={{ display:"flex",alignItems:"center",gap:10,padding:"6px 10px",borderRadius:6,
                            background:i%2===0?"transparent":"var(--bg-card)",marginBottom:2 }}>
                            <span style={{ width:6,height:6,borderRadius:"50%",
                              background:s.is_active?"#22C55E":"#6B7280",flexShrink:0,
                              boxShadow:s.is_active?"0 0 4px #22C55E":"none" }}/>
                            <code style={{ fontSize:13,color:"var(--accent-text)",minWidth:110 }}>{s.ip}</code>
                            <span style={{ fontSize:13,color:"var(--txt2)",flex:1 }}>{s.browser} / {s.os}</span>
                            <span style={{ fontSize:13,color:"var(--txt3)" }}>{s.last_seen?.slice(11)}</span>
                            <span style={{ fontSize:13,color:"var(--txt3)" }}>{s.req_count}건</span>
                          </div>
                        ))}
                      </div>
                    )}
                    <button onClick={loadVisitors}
                      style={{ marginTop:8,padding:"5px 14px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
                      ↻ 새로고침
                    </button>
                  </div>
                )}

              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

function DeptRow({ d, i, users, onDel }) {
  return (
    <div style={{ display:"flex",alignItems:"center",gap:10,
      padding:"9px 14px 9px 24px",borderBottom:"1px solid var(--bdr)",
      background:i%2===0?"transparent":"var(--bg-card2)" }}>
      <span style={{ fontSize:13 }}>🏢</span>
      <div style={{ flex:1,minWidth:0 }}>
        <div style={{ fontSize:12,fontWeight:500,color:"var(--txt)" }}>{d.name}</div>
        <div style={{ fontSize:11,color:"var(--txt3)" }}>직원 {users.filter(u=>u.dept===d.name).length}명</div>
      </div>
      <button onClick={onDel}
        style={{ padding:"2px 8px",borderRadius:4,fontSize:11,cursor:"pointer",
          border:"1px solid rgba(220,38,38,.3)",background:"transparent",color:"#F87171" }}>삭제</button>
    </div>
  );
}

export function PageAdmin({ onNav }) {
  const [tab,       setTab]      = useState("users");
  const [depts,     setDepts]    = useState([]);
  const [divs,      setDivs]     = useState([]);
  const [users,     setUsers]    = useState([]);
  const [loading,   setLoading]  = useState(true);
  const [newDept,   setNewDept]  = useState("");
  const [newDiv,    setNewDiv]   = useState("");
  const [newDeptDiv,setNewDeptDiv] = useState(""); // 부서 추가 시 소속 본부
  const [newUser,   setNewUser]  = useState({ name:"", division:"", dept:"", title:"", role:"user", email:"", phone:"" });
  const [bulkText,   setBulkText]   = useState("");
  const [bulkMsg,    setBulkMsg]    = useState(null);
  const [bulkPreview,setBulkPreview]= useState([]);

  // ── DB에서 사용자 로드
  const loadUsers = async () => {
    try {
      const dbUsers = await fetch(`${API_BASE}/api/system-users`).then(r=>r.json());
      if (Array.isArray(dbUsers)) {
        setUsers(dbUsers);
        // localStorage도 동기화 (자동완성용 캐시)
        localStorage.setItem("ssk_users", JSON.stringify(dbUsers));
      }
    } catch {}
    setLoading(false);
  };
  useEffect(() => { loadUsers(); }, []);

  // ── saveUsers: DB + localStorage 동시 저장
  const saveUsers = async (u) => {
    setUsers(u);
    localStorage.setItem("ssk_users", JSON.stringify(u));
    // 전체를 DB에 bulk upsert
    try {
      await fetch(`${API_BASE}/api/system-users/bulk`, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify(u.map(usr=>({
          name: usr.name, division: usr.division||"", dept: usr.dept||"",
          role: usr.role||"user", email: usr.email||"", phone: usr.phone||""
        })))
      });
    } catch {}
  };

  const loadDivsFromDB  = async () => {
    try {
      const r = await fetch(`${API_BASE}/api/divisions`).then(r=>r.json()).catch(()=>[]);
      if (Array.isArray(r)) setDivs(r);
    } catch {}
  };
  const loadDeptsFromDB = async () => {
    try {
      const r = await fetch(`${API_BASE}/api/departments`).then(r=>r.json()).catch(()=>[]);
      if (Array.isArray(r)) setDepts(r);
    } catch {}
  };
  const saveDivs  = async (list) => { setDivs(list); };
  const saveDepts = async (list) => { setDepts(list); };

  const addDept = async () => {
    if (!newDept.trim()) return;
    try {
      await fetch(`${API_BASE}/api/departments`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({name:newDept.trim(), division_name:newDeptDiv.trim()})
      });
      await loadDeptsFromDB();
      setNewDept("");
    } catch {}
  };

  const addDiv = async () => {
    if (!newDiv.trim()) return;
    try {
      await fetch(`${API_BASE}/api/divisions`, {
        method:"POST", headers:{"Content-Type":"application/json"},
        body:JSON.stringify({name:newDiv.trim()})
      });
      await loadDivsFromDB();
      setNewDiv("");
    } catch {}
  };

  // 단일 사용자 추가 — DB 직접 저장
  const addUserToDB = async (userData) => {
    try {
      await fetch(`${API_BASE}/api/system-users`, {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body: JSON.stringify(userData)
      });
      await loadUsers(); // 목록 새로고침
    } catch { alert("저장 실패"); }
  };

  const addUser = () => {
    if (!newUser.name.trim()) return;
    const updated = [...users, { id:Date.now(), ...newUser, createdAt:new Date().toISOString() }];
    saveUsers(updated); setNewUser({ name:"", division:"", dept:"", title:"", role:"user", email:"", phone:"" });
  };

  const parseBulkLines = (text) => {
    const lines = text.trim().split("\n").filter(Boolean);
    const result = [];
    for (const line of lines) {
      const cols = line.split(/[,\t]/).map(s=>s.replace(/^"|"$/g,"").trim());
      if (cols[0]==="이름(필수)"||cols[0]==="이름"||cols[0]==="name") continue;
      // 컬럼: 이름, 본부, 부서, 직책, 역할, 이메일, 전화
      // 컬럼: 이름*, 본부(선택), 부서*, 직책, 역할, 이메일, 전화
      // CSV가 "이름,부서" 2컬럼인 경우 → 본부 없음, 부서가 2번째
      let [name, col2, col3, title, role, email, phone] = cols;
      if (!name) continue;
      // col2가 역할값이면 본부 없는 구 양식 — col2를 부서로 처리
      let division = "", dept = "";
      if (["admin","manager","user","viewer"].includes(col3)) {
        // 이름, 부서, 역할, ... 구 양식
        dept = col2 || ""; division = ""; title = col3; role = "user"; email = ""; phone = "";
        [,,,title,role,email,phone] = cols; // 재매핑
        dept = col2||""; division="";
      } else if (!col3) {
        // 이름, 부서 2컬럼
        dept = col2||""; division="";
      } else {
        // 이름, 본부, 부서, ... 신규 양식
        division = col2||""; dept = col3||"";
      }
      const validRole = ["admin","manager","user","viewer"].includes(role) ? role : "user";
      result.push({ id:Date.now()+Math.random(), name, division, dept,
        title:title||"", role:validRole, email:email||"", phone:phone||"",
        createdAt:new Date().toISOString() });
    }
    return result;
  };

  const handleBulkFile = (file) => {
    // 먼저 ArrayBuffer로 읽어 인코딩 자동 감지
    const bufReader = new FileReader();
    bufReader.onload = e => {
      const buf = e.target.result;
      const bytes = new Uint8Array(buf);

      // BOM 확인: UTF-8 BOM (EF BB BF), UTF-16 LE BOM (FF FE)
      const hasUtf8Bom  = bytes[0]===0xEF && bytes[1]===0xBB && bytes[2]===0xBF;
      const hasUtf16Bom = bytes[0]===0xFF && bytes[1]===0xFE;

      // EUC-KR/CP949 여부 휴리스틱: 0x80~0xFF 범위 바이트가 있고 UTF-8 디코딩 시 깨지는지 확인
      let encoding = "UTF-8";
      if (!hasUtf8Bom && !hasUtf16Bom) {
        try {
          const testDec = new TextDecoder("UTF-8", { fatal: true });
          testDec.decode(buf);
          encoding = "UTF-8";
        } catch {
          // UTF-8 디코딩 실패 → EUC-KR 시도
          encoding = "EUC-KR";
        }
      }

      try {
        const dec = new TextDecoder(encoding);
        let text = dec.decode(buf);
        // BOM 제거
        if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
        const parsed = parseBulkLines(text);
        if (parsed.length===0) { setBulkMsg({ok:false,text:"파싱할 데이터가 없습니다. 양식을 확인하세요."}); return; }
        setBulkPreview(parsed);
        setBulkMsg({ok:true,text:`${parsed.length}명 파싱 완료 (${encoding}) — 미리보기를 확인 후 등록하세요`});
      } catch(err) {
        setBulkMsg({ok:false,text:`파일 읽기 오류: ${err.message}`});
      }
    };
    bufReader.readAsArrayBuffer(file);
  };

  const bulkImport = () => {
    const imported = parseBulkLines(bulkText);
    if (imported.length===0) { setBulkMsg({ok:false,text:"가져올 데이터가 없습니다"}); return; }
    saveUsers([...users, ...imported]);
    setBulkMsg({ok:true,text:`${imported.length}명 등록 완료 — 사용자 관리 탭으로 이동합니다`});
    setBulkText("");
    setTimeout(()=>{ setBulkMsg(null); setTab("users"); },1500);
  };



  const ROLE_LABELS = { admin:"관리자", manager:"팀장", user:"사용자", viewer:"읽기전용" };
  const ROLE_COLORS = { admin:"#F87171", manager:"#FBBF24", user:"#60A5FA", viewer:"#94A3B8" };

  const TABS = [
    { id:"users",  icon:"👤", label:"사용자 관리" },
    { id:"depts",  icon:"🏢", label:"부서 관리" },
    { id:"bulk",   icon:"📋", label:"일괄 등록" },
    { id:"system", icon:"🔧", label:"시스템 설정" },
  ];

  const iStyle = (k) => ({
    width:"100%", padding:"9px 12px", borderRadius:6,
    border:"1px solid var(--bdr)", background:"var(--bg-input)",
    color:"var(--txt)", fontSize:13, outline:"none"
  });

  return (
    <div style={{ padding:"20px 24px" }}>
      {/* 헤더 */}
      <div style={{ marginBottom:18, display:"flex", alignItems:"center", gap:12 }}>
        <div style={{ width:40,height:40,borderRadius:10,background:"rgba(220,38,38,.1)",border:"1px solid rgba(220,38,38,.2)",display:"flex",alignItems:"center",justifyContent:"center",fontSize:20 }}>🔧</div>
        <div>
          <div style={{ fontSize:16,fontWeight:700,color:"var(--txt)" }}>관리자</div>
          <div style={{ fontSize:13,color:"var(--txt3)" }}>사용자·부서 관리 / 시스템 설정 / 보안 정책</div>
        </div>
      </div>

      {/* 탭 */}
      <div style={{ display:"flex",gap:0,background:"var(--bg-card2)",borderRadius:8,padding:3,border:"1px solid var(--bdr)",marginBottom:16,width:"fit-content" }}>
        {TABS.map(tb=>(
          <button key={tb.id} onClick={()=>setTab(tb.id)}
            style={{ padding:"7px 16px",borderRadius:6,border:"none",cursor:"pointer",fontSize:13,fontWeight:tab===tb.id?700:400,
              background:tab===tb.id?"var(--bg-active)":"transparent",
              color:tab===tb.id?"var(--accent-text)":"var(--txt3)",display:"flex",alignItems:"center",gap:5 }}>
            {tb.icon} {tb.label}
          </button>
        ))}
      </div>

      {/* ── 사용자 관리 ── */}
      {tab==="users" && (
        <div style={{ display:"flex",flexDirection:"column",gap:14 }}>

          {/* 상단: 등록 폼 + KPI */}
          <div style={{ display:"grid",gridTemplateColumns:"360px 1fr",gap:14 }}>
            {/* 등록 폼 */}
            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px" }}>
              <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:12,paddingBottom:8,borderBottom:"1px solid var(--bdr)" }}>신규 사용자 등록</div>
              <div style={{ display:"flex",flexDirection:"column",gap:8 }}>
                {[
                  {label:"이름 *",  key:"name",  ph:"홍길동"},
                  {label:"이메일",  key:"email", ph:"hong@company.com"},
                  {label:"전화번호",key:"phone", ph:"010-1234-5678"},
                  {label:"직책",    key:"title", ph:"보안담당"},
                ].map(f=>(
                  <div key={f.key}>
                    <label style={{ fontSize:13,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>{f.label}</label>
                    <input value={newUser[f.key]||""} onChange={e=>setNewUser(p=>({...p,[f.key]:e.target.value}))}
                      placeholder={f.ph} style={iStyle(f.key)}/>
                  </div>
                ))}
                <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:8 }}>
                  <div>
                    <label style={{ fontSize:13,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>부서</label>
                    <select value={newUser.dept||""} onChange={e=>setNewUser(p=>({...p,dept:e.target.value}))} style={iStyle("dept")}>
                      <option value="">— 선택 —</option>
                      {depts.map(d=><option key={d.id} value={d.name}>{d.name}</option>)}
                    </select>
                  </div>
                  <div>
                    <label style={{ fontSize:13,color:"var(--txt3)",fontWeight:600,textTransform:"uppercase",letterSpacing:".05em",display:"block",marginBottom:3 }}>역할</label>
                    <select value={newUser.role||"user"} onChange={e=>setNewUser(p=>({...p,role:e.target.value}))} style={iStyle("role")}>
                      {Object.entries(ROLE_LABELS).map(([k,v])=><option key={k} value={k}>{v}</option>)}
                    </select>
                  </div>
                </div>
                <button onClick={addUser}
                  style={{ padding:"8px",borderRadius:7,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:13,fontWeight:700,cursor:"pointer",marginTop:2 }}>
                  + 사용자 등록
                </button>
              </div>
            </div>

            {/* KPI */}
            <div style={{ display:"flex",flexDirection:"column",gap:10 }}>
              <div style={{ display:"grid",gridTemplateColumns:"repeat(2,1fr)",gap:8 }}>
                {[
                  {icon:"👤",label:"전체 사용자",val:users.length,c:"var(--accent-text)"},
                  {icon:"🏢",label:"등록 부서",  val:depts.length,c:"#FBBF24"},
                  {icon:"🔴",label:"관리자",     val:users.filter(u=>u.role==="admin").length,c:"#F87171"},
                  {icon:"🟡",label:"팀장",       val:users.filter(u=>u.role==="manager").length,c:"#FBBF24"},
                  {icon:"🔵",label:"일반 사용자",val:users.filter(u=>u.role==="user").length,c:"#60A5FA"},
                  {icon:"⚪",label:"읽기전용",   val:users.filter(u=>u.role==="viewer").length,c:"#94A3B8"},
                ].map(k=>(
                  <div key={k.label} style={{ background:"var(--bg-card)",borderRadius:8,padding:"10px 12px",border:"1px solid var(--bdr)",display:"flex",alignItems:"center",gap:10 }}>
                    <span style={{ fontSize:18 }}>{k.icon}</span>
                    <div>
                      <div style={{ fontSize:13,color:"var(--txt3)" }}>{k.label}</div>
                      <div style={{ fontSize:20,fontWeight:700,color:k.c }}>{k.val}</div>
                    </div>
                  </div>
                ))}
              </div>
              {/* 엑셀 내보내기 */}
              <button onClick={()=>{
                const rows = [["이름","이메일","전화번호","직책","부서","역할","등록일"]];
                users.forEach(u=>rows.push([u.name,u.email||"",u.phone||"",u.title||"",u.dept||"",ROLE_LABELS[u.role]||u.role,u.createdAt?.slice(0,10)||""]));
                const csv = rows.map(r=>r.map(v=>`"${v}"`).join(",")).join("\r\n");
                const blob = new Blob(["﻿"+csv],{type:"text/csv;charset=utf-8"});
                const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
                a.download=`사용자목록_${new Date().toISOString().slice(0,10)}.csv`; a.click();
              }}
                style={{ padding:"8px",borderRadius:7,border:"1px solid rgba(22,163,74,.3)",background:"rgba(22,163,74,.08)",color:"#4ADE80",fontSize:13,fontWeight:600,cursor:"pointer" }}>
                📥 전체 목록 CSV 내보내기
              </button>
            </div>
          </div>

          {/* 사용자 목록 테이블 */}
          <UserListTable users={users} depts={depts} saveUsers={saveUsers} ROLE_LABELS={ROLE_LABELS} ROLE_COLORS={ROLE_COLORS} iStyle={iStyle} API_BASE={API_BASE}/>
        </div>
      )}

      {/* ── 부서 관리 ── */}
      {tab==="depts" && (
        <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:16 }}>

          {/* ── 왼쪽: 본부 관리 ── */}
          <div>
            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px",marginBottom:12 }}>
              <div style={{ fontSize:12,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:10,paddingBottom:6,borderBottom:"1px solid var(--bdr)" }}>
                🏛 본부 추가
              </div>
              <div style={{ display:"flex",gap:6 }}>
                <input value={newDiv} onChange={e=>setNewDiv(e.target.value)}
                  onKeyDown={e=>e.key==="Enter"&&addDiv()}
                  placeholder="예: IT본부, 경영전략본부"
                  style={{...iStyle("nd"),flex:1,fontSize:12}}/>
                <button onClick={addDiv}
                  style={{ padding:"7px 14px",borderRadius:6,border:"1px solid var(--accent)",
                    background:"var(--bg-active)",color:"var(--accent-text)",
                    fontSize:12,fontWeight:700,cursor:"pointer",whiteSpace:"nowrap" }}>+ 추가</button>
              </div>
              <div style={{ fontSize:11,color:"var(--txt3)",marginTop:5 }}>Enter 키로도 추가</div>
            </div>

            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,overflow:"hidden" }}>
              <div style={{ padding:"10px 14px",borderBottom:"1px solid var(--bdr)",background:"var(--bg-card2)",
                display:"flex",alignItems:"center",justifyContent:"space-between" }}>
                <span style={{ fontSize:12,fontWeight:700,color:"var(--txt)" }}>등록 본부</span>
                <span style={{ fontSize:11,color:"var(--txt3)" }}>{divs.length}개</span>
              </div>
              {divs.length===0 ? (
                <div style={{ textAlign:"center",padding:"32px 0",color:"var(--txt3)",fontSize:12 }}>
                  등록된 본부가 없습니다
                </div>
              ) : (
                <div>
                  {divs.map((d,i)=>{
                    const memberCount = users.filter(u=>u.division===d.name).length;
                    const deptCount   = depts.filter(dp=>dp.division_name===d.name).length;
                    return (
                      <div key={d.id} style={{ display:"flex",alignItems:"center",gap:10,
                        padding:"10px 14px",borderBottom:"1px solid var(--bdr)",
                        background:i%2===0?"transparent":"var(--bg-card2)",
                        transition:"background .1s" }}>
                        <span style={{ fontSize:16 }}>🏛</span>
                        <div style={{ flex:1,minWidth:0 }}>
                          <div style={{ fontSize:13,fontWeight:600,color:"var(--txt)" }}>{d.name}</div>
                          <div style={{ fontSize:11,color:"var(--txt3)",marginTop:1 }}>
                            부서 {deptCount}개 · 직원 {memberCount}명
                          </div>
                        </div>
                        <button onClick={async()=>{
                          if(!window.confirm(`"${d.name}"을 삭제하시겠습니까?`)) return;
                          await fetch(`${API_BASE}/api/divisions/${d.id}`,{method:"DELETE"}).catch(()=>{});
                          await loadDivsFromDB();
                        }} style={{ padding:"3px 8px",borderRadius:4,fontSize:11,cursor:"pointer",
                          border:"1px solid rgba(220,38,38,.3)",background:"transparent",color:"#F87171" }}>삭제</button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </div>

          {/* ── 오른쪽: 부서 관리 ── */}
          <div>
            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"16px 18px",marginBottom:12 }}>
              <div style={{ fontSize:12,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em",marginBottom:10,paddingBottom:6,borderBottom:"1px solid var(--bdr)" }}>
                🏢 부서 추가
              </div>
              <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:6,marginBottom:6 }}>
                <div>
                  <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:600,display:"block",marginBottom:3 }}>소속 본부 (선택)</label>
                  <select value={newDeptDiv||""} onChange={e=>setNewDeptDiv(e.target.value)}
                    style={{...iStyle("nd"),width:"100%",fontSize:12,cursor:"pointer"}}>
                    <option value="">— 본부 선택 —</option>
                    {divs.map(d=><option key={d.id} value={d.name}>{d.name}</option>)}
                  </select>
                </div>
                <div>
                  <label style={{ fontSize:10,color:"var(--txt3)",fontWeight:600,display:"block",marginBottom:3 }}>부서명 *</label>
                  <input value={newDept} onChange={e=>setNewDept(e.target.value)}
                    onKeyDown={e=>e.key==="Enter"&&addDept()}
                    placeholder="예: IT감리팀"
                    style={{...iStyle("nd"),width:"100%",fontSize:12}}/>
                </div>
              </div>
              <button onClick={addDept}
                style={{ width:"100%",padding:"7px 0",borderRadius:6,border:"1px solid var(--accent)",
                  background:"var(--bg-active)",color:"var(--accent-text)",
                  fontSize:12,fontWeight:700,cursor:"pointer" }}>+ 부서 추가</button>
              <div style={{ fontSize:11,color:"var(--txt3)",marginTop:5 }}>Enter 키로도 추가</div>
            </div>

            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,overflow:"hidden" }}>
              <div style={{ padding:"10px 14px",borderBottom:"1px solid var(--bdr)",background:"var(--bg-card2)",
                display:"flex",alignItems:"center",justifyContent:"space-between" }}>
                <span style={{ fontSize:12,fontWeight:700,color:"var(--txt)" }}>등록 부서</span>
                <span style={{ fontSize:11,color:"var(--txt3)" }}>{depts.length}개</span>
              </div>
              {depts.length===0 ? (
                <div style={{ textAlign:"center",padding:"32px 0",color:"var(--txt3)",fontSize:12 }}>
                  등록된 부서가 없습니다
                </div>
              ) : (
                <div style={{ maxHeight:400,overflowY:"auto" }}>
                  {divs.length > 0
                    ? divs.map(div=>{
                        const divDepts = depts.filter(d=>d.division_name===div.name);
                        if (divDepts.length===0) return null;
                        return (
                          <div key={div.id}>
                            <div style={{ padding:"6px 14px",background:"var(--bg-card2)",
                              fontSize:11,fontWeight:700,color:"var(--txt3)",
                              borderBottom:"1px solid var(--bdr)",
                              display:"flex",alignItems:"center",gap:5 }}>
                              <span>🏛</span> {div.name}
                              <span style={{ fontWeight:400,opacity:.6 }}>({divDepts.length}개)</span>
                            </div>
                            {divDepts.map((d,i)=>(
                              <DeptRow key={d.id} d={d} i={i} users={users}
                                onDel={async()=>{ await fetch(`${API_BASE}/api/departments/${d.id}`,{method:"DELETE"}).catch(()=>{}); await loadDeptsFromDB(); }}/>
                            ))}
                          </div>
                        );
                      })
                    : null
                  }
                  {/* 본부 미지정 부서 */}
                  {depts.filter(d=>!d.division_name).length > 0 && (
                    <div>
                      <div style={{ padding:"6px 14px",background:"var(--bg-card2)",
                        fontSize:11,fontWeight:700,color:"var(--txt3)",
                        borderBottom:"1px solid var(--bdr)" }}>
                        📋 본부 미지정
                      </div>
                      {depts.filter(d=>!d.division_name).map((d,i)=>(
                        <DeptRow key={d.id} d={d} i={i} users={users}
                          onDel={async()=>{ await fetch(`${API_BASE}/api/departments/${d.id}`,{method:"DELETE"}).catch(()=>{}); await loadDeptsFromDB(); }}/>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

        </div>
      )}

      {/* ── 일괄 등록 ── */}
      {tab==="bulk" && (
        <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:16 }}>
          <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"18px",display:"flex",flexDirection:"column",gap:12 }}>

            {/* ── 기존 데이터 초기화 ── */}
            <div style={{ background:"rgba(248,113,113,.06)",borderRadius:8,padding:"12px 14px",border:"1px solid rgba(248,113,113,.2)",marginBottom:8 }}>
              <div style={{ fontSize:13,fontWeight:700,color:"#F87171",marginBottom:6 }}>⚠ 기존 사용자 데이터 초기화</div>
              <div style={{ fontSize:12,color:"var(--txt3)",marginBottom:10,lineHeight:1.6 }}>
                잘못 등록된 데이터를 삭제하고 새로 등록할 때 사용합니다.<br/>
                <strong style={{color:"#F87171"}}>삭제 후 복구 불가</strong> — 신중하게 사용하세요.
              </div>
              <button onClick={async()=>{
                if(!window.confirm(`사용자 ${users.length}명 전체를 삭제하고 초기화하시겠습니까?\n\n이 작업은 되돌릴 수 없습니다.`)) return;
                saveUsers([]);
                try { await fetch(`${API_BASE}/api/system-users`,{method:"DELETE"}); } catch {}
              }}
                style={{ width:"100%",padding:"7px 0",borderRadius:6,
                  border:"1px solid rgba(248,113,113,.4)",background:"rgba(248,113,113,.1)",
                  color:"#F87171",fontSize:13,fontWeight:700,cursor:"pointer" }}>
                🗑 사용자 전체 삭제 ({users.length}명)
              </button>
            </div>

            {/* 양식 다운로드 */}
            <div style={{ background:"var(--bg-card2)",borderRadius:8,padding:"12px 14px",border:"1px solid var(--bdr)" }}>
              <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:6 }}>📥 등록 양식 다운로드</div>
              <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:10,lineHeight:1.7 }}>
                아래 버튼으로 양식을 다운로드하세요.<br/>
                <strong style={{ color:"var(--txt2)" }}>컬럼: 이름*, 본부, 부서*, 직책, 역할, 이메일</strong><br/>
                역할값: admin / manager / user(기본) / viewer
              </div>
              <div style={{ display:"flex",gap:6 }}>
                <button onClick={()=>{
                  const rows=[
                    ["이름(필수)","본부","부서(필수)","직책","역할","이메일","전화번호"],
                    ["홍길동","IT본부","IT운영팀","팀장","manager","hong@company.com","010-1234-5678"],
                    ["김철수","IT본부","정보보호팀","보안담당","user","kim@company.com","010-2345-6789"],
                    ["박영희","경영본부","IT운영팀","본부장","admin","park@company.com","010-3456-7890"],
                    ["이민준","IT본부","개발팀","개발자","viewer","lee@company.com","010-4567-8901"],
                  ];
                  const csv = rows.map(r=>r.map(v=>`"${v}"`).join(",")).join("\r\n");
                  // UTF-8 BOM 포함 → Excel에서 한글 깨짐 없음
                  const bom = "\uFEFF";
                  const blob = new Blob([bom+csv], {type:"text/csv;charset=utf-8"});
                  const a = document.createElement("a");
                  a.href = URL.createObjectURL(blob);
                  a.download = "사용자_등록양식.csv"; a.click();
                }}
                  style={{ flex:1,padding:"7px 0",borderRadius:6,border:"1px solid rgba(37,99,235,.4)",background:"rgba(37,99,235,.1)",color:"#60A5FA",fontSize:13,fontWeight:600,cursor:"pointer" }}>
                  📄 CSV 양식
                </button>
                <button onClick={()=>{
                  const header="이름(필수)\t본부\t부서(필수)\t직책\t역할\t이메일";
                  const sample="홍길동\tIT본부\tIT운영팀\t팀장\tmanager\thong@company.com\n김철수\tIT본부\t정보보호팀\t보안담당\tuser\tkim@company.com";
                  const blob=new Blob(["\uFEFF"+header+"\n"+sample],{type:"text/plain;charset=utf-8"});
                  const a=document.createElement("a"); a.href=URL.createObjectURL(blob);
                  a.download="사용자_등록양식.txt"; a.click();
                }}
                  style={{ flex:1,padding:"7px 0",borderRadius:6,border:"1px solid rgba(16,185,129,.4)",background:"rgba(16,185,129,.1)",color:"#4ADE80",fontSize:13,fontWeight:600,cursor:"pointer" }}>
                  📝 TXT 양식
                </button>
              </div>
            </div>

            {/* 파일 업로드 */}
            <div>
              <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:6 }}>📤 파일로 등록</div>
              <label style={{ display:"block",padding:"16px",borderRadius:8,border:"2px dashed var(--bdr2)",textAlign:"center",cursor:"pointer",background:"var(--bg-card2)",transition:"border-color .15s" }}
                onDragOver={e=>{e.preventDefault();e.currentTarget.style.borderColor="var(--accent)"}}
                onDragLeave={e=>{e.currentTarget.style.borderColor="var(--bdr2)"}}
                onDrop={e=>{
                  e.preventDefault(); e.currentTarget.style.borderColor="var(--bdr2)";
                  const file=e.dataTransfer.files[0]; if(file) handleBulkFile(file);
                }}>
                <div style={{ fontSize:24,marginBottom:6 }}>📂</div>
                <div style={{ fontSize:13,color:"var(--txt2)",fontWeight:500 }}>CSV / TXT 파일을 드래그하거나 클릭</div>
                <div style={{ fontSize:13,color:"var(--txt3)",marginTop:3 }}>UTF-8 BOM / EUC-KR 자동 감지 — Excel 저장 파일도 OK</div>
                <input type="file" accept=".csv,.txt,.tsv" style={{ display:"none" }}
                  onChange={e=>{ const f=e.target.files[0]; if(f) handleBulkFile(f); e.target.value=""; }}/>
              </label>
            </div>

            {/* 직접 입력 */}
            <div>
              <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:6 }}>✏️ 직접 입력</div>
              <textarea value={bulkText} onChange={e=>setBulkText(e.target.value)}
                placeholder={"홍길동, IT운영팀, manager, hong@co.kr\n김철수, 정보보호팀, user, kim@co.kr"}
                style={{ width:"100%",height:100,padding:"10px 12px",borderRadius:7,border:"1px solid var(--bdr)",
                  background:"var(--bg-input)",color:"var(--txt)",fontSize:13,fontFamily:"monospace",
                  resize:"none",outline:"none",lineHeight:1.6 }}/>
              <button onClick={bulkImport}
                style={{ marginTop:6,width:"100%",padding:"8px",borderRadius:7,border:"1px solid var(--accent)",
                  background:"var(--bg-active)",color:"var(--accent-text)",fontSize:13,fontWeight:700,cursor:"pointer" }}>
                📋 직접 입력 등록
              </button>
            </div>

            {bulkMsg && (
              <div style={{ padding:"10px 12px",borderRadius:6,fontSize:13,
                background:bulkMsg.ok?"rgba(22,163,74,.1)":"rgba(220,38,38,.1)",
                color:bulkMsg.ok?"#4ADE80":"#F87171",border:`1px solid ${bulkMsg.ok?"rgba(22,163,74,.3)":"rgba(220,38,38,.3)"}`}}>
                {bulkMsg.ok?"✓ ":"✗ "}{bulkMsg.text}
              </div>
            )}
          </div>

          {/* 현황 + 미리보기 */}
          <div style={{ display:"flex",flexDirection:"column",gap:12 }}>
            <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,padding:"14px 16px" }}>
              <div style={{ fontSize:13,fontWeight:700,color:"var(--txt)",marginBottom:10 }}>등록 현황</div>
              <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:8 }}>
                {[
                  {icon:"👤",label:"전체 사용자",val:users.length,c:"var(--accent-text)"},
                  {icon:"🏢",label:"등록 부서",  val:depts.length,c:"#FBBF24"},
                  {icon:"🔴",label:"관리자",     val:users.filter(u=>u.role==="admin").length,c:"#F87171"},
                  {icon:"🔵",label:"일반 사용자",val:users.filter(u=>u.role==="user").length,c:"#60A5FA"},
                ].map(k=>(
                  <div key={k.label} style={{ background:"var(--bg-card2)",borderRadius:8,padding:"10px 12px",border:"1px solid var(--bdr)" }}>
                    <div style={{ fontSize:13,color:"var(--txt3)",marginBottom:3 }}>{k.icon} {k.label}</div>
                    <div style={{ fontSize:22,fontWeight:700,color:k.c }}>{k.val}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* 미리보기 */}
            {bulkPreview.length>0 && (
              <div style={{ background:"var(--bg-card)",border:"1px solid var(--bdr)",borderRadius:10,overflow:"hidden" }}>
                <div style={{ padding:"10px 14px",background:"var(--bg-card2)",borderBottom:"1px solid var(--bdr)",display:"flex",justifyContent:"space-between",alignItems:"center" }}>
                  <span style={{ fontSize:13,fontWeight:700,color:"var(--txt)" }}>미리보기 ({bulkPreview.length}명)</span>
                  <div style={{ display:"flex",gap:6 }}>
                    <button onClick={async()=>{
                        const merged = [...users,...bulkPreview];
                        saveUsers(merged);
                        setBulkPreview([]);
                        // 백엔드 DB에도 저장
                        try {
                          await fetch(`${API_BASE}/api/system-users/bulk`,{
                            method:"POST",
                            headers:{"Content-Type":"application/json"},
                            body:JSON.stringify(bulkPreview.map(u=>({
                              name:u.name,division:u.division||"",dept:u.dept||""
                            })))
                          });
                        } catch{}
                        setBulkMsg({ok:true,text:`${bulkPreview.length}명 등록 완료`});
                        setTimeout(()=>{setBulkMsg(null);setTab("users");},1500);
                      }}
                      style={{ padding:"4px 12px",borderRadius:5,border:"1px solid var(--accent)",background:"var(--bg-active)",color:"var(--accent-text)",fontSize:13,fontWeight:700,cursor:"pointer" }}>
                      ✓ 확인 등록
                    </button>
                    <button onClick={()=>setBulkPreview([])}
                      style={{ padding:"4px 10px",borderRadius:5,border:"1px solid var(--bdr)",background:"transparent",color:"var(--txt3)",fontSize:13,cursor:"pointer" }}>
                      취소
                    </button>
                  </div>
                </div>
                <div style={{ maxHeight:200,overflowY:"auto" }}>
                  <table style={{ width:"100%",borderCollapse:"collapse",fontSize:10 }}>
                    <thead><tr style={{ background:"var(--bg-card2)" }}>
                      {["이름","본부","부서","역할","이메일"].map(h=>(
                        <th key={h} style={{ padding:"7px 10px",textAlign:"left",fontSize:13,fontWeight:700,color:"var(--txt3)",borderBottom:"1px solid var(--bdr)" }}>{h}</th>
                      ))}
                    </tr></thead>
                    <tbody>
                      {bulkPreview.map((u,i)=>(
                        <tr key={i} style={{ borderBottom:"1px solid var(--bdr)",background:i%2===0?"transparent":"var(--bg-card2)" }}>
                          <td style={{ padding:"7px 10px",color:"var(--txt)",fontWeight:500 }}>{u.name}</td>
                          <td style={{ padding:"7px 10px",color:"var(--txt3)" }}>{u.division||"—"}</td>
                          <td style={{ padding:"7px 10px",color:"var(--txt3)" }}>{u.dept||"—"}</td>
                          <td style={{ padding:"7px 10px" }}>
                            <span style={{ fontSize:13,padding:"1px 5px",borderRadius:8,fontWeight:700,
                              background:{admin:"rgba(248,113,113,.15)",manager:"rgba(251,191,36,.15)",user:"rgba(96,165,250,.15)",viewer:"rgba(148,163,184,.15)"}[u.role]||"rgba(96,165,250,.15)",
                              color:{admin:"#F87171",manager:"#FBBF24",user:"#60A5FA",viewer:"#94A3B8"}[u.role]||"#60A5FA" }}>
                              {{"admin":"관리자","manager":"팀장","user":"사용자","viewer":"읽기전용"}[u.role]||u.role}
                            </span>
                          </td>
                          <td style={{ padding:"7px 10px",color:"var(--txt3)" }}>{u.email||"—"}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <button onClick={async()=>{
                const ok = window.confirm("모든 사용자 데이터를 초기화하시겠습니까?\n이 작업은 되돌릴 수 없습니다.");
                if (ok) {
                  saveUsers([]);
                try { await fetch(`${API_BASE}/api/system-users`,{method:"DELETE"}); } catch {}
                  setBulkPreview([]);
                  setBulkMsg({ok:true, text:"초기화 완료"});
                  setTimeout(()=>setBulkMsg(null), 2000);
                }
              }}
              style={{ padding:"7px",borderRadius:6,border:"1px solid rgba(220,38,38,.3)",background:"transparent",color:"#F87171",fontSize:13,cursor:"pointer",width:"100%" }}>
              🗑 사용자 데이터 초기화
            </button>
          </div>
        </div>
      )}

      {/* ── 시스템 설정 ── */}
      {tab==="system" && <SystemSettings API_BASE={API_BASE}/>}
    </div>
  );
}// ═══════════════════════════════════════════════════════════════
// REPORTS
// ═══════════════════════════════════════════════════════════════
// ── 보고서별 이력 관리 훅 ─────────────────────────────────────
function useReportHistory(reportId) {
  const KEY = `ssk_rpt_${reportId}`;
  const [list, setList] = useState(() => {
    try { return JSON.parse(localStorage.getItem(KEY)||"[]"); } catch { return []; }
  });
  const add = (entry) => {
    const next = [entry, ...list].slice(0, 50);
    setList(next); localStorage.setItem(KEY, JSON.stringify(next));
  };
  const del = (jobId) => {
    const next = list.filter(x=>x.jobId!==jobId);
    setList(next); localStorage.setItem(KEY, JSON.stringify(next));
  };
  const clear = () => { setList([]); localStorage.removeItem(KEY); };
  return { list, add, del, clear };
}

// ── 보고서 이력 테이블 컴포넌트 ──────────────────────────────
function ReportHistoryTable({ list, del, color, isPdf }) {
  const [sort, setSort] = useState({ key:"createdAt", asc:false });
  const sorted = [...list].sort((a,b)=>{
    const r = String(a[sort.key]||"").localeCompare(String(b[sort.key]||""));
    return sort.asc ? r : -r;
  });
  const Th = ({ k, children }) => (
    <th onClick={()=>setSort(p=>({key:k,asc:p.key===k?!p.asc:true}))}
      style={{ padding:"6px 10px", fontSize:13, fontWeight:700, color:sort.key===k?"var(--accent-text)":"var(--txt3)",
        textTransform:"uppercase", letterSpacing:".06em", background:"var(--bg-card2)",
        borderBottom:"1px solid var(--bdr)", cursor:"pointer", whiteSpace:"nowrap", userSelect:"none" }}>
      {children} <span style={{ fontSize:12, opacity:sort.key===k?1:.3 }}>{sort.key===k?(sort.asc?"▲":"▼"):"⇅"}</span>
    </th>
  );
  if (list.length===0) return (
    <div style={{ textAlign:"center", padding:"24px 0", color:"var(--txt3)", fontSize:11 }}>
      생성된 보고서가 없습니다
    </div>
  );
  return (
    <div style={{ border:"1px solid var(--bdr)", borderRadius:8, overflow:"hidden" }}>
      <table style={{ width:"100%", borderCollapse:"collapse", fontSize:11 }}>
        <thead><tr>
          <Th k="createdAt">생성 일시</Th>
          <Th k="jobId">ID</Th>
          <th style={{ padding:"6px 10px", fontSize:13, fontWeight:700, color:"var(--txt3)", textTransform:"uppercase", letterSpacing:".06em", background:"var(--bg-card2)", borderBottom:"1px solid var(--bdr)" }}>액션</th>
        </tr></thead>
        <tbody>
          {sorted.map((h,i)=>{
            const fullViewUrl  = `${API_BASE}${(h.url||"").replace("/download/","/view/")}`;
            const fullDownUrl  = `${API_BASE}${h.url||""}`;
            return (
              <tr key={h.jobId} style={{ borderBottom:"1px solid var(--bdr)", background:i%2===0?"transparent":"var(--bg-card2)" }}>
                <td style={{ padding:"9px 12px", color:"var(--txt3)", whiteSpace:"nowrap" }}>
                  {new Date(h.createdAt).toLocaleString("ko-KR",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit",second:"2-digit"})}
                </td>
                <td style={{ padding:"9px 12px" }}>
                  <code style={{ fontSize:13, color:"var(--txt3)", background:"var(--bg-card2)", padding:"1px 5px", borderRadius:3 }}>{h.jobId}</code>
                </td>
                <td style={{ padding:"9px 12px" }}>
                  <div style={{ display:"flex", gap:5 }}>
                    {isPdf && (
                      <button onClick={()=>window.open(fullViewUrl,"_blank","width=1100,height=850,resizable=yes")}
                        style={{ padding:"3px 9px", borderRadius:4, border:`1px solid ${color}44`, background:`${color}12`, color, fontSize:13, fontWeight:600, cursor:"pointer" }}>
                        👁 보기
                      </button>
                    )}
                    <a href={fullDownUrl} download
                      style={{ padding:"3px 9px", borderRadius:4, border:"1px solid rgba(22,163,74,.3)", background:"rgba(22,163,74,.08)", color:"#4ADE80", fontSize:13, fontWeight:600, textDecoration:"none" }}>
                      ⬇ 저장
                    </a>
                    <button onClick={()=>del(h.jobId)}
                      style={{ padding:"3px 9px", borderRadius:4, border:"1px solid rgba(220,38,38,.3)", background:"transparent", color:"#F87171", fontSize:13, cursor:"pointer" }}>
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
  );
}

// ── 보고서 카드 컴포넌트 ──────────────────────────────────────
function ReportCard({ rpt, history, onGenerate, generating }) {
  const isPdf = rpt.badge !== "Excel";
  const isGen = generating === rpt.id;
  const lastResult = history.list[0];

  return (
    <div style={{ background:"var(--bg-card)", border:"1px solid var(--bdr)", borderRadius:10, overflow:"hidden" }}>
      {/* 컬러 바 */}
      <div style={{ height:3, background:rpt.color }}/>
      <div style={{ padding:"14px 16px" }}>
        {/* 헤더 */}
        <div style={{ display:"flex", alignItems:"flex-start", gap:10, marginBottom:10 }}>
          <div style={{ width:36,height:36,borderRadius:8,background:`${rpt.color}18`,border:`1px solid ${rpt.color}30`,
            display:"flex",alignItems:"center",justifyContent:"center",fontSize:20,flexShrink:0 }}>
            {rpt.icon}
          </div>
          <div style={{ flex:1,minWidth:0 }}>
            <div style={{ display:"flex",alignItems:"center",gap:6,marginBottom:2 }}>
              <span style={{ fontSize:13,fontWeight:700,color:"var(--txt)" }}>{rpt.title}</span>
              <span style={{ fontSize:13,padding:"1px 6px",borderRadius:8,fontWeight:700,
                background:`${rpt.color}18`,color:rpt.color,border:`1px solid ${rpt.color}33` }}>{rpt.badge}</span>
              {history.list.length>0 && (
                <span style={{ fontSize:13,padding:"1px 6px",borderRadius:8,
                  background:"var(--bg-card2)",color:"var(--txt3)",border:"1px solid var(--bdr)",marginLeft:"auto" }}>
                  {history.list.length}개 이력
                </span>
              )}
            </div>
            <div style={{ fontSize:13,color:"var(--txt3)",lineHeight:1.5 }}>{rpt.desc}</div>
          </div>
        </div>

        {/* 포함 내용 */}
        <div style={{ display:"grid",gridTemplateColumns:"1fr 1fr",gap:3,marginBottom:10 }}>
          {rpt.features.map((f,i)=>(
            <div key={i} style={{ display:"flex",alignItems:"center",gap:4,fontSize:13,color:"var(--txt2)" }}>
              <span style={{ width:4,height:4,borderRadius:"50%",background:rpt.color,flexShrink:0 }}/>
              {f}
            </div>
          ))}
        </div>

        {/* 마지막 생성 결과 */}
        {lastResult && (
          <div style={{ marginBottom:8,padding:"6px 10px",borderRadius:6,
            background:"rgba(22,163,74,.07)",border:"1px solid rgba(22,163,74,.2)",
            display:"flex",alignItems:"center",gap:8 }}>
            <span style={{ fontSize:13,color:"#4ADE80",fontWeight:600 }}>✓ 최근 생성</span>
            <span style={{ fontSize:13,color:"var(--txt3)" }}>
              {new Date(lastResult.createdAt).toLocaleString("ko-KR",{month:"2-digit",day:"2-digit",hour:"2-digit",minute:"2-digit"})}
            </span>
            <div style={{ marginLeft:"auto",display:"flex",gap:5 }}>
              {isPdf && (
                <button onClick={()=>window.open(`${API_BASE}${(lastResult.url||"").replace("/download/","/view/")}`,
                  "_blank","width=1100,height=850,resizable=yes")}
                  style={{ padding:"2px 8px",borderRadius:4,border:`1px solid ${rpt.color}44`,background:`${rpt.color}12`,color:rpt.color,fontSize:13,fontWeight:600,cursor:"pointer" }}>
                  👁 보기
                </button>
              )}
              <a href={`${API_BASE}${lastResult.url}`} download
                style={{ padding:"2px 8px",borderRadius:4,border:"1px solid rgba(22,163,74,.3)",background:"rgba(22,163,74,.08)",color:"#4ADE80",fontSize:13,fontWeight:600,textDecoration:"none" }}>
                ⬇ 저장
              </a>
            </div>
          </div>
        )}

        {/* 생성 버튼 */}
        <button onClick={()=>onGenerate(rpt.type, rpt.id)} disabled={isGen}
          style={{ width:"100%",padding:"8px 0",borderRadius:7,
            border:`1.5px solid ${isGen?"var(--bdr)":rpt.color}`,
            background:isGen?"var(--bg-card2)":`${rpt.color}15`,
            color:isGen?"var(--txt3)":rpt.color,
            fontSize:13,fontWeight:700,cursor:isGen?"wait":"pointer",
            display:"flex",alignItems:"center",justifyContent:"center",gap:6,transition:"all .15s" }}>
          {isGen
            ? <><span style={{ width:12,height:12,borderRadius:"50%",border:`2px solid ${rpt.color}`,borderTopColor:"transparent",animation:"spin .8s linear infinite",display:"inline-block" }}/> 생성 중...</>
            : `${rpt.icon} 보고서 생성`}
        </button>
      </div>

      {/* 이력 */}
      {history.list.length>0 && (
        <div style={{ borderTop:"1px solid var(--bdr)", padding:"10px 14px", background:"var(--bg-card2)" }}>
          <div style={{ display:"flex",alignItems:"center",justifyContent:"space-between",marginBottom:8 }}>
            <span style={{ fontSize:13,fontWeight:700,color:"var(--txt3)",textTransform:"uppercase",letterSpacing:".06em" }}>
              생성 이력
            </span>
            <button onClick={()=>{ if(window.confirm("이력을 모두 삭제하시겠습니까?")) history.clear(); }}
              style={{ padding:"2px 8px",borderRadius:4,border:"1px solid rgba(220,38,38,.25)",background:"transparent",color:"#F87171",fontSize:13,cursor:"pointer" }}>
              전체 삭제
            </button>
          </div>
          <ReportHistoryTable list={history.list} del={history.del} color={rpt.color} isPdf={isPdf}/>
        </div>
      )}
    </div>
  );
}

export function PageReports() {
  const [generating, setGenerating] = useState(null);

  const REPORT_TYPES = [
    { id:"exec",       type:"executive",  icon:"📊", title:"경영진 요약 보고서",
      badge:"Executive", color:"#3B82F6",
      desc:"취약점 현황 KPI, 즉각 조치 권고, 위험도 평가 — 임원 보고용",
      features:["취약점 KPI 6종","즉각 조치 Top 10","종합 위험도 평가","컴플라이언스 준수율"] },
    { id:"technical",  type:"technical",  icon:"🔬", title:"기술 상세 보고서",
      badge:"Technical", color:"#8B5CF6",
      desc:"전체 취약점 상세 분석, CVSS 점수, 자산별 현황, 기술적 조치 가이드",
      features:["취약점 전체 목록","CVSS·반복 분석","자산별 위험 현황","조치 이행 계획표"] },
    { id:"compliance", type:"compliance", icon:"✅", title:"컴플라이언스 보고서",
      badge:"Compliance", color:"#10B981",
      desc:"ISMS-P, 전자금융감독규정, 금융보안원 가이드, PCI-DSS, ISO 27001 준수 현황",
      features:["6개 규정 준수율","규정별 관련 취약점","미준수 항목 현황","개선 권고 사항"] },
    { id:"excel",      type:"excel",      icon:"📋", title:"취약점 데이터 (Excel)",
      badge:"Excel", color:"#F59E0B",
      desc:"필터·정렬 가능한 전체 취약점 데이터 — 담당자 배포 및 추적 관리용",
      features:["전체 취약점 목록","자산별 그룹핑","조치 상태 추적","담당자 배포용"] },
  ];

  const histories = {
    exec:       useReportHistory("exec"),
    technical:  useReportHistory("technical"),
    compliance: useReportHistory("compliance"),
    excel:      useReportHistory("excel"),
  };

  const onGenerate = async (type, id) => {
    setGenerating(id);
    try {
      const r = await generateReport(type);
      histories[id].add({
        jobId: r.job_id,
        url:   r.download_url,
        createdAt: new Date().toISOString(),
      });
    } catch(e) {
      alert("생성 실패: " + e.message);
    } finally { setGenerating(null); }
  };

  return (
    <div style={{ padding:"16px 20px" }}>
      <div style={{ marginBottom:14 }}>
        <div style={{ fontSize:16,fontWeight:700,color:"var(--txt)",marginBottom:2 }}>리포트 센터</div>
        <div style={{ fontSize:13,color:"var(--txt3)" }}>금융권 보안점검 결과 공식 보고서 생성 · 관리 · 배포</div>
      </div>
      <div style={{ display:"grid", gridTemplateColumns:"1fr 1fr", gap:12 }}>
        {REPORT_TYPES.map(r => (
          <ReportCard key={r.id} rpt={r}
            history={histories[r.id]}
            onGenerate={onGenerate}
            generating={generating}/>
        ))}
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════════
// SCAN HISTORY
// ═══════════════════════════════════════════════════════════════
