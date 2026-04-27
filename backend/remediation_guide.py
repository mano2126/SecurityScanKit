"""
remediation_guide.py
취약점 유형별 단계별 조치 가이드 — 실제 실행 가능한 정확한 명령어
"""

GUIDES = {
    "smb": {
        "title": "SMB 포트(445) 취약점 조치",
        "risk": "랜섬웨어(WannaCry, NotPetya) 등 대규모 사이버 공격의 주요 진입 경로. EternalBlue 익스플로잇 대상",
        "steps": [
            {
                "no": 1,
                "title": "Windows 보안 업데이트 적용 (MS17-010)",
                "cmd": "# [방법 1] Windows Update GUI\n"
                       "# 제어판 → Windows Update → 업데이트 확인 → 설치\n\n"
                       "# [방법 2] PowerShell — 업데이트 목록 확인\n"
                       "Get-HotFix | Where-Object {$_.HotFixID -eq 'KB4012212'}\n\n"
                       "# [방법 3] WUSA 명령으로 수동 설치 (다운로드 후)\n"
                       "wusa.exe C:\\path\\to\\KB4012212.msu /quiet /norestart\n\n"
                       "# 패치 다운로드 URL (Microsoft Catalog)\n"
                       "# https://www.catalog.update.microsoft.com/Search.aspx?q=KB4012212",
                "note": "MS17-010 패치 여부 확인: Get-HotFix KB4012212 — 결과가 출력되면 적용 완료"
            },
            {
                "no": 2,
                "title": "방화벽에서 SMB 포트 인바운드 차단",
                "cmd": "# 관리자 권한 PowerShell 또는 CMD에서 실행\n\n"
                       "# TCP 445 차단\n"
                       "netsh advfirewall firewall add rule name=\"Block_SMB_445\" dir=in action=block protocol=TCP localport=445\n\n"
                       "# TCP 139 차단\n"
                       "netsh advfirewall firewall add rule name=\"Block_SMB_139\" dir=in action=block protocol=TCP localport=139\n\n"
                       "# UDP 137, 138 차단\n"
                       "netsh advfirewall firewall add rule name=\"Block_NetBIOS_137\" dir=in action=block protocol=UDP localport=137\n"
                       "netsh advfirewall firewall add rule name=\"Block_NetBIOS_138\" dir=in action=block protocol=UDP localport=138\n\n"
                       "# 적용 확인\n"
                       "netsh advfirewall firewall show rule name=\"Block_SMB_445\"",
                "note": "내부 파일 공유가 필요한 경우 특정 IP만 허용: localport=445 remoteip=192.168.1.0/24"
            },
            {
                "no": 3,
                "title": "SMBv1 프로토콜 비활성화",
                "cmd": "# [Windows 10 / Server 2016 이상] PowerShell — 관리자 권한\n"
                       "Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force\n\n"
                       "# 적용 확인\n"
                       "Get-SmbServerConfiguration | Select EnableSMB1Protocol\n"
                       "# 출력: EnableSMB1Protocol : False  → 정상\n\n"
                       "# [Windows 7 / Server 2008R2] 레지스트리 방식\n"
                       "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\" /v SMB1 /t REG_DWORD /d 0 /f\n\n"
                       "# [Windows 기능에서 제거]\n"
                       "dism /online /norestart /disable-feature /featurename:SMB1Protocol",
                "note": "SMBv1 비활성화 후 재부팅 권장. 일부 구형 NAS/프린터는 SMBv1만 지원할 수 있으니 확인 후 적용"
            },
            {
                "no": 4,
                "title": "조치 완료 검증",
                "cmd": "# SMBv1 비활성화 확인\n"
                       "Get-SmbServerConfiguration | Select EnableSMB1Protocol\n\n"
                       "# 방화벽 규칙 확인\n"
                       "netsh advfirewall firewall show rule name=all | findstr \"Block_SMB\"\n\n"
                       "# 포트 열림 여부 확인 (445가 LISTENING이면 미조치)\n"
                       "netstat -an | findstr \":445\"\n\n"
                       "# 핫픽스 적용 확인\n"
                       "Get-HotFix -Id KB4012212",
                "note": "netstat에서 445가 조회되지 않거나 방화벽 차단 규칙이 있으면 조치 완료"
            }
        ]
    },

    "rdp": {
        "title": "RDP(3389) 취약점 조치",
        "risk": "원격 데스크탑 무차별 대입 공격, BlueKeep(CVE-2019-0708) 취약점 악용 경로",
        "steps": [
            {
                "no": 1,
                "title": "RDP 포트 번호 변경 (3389 → 비표준 포트)",
                "cmd": "# 레지스트리 편집기 (regedit.exe) 직접 수정:\n"
                       "# 경로: HKEY_LOCAL_MACHINE\\System\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\n"
                       "# 값: PortNumber → 10진수로 변경 (예: 33890)\n\n"
                       "# 또는 PowerShell — 관리자 권한\n"
                       "$portNumber = 33890\n"
                       "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name 'PortNumber' -Value $portNumber\n\n"
                       "# 새 포트 방화벽 허용 추가\n"
                       "netsh advfirewall firewall add rule name=\"RDP_Custom_Port\" dir=in action=allow protocol=TCP localport=33890\n\n"
                       "# 기존 3389 차단\n"
                       "netsh advfirewall firewall add rule name=\"Block_RDP_3389\" dir=in action=block protocol=TCP localport=3389\n\n"
                       "# Remote Desktop Services 재시작\n"
                       "net stop TermService && net start TermService",
                "note": "포트 변경 후 접속 시 mstsc.exe → 컴퓨터 주소:33890 형식으로 입력"
            },
            {
                "no": 2,
                "title": "NLA(네트워크 수준 인증) 강제 활성화",
                "cmd": "# 방법 1: 시스템 속성 GUI\n"
                       "# 내 PC 우클릭 → 속성 → 원격 설정\n"
                       "# '네트워크 수준 인증을 사용하는 원격 데스크탑만 허용' 선택\n\n"
                       "# 방법 2: PowerShell\n"
                       "(Get-WmiObject -class Win32_TSGeneralSetting -Namespace root\\cimv2\\terminalservices -Filter \"TerminalName='RDP-tcp'\").SetUserAuthenticationRequired(1)\n\n"
                       "# 방법 3: 레지스트리\n"
                       "reg add \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication /t REG_DWORD /d 1 /f\n\n"
                       "# 확인\n"
                       "reg query \"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp\" /v UserAuthentication\n"
                       "# UserAuthentication = 0x1 이면 NLA 활성화 완료",
                "note": "NLA 활성화 시 RDP 연결 전에 Windows 인증을 먼저 수행하여 세션 하이재킹 방지"
            },
            {
                "no": 3,
                "title": "계정 잠금 정책 설정 (무차별 대입 방지)",
                "cmd": "# 로컬 보안 정책 (secpol.msc) GUI:\n"
                       "# 보안 설정 → 계정 정책 → 계정 잠금 정책\n"
                       "# - 계정 잠금 임계값: 5\n"
                       "# - 계정 잠금 기간: 30분\n"
                       "# - 계정 잠금 초기화 시간: 30분\n\n"
                       "# 명령줄 설정 (관리자 CMD)\n"
                       "net accounts /lockoutthreshold:5\n"
                       "net accounts /lockoutduration:30\n"
                       "net accounts /lockoutwindow:30\n\n"
                       "# 확인\n"
                       "net accounts",
                "note": "5회 로그인 실패 시 30분 잠금. 관리자 계정(Administrator)은 잠금 정책 적용 안 됨 — 계정명 변경 권장"
            },
            {
                "no": 4,
                "title": "접근 IP 화이트리스트 제한",
                "cmd": "# 특정 IP만 RDP 허용 (관리자 CMD)\n"
                       "# 기존 RDP 허용 규칙 삭제\n"
                       "netsh advfirewall firewall delete rule name=\"Remote Desktop - User Mode (TCP-In)\"\n\n"
                       "# 허용 IP만 재등록 (예: 192.168.1.100, 10.0.0.0/8)\n"
                       "netsh advfirewall firewall add rule name=\"RDP_Whitelist\" dir=in action=allow protocol=TCP localport=33890 remoteip=192.168.1.100,10.0.0.0/8\n\n"
                       "# 확인\n"
                       "netsh advfirewall firewall show rule name=\"RDP_Whitelist\"",
                "note": "VPN 연결 후에만 RDP 허용하는 구조가 가장 안전. 퍼블릭 IP 직접 노출 금지"
            }
        ]
    },

    "ssl": {
        "title": "SSL/TLS 인증서 및 프로토콜 취약점 조치",
        "risk": "인증서 만료 시 서비스 중단 및 브라우저 경고, TLS 1.0/1.1은 POODLE/BEAST 공격 대상",
        "steps": [
            {
                "no": 1,
                "title": "인증서 만료 확인 및 갱신",
                "cmd": "# [IIS] PowerShell로 인증서 만료 확인\n"
                       "Get-ChildItem -Path Cert:\\LocalMachine\\My | Select Subject, NotAfter | Sort NotAfter\n\n"
                       "# [IIS] 인증서 갱신 절차:\n"
                       "# IIS 관리자 → 서버 인증서 → 인증서 갱신 요청\n"
                       "# 또는 certlm.msc → 개인 → 인증서 → 우클릭 → 모든 작업 → 갱신\n\n"
                       "# [Apache/Nginx] OpenSSL로 현재 인증서 만료일 확인\n"
                       "openssl s_client -connect yourdomain.com:443 -servername yourdomain.com < /dev/null 2>/dev/null | openssl x509 -noout -dates\n\n"
                       "# [Let's Encrypt] 자동 갱신 실행\n"
                       "certbot renew --dry-run   # 먼저 테스트\n"
                       "certbot renew             # 실제 갱신",
                "note": "인증서 만료 30일 전 갱신 권장. 자동 갱신 크론잡: 0 3 * * * certbot renew --quiet"
            },
            {
                "no": 2,
                "title": "TLS 1.0 / TLS 1.1 비활성화 (Windows IIS)",
                "cmd": "# 관리자 PowerShell에서 실행\n\n"
                       "# TLS 1.0 비활성화\n"
                       "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Force\n"
                       "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'Enabled' -Value 0 -PropertyType DWord -Force\n"
                       "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.0\\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force\n\n"
                       "# TLS 1.1 비활성화 (동일 패턴)\n"
                       "New-Item -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Force\n"
                       "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name 'Enabled' -Value 0 -PropertyType DWord -Force\n"
                       "New-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.1\\Server' -Name 'DisabledByDefault' -Value 1 -PropertyType DWord -Force\n\n"
                       "# 적용 후 서버 재부팅 필요\n"
                       "# Restart-Computer -Force",
                "note": "IIS Crypto (무료 GUI 도구) 사용 시 더 간편: https://www.nartac.com/Products/IISCrypto — Best Practices 클릭"
            },
            {
                "no": 3,
                "title": "TLS 1.0 / 1.1 비활성화 (Linux Nginx/Apache)",
                "cmd": "# [Nginx] /etc/nginx/nginx.conf 또는 사이트 설정 파일\n"
                       "ssl_protocols TLSv1.2 TLSv1.3;\n"
                       "ssl_ciphers 'ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305';\n"
                       "ssl_prefer_server_ciphers on;\n"
                       "ssl_session_cache shared:SSL:10m;\n\n"
                       "# 문법 확인 및 재시작\n"
                       "nginx -t && systemctl reload nginx\n\n"
                       "# [Apache] /etc/apache2/mods-enabled/ssl.conf 또는 VirtualHost\n"
                       "SSLProtocol -all +TLSv1.2 +TLSv1.3\n"
                       "SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384\n"
                       "SSLHonorCipherOrder on\n\n"
                       "# 적용\n"
                       "apachectl configtest && systemctl reload apache2",
                "note": "적용 후 ssllabs.com/ssltest 에서 등급 확인 권장 — A 이상 목표"
            },
            {
                "no": 4,
                "title": "조치 완료 검증",
                "cmd": "# TLS 버전별 연결 테스트 (openssl)\n"
                       "# TLS 1.0 차단 확인 (연결 실패해야 정상)\n"
                       "openssl s_client -connect yourdomain.com:443 -tls1\n\n"
                       "# TLS 1.1 차단 확인 (연결 실패해야 정상)\n"
                       "openssl s_client -connect yourdomain.com:443 -tls1_1\n\n"
                       "# TLS 1.2 허용 확인 (연결 성공해야 정상)\n"
                       "openssl s_client -connect yourdomain.com:443 -tls1_2\n\n"
                       "# 인증서 만료일 재확인\n"
                       "openssl s_client -connect yourdomain.com:443 < /dev/null 2>/dev/null | openssl x509 -noout -enddate",
                "note": "연결 실패 시 'no peer certificate' 또는 'handshake failure' 메시지 확인"
            }
        ]
    },

    "http": {
        "title": "HTTP 보안 헤더 누락 조치",
        "risk": "XSS, 클릭재킹(Clickjacking), MIME 스니핑 등 웹 공격에 노출. 금감원 전자금융 취약점 점검 필수 항목",
        "steps": [
            {
                "no": 1,
                "title": "보안 헤더 적용 — Nginx",
                "cmd": "# /etc/nginx/conf.d/security-headers.conf 파일 생성\n"
                       "# 아래 내용 추가 후 저장\n\n"
                       "add_header X-Content-Type-Options 'nosniff' always;\n"
                       "add_header X-Frame-Options 'DENY' always;\n"
                       "add_header X-XSS-Protection '1; mode=block' always;\n"
                       "add_header Referrer-Policy 'strict-origin-when-cross-origin' always;\n"
                       "add_header Permissions-Policy 'geolocation=(), microphone=(), camera=()' always;\n"
                       "add_header Strict-Transport-Security 'max-age=31536000; includeSubDomains' always;\n"
                       "add_header Content-Security-Policy \"default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'\" always;\n"
                       "server_tokens off;\n\n"
                       "# 적용\n"
                       "nginx -t && systemctl reload nginx",
                "note": "X-Frame-Options DENY: 아이프레임 삽입 완전 차단. 필요시 SAMEORIGIN으로 변경"
            },
            {
                "no": 2,
                "title": "보안 헤더 적용 — IIS (Windows)",
                "cmd": "# IIS 관리자 → 사이트 선택 → HTTP 응답 헤더 → 추가\n\n"
                       "# 또는 web.config 파일 수정 (<system.webServer> 안에 추가):\n"
                       "<httpProtocol>\n"
                       "  <customHeaders>\n"
                       "    <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n"
                       "    <add name=\"X-Frame-Options\" value=\"DENY\" />\n"
                       "    <add name=\"X-XSS-Protection\" value=\"1; mode=block\" />\n"
                       "    <add name=\"Strict-Transport-Security\" value=\"max-age=31536000; includeSubDomains\" />\n"
                       "    <add name=\"Referrer-Policy\" value=\"strict-origin-when-cross-origin\" />\n"
                       "  </customHeaders>\n"
                       "  <redirectHeaders>\n"
                       "    <add name=\"X-Content-Type-Options\" value=\"nosniff\" />\n"
                       "  </redirectHeaders>\n"
                       "</httpProtocol>\n\n"
                       "# 서버 버전 정보 숨기기 (web.config)\n"
                       "<security><requestFiltering removeServerHeader=\"true\" /></security>",
                "note": "web.config 수정 후 IIS 재시작 불필요 — 자동 즉시 적용"
            },
            {
                "no": 3,
                "title": "보안 헤더 적용 — Apache",
                "cmd": "# mod_headers 활성화 확인\n"
                       "a2enmod headers\n\n"
                       "# /etc/apache2/conf-available/security-headers.conf 생성\n"
                       "Header always set X-Content-Type-Options \"nosniff\"\n"
                       "Header always set X-Frame-Options \"DENY\"\n"
                       "Header always set X-XSS-Protection \"1; mode=block\"\n"
                       "Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains\"\n"
                       "Header always set Referrer-Policy \"strict-origin-when-cross-origin\"\n"
                       "ServerTokens Prod\n"
                       "ServerSignature Off\n\n"
                       "# 활성화 및 적용\n"
                       "a2enconf security-headers\n"
                       "apachectl configtest && systemctl reload apache2",
                "note": "ServerTokens Prod: Apache 버전 정보 숨김. ServerSignature Off: 에러 페이지 서버 정보 제거"
            },
            {
                "no": 4,
                "title": "조치 완료 검증",
                "cmd": "# curl로 헤더 확인 (Linux/WSL)\n"
                       "curl -I https://yourdomain.com\n\n"
                       "# PowerShell로 헤더 확인 (Windows)\n"
                       "$r = Invoke-WebRequest -Uri 'https://yourdomain.com' -Method Head\n"
                       "$r.Headers\n\n"
                       "# 아래 헤더가 응답에 포함되어 있으면 정상:\n"
                       "# x-content-type-options: nosniff\n"
                       "# x-frame-options: DENY\n"
                       "# x-xss-protection: 1; mode=block\n"
                       "# strict-transport-security: max-age=...\n\n"
                       "# 온라인 검증 도구\n"
                       "# https://securityheaders.com — 사이트 주소 입력 후 A 이상 확인",
                "note": "securityheaders.com에서 A+ 등급 목표. 금감원 전자금융 점검 시 헤더 누락은 취약점으로 지적됨"
            }
        ]
    },

    "db": {
        "title": "데이터베이스 보안 취약점 조치",
        "risk": "DB 직접 접근, 기본 계정 악용으로 개인정보·금융정보 유출 위험. 금융감독원 IT 검사 주요 지적 항목",
        "steps": [
            {
                "no": 1,
                "title": "DB 포트 방화벽 차단 (외부 접근 차단)",
                "cmd": "# [Windows — MySQL 3306 차단]\n"
                       "netsh advfirewall firewall add rule name=\"Block_MySQL_External\" dir=in action=block protocol=TCP localport=3306\n"
                       "# 애플리케이션 서버만 허용\n"
                       "netsh advfirewall firewall add rule name=\"Allow_MySQL_AppSrv\" dir=in action=allow protocol=TCP localport=3306 remoteip=192.168.1.10\n\n"
                       "# [Linux — iptables]\n"
                       "# 전체 차단\n"
                       "iptables -A INPUT -p tcp --dport 3306 -j DROP\n"
                       "# 애플리케이션 서버만 허용 (차단 앞에 추가)\n"
                       "iptables -I INPUT -p tcp --dport 3306 -s 192.168.1.10 -j ACCEPT\n"
                       "service iptables save\n\n"
                       "# [Linux — firewalld]\n"
                       "firewall-cmd --permanent --remove-service=mysql\n"
                       "firewall-cmd --permanent --add-rich-rule='rule family=ipv4 source address=192.168.1.10 port port=3306 protocol=tcp accept'\n"
                       "firewall-cmd --reload",
                "note": "DB는 절대 외부 인터넷에서 직접 접근 불가해야 함. 반드시 애플리케이션 서버 경유"
            },
            {
                "no": 2,
                "title": "기본 계정 비밀번호 변경 및 원격 접속 차단",
                "cmd": "# [MySQL] root 계정 비밀번호 변경 및 원격 접속 차단\n"
                       "mysql -u root -p\n\n"
                       "-- root 원격 접속 계정 삭제\n"
                       "DELETE FROM mysql.user WHERE User='root' AND Host != 'localhost';\n\n"
                       "-- root 비밀번호 변경 (MySQL 5.7+)\n"
                       "ALTER USER 'root'@'localhost' IDENTIFIED BY 'C0mplex!P@ssw0rd';\n"
                       "FLUSH PRIVILEGES;\n\n"
                       "-- anonymous 계정 삭제\n"
                       "DELETE FROM mysql.user WHERE User='';\n"
                       "FLUSH PRIVILEGES;\n\n"
                       "-- test 데이터베이스 삭제\n"
                       "DROP DATABASE IF EXISTS test;\n\n"
                       "-- 현재 계정 목록 확인\n"
                       "SELECT User, Host, authentication_string FROM mysql.user;",
                "note": "비밀번호 복잡도: 대문자+소문자+숫자+특수문자 12자 이상. 금융권 3개월 주기 변경 권장"
            },
            {
                "no": 3,
                "title": "최소 권한 원칙 적용 — 애플리케이션 전용 계정 생성",
                "cmd": "# [MySQL] 애플리케이션 전용 계정 생성 (최소 권한)\n"
                       "mysql -u root -p\n\n"
                       "-- 애플리케이션 전용 계정 생성 (localhost만 허용)\n"
                       "CREATE USER 'appuser'@'192.168.1.10' IDENTIFIED BY 'AppUser!P@ss2024';\n\n"
                       "-- 필요한 권한만 부여 (SELECT, INSERT, UPDATE, DELETE만)\n"
                       "GRANT SELECT, INSERT, UPDATE, DELETE ON appdb.* TO 'appuser'@'192.168.1.10';\n"
                       "FLUSH PRIVILEGES;\n\n"
                       "-- 부여된 권한 확인\n"
                       "SHOW GRANTS FOR 'appuser'@'192.168.1.10';\n\n"
                       "-- [Oracle] 최소 권한 계정\n"
                       "CREATE USER appuser IDENTIFIED BY \"AppUser!P@ss2024\";\n"
                       "GRANT CREATE SESSION TO appuser;\n"
                       "GRANT SELECT, INSERT, UPDATE, DELETE ON appschema.* TO appuser;",
                "note": "애플리케이션 계정에 DROP, CREATE, GRANT 권한 절대 금지. DBA 권한 계정은 관리용으로만 분리"
            },
            {
                "no": 4,
                "title": "DB 감사 로그 활성화",
                "cmd": "# [MySQL] 일반 쿼리 로그 및 슬로우 쿼리 로그 활성화\n"
                       "# /etc/mysql/my.cnf 또는 /etc/my.cnf 에 추가:\n"
                       "[mysqld]\n"
                       "general_log = 1\n"
                       "general_log_file = /var/log/mysql/general.log\n"
                       "slow_query_log = 1\n"
                       "slow_query_log_file = /var/log/mysql/slow.log\n"
                       "long_query_time = 2\n\n"
                       "# 적용 (재시작 없이)\n"
                       "mysql -u root -p -e \"SET GLOBAL general_log = 'ON';\"\n\n"
                       "# [Oracle] 감사 설정\n"
                       "-- sys 계정으로 실행\n"
                       "AUDIT ALL BY ACCESS;\n"
                       "AUDIT SELECT TABLE BY ACCESS;\n"
                       "AUDIT CREATE SESSION BY ACCESS;\n\n"
                       "# [MSSQL] 감사 활성화\n"
                       "-- SQL Server Management Studio → 보안 → 감사 → 새 감사",
                "note": "감사 로그는 90일 이상 보관 권장 (금융보안원 가이드). 로그 파일 주기적 백업 필수"
            }
        ]
    },

    "ssh": {
        "title": "SSH 보안 취약점 조치",
        "risk": "루트 직접 로그인 허용, 비밀번호 인증 시 무차별 대입(Brute Force) 공격으로 서버 장악 위험",
        "steps": [
            {
                "no": 1,
                "title": "SSH 설정 파일 강화 (/etc/ssh/sshd_config)",
                "cmd": "# 현재 설정 백업\n"
                       "sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak.$(date +%Y%m%d)\n\n"
                       "# /etc/ssh/sshd_config 수정 (sudo vi 또는 sudo nano)\n"
                       "# 아래 항목 변경/추가:\n\n"
                       "Port 2222                          # 기본 22에서 변경\n"
                       "PermitRootLogin no                 # root 직접 로그인 차단\n"
                       "PasswordAuthentication no          # 비밀번호 인증 비활성화\n"
                       "PubkeyAuthentication yes           # 키 기반 인증 활성화\n"
                       "MaxAuthTries 3                     # 최대 인증 시도 횟수\n"
                       "LoginGraceTime 30                  # 로그인 대기 시간(초)\n"
                       "ClientAliveInterval 300            # 비활성 세션 타임아웃\n"
                       "ClientAliveCountMax 2\n"
                       "AllowUsers <허용할계정명>            # 특정 계정만 SSH 허용\n"
                       "X11Forwarding no                   # X11 포워딩 차단\n"
                       "AllowTcpForwarding no              # TCP 포워딩 차단\n\n"
                       "# 설정 확인 및 재시작\n"
                       "sudo sshd -t                       # 문법 확인 (오류 없으면 정상)\n"
                       "sudo systemctl restart sshd",
                "note": "⚠ 중요: 재시작 전 반드시 새 터미널에서 새 포트(2222)로 접속 테스트 후 기존 세션 종료"
            },
            {
                "no": 2,
                "title": "SSH 키 기반 인증 설정",
                "cmd": "# [클라이언트 — Windows PowerShell]\n"
                       "# RSA 4096bit 키 생성\n"
                       "ssh-keygen -t rsa -b 4096 -C \"admin@company.com\" -f $env:USERPROFILE\\.ssh\\id_rsa_server\n\n"
                       "# 공개키 서버에 복사 (서버 주소와 포트 변경)\n"
                       "type $env:USERPROFILE\\.ssh\\id_rsa_server.pub | ssh admin@192.168.1.100 -p 2222 \"mkdir -p ~/.ssh && cat >> ~/.ssh/authorized_keys\"\n\n"
                       "# [서버 — Linux] authorized_keys 권한 설정\n"
                       "chmod 700 ~/.ssh\n"
                       "chmod 600 ~/.ssh/authorized_keys\n"
                       "chown -R $(whoami) ~/.ssh\n\n"
                       "# [클라이언트 — Linux/Mac]\n"
                       "ssh-keygen -t ed25519 -C 'admin@company'\n"
                       "ssh-copy-id -i ~/.ssh/id_ed25519.pub -p 2222 admin@192.168.1.100",
                "note": "ed25519 알고리즘이 RSA보다 더 안전하고 빠름. 키 파일은 외부 유출 절대 금지"
            },
            {
                "no": 3,
                "title": "Fail2Ban 설치 — 무차별 대입 공격 자동 차단",
                "cmd": "# [Ubuntu/Debian]\n"
                       "sudo apt-get update && sudo apt-get install -y fail2ban\n\n"
                       "# [CentOS/RHEL]\n"
                       "sudo yum install -y epel-release && sudo yum install -y fail2ban\n\n"
                       "# 설정 파일 생성 (원본 덮어쓰기 방지)\n"
                       "sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local\n"
                       "sudo vi /etc/fail2ban/jail.local\n\n"
                       "# [sshd] 섹션 수정:\n"
                       "[sshd]\n"
                       "enabled  = true\n"
                       "port     = 2222\n"
                       "filter   = sshd\n"
                       "logpath  = /var/log/auth.log\n"
                       "maxretry = 3\n"
                       "bantime  = 3600\n"
                       "findtime = 600\n\n"
                       "# 시작 및 자동 실행 등록\n"
                       "sudo systemctl enable fail2ban\n"
                       "sudo systemctl start fail2ban",
                "note": "maxretry=3: 10분 내 3회 실패 시 1시간 차단. 차단된 IP 확인: sudo fail2ban-client status sshd"
            },
            {
                "no": 4,
                "title": "방화벽 SSH 포트 접근 제한 및 조치 검증",
                "cmd": "# [firewalld] 기존 22 차단, 새 포트 허용\n"
                       "sudo firewall-cmd --permanent --remove-service=ssh\n"
                       "sudo firewall-cmd --permanent --add-port=2222/tcp\n"
                       "sudo firewall-cmd --reload\n\n"
                       "# [iptables]\n"
                       "sudo iptables -A INPUT -p tcp --dport 2222 -s 192.168.1.0/24 -j ACCEPT\n"
                       "sudo iptables -A INPUT -p tcp --dport 2222 -j DROP\n"
                       "sudo iptables -A INPUT -p tcp --dport 22 -j DROP\n"
                       "sudo service iptables save\n\n"
                       "# 조치 검증\n"
                       "# root 직접 로그인 차단 확인 (실패해야 정상)\n"
                       "ssh root@192.168.1.100 -p 2222\n\n"
                       "# 비밀번호 인증 차단 확인 (Permission denied 출력되면 정상)\n"
                       "ssh -o PreferredAuthentications=password admin@192.168.1.100 -p 2222\n\n"
                       "# Fail2Ban 동작 확인\n"
                       "sudo fail2ban-client status sshd\n"
                       "sudo tail -f /var/log/fail2ban.log",
                "note": "조치 완료 후 반드시 키 인증으로 접속 성공 확인. 비밀번호 인증 비활성화 전 키 등록 확인 필수"
            }
        ]
    },

    "port": {
        "title": "불필요 포트/서비스 개방 취약점 조치",
        "risk": "불필요한 포트 개방은 공격 표면(Attack Surface) 확대. 알려지지 않은 서비스의 취약점 악용 경로",
        "steps": [
            {
                "no": 1,
                "title": "현재 개방된 포트 전체 목록 확인",
                "cmd": "# [Windows] 관리자 CMD 또는 PowerShell\n"
                       "# 열려있는 포트와 연결된 프로세스 확인\n"
                       "netstat -ano | findstr LISTENING\n\n"
                       "# 특정 포트의 프로세스 확인 (예: PID 1234)\n"
                       "tasklist | findstr 1234\n\n"
                       "# PowerShell로 더 상세한 정보\n"
                       "Get-NetTCPConnection -State Listen | Select LocalAddress, LocalPort, OwningProcess | Sort LocalPort\n\n"
                       "# [Linux]\n"
                       "sudo ss -tlnp          # TCP 리스닝 포트 + 프로세스\n"
                       "sudo netstat -tlnp     # 구버전 호환\n"
                       "sudo lsof -i -P -n | grep LISTEN",
                "note": "업무상 불필요한 포트(FTP 21, Telnet 23, SNMP 161 등)는 즉시 차단 대상"
            },
            {
                "no": 2,
                "title": "불필요 서비스 중지 및 비활성화",
                "cmd": "# [Windows] 서비스 중지\n"
                       "# 예: Telnet 서비스 중지\n"
                       "net stop Telnet\n"
                       "sc config Telnet start= disabled\n\n"
                       "# 예: FTP Publishing Service 중지\n"
                       "net stop FTPSVC\n"
                       "sc config FTPSVC start= disabled\n\n"
                       "# 서비스 상태 확인\n"
                       "sc query Telnet\n"
                       "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name, DisplayName\n\n"
                       "# [Linux] systemd 서비스 중지\n"
                       "sudo systemctl stop telnet.socket\n"
                       "sudo systemctl disable telnet.socket\n"
                       "sudo systemctl stop vsftpd\n"
                       "sudo systemctl disable vsftpd",
                "note": "서비스 중지 전 해당 서비스 사용 여부 업무팀과 확인 필수. 운영 중단 위험"
            },
            {
                "no": 3,
                "title": "방화벽에서 불필요 포트 차단",
                "cmd": "# [Windows — 여러 포트 일괄 차단]\n"
                       "# Telnet(23), FTP(21), SNMP(161), Rlogin(513) 차단\n"
                       "for %p in (21 23 161 513) do netsh advfirewall firewall add rule name=\"Block_Port_%p\" dir=in action=block protocol=TCP localport=%p\n\n"
                       "# [Linux — firewalld]\n"
                       "sudo firewall-cmd --permanent --add-rich-rule='rule port port=23 protocol=tcp drop'\n"
                       "sudo firewall-cmd --permanent --add-rich-rule='rule port port=21 protocol=tcp drop'\n"
                       "sudo firewall-cmd --reload\n\n"
                       "# [Linux — iptables 일괄 차단]\n"
                       "for port in 21 23 161 513; do\n"
                       "  sudo iptables -A INPUT -p tcp --dport $port -j DROP\n"
                       "done\n"
                       "sudo service iptables save",
                "note": "UDP 포트도 확인 필요. SNMP는 UDP 161/162 차단. 차단 규칙 추가 후 업무 영향도 모니터링"
            },
            {
                "no": 4,
                "title": "조치 완료 검증 및 정기 점검 등록",
                "cmd": "# [Windows] 차단 후 포트 재확인\n"
                       "netstat -ano | findstr LISTENING\n"
                       "# 차단한 포트가 목록에서 사라지면 정상\n\n"
                       "# [Linux] 포트 스캔으로 검증\n"
                       "# nmap이 설치된 경우 (동일 네트워크 내 다른 서버에서 실행)\n"
                       "nmap -sV -p 1-1024 192.168.1.100\n\n"
                       "# 또는 nc(netcat)으로 특정 포트 연결 테스트\n"
                       "nc -zv 192.168.1.100 23    # 연결 거부(refused)되면 정상 차단\n"
                       "nc -zv 192.168.1.100 21    # 연결 거부(refused)되면 정상 차단\n\n"
                       "# 윈도우 PowerShell로 포트 테스트\n"
                       "Test-NetConnection -ComputerName 192.168.1.100 -Port 23\n"
                       "# TcpTestSucceeded : False 이면 차단 완료",
                "note": "월 1회 포트 스캔 정기 점검 권장. 변경관리 시스템에 방화벽 정책 변경 이력 기록"
            }
        ]
    },

    "default": {
        "title": "보안 취약점 조치 가이드",
        "risk": "보안 취약점 방치 시 내부 시스템 침해 및 개인정보 유출 위험",
        "steps": [
            {
                "no": 1,
                "title": "취약점 상세 정보 확인",
                "cmd": "# CVE 번호로 상세 정보 조회\n"
                       "# NVD 공식 사이트: https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX\n\n"
                       "# KISA 보호나라 취약점 정보\n"
                       "# https://www.krcert.or.kr/data/vulnView.do\n\n"
                       "# 영향받는 버전 확인\n"
                       "# [Windows] winver 실행 → 버전 확인\n"
                       "winver\n\n"
                       "# [Linux] OS 버전 확인\n"
                       "cat /etc/os-release\n"
                       "uname -a\n\n"
                       "# 설치된 소프트웨어 버전 확인\n"
                       "# [Windows] 프로그램 추가/제거 목록\n"
                       "Get-WmiObject -Class Win32_Product | Select Name, Version | Sort Name",
                "note": "취약점 CVE 번호 확인 후 공식 패치 여부를 반드시 벤더사 사이트에서 확인"
            },
            {
                "no": 2,
                "title": "운영체제 및 소프트웨어 패치 적용",
                "cmd": "# [Windows] Windows Update 실행\n"
                       "# 제어판 → Windows Update → 업데이트 확인 → 모두 설치\n\n"
                       "# PowerShell로 설치된 업데이트 목록 확인\n"
                       "Get-HotFix | Sort InstalledOn -Descending | Select HotFixID, InstalledOn | Select -First 20\n\n"
                       "# [Ubuntu/Debian] 전체 업데이트\n"
                       "sudo apt-get update\n"
                       "sudo apt-get upgrade -y\n"
                       "sudo apt-get dist-upgrade -y\n\n"
                       "# [CentOS/RHEL] 전체 업데이트\n"
                       "sudo yum update -y\n"
                       "# 또는\n"
                       "sudo dnf update -y\n\n"
                       "# 보안 업데이트만 적용\n"
                       "sudo yum update --security -y",
                "note": "패치 적용 전 스냅샷/백업 필수. 운영 서버는 검증 서버에서 먼저 테스트 후 적용"
            },
            {
                "no": 3,
                "title": "불필요 기능 비활성화 및 설정 강화",
                "cmd": "# [Windows] 불필요 서비스 확인 및 중지\n"
                       "# 실행 중인 서비스 전체 목록\n"
                       "Get-Service | Where-Object {$_.Status -eq 'Running'} | Select Name, DisplayName\n\n"
                       "# 불필요 서비스 중지 예시 (Telnet)\n"
                       "Stop-Service -Name Telnet -Force\n"
                       "Set-Service -Name Telnet -StartupType Disabled\n\n"
                       "# [Linux] 불필요 서비스 비활성화\n"
                       "sudo systemctl list-units --type=service --state=running\n"
                       "sudo systemctl disable <서비스명>\n"
                       "sudo systemctl stop <서비스명>\n\n"
                       "# 자동 시작 서비스 목록 확인\n"
                       "sudo systemctl list-unit-files --type=service | grep enabled",
                "note": "공격 표면 최소화: 사용하지 않는 서비스는 모두 중지. 각 서비스의 업무 필요성 확인 후 결정"
            },
            {
                "no": 4,
                "title": "조치 완료 확인 및 재점검 등록",
                "cmd": "# 변경 사항 기록 (변경관리 시스템 등록)\n"
                       "# - 변경 일시\n"
                       "# - 변경 내용 (패치 번호, 설정 변경 항목)\n"
                       "# - 변경 담당자\n"
                       "# - 변경 전/후 스크린샷\n\n"
                       "# [Windows] 시스템 이벤트 로그 확인\n"
                       "Get-EventLog -LogName System -Newest 20 | Select TimeGenerated, EntryType, Source, Message\n\n"
                       "# [Linux] 시스템 로그 확인\n"
                       "sudo tail -50 /var/log/syslog\n"
                       "sudo tail -50 /var/log/messages\n\n"
                       "# 조치 후 SecurityScanKit 재점검 실행\n"
                       "# → 점검 메뉴 → 해당 자산 선택 → 점검 실행\n"
                       "# → 취약점이 사라지면 조치 완료",
                "note": "조치 완료 후 반드시 재점검을 통해 취약점이 해소되었는지 확인. 조치 완료 체크는 재점검 결과 기반"
            }
        ]
    }
}


def get_guide(finding: dict) -> dict:
    """취약점 정보에서 적합한 조치 가이드 선택"""
    title   = (finding.get("title","") or "").lower()
    vuln_id = (finding.get("vuln_id","") or "").lower()
    desc    = (finding.get("description","") or "").lower()
    scan_t  = (finding.get("scan_type","") or "").lower()
    text    = f"{title} {vuln_id} {desc}"

    if any(k in text for k in ["smb","445","139","ms17","eternalblue","wannacry"]):
        g = GUIDES["smb"]
    elif any(k in text for k in ["rdp","3389","원격 데스크","bluekeep","remote desktop"]):
        g = GUIDES["rdp"]
    elif any(k in text for k in ["ssl","tls","인증서","certificate","https"]) or scan_t=="ssl":
        g = GUIDES["ssl"]
    elif any(k in text for k in ["http","header","xss","csrf","클릭재킹","보안헤더","clickjack"]) or scan_t=="web":
        g = GUIDES["http"]
    elif any(k in text for k in ["db","database","mysql","oracle","mssql","3306","1521","sql injection"]) or scan_t=="db":
        g = GUIDES["db"]
    elif any(k in text for k in ["ssh","openssh"]):
        g = GUIDES["ssh"]
    elif scan_t=="port" or any(k in text for k in ["포트","port","서비스 개방","불필요"]):
        g = GUIDES["port"]
    else:
        g = GUIDES["default"]

    import copy
    g = copy.deepcopy(g)

    # recommendation 필드가 있으면 첫 스텝 노트에 반영
    rec = (finding.get("recommendation","") or "").strip()
    if rec:
        first = g["steps"][0]
        first["note"] = f"📌 점검 권고사항: {rec[:180]}"

    return g


def build_remediation_html(finding: dict) -> str:
    """단계별 조치 HTML 블록 생성"""
    g = get_guide(finding)
    SEV_COLOR = {"critical":"#B71C1C","high":"#E65100","medium":"#F57F17","low":"#2E7D32"}
    SEV_LABEL = {"critical":"긴급","high":"고위험","medium":"중위험","low":"저위험"}
    sev   = finding.get("severity","medium")
    color = SEV_COLOR.get(sev,"#546E7A")
    label = SEV_LABEL.get(sev, sev)

    steps_html = ""
    for s in g["steps"]:
        cmd_escaped = (s["cmd"]
            .replace("&","&amp;")
            .replace("<","&lt;")
            .replace(">","&gt;")
            .replace('"',"&quot;")
            .replace("\n","<br>")
        )
        steps_html += f"""
        <div style="margin-bottom:16px">
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
            <div style="width:24px;height:24px;border-radius:50%;background:{color};color:#fff;
              font-size:12px;font-weight:700;display:flex;align-items:center;justify-content:center;
              flex-shrink:0;font-family:Arial">{s['no']}</div>
            <div style="font-size:13px;font-weight:700;color:#212121;font-family:맑은 고딕,Arial">{s['title']}</div>
          </div>
          <div style="background:#1a2332;border-radius:6px;padding:12px 16px;margin-bottom:8px;margin-left:32px;
            border-left:3px solid {color}">
            <code style="font-size:11px;color:#a8d1f5;line-height:1.9;white-space:pre-wrap;
              display:block;font-family:'Courier New',Consolas,monospace">{cmd_escaped}</code>
          </div>
          <div style="font-size:11px;color:#546E7A;margin-left:32px;padding:6px 10px;
            background:#F8FAFC;border-left:3px solid #90CAF9;border-radius:0 4px 4px 0;
            font-family:맑은 고딕,Arial;line-height:1.6">
            💡 {s['note']}
          </div>
        </div>"""

    desc_text = (finding.get("description","") or "")[:300]

    return f"""
    <div style="margin-bottom:24px;border:1px solid #E0E0E0;border-left:5px solid {color};
      border-radius:0 8px 8px 0;overflow:hidden">
      <!-- 취약점 헤더 -->
      <div style="background:{'#FFF5F5' if sev=='critical' else '#FFF8F0' if sev=='high' else '#FFFDE7' if sev=='medium' else '#F1F8E9'};
        padding:14px 18px;border-bottom:1px solid #E0E0E0">
        <div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">
          <span style="font-size:10px;font-weight:700;padding:2px 8px;border-radius:4px;
            background:{color};color:#fff;font-family:Arial">{label}</span>
          <span style="font-size:11px;color:#546E7A;font-family:맑은 고딕,Arial">
            자산: {finding.get('asset_name','')} ({finding.get('asset_ip','')})
          </span>
        </div>
        <div style="font-size:15px;font-weight:700;color:#0D1B2A;margin-bottom:4px;
          font-family:맑은 고딕,Arial">{finding.get('title','')}</div>
        <div style="font-size:12px;color:#D32F2F;font-weight:600;margin-bottom:6px;
          font-family:맑은 고딕,Arial">⚠ 위험: {g['risk']}</div>
        <div style="font-size:12px;color:#424242;padding:8px 10px;background:rgba(255,255,255,.7);
          border-radius:4px;font-family:맑은 고딕,Arial;line-height:1.7">
          <strong>현상:</strong> {desc_text}
        </div>
      </div>
      <!-- 조치 절차 -->
      <div style="padding:16px 18px;background:#FAFAFA">
        <div style="font-size:13px;font-weight:700;color:#0D1B2A;margin-bottom:14px;
          padding-bottom:8px;border-bottom:1px solid #E0E0E0;font-family:맑은 고딕,Arial">
          🔧 단계별 조치 절차 — {g['title']}
        </div>
        {steps_html}
      </div>
    </div>"""
