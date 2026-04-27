"""
웹 취약점 스캐너
aiohttp 없을 때 urllib 폴백 자동 적용
"""
import asyncio
import ssl
import json
from typing import List
from urllib.parse import urljoin

# aiohttp 선택적 임포트
try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

SECURITY_HEADERS = {
    "Strict-Transport-Security": {"severity":"high",  "desc":"HSTS 미설정 — HTTP 다운그레이드 공격 가능", "rec":"max-age=31536000; includeSubDomains 설정"},
    "X-Frame-Options":           {"severity":"medium","desc":"클릭재킹 방어 헤더 미설정",                 "rec":"DENY 또는 SAMEORIGIN 설정"},
    "X-Content-Type-Options":    {"severity":"medium","desc":"MIME 타입 스니핑 방어 헤더 미설정",         "rec":"nosniff 설정"},
    "Content-Security-Policy":   {"severity":"medium","desc":"CSP 미설정 — XSS 방어 정책 없음",          "rec":"적절한 CSP 정책 수립 및 적용"},
    "X-XSS-Protection":          {"severity":"low",   "desc":"XSS 필터링 헤더 미설정",                   "rec":"1; mode=block 설정"},
    "Referrer-Policy":           {"severity":"low",   "desc":"Referrer 정책 미설정",                     "rec":"strict-origin-when-cross-origin 설정"},
}

INFO_LEAK_HEADERS = ["Server","X-Powered-By","X-AspNet-Version","X-Generator"]

SENSITIVE_PATHS = [
    "/admin","/administrator","/manage","/console",
    "/phpinfo.php","/.env","/.git/config","/web.config",
    "/backup","/db.sql","/robots.txt","/.htaccess",
    "/api/swagger","/swagger-ui.html","/actuator","/actuator/env",
    "/server-status","/_admin","/login","/wp-admin",
]

# ── SQL Injection 탐지 페이로드 (에러 기반) ───────────────────────
SQL_PAYLOADS = [
    ("'",             "WEB-SQLI-BASIC", "SQL Injection 취약점 — 따옴표 에러 유발"),
    ("' OR '1'='1",   "WEB-SQLI-OR",   "SQL Injection 취약점 — OR 1=1 조건 우회"),
    ("1 AND 1=CONVERT(int,@@version)--", "WEB-SQLI-VER", "SQL Injection 취약점 — DB 버전 추출 시도"),
]
SQL_ERROR_SIGNS = [
    "sql syntax","mysql_fetch","ora-0","pg_query","sqlite3",
    "unclosed quotation","syntax error","sqlstate","jdbc",
    "you have an error in your sql","warning: mysql",
    "microsoft ole db","odbc sql server","invalid query",
    "supplied argument is not a valid mysql",
]

# ── XSS 탐지 페이로드 (반사형) ────────────────────────────────────
XSS_PAYLOAD = "<ssk-xss-test>alert(1)</ssk-xss-test>"

# ── Command Injection 탐지 페이로드 ──────────────────────────────
CMD_PAYLOADS = [
    (";id",          "WEB-CMDI-ID",  "Command Injection 취약점 — id 명령어 삽입"),
    ("| whoami",     "WEB-CMDI-WHO", "Command Injection 취약점 — whoami 명령어 삽입"),
]
CMD_SIGNS = ["uid=0","root:","www-data","apache","uid=("]

# ── Path Traversal 탐지 페이로드 ─────────────────────────────────
TRAVERSAL_PAYLOADS = [
    ("/../../../etc/passwd",       "WEB-TRAV-LNX", "Path Traversal — /etc/passwd 접근 시도"),
    ("\\..\\..\\windows\\win.ini", "WEB-TRAV-WIN", "Path Traversal — win.ini 접근 시도"),
]
TRAVERSAL_SIGNS = ["root:x:","daemon:","[extensions]","for 16-bit"]

class WebScanner:
    def __init__(self, target_ip: str, http_port: int = 80, https_port: int = 443):
        self.target_ip  = target_ip
        self.http_url   = f"http://{target_ip}:{http_port}"
        self.https_url  = f"https://{target_ip}:{https_port}"
        self.vulns: List[dict] = []

    async def run(self) -> dict:
        result = {
            "scan_type": "web_scan",
            "target": self.target_ip,
            "vulnerabilities": [],
            "scanner": "aiohttp" if HAS_AIOHTTP else "urllib",
        }
        if HAS_AIOHTTP:
            await self._scan_aiohttp()
        else:
            await self._scan_urllib()

        result["vulnerabilities"] = self.vulns
        return result

    # ── aiohttp 버전 ────────────────────────────────────────────
    async def _scan_aiohttp(self):
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=10, connect=5)
        async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
            await asyncio.gather(
                self._check_headers_aiohttp(session),
                self._check_redirect_aiohttp(session),
                self._check_paths_aiohttp(session),
                self._check_info_leak_aiohttp(session),
                self._check_injection_aiohttp(session),
                return_exceptions=True
            )

    async def _check_headers_aiohttp(self, session):
        for url in [self.https_url, self.http_url]:
            try:
                async with session.get(url, allow_redirects=True) as r:
                    self._analyze_headers(dict(r.headers))
                    return
            except Exception:
                continue

    async def _check_redirect_aiohttp(self, session):
        try:
            async with session.get(self.http_url, allow_redirects=False) as r:
                loc = r.headers.get("Location","")
                if r.status not in (301,302,307,308) or "https" not in loc.lower():
                    self._add_vuln("WEB-HTTP-REDIRECT","HTTP→HTTPS 자동 리다이렉트 미설정","high",
                        "HTTP 접속 시 HTTPS로 전환 안 됨","301 리다이렉트로 HTTPS 강제 설정","ISMS-P 2.7.1")
        except Exception:
            pass

    async def _check_paths_aiohttp(self, session):
        async def chk(path):
            try:
                async with session.get(urljoin(self.https_url, path), allow_redirects=False) as r:
                    if r.status == 200:
                        self._add_vuln(f"WEB-PATH-{abs(hash(path))%9999:04d}",
                            f"민감 경로 노출: {path}","high",
                            f"HTTP 200 응답 ({path})","접근 제어 또는 경로 제거","OWASP A05")
            except Exception:
                pass
        await asyncio.gather(*[chk(p) for p in SENSITIVE_PATHS[:10]], return_exceptions=True)

    async def _check_info_leak_aiohttp(self, session):
        for url in [self.https_url, self.http_url]:
            try:
                async with session.get(url) as r:
                    for h in INFO_LEAK_HEADERS:
                        if h in r.headers:
                            self._add_vuln(f"WEB-INFO-{h[:20]}",
                                f"서버 정보 노출: {h}","low",
                                f"{h}: {r.headers[h]}",
                                f"웹서버 설정에서 {h} 헤더 제거","OWASP Testing Guide")
                    return
            except Exception:
                continue

    async def _check_injection_aiohttp(self, session):
        """SQL Injection / XSS / Command Injection / Path Traversal 탐지"""
        # 탐지 대상 파라미터 후보 URL 수집 — 로그인·검색·쿼리 파라미터가 있을 법한 경로
        candidate_urls = []
        for url_base in [self.https_url, self.http_url]:
            candidate_urls += [
                f"{url_base}/?id=1", f"{url_base}/?q=test",
                f"{url_base}/search?q=test", f"{url_base}/login?user=test",
                f"{url_base}/api/search?keyword=test",
            ]

        # ── SQL Injection (에러 기반) ──
        for base_url in candidate_urls[:3]:
            for payload, vid, title in SQL_PAYLOADS:
                try:
                    test_url = base_url.split("=")[0] + "=" + payload
                    async with session.get(test_url, allow_redirects=True,
                                           timeout=aiohttp.ClientTimeout(total=6)) as r:
                        body = (await r.text()).lower()
                        if any(sig in body for sig in SQL_ERROR_SIGNS):
                            self._add_vuln(vid, title, "critical",
                                f"SQL 에러 메시지 노출 확인 ({test_url}) — DB 구조 및 데이터 탈취 가능",
                                "입력값 파라미터화(Prepared Statement) 적용. ORM 사용. 에러 메시지 숨김",
                                "OWASP A03:2021, 금융보안원 웹 취약점 점검 가이드, ISMS-P 2.7")
                            break
                except Exception:
                    pass

        # ── Reflected XSS ──
        for base_url in candidate_urls[:3]:
            try:
                test_url = base_url.split("=")[0] + "=" + XSS_PAYLOAD
                async with session.get(test_url, allow_redirects=True,
                                       timeout=aiohttp.ClientTimeout(total=6)) as r:
                    body = await r.text()
                    if XSS_PAYLOAD in body:
                        self._add_vuln("WEB-XSS-REFLECT", "Reflected XSS 취약점", "high",
                            f"입력값이 HTML 인코딩 없이 응답에 그대로 반사됨 ({test_url})",
                            "모든 출력값 HTML 인코딩 적용. CSP 헤더 설정",
                            "OWASP A03:2021, 금융보안원 웹 취약점 점검 가이드")
                        break
            except Exception:
                pass

        # ── Path Traversal ──
        for path_payload, vid, title in TRAVERSAL_PAYLOADS:
            for url_base in [self.https_url, self.http_url]:
                try:
                    test_url = f"{url_base}/download?file={path_payload}"
                    async with session.get(test_url, allow_redirects=False,
                                           timeout=aiohttp.ClientTimeout(total=5)) as r:
                        body = (await r.text()).lower()
                        if any(sig in body for sig in TRAVERSAL_SIGNS):
                            self._add_vuln(vid, title, "critical",
                                f"경로 탐색 공격으로 시스템 파일 접근 가능 ({test_url})",
                                "파일 경로 입력값 화이트리스트 검증. 절대 경로 사용 금지",
                                "OWASP A01:2021, 금융보안원 웹 취약점 점검 가이드")
                            break
                except Exception:
                    pass

    # ── urllib 폴백 버전 (aiohttp 없을 때) ──────────────────────
    async def _scan_urllib(self):
        """aiohttp 없을 때 urllib로 대체 — 동기 코드를 executor에서 실행"""
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._scan_urllib_sync)

    def _scan_urllib_sync(self):
        import urllib.request
        import urllib.error

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        for url in [self.https_url, self.http_url]:
            try:
                req = urllib.request.Request(url, headers={"User-Agent":"SecurityScanKit/1.0"})
                with urllib.request.urlopen(req, timeout=8, context=ssl_ctx) as resp:
                    headers = dict(resp.getheaders())
                    self._analyze_headers(headers)
                    # 서버 정보 노출
                    for h in INFO_LEAK_HEADERS:
                        if h in headers:
                            self._add_vuln(f"WEB-INFO-{h[:20]}",
                                f"서버 정보 노출: {h}","low",
                                f"{h}: {headers[h]}",
                                f"웹서버 설정에서 {h} 헤더 제거","OWASP Testing Guide")
                break
            except Exception:
                continue

        # HTTP→HTTPS 리다이렉트 체크
        try:
            req = urllib.request.Request(self.http_url)
            # allow_redirects=False 효과
            import http.client
            parsed = self.http_url.replace("http://","").split(":")
            host = parsed[0]
            port = int(parsed[1]) if len(parsed) > 1 else 80
            conn = http.client.HTTPConnection(host, port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            loc = resp.getheader("Location","")
            if resp.status not in (301,302,307,308) or "https" not in loc.lower():
                self._add_vuln("WEB-HTTP-REDIRECT","HTTP→HTTPS 자동 리다이렉트 미설정","high",
                    "HTTP 접속 시 HTTPS로 전환 안 됨","301 리다이렉트로 HTTPS 강제 설정","ISMS-P 2.7.1")
            conn.close()
        except Exception:
            pass

        # 민감 경로 체크 (일부만)
        for path in SENSITIVE_PATHS[:8]:
            try:
                req = urllib.request.Request(urljoin(self.https_url, path))
                with urllib.request.urlopen(req, timeout=4, context=ssl_ctx) as resp:
                    if resp.status == 200:
                        self._add_vuln(f"WEB-PATH-{abs(hash(path))%9999:04d}",
                            f"민감 경로 노출: {path}","high",
                            f"HTTP 200 응답","접근 제어 또는 경로 제거","OWASP A05")
            except Exception:
                pass

    def _analyze_headers(self, headers: dict):
        # 대소문자 정규화
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for hdr, meta in SECURITY_HEADERS.items():
            if hdr.lower() not in lower_headers:
                self._add_vuln(
                    f"WEB-HDR-{hdr.replace('-','')[:20]}",
                    f"보안 헤더 누락: {hdr}",
                    meta["severity"],
                    meta["desc"],
                    meta["rec"],
                    "OWASP Secure Headers Project"
                )

    def _add_vuln(self, vid, title, severity, desc, rec, ref=""):
        self.vulns.append({
            "id":             vid,
            "title":          title,
            "severity":       severity,
            "description":    desc,
            "recommendation": rec,
            "reference":      ref,
        })
