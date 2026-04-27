"""
네트워크 장비 취약점 스캐너
aiohttp 없을 때 socket 폴백 자동 적용
"""
import asyncio
import socket
from typing import List

try:
    import aiohttp
    HAS_AIOHTTP = True
except ImportError:
    HAS_AIOHTTP = False

NETWORK_MGMT_PORTS = [
    (22,   "SSH 관리"),
    (23,   "Telnet 관리"),
    (80,   "HTTP 웹 관리"),
    (443,  "HTTPS 웹 관리"),
    (161,  "SNMP"),
    (8080, "HTTP 대체"),
    (8443, "HTTPS 대체"),
]

class NetworkScanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.vulns: List[dict] = []

    async def run(self) -> dict:
        result = {
            "scan_type": "network_scan",
            "target": self.target_ip,
            "vulnerabilities": [],
            "open_ports": [],
        }
        await self._check_mgmt_ports(result)
        await self._check_snmp(result)
        if HAS_AIOHTTP:
            await self._check_default_creds_aiohttp(result)
        result["vulnerabilities"] = self.vulns
        return result

    async def _check_mgmt_ports(self, result):
        open_ports = []
        async def chk(port, desc):
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(self.target_ip, port), timeout=3)
                writer.close()
                try: await writer.wait_closed()
                except: pass
                open_ports.append({"port": port, "desc": desc})
                if port == 23:
                    self.vulns.append({"id":f"NET-TELNET-{port}","title":"Telnet 관리 포트 개방",
                        "severity":"critical","description":"평문 통신 자격증명 스니핑 가능",
                        "recommendation":"Telnet 비활성화, SSH v2로 전환","reference":"금융보안원 네트워크 보안 가이드"})
                elif port == 80:
                    self.vulns.append({"id":"NET-HTTP-MGMT","title":"HTTP 평문 관리 인터페이스 개방",
                        "severity":"high","description":"자격증명 탈취 위험",
                        "recommendation":"HTTP 관리 비활성화, HTTPS만 사용","reference":"CIS Controls"})
            except Exception:
                pass
        await asyncio.gather(*[chk(p, d) for p, d in NETWORK_MGMT_PORTS], return_exceptions=True)
        result["open_ports"] = open_ports

    async def _check_snmp(self, result):
        """SNMP Community String 'public' 점검 (UDP)"""
        loop = asyncio.get_event_loop()
        def snmp_check():
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                # SNMPv1 GetRequest community=public
                pkt = (b"\x30\x26\x02\x01\x00\x04\x06public"
                       b"\xa0\x19\x02\x04\x71\x68\x55\x79"
                       b"\x02\x01\x00\x02\x01\x00\x30\x0b"
                       b"\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00")
                sock.sendto(pkt, (self.target_ip, 161))
                data, _ = sock.recvfrom(1024)
                sock.close()
                if data:
                    self.vulns.append({"id":"NET-SNMP-PUBLIC",
                        "title":"SNMP Community String 'public' 허용",
                        "severity":"medium","description":"기본 SNMP Community String 응답 — 네트워크 정보 노출",
                        "recommendation":"SNMPv3 전환, Community String 변경","reference":"금융보안원 네트워크 장비 보안 가이드"})
            except Exception:
                pass
        await loop.run_in_executor(None, snmp_check)

    async def _check_default_creds_aiohttp(self, result):
        """기본 자격증명 점검 (aiohttp 있을 때만)"""
        import ssl
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        conn = aiohttp.TCPConnector(ssl=ssl_ctx)
        timeout = aiohttp.ClientTimeout(total=5)
        creds = [("admin","admin"),("admin",""),("admin","1234")]
        for port, scheme in [(443,"https"),(80,"http"),(8080,"http")]:
            for user, pwd in creds[:2]:
                try:
                    url = f"{scheme}://{self.target_ip}:{port}/login"
                    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as s:
                        async with s.post(url, data={"username":user,"password":pwd},
                                          allow_redirects=False) as r:
                            if r.status in (200,302) and r.status != 401:
                                self.vulns.append({"id":f"NET-DEFCRED-{port}",
                                    "title":f"기본 자격증명 허용 가능 ({user}/{pwd})",
                                    "severity":"critical","description":f"포트 {port} 기본 자격증명 로그인 시도 성공",
                                    "recommendation":"기본 비밀번호 즉시 변경","reference":"OWASP Testing Guide"})
                except Exception:
                    pass
