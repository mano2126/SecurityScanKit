"""
포트 스캐너
Python 3.14 + Windows 호환
- asyncio.create_subprocess_exec 대신 concurrent.futures + subprocess 사용
- nmap 없으면 asyncio socket 폴백
"""
import asyncio
import subprocess
import socket
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, List

try:
    from config_loader import get_config as _get_cfg
    _cfg = _get_cfg()
    _NMAP_EXEC = _cfg.nmap_path or "nmap"
    _TIMEOUT   = _cfg.default_timeout
except Exception:
    _NMAP_EXEC = "nmap"
    _TIMEOUT   = 10

# 금융권 주요 위험 포트
DANGEROUS_PORTS = {
    21:    ("FTP",         "high",     "평문 전송, 익명 접근 가능"),
    22:    ("SSH",         "info",     "브루트포스 위험, 버전 확인 필요"),
    23:    ("Telnet",      "critical", "평문 전송 — 즉시 차단 필요"),
    25:    ("SMTP",        "medium",   "릴레이 설정 확인 필요"),
    53:    ("DNS",         "medium",   "Zone Transfer 설정 확인"),
    80:    ("HTTP",        "medium",   "HTTPS 리다이렉트 여부 확인"),
    110:   ("POP3",        "high",     "평문 메일 전송"),
    135:   ("RPC",         "high",     "Windows RPC — 원격 공격 위험"),
    139:   ("NetBIOS",     "high",     "SMB 취약점 노출 가능"),
    443:   ("HTTPS",       "info",     "SSL/TLS 설정 별도 점검"),
    445:   ("SMB",         "critical", "EternalBlue 등 랜섬웨어 경로"),
    1433:  ("MSSQL",       "high",     "DB 포트 외부 노출 여부 확인"),
    1521:  ("Oracle",      "high",     "DB 포트 외부 노출 여부 확인"),
    3306:  ("MySQL",       "high",     "DB 포트 외부 노출 여부 확인"),
    3389:  ("RDP",         "critical", "원격 데스크탑 — 브루트포스/취약점 위험"),
    5432:  ("PostgreSQL",  "high",     "DB 포트 외부 노출 여부 확인"),
    5900:  ("VNC",         "critical", "원격 접속 평문, 취약한 인증"),
    6379:  ("Redis",       "critical", "인증 없이 원격 접근 가능"),
    8080:  ("HTTP-alt",    "medium",   "관리 콘솔 노출 가능"),
    8443:  ("HTTPS-alt",   "low",      "SSL 설정 점검 필요"),
    27017: ("MongoDB",     "critical", "기본 설정 시 인증 없음"),
}

NMAP_TOP_PORTS = "21,22,23,25,53,80,110,135,139,443,445,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017"

_executor = ThreadPoolExecutor(max_workers=4)


def _check_nmap_sync() -> bool:
    """동기 방식으로 nmap 가용성 확인"""
    try:
        r = subprocess.run(
            [_NMAP_EXEC, "--version"],
            capture_output=True, timeout=5
        )
        return r.returncode == 0
    except Exception:
        return False


def _run_nmap_sync(target_ip: str) -> dict:
    """동기 방식으로 nmap 실행 (ThreadPoolExecutor 에서 호출)"""
    cmd = [
        _NMAP_EXEC, "-sV", "--open",
        "-p", NMAP_TOP_PORTS,
        "-oX", "-",
        target_ip
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=120)
        xml = r.stdout.decode("utf-8", errors="replace")
        return _parse_nmap_xml(xml)
    except subprocess.TimeoutExpired:
        return {"open_ports": [], "error": "nmap timeout"}
    except Exception as e:
        return {"open_ports": [], "error": str(e)}


def _parse_nmap_xml(xml_data: str) -> dict:
    open_ports = []
    try:
        root = ET.fromstring(xml_data)
        for host in root.findall("host"):
            for port in host.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                port_num  = int(port.get("portid", 0))
                service   = port.find("service")
                svc_name  = service.get("name", "unknown")  if service is not None else "unknown"
                svc_ver   = service.get("version", "")      if service is not None else ""
                svc_prod  = service.get("product", "")      if service is not None else ""
                scripts   = {}
                for sc in port.findall("script"):
                    scripts[sc.get("id")] = sc.get("output", "")
                open_ports.append({
                    "port": port_num, "protocol": port.get("protocol","tcp"),
                    "service": svc_name, "product": svc_prod,
                    "version": svc_ver, "scripts": scripts
                })
    except ET.ParseError:
        pass
    return {"open_ports": open_ports}


def _socket_scan_sync(target_ip: str) -> dict:
    """동기 소켓 스캔 - 병렬 처리로 속도 개선"""
    from concurrent.futures import ThreadPoolExecutor, as_completed

    open_ports = []
    ports = [int(p) for p in NMAP_TOP_PORTS.split(",")]

    def check_port(port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            result = sock.connect_ex((target_ip, port))
            sock.close()
            if result == 0:
                known = DANGEROUS_PORTS.get(port, (str(port), "info", ""))
                return {"port": port, "protocol": "tcp",
                        "service": known[0], "product": "", "version": "", "scripts": {}}
        except Exception:
            pass
        return None

    with ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_port, p): p for p in ports}
        for future in as_completed(futures):
            r = future.result()
            if r:
                open_ports.append(r)

    open_ports.sort(key=lambda x: x["port"])
    return {"open_ports": open_ports}


class PortScanner:
    def __init__(self, target_ip: str):
        self.target_ip = target_ip

    async def run(self) -> dict:
        loop = asyncio.get_event_loop()

        # nmap 가용성 확인 (동기, executor)
        nmap_ok = await loop.run_in_executor(_executor, _check_nmap_sync)

        result = {
            "scan_type":      "port_scan",
            "target":         self.target_ip,
            "open_ports":     [],
            "vulnerabilities":[],
            "nmap_available": nmap_ok,
        }

        if nmap_ok:
            scan_result = await loop.run_in_executor(
                _executor, _run_nmap_sync, self.target_ip)
        else:
            scan_result = await loop.run_in_executor(
                _executor, _socket_scan_sync, self.target_ip)

        result["open_ports"] = scan_result.get("open_ports", [])
        result["vulnerabilities"] = self._classify(result["open_ports"])
        return result

    def _classify(self, open_ports: list) -> list:
        vulns = []
        for p in open_ports:
            port_num = p["port"]
            if port_num in DANGEROUS_PORTS:
                name, severity, desc = DANGEROUS_PORTS[port_num]
                vulns.append({
                    "id":             f"PORT-{port_num:05d}",
                    "title":          f"{name} 포트({port_num}) 개방",
                    "severity":       severity,
                    "description":    desc,
                    "recommendation": self._recommend(port_num),
                    "reference":      "금융보안원 취약점 점검 가이드",
                    "port":           port_num,
                    "service":        p.get("service", name),
                    "cvss_score":     self._cvss(severity),
                })
            # nmap script 취약점 추출
            for script_id, output in p.get("scripts", {}).items():
                if any(kw in output.lower() for kw in ["vuln","exploit","vulnerable"]):
                    vulns.append({
                        "id":             f"SCRIPT-{port_num}-{script_id[:15]}",
                        "title":          f"포트 {port_num} — {script_id} 취약점",
                        "severity":       "high",
                        "description":    output[:300],
                        "recommendation": "해당 취약점 패치 적용 또는 서비스 비활성화",
                        "reference":      "CVE 데이터베이스 참조",
                        "port":           port_num,
                        "cvss_score":     7.0,
                    })
        return vulns

    def _cvss(self, severity: str) -> float:
        return {"critical":9.0,"high":7.5,"medium":5.0,"low":2.5,"info":0.0}.get(severity, 0.0)

    def _recommend(self, port: int) -> str:
        recs = {
            23:    "Telnet 서비스 즉시 비활성화, SSH로 전환",
            445:   "SMB 서비스 외부 차단, 최신 보안 패치 적용 (MS17-010)",
            3389:  "RDP NLA 활성화, VPN 뒤에 배치, 포트 변경",
            5900:  "VNC 서비스 비활성화 또는 VPN 뒤에 배치",
            6379:  "Redis 인증(requirepass) 설정, 외부 접근 차단",
            27017: "MongoDB 인증 활성화, bindIp를 127.0.0.1로 제한",
            21:    "FTP 대신 SFTP 사용, 익명 접근 비활성화",
            1433:  "DB 포트 외부 노출 차단, 허용 IP 제한",
            1521:  "DB 포트 외부 노출 차단, 허용 IP 제한",
            3306:  "DB 포트 외부 노출 차단, 허용 IP 제한",
        }
        return recs.get(port, "불필요 시 포트 차단, 서비스 버전 최신화 유지")
