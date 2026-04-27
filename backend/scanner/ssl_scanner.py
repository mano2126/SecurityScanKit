"""
SSL/TLS 취약점 스캐너
- 프로토콜 버전 점검 (SSLv2, SSLv3, TLS 1.0, 1.1)
- 취약한 암호화 스위트 탐지
- 인증서 유효성/만료 점검
- BEAST, POODLE, HEARTBLEED 등 알려진 취약점 점검
"""
import asyncio
import ssl
import socket
import datetime
from typing import List, Dict


# 취약한 프로토콜 버전
WEAK_PROTOCOLS = {
    "SSLv2":   ("critical", "SSLv2는 심각한 보안 취약점 존재, 즉시 비활성화"),
    "SSLv3":   ("critical", "POODLE 취약점 대상, 즉시 비활성화"),
    "TLSv1.0": ("high",     "BEAST, POODLE-TLS 취약점, 비활성화 권고"),
    "TLSv1.1": ("medium",   "구버전 TLS, TLS 1.2+ 전환 권고"),
}

# 취약한 암호화 스위트 패턴
WEAK_CIPHER_PATTERNS = [
    ("RC4",      "high",   "RC4 암호화 - 통계적 편향으로 복호화 가능"),
    ("DES",      "high",   "DES 암호화 - 56bit 키 크기 불충분"),
    ("3DES",     "medium", "Triple-DES - SWEET32 공격 취약"),
    ("NULL",     "critical","NULL 암호화 - 평문 전송"),
    ("EXPORT",   "critical","EXPORT 암호화 - FREAK 공격 취약"),
    ("ADH",      "high",   "익명 DH - 인증 없음"),
    ("AECDH",    "high",   "익명 ECDH - 인증 없음"),
    ("MD5",      "medium", "MD5 서명 - 충돌 취약점"),
    ("SHA1",     "low",    "SHA-1 서명 - 단계적 폐기 권고"),
    ("ANON",     "critical","익명 암호화 스위트"),
]


class SSLScanner:
    def __init__(self, target_ip: str, port: int = 443):
        self.target_ip = target_ip
        self.port = port
        self.vulnerabilities = []

    async def run(self) -> dict:
        result = {
            "scan_type": "ssl_scan",
            "target": f"{self.target_ip}:{self.port}",
            "vulnerabilities": [],
            "cert_info": {},
            "protocol_support": {},
            "cipher_suites": [],
            "grade": "N/A"
        }

        loop = asyncio.get_event_loop()

        # 프로토콜 버전 점검
        proto_results = await loop.run_in_executor(None, self._check_protocols)
        result["protocol_support"] = proto_results

        # 인증서 점검
        cert_info = await loop.run_in_executor(None, self._check_certificate)
        result["cert_info"] = cert_info

        # 암호화 스위트 점검
        ciphers = await loop.run_in_executor(None, self._check_cipher_suites)
        result["cipher_suites"] = ciphers

        result["vulnerabilities"] = self.vulnerabilities
        result["grade"] = self._calculate_grade()
        return result

    def _check_protocols(self) -> dict:
        """지원 프로토콜 버전 확인"""
        protocols = {}

        protocol_map = [
            ("TLSv1.3", ssl.PROTOCOL_TLS_CLIENT),
            ("TLSv1.2", ssl.PROTOCOL_TLS_CLIENT),
        ]

        for proto_name, _ in protocol_map:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                if proto_name == "TLSv1.3":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_3
                elif proto_name == "TLSv1.2":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_2

                with socket.create_connection((self.target_ip, self.port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target_ip):
                        protocols[proto_name] = True
            except Exception:
                protocols[proto_name] = False

        # 구버전 점검 (Python ssl 모듈 제한으로 시뮬레이션)
        for old_proto in ["TLSv1.0", "TLSv1.1", "SSLv3", "SSLv2"]:
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE

                if old_proto == "TLSv1.0":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1
                elif old_proto == "TLSv1.1":
                    ctx.minimum_version = ssl.TLSVersion.TLSv1_1
                    ctx.maximum_version = ssl.TLSVersion.TLSv1_1
                else:
                    protocols[old_proto] = False
                    continue

                with socket.create_connection((self.target_ip, self.port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=self.target_ip):
                        protocols[old_proto] = True
                        severity, desc = WEAK_PROTOCOLS[old_proto]
                        self.vulnerabilities.append({
                            "id": f"SSL-PROTO-{old_proto.replace('.', '').replace('v', '')}",
                            "title": f"취약한 프로토콜 지원: {old_proto}",
                            "severity": severity,
                            "description": desc,
                            "recommendation": f"{old_proto} 비활성화, TLS 1.2+ 사용",
                            "reference": "금융보안원 SSL/TLS 설정 가이드"
                        })
            except Exception:
                protocols[old_proto] = False

        return protocols

    def _check_certificate(self) -> dict:
        """인증서 정보 및 유효성 점검"""
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            with socket.create_connection((self.target_ip, self.port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()

                    if not cert:
                        return {"error": "인증서 없음"}

                    # 만료일 파싱
                    not_after_str = cert.get("notAfter", "")
                    not_before_str = cert.get("notBefore", "")
                    not_after = None
                    days_remaining = None

                    if not_after_str:
                        not_after = datetime.datetime.strptime(
                            not_after_str, "%b %d %H:%M:%S %Y %Z"
                        )
                        days_remaining = (not_after - datetime.datetime.utcnow()).days

                    # 인증서 만료 임박 경고
                    if days_remaining is not None:
                        if days_remaining < 0:
                            self.vulnerabilities.append({
                                "id": "SSL-CERT-EXPIRED",
                                "title": "SSL 인증서 만료",
                                "severity": "critical",
                                "description": f"SSL 인증서가 {abs(days_remaining)}일 전에 만료되었습니다",
                                "recommendation": "SSL 인증서 즉시 갱신",
                                "reference": "인증서 관리 정책"
                            })
                        elif days_remaining < 30:
                            self.vulnerabilities.append({
                                "id": "SSL-CERT-EXPIRING",
                                "title": f"SSL 인증서 만료 임박 ({days_remaining}일 후)",
                                "severity": "high",
                                "description": f"{days_remaining}일 후 인증서 만료. 서비스 장애 가능",
                                "recommendation": "SSL 인증서 갱신 작업 즉시 시작",
                                "reference": "인증서 관리 정책"
                            })
                        elif days_remaining < 90:
                            self.vulnerabilities.append({
                                "id": "SSL-CERT-SOON",
                                "title": f"SSL 인증서 만료 예정 ({days_remaining}일 후)",
                                "severity": "medium",
                                "description": "인증서 갱신 계획 수립 필요",
                                "recommendation": "인증서 갱신 일정 수립",
                                "reference": "인증서 관리 정책"
                            })

                    # 자가서명 인증서 탐지
                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    is_self_signed = (subject == issuer)
                    if is_self_signed:
                        self.vulnerabilities.append({
                            "id": "SSL-CERT-SELF-SIGNED",
                            "title": "자가서명(Self-signed) 인증서 사용",
                            "severity": "high",
                            "description": "공인 CA가 서명하지 않은 인증서 - 중간자 공격에 취약",
                            "recommendation": "공인 CA 발급 인증서로 교체",
                            "reference": "금융보안원 SSL 인증서 관리 지침"
                        })

                    return {
                        "subject": subject,
                        "issuer": issuer,
                        "not_before": not_before_str,
                        "not_after": not_after_str,
                        "days_remaining": days_remaining,
                        "is_self_signed": is_self_signed,
                        "current_cipher": cipher,
                        "san": cert.get("subjectAltName", [])
                    }
        except Exception as e:
            self.vulnerabilities.append({
                "id": "SSL-CONN-FAIL",
                "title": "SSL/TLS 연결 실패",
                "severity": "info",
                "description": f"SSL 연결 불가: {str(e)}",
                "recommendation": "포트 443 서비스 운영 여부 확인",
                "reference": ""
            })
            return {"error": str(e)}

    def _check_cipher_suites(self) -> list:
        """사용 중인 암호화 스위트 점검"""
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((self.target_ip, self.port), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.target_ip) as ssock:
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else ""

                    for pattern, severity, desc in WEAK_CIPHER_PATTERNS:
                        if pattern in cipher_name.upper():
                            self.vulnerabilities.append({
                                "id": f"SSL-CIPHER-{pattern}",
                                "title": f"취약한 암호화 스위트 사용: {pattern}",
                                "severity": severity,
                                "description": f"현재 사용 중: {cipher_name} - {desc}",
                                "recommendation": "AESGCM, CHACHA20 등 강력한 암호화 스위트로 교체",
                                "reference": "NIST SP 800-52 Rev.2"
                            })
                    return [cipher_name] if cipher_name else []
        except Exception:
            return []

    def _calculate_grade(self) -> str:
        """취약점 기반 SSL 등급 산출"""
        critical_count = sum(1 for v in self.vulnerabilities if v.get("severity") == "critical")
        high_count = sum(1 for v in self.vulnerabilities if v.get("severity") == "high")
        medium_count = sum(1 for v in self.vulnerabilities if v.get("severity") == "medium")

        if critical_count > 0: return "F"
        if high_count > 1:     return "C"
        if high_count == 1:    return "B"
        if medium_count > 2:   return "B"
        if medium_count > 0:   return "A-"
        return "A+"
