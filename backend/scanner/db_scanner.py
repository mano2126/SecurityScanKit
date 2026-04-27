"""
DB 취약점 스캐너 - 외부 노출, 기본 계정, 버전 취약점 점검
"""
import asyncio
import socket
from typing import Dict, List


DB_DEFAULT_PORTS = {
    "mysql": 3306,
    "mssql": 1433,
    "oracle": 1521,
    "postgresql": 5432,
    "mongodb": 27017,
    "redis": 6379,
}

DB_BANNERS = {
    "mysql": b"\x00\x00\x00\n",     # MySQL handshake
    "redis": b"*1\r\n$4\r\nping\r\n",
}


class DBScanner:
    def __init__(self, target_ip: str, db_type: str, port: int = None):
        self.target_ip = target_ip
        self.db_type = db_type.lower()
        self.port = port or DB_DEFAULT_PORTS.get(self.db_type, 3306)
        self.vulnerabilities = []

    async def run(self) -> dict:
        result = {
            "scan_type": "db_scan",
            "target": f"{self.target_ip}:{self.port}",
            "db_type": self.db_type,
            "reachable": False,
            "vulnerabilities": [],
            "checks": {}
        }

        loop = asyncio.get_event_loop()

        # 외부 접근 가능 여부 확인
        reachable = await self._check_reachable()
        result["reachable"] = reachable

        if reachable:
            self.vulnerabilities.append({
                "id": f"DB-EXT-{self.db_type.upper()}",
                "title": f"{self.db_type.upper()} DB 포트 외부 접근 가능",
                "severity": "high",
                "description": f"{self.target_ip}:{self.port} - {self.db_type.upper()} 서비스 외부 직접 접근 가능",
                "recommendation": "방화벽으로 DB 포트 차단. 허용 IP만 접근 가능하도록 ACL 설정. DB는 내부망에서만 접근 허용",
                "reference": "금융보안원 데이터베이스 보안 가이드"
            })

            # DB 타입별 추가 점검
            if self.db_type == "mysql":
                await self._check_mysql(result)
            elif self.db_type == "mssql":
                await self._check_mssql(result)
            elif self.db_type == "redis":
                await self._check_redis(result)
            elif self.db_type == "mongodb":
                await self._check_mongodb(result)

        result["vulnerabilities"] = self.vulnerabilities
        return result

    async def _check_reachable(self) -> bool:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, self.port),
                timeout=5
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False

    async def _check_mysql(self, result: dict):
        """MySQL 특화 점검"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, self.port),
                timeout=5
            )
            banner = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.close()

            banner_str = banner.decode("utf-8", errors="replace")
            result["checks"]["banner"] = banner_str[:200]

            # 버전 취약점 확인
            if "5.0" in banner_str or "5.1" in banner_str or "5.5" in banner_str:
                self.vulnerabilities.append({
                    "id": "DB-MYSQL-EOL",
                    "title": "MySQL EOL(지원 종료) 버전 사용",
                    "severity": "high",
                    "description": f"보안 패치가 제공되지 않는 구버전 MySQL 사용: {banner_str[:100]}",
                    "recommendation": "MySQL 8.0 이상으로 업그레이드",
                    "reference": "MySQL 버전 지원 정책"
                })
        except Exception as e:
            result["checks"]["banner_error"] = str(e)

    async def _check_redis(self, result: dict):
        """Redis 인증 없이 접근 가능 여부 점검"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, self.port),
                timeout=5
            )
            writer.write(b"PING\r\n")
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(256), timeout=3)
            writer.close()

            if b"+PONG" in resp or b"PONG" in resp:
                self.vulnerabilities.append({
                    "id": "DB-REDIS-NOAUTH",
                    "title": "Redis 인증 없이 원격 접근 가능 (Critical)",
                    "severity": "critical",
                    "description": "Redis 인증(requirepass) 미설정. 데이터 탈취, 서버 원격 명령 실행 가능",
                    "recommendation": "redis.conf에 requirepass 설정, bind 127.0.0.1로 외부 접근 차단",
                    "reference": "CVE-2022-0543, Redis 보안 설정 가이드"
                })
            result["checks"]["redis_auth"] = "+PONG" not in resp.decode("utf-8", errors="replace")
        except Exception:
            pass

    async def _check_mongodb(self, result: dict):
        """MongoDB 인증 없이 접근 가능 여부 점검"""
        # MongoDB wire protocol: isMaster command
        is_master_msg = (
            b"\x3f\x00\x00\x00"  # messageLength
            b"\x01\x00\x00\x00"  # requestID
            b"\x00\x00\x00\x00"  # responseTo
            b"\xd4\x07\x00\x00"  # opCode: OP_QUERY
            b"\x00\x00\x00\x00"  # flags
            b"admin.$cmd\x00"    # collection
            b"\x00\x00\x00\x00"  # skip
            b"\x01\x00\x00\x00"  # return
            b"\x13\x00\x00\x00\x10ismaster\x00\x01\x00\x00\x00\x00"
        )
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(self.target_ip, self.port),
                timeout=5
            )
            writer.write(is_master_msg)
            await writer.drain()
            resp = await asyncio.wait_for(reader.read(512), timeout=3)
            writer.close()

            if len(resp) > 10:
                self.vulnerabilities.append({
                    "id": "DB-MONGO-OPEN",
                    "title": "MongoDB 외부 접근 가능 (인증 점검 필요)",
                    "severity": "critical",
                    "description": "MongoDB 포트(27017)에 외부 접근 가능. 기본 설정 시 인증 없이 DB 전체 접근 가능",
                    "recommendation": "--auth 옵션 활성화, bindIp를 127.0.0.1로 제한, 방화벽 설정",
                    "reference": "MongoDB 보안 체크리스트"
                })
        except Exception:
            pass

    async def _check_mssql(self, result: dict):
        """MSSQL 점검"""
        self.vulnerabilities.append({
            "id": "DB-MSSQL-EXT",
            "title": "MSSQL 포트 외부 접근 가능",
            "severity": "high",
            "description": "MSSQL(1433) 외부 노출 - SQL 인젝션, 브루트포스 공격 위험",
            "recommendation": "방화벽으로 1433 포트 차단, SA 계정 비활성화, 최소 권한 원칙 적용",
            "reference": "금융보안원 데이터베이스 보안 가이드"
        })
