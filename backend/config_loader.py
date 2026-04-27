"""
config_loader.py
config.json 을 읽어 OS별 설정을 자동 적용하는 핵심 모듈
"""
import json
import os
import sys
import platform
import shutil
from pathlib import Path
from typing import Optional

# ── 프로젝트 루트 ─────────────────────────────────────────────────────
ROOT = Path(__file__).parent.parent          # SecurityScanKit_v3/
CONFIG_PATH = ROOT / "config.json"


def _load_raw() -> dict:
    if not CONFIG_PATH.exists():
        raise FileNotFoundError(f"config.json not found: {CONFIG_PATH}")
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


class AppConfig:
    """config.json 기반 OS-aware 설정 싱글톤"""

    def __init__(self):
        raw = _load_raw()

        # ── OS 결정 ───────────────────────────────────────────────────
        cfg_os = raw.get("os", "auto").lower().strip()
        if cfg_os == "auto":
            self.os = "windows" if platform.system() == "Windows" else "linux"
        elif cfg_os in ("windows", "linux"):
            self.os = cfg_os
        else:
            raise ValueError(f"config.json 'os' must be 'windows' or 'linux', got: {cfg_os!r}")

        self.is_windows = (self.os == "windows")
        self.is_linux   = (self.os == "linux")

        # ── 서버 설정 ─────────────────────────────────────────────────
        srv = raw.get("server", {})
        self.backend_host      = srv.get("backend_host", "0.0.0.0")
        self.backend_port      = int(srv.get("backend_port", 8000))
        self.frontend_port     = int(srv.get("frontend_port", 3000))
        self.auto_open_browser = bool(srv.get("auto_open_browser", True))

        # ── 스캔 설정 ─────────────────────────────────────────────────
        scn = raw.get("scan", {})
        self.default_timeout   = int(scn.get("default_timeout_sec", 10))
        self.max_concurrent    = int(scn.get("max_concurrent_scans", 5))
        self._nmap_path_cfg    = scn.get("nmap_path", "").strip()
        self.report_output_dir = Path(scn.get("report_output_dir", "./reports"))
        if not self.report_output_dir.is_absolute():
            self.report_output_dir = ROOT / self.report_output_dir

        # ── AI 설정 ───────────────────────────────────────────────────
        ai = raw.get("ai", {})
        self.ai_enabled = bool(ai.get("enabled", True))
        self.ai_model   = ai.get("model", "claude-sonnet-4-20250514")

        # ── 네트워크/프록시 설정 ─────────────────────────────────────
        net = raw.get("network", {})
        self.pip_proxy        = net.get("pip_proxy", "").strip()
        self.npm_proxy        = net.get("npm_proxy", "").strip()
        self.pip_trusted_hosts = net.get("pip_trusted_hosts", [
            "pypi.org", "files.pythonhosted.org", "pypi.python.org"
        ])

        # ── 알람 설정 ─────────────────────────────────────────────────
        alr = raw.get("alert", {})
        self.repeat_threshold     = int(alr.get("repeat_threshold", 2))
        self.ssl_expiry_warn_days = int(alr.get("ssl_expiry_warn_days", 30))
        self.email_enabled        = bool(alr.get("email_enabled", False))
        self.email_smtp           = alr.get("email_smtp", "")
        self.email_from           = alr.get("email_from", "")
        self.email_to             = alr.get("email_to", [])

        # ── 뉴스 설정 ─────────────────────────────────────────────────
        nws = raw.get("news", {})
        self.news_enabled          = bool(nws.get("enabled", True))
        self.news_refresh_interval = int(nws.get("refresh_interval_min", 60))
        self.news_sources          = nws.get("sources", ["krcert", "kisa"])

        # 보고서 디렉토리 생성
        self.report_output_dir.mkdir(parents=True, exist_ok=True)

    # ── nmap 경로 (OS별 자동 탐색) ───────────────────────────────────
    @property
    def nmap_path(self) -> Optional[str]:
        if self._nmap_path_cfg:
            return self._nmap_path_cfg if Path(self._nmap_path_cfg).exists() else None

        if self.is_windows:
            candidates = [
                r"C:\Program Files (x86)\Nmap\nmap.exe",
                r"C:\Program Files\Nmap\nmap.exe",
                r"C:\Nmap\nmap.exe",
            ]
            for c in candidates:
                if Path(c).exists():
                    return c
            # PATH에서 찾기
            found = shutil.which("nmap")
            return found

        else:  # linux
            candidates = ["/usr/bin/nmap", "/usr/local/bin/nmap", "/bin/nmap"]
            for c in candidates:
                if Path(c).exists():
                    return c
            return shutil.which("nmap")

    @property
    def nmap_available(self) -> bool:
        return self.nmap_path is not None

    # ── OS별 프로세스 실행 커맨드 ─────────────────────────────────────
    @property
    def uvicorn_cmd(self) -> list:
        return [
            sys.executable, "-m", "uvicorn",
            "main:app",
            "--host", self.backend_host,
            "--port", str(self.backend_port),
            "--reload"
        ]

    @property
    def npm_cmd(self) -> str:
        return "npm.cmd" if self.is_windows else "npm"

    @property
    def shell(self) -> bool:
        """subprocess shell=True 여부"""
        return self.is_windows

    # ── 브라우저 오픈 ─────────────────────────────────────────────────
    def open_browser(self, url: str):
        if not self.auto_open_browser:
            return
        import subprocess
        if self.is_windows:
            os.startfile(url)
        else:
            # Linux: xdg-open / wslview 시도
            for cmd in ["xdg-open", "wslview", "sensible-browser"]:
                if shutil.which(cmd):
                    subprocess.Popen([cmd, url])
                    return

    # ── 요약 출력 ─────────────────────────────────────────────────────
    def print_summary(self):
        sep = "=" * 52
        print(sep)
        print(f"  SecurityScanKit v2.0 — Config Summary")
        print(sep)
        print(f"  OS Mode      : {self.os.upper()}")
        print(f"  Backend      : http://{self.backend_host}:{self.backend_port}")
        print(f"  Frontend     : http://localhost:{self.frontend_port}")
        print(f"  nmap         : {self.nmap_path or 'NOT FOUND (socket fallback)'}")
        print(f"  AI Analysis  : {'enabled' if self.ai_enabled else 'disabled'}")
        print(f"  Reports Dir  : {self.report_output_dir}")
        print(f"  Email Alerts : {'enabled' if self.email_enabled else 'disabled'}")
        if self.pip_proxy:
            print(f"  Proxy        : {self.pip_proxy}")
        print(sep)


# ── 싱글톤 인스턴스 ───────────────────────────────────────────────────
_config: Optional[AppConfig] = None

def get_config() -> AppConfig:
    global _config
    if _config is None:
        _config = AppConfig()
    return _config


if __name__ == "__main__":
    cfg = get_config()
    cfg.print_summary()
