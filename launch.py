#!/usr/bin/env python3
"""
launch.py -- SecurityScanKit OS-aware launcher
config.json 의 "os" 값을 읽어 Windows / Linux 에 맞게 서버를 실행합니다.

Usage:
  python launch.py          # start servers
  python launch.py stop     # stop servers
  python launch.py status   # check status
  python launch.py config   # show config
"""
import sys
import os
import subprocess
import time
import signal
import json
from pathlib import Path

ROOT = Path(__file__).parent
sys.path.insert(0, str(ROOT / "backend"))
from config_loader import get_config

PID_FILE = ROOT / ".pids.json"


# ── PID 관리 ────────────────────────────────────────────────────────
def save_pids(pids: dict):
    with open(PID_FILE, "w") as f:
        json.dump(pids, f)

def load_pids() -> dict:
    if PID_FILE.exists():
        with open(PID_FILE) as f:
            return json.load(f)
    return {}

def clear_pids():
    if PID_FILE.exists():
        PID_FILE.unlink()


# ── 패키지 설치 ─────────────────────────────────────────────────────
def install_backend(cfg):
    print("[1/4] Installing backend packages...")
    req = ROOT / "backend" / "requirements.txt"

    # 기본 pip 명령
    pip_cmd = [sys.executable, "-m", "pip", "install", "-r", str(req), "-q"]

    # 회사 방화벽/프록시 SSL 인증서 문제 우회 옵션 추가
    # config.json 의 pip_trusted_hosts 설정 사용 (없으면 기본값)
    trusted = getattr(cfg, "pip_trusted_hosts", [
        "pypi.org", "files.pythonhosted.org", "pypi.python.org"
    ])
    for host in trusted:
        pip_cmd += ["--trusted-host", host]

    # 프록시 설정이 있으면 추가
    proxy = getattr(cfg, "pip_proxy", "")
    if proxy:
        pip_cmd += ["--proxy", proxy]

    result = subprocess.run(pip_cmd, shell=cfg.shell)

    if result.returncode != 0:
        print()
        print("  [RETRY] SSL error detected. Retrying with --trusted-host...")
        # 재시도: trusted-host 강제 적용
        retry_cmd = [
            sys.executable, "-m", "pip", "install", "-r", str(req), "-q",
            "--trusted-host", "pypi.org",
            "--trusted-host", "files.pythonhosted.org",
            "--trusted-host", "pypi.python.org",
            "--trusted-host", "static.rust-lang.org",
        ]
        if proxy:
            retry_cmd += ["--proxy", proxy]
        result2 = subprocess.run(retry_cmd, shell=cfg.shell)
        if result2.returncode != 0:
            print("  [ERROR] Package install failed.")
            print()
            print("  Solutions:")
            print("  1. Set pip_proxy in config.json if behind proxy")
            print("  2. Run manually:")
            print(f"     pip install -r backend/requirements.txt --trusted-host pypi.org --trusted-host files.pythonhosted.org")
            print()
            sys.exit(1)

    print("  [OK] Backend packages ready")


def install_frontend(cfg):
    print("[2/4] Installing frontend packages...")
    npm = cfg.npm_cmd
    if not _cmd_exists(npm):
        print("  [SKIP] npm not found -- frontend will not start")
        print("         Install Node.js 18+ from https://nodejs.org/")
        return False

    fe_dir = ROOT / "frontend"

    # npm도 프록시 설정 전달
    env = os.environ.copy()
    proxy = getattr(cfg, "npm_proxy", "")
    if proxy:
        env["HTTP_PROXY"]  = proxy
        env["HTTPS_PROXY"] = proxy
        env["npm_config_proxy"] = proxy
        env["npm_config_https_proxy"] = proxy
        env["NODE_TLS_REJECT_UNAUTHORIZED"] = "0"

    result = subprocess.run(
        [npm, "install", "--silent"],
        cwd=str(fe_dir),
        shell=cfg.shell,
        env=env
    )
    if result.returncode != 0:
        print("  WARN: npm install failed")
        return False
    print("  [OK] Frontend packages ready")
    return True


def _cmd_exists(cmd: str) -> bool:
    import shutil
    return shutil.which(cmd) is not None


# ── 서버 실행 ───────────────────────────────────────────────────────
def start_backend(cfg) -> subprocess.Popen:
    print("[3/4] Starting backend server...")
    be_dir = ROOT / "backend"
    env = os.environ.copy()
    env["PYTHONPATH"] = str(be_dir)

    if cfg.is_windows:
        proc = subprocess.Popen(
            cfg.uvicorn_cmd,
            cwd=str(be_dir),
            env=env,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        log_path = ROOT / "logs" / "backend.log"
        log_path.parent.mkdir(exist_ok=True)
        proc = subprocess.Popen(
            cfg.uvicorn_cmd,
            cwd=str(be_dir),
            env=env,
            stdout=open(log_path, "w"),
            stderr=subprocess.STDOUT
        )
        print(f"  Log: {log_path}")

    print(f"  [OK] Backend PID={proc.pid} --> http://localhost:{cfg.backend_port}")
    return proc


def start_frontend(cfg) -> subprocess.Popen:
    print("[4/4] Starting frontend server...")
    fe_dir = ROOT / "frontend"
    npm = cfg.npm_cmd
    env = os.environ.copy()

    proxy = getattr(cfg, "npm_proxy", "")
    if proxy:
        env["HTTP_PROXY"]  = proxy
        env["HTTPS_PROXY"] = proxy

    if cfg.is_windows:
        proc = subprocess.Popen(
            [npm, "run", "dev"],
            cwd=str(fe_dir),
            shell=True,
            env=env,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )
    else:
        log_path = ROOT / "logs" / "frontend.log"
        log_path.parent.mkdir(exist_ok=True)
        proc = subprocess.Popen(
            [npm, "run", "dev"],
            cwd=str(fe_dir),
            env=env,
            stdout=open(log_path, "w"),
            stderr=subprocess.STDOUT
        )
        print(f"  Log: {log_path}")

    print(f"  [OK] Frontend PID={proc.pid} --> http://localhost:{cfg.frontend_port}")
    return proc


# ── 서버 종료 ───────────────────────────────────────────────────────
def stop_servers(cfg):
    print("Stopping SecurityScanKit servers...")
    pids = load_pids()
    if cfg.is_windows:
        for name, pid in pids.items():
            subprocess.run(["taskkill", "/F", "/PID", str(pid)], capture_output=True)
            print(f"  Stopped: {name} (PID {pid})")
    else:
        for name, pid in pids.items():
            try:
                os.kill(int(pid), signal.SIGTERM)
                print(f"  Stopped: {name} (PID {pid})")
            except ProcessLookupError:
                print(f"  Already stopped: {name}")
    clear_pids()
    print("Done.")


# ── 상태 확인 ───────────────────────────────────────────────────────
def check_status(cfg):
    import urllib.request
    pids = load_pids()
    print("\n=== SecurityScanKit Status ===")
    print(f"  OS       : {cfg.os.upper()}")
    print(f"  nmap     : {cfg.nmap_path or 'Not found (socket fallback)'}")
    print()
    for name, pid in pids.items():
        try:
            if cfg.is_windows:
                r = subprocess.run(["tasklist", "/FI", f"PID eq {pid}"],
                                   capture_output=True, text=True)
                alive = str(pid) in r.stdout
            else:
                os.kill(int(pid), 0)
                alive = True
        except Exception:
            alive = False
        print(f"  {'[OK]' if alive else '[--]'} {name:<12} PID={pid}  {'RUNNING' if alive else 'STOPPED'}")
    print()
    for label, url in [
        ("Backend", f"http://localhost:{cfg.backend_port}/api/health"),
        ("Frontend", f"http://localhost:{cfg.frontend_port}"),
    ]:
        try:
            urllib.request.urlopen(url, timeout=2)
            print(f"  [OK] {label:<10} {url}")
        except Exception:
            print(f"  [--] {label:<10} {url}  (not responding)")
    print()


# ── 메인 ────────────────────────────────────────────────────────────
def main():
    cfg = get_config()
    cfg.print_summary()

    cmd = sys.argv[1].lower() if len(sys.argv) > 1 else "start"

    if cmd == "config":
        return
    if cmd == "stop":
        stop_servers(cfg)
        return
    if cmd == "status":
        check_status(cfg)
        return
    if cmd != "start":
        print(f"Unknown command: {cmd}")
        print("Usage: python launch.py [start|stop|status|config]")
        sys.exit(1)

    install_backend(cfg)
    has_frontend = install_frontend(cfg)

    be_proc = start_backend(cfg)
    time.sleep(2)

    fe_proc = None
    if has_frontend:
        fe_proc = start_frontend(cfg)
        time.sleep(3)

    pids = {"backend": be_proc.pid}
    if fe_proc:
        pids["frontend"] = fe_proc.pid
    save_pids(pids)

    print()
    print("=" * 52)
    print("  SecurityScanKit is RUNNING")
    print(f"  Dashboard : http://localhost:{cfg.frontend_port}")
    print(f"  API Docs  : http://localhost:{cfg.backend_port}/docs")
    print()
    print("  Stop      : python launch.py stop")
    print("  Status    : python launch.py status")
    print("=" * 52)

    if has_frontend:
        cfg.open_browser(f"http://localhost:{cfg.frontend_port}")
    else:
        cfg.open_browser(f"http://localhost:{cfg.backend_port}/docs")

    if cfg.is_linux:
        print("\n  Press Ctrl+C to stop\n")
        try:
            be_proc.wait()
        except KeyboardInterrupt:
            stop_servers(cfg)


if __name__ == "__main__":
    main()
