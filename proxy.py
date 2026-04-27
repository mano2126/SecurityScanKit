"""
SecurityScanKit Simple Proxy
80 포트로 접속 → 8000(Release) 또는 3000(Dev) 으로 자동 전달
"""
import http.server
import urllib.request
import urllib.error
import sys
import os

PROXY_PORT = 80

def detect_backend():
    """8000(Release) 먼저 확인, 없으면 3000(Dev)"""
    for port in [8000, 3000]:
        try:
            urllib.request.urlopen(f"http://localhost:{port}", timeout=1)
            return port
        except:
            pass
    return 8000  # 기본값

class ProxyHandler(http.server.BaseHTTPRequestHandler):
    target_port = None

    def log_message(self, format, *args):
        pass  # 조용한 로그

    def do_request(self):
        if not ProxyHandler.target_port:
            ProxyHandler.target_port = detect_backend()

        target = f"http://localhost:{ProxyHandler.target_port}{self.path}"
        try:
            headers = {}
            for k, v in self.headers.items():
                if k.lower() not in ('host', 'content-length'):
                    headers[k] = v

            body = None
            if self.command in ('POST', 'PUT', 'PATCH'):
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length) if length else None

            req = urllib.request.Request(target, data=body, headers=headers, method=self.command)
            resp = urllib.request.urlopen(req, timeout=30)

            self.send_response(resp.status)
            for k, v in resp.headers.items():
                if k.lower() not in ('transfer-encoding',):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(resp.read())

        except urllib.error.HTTPError as e:
            self.send_response(e.code)
            for k, v in e.headers.items():
                if k.lower() not in ('transfer-encoding',):
                    self.send_header(k, v)
            self.end_headers()
            self.wfile.write(e.read())
        except Exception as e:
            self.send_response(502)
            self.send_header('Content-Type', 'text/plain')
            self.end_headers()
            self.wfile.write(f"Proxy Error: {e}".encode())

    do_GET     = do_request
    do_POST    = do_request
    do_PUT     = do_request
    do_DELETE  = do_request
    do_PATCH   = do_request
    do_OPTIONS = do_request
    do_HEAD    = do_request

if __name__ == "__main__":
    port = detect_backend()
    print(f"[SSK Proxy] Backend detected: localhost:{port}")
    print(f"[SSK Proxy] Listening on port {PROXY_PORT}")
    print(f"[SSK Proxy] Access: http://[server-ip]")
    ProxyHandler.target_port = port
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PROXY_PORT), ProxyHandler)
    server.serve_forever()
