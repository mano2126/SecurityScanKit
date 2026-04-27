"""
sitecustomize.py
Python이 어떤 모듈을 import하기 전에 가장 먼저 실행되는 파일.
이 파일을 backend/ 폴더에 두면 uvicorn 워커 시작 시 제일 먼저 적용됨.
"""
import logging

# websockets/uvicorn 프로토콜 DEBUG 로그 완전 차단
_SILENCE = [
    "websockets", "websockets.server", "websockets.client",
    "websockets.protocol", "websockets.legacy",
    "websockets.legacy.server", "websockets.legacy.client",
    "websockets.legacy.protocol",
    "uvicorn.protocols", "uvicorn.protocols.websockets",
    "uvicorn.protocols.websockets.websockets_impl",
    "uvicorn.protocols.websockets.wsproto_impl",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.http.httptools_impl",
    "h11", "asyncio",
]

_null = logging.NullHandler()
for _name in _SILENCE:
    _l = logging.getLogger(_name)
    _l.setLevel(logging.CRITICAL)
    _l.handlers = [_null]
    _l.propagate = False
