"""
log_config.py
uvicorn 로그 설정 — websockets 라이브러리 노이즈 완전 차단
"""

LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "default": {
            "()": "uvicorn.logging.DefaultFormatter",
            "fmt": "%(levelprefix)s %(message)s",
            "use_colors": True,
        },
        "access": {
            "()": "uvicorn.logging.AccessFormatter",
            "fmt": '%(levelprefix)s %(client_addr)s - "%(request_line)s" %(status_code)s',
        },
    },
    "handlers": {
        "default": {
            "formatter": "default",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stderr",
        },
        "access": {
            "formatter": "access",
            "class": "logging.StreamHandler",
            "stream": "ext://sys.stdout",
        },
        "null": {
            "class": "logging.NullHandler",
        },
    },
    "loggers": {
        # uvicorn 정상 로그
        "uvicorn":          {"handlers": ["default"], "level": "INFO",    "propagate": False},
        "uvicorn.error":    {"handlers": ["default"], "level": "INFO",    "propagate": False},
        "uvicorn.access":   {"handlers": ["access"],  "level": "INFO",    "propagate": False},

        # ── 완전 억제 대상 (NullHandler) ──────────────────────────
        # websockets 라이브러리: 프레임 송수신마다 DEBUG 찍음
        "websockets":                              {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.server":                       {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.client":                       {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.protocol":                     {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.legacy":                       {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.legacy.server":                {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.legacy.client":                {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "websockets.legacy.protocol":              {"handlers": ["null"], "level": "WARNING", "propagate": False},

        # uvicorn 내부 프로토콜 레이어
        "uvicorn.protocols":                       {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "uvicorn.protocols.websockets":            {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "uvicorn.protocols.websockets.websockets_impl": {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "uvicorn.protocols.websockets.wsproto_impl":    {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "uvicorn.protocols.http":                  {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "uvicorn.protocols.http.h11_impl":         {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "uvicorn.protocols.http.httptools_impl":   {"handlers": ["null"], "level": "WARNING", "propagate": False},

        # 기타 노이즈
        "h11":      {"handlers": ["null"], "level": "WARNING", "propagate": False},
        "asyncio":  {"handlers": ["null"], "level": "WARNING", "propagate": False},

        # 앱 로거
        "ssk":                   {"handlers": ["default"], "level": "DEBUG",   "propagate": False},
        "core.intel_collector":  {"handlers": ["default"], "level": "INFO",    "propagate": False},
        "sqlalchemy.engine":     {"handlers": ["null"],    "level": "WARNING", "propagate": False},
    },
}
