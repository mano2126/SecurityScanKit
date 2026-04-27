"""
core/intel_collector.py
보안 위협 인텔리전스 수집 엔진
- KrCERT/CC RSS   : 취약점·보안 공지
- KISA 보호나라   : 보안 공지·취약점
- 금융보안원      : 금융 보안 공지
- KISA CVE API    : 국내 CVE 데이터
- NVD API         : 글로벌 CVSS 9.0+ CVE
- CISA KEV        : 실제 악용 취약점
"""
import asyncio, json, re, hashlib
from datetime  import datetime, timezone, timedelta
from pathlib   import Path
from db.schema import SessionLocal
from db.crud   import save_news, upsert_cve

TIMEOUT    = 15
FEED_LIMIT = 10   # 소스당 최대 저장 건수

# ── 공통 브라우저 헤더 ────────────────────────────────────────────
BROWSER_HEADERS = {
    "User-Agent":      "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "ko-KR,ko;q=0.9,en-US;q=0.8,en;q=0.7",
    "Accept-Encoding": "gzip, deflate, br",
    "Connection":      "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Cache-Control":   "max-age=0",
}

# ── 심각도 분류 ───────────────────────────────────────────────────
CRIT_KW = ["critical","긴급","zero-day","0-day","actively exploited","원격 코드 실행","RCE","랜섬웨어","ransomware"]
HIGH_KW = ["high","고위험","buffer overflow","privilege escalation","권한 상승","인증 우회","bypass","취약점"]
MED_KW  = ["medium","중위험","denial of service","DoS","information disclosure","정보 노출"]

def _classify_sev(text: str, base: str = "medium") -> str:
    t = text.lower()
    if any(k.lower() in t for k in CRIT_KW): return "critical"
    if any(k.lower() in t for k in HIGH_KW):  return "high"
    if any(k.lower() in t for k in MED_KW):   return "medium"
    return base

def _clean(text: str) -> str:
    if not text: return ""
    text = re.sub(r"<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text[:800]

def _uid(url: str, title: str) -> str:
    return hashlib.md5(f"{url}{title}".encode()).hexdigest()[:16]

def _req_get(url: str, **kwargs):
    """동기 requests.get 래퍼"""
    import requests as req
    import warnings
    warnings.filterwarnings("ignore")
    return req.get(url, headers=BROWSER_HEADERS, timeout=TIMEOUT,
                   verify=False, **kwargs)

async def _get(url: str, **kwargs):
    """비동기 GET"""
    loop = asyncio.get_event_loop()
    return await loop.run_in_executor(None, lambda: _req_get(url, **kwargs))


# ═══════════════════════════════════════════════════════════════════
# 소스별 수집 함수
# ═══════════════════════════════════════════════════════════════════

async def _fetch_krcert() -> list:
    """KrCERT/CC — 취약점 공지 + 보안 공지 RSS"""
    import feedparser
    results = []
    feeds = [
        ("https://www.krcert.or.kr/rss/vitiList.do",    "high"),
        ("https://www.krcert.or.kr/rss/secNoticeList.do","medium"),
        ("https://www.krcert.or.kr/rss/malwareList.do",  "high"),
    ]
    for rss_url, base_sev in feeds:
        try:
            resp = await _get(rss_url)
            if resp.status_code != 200:
                continue
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","") or e.get("id","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"KrCERT","source_tag":"KrCERT","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary, base_sev),
                    "published_at":pub,"affects_assets":False,
                })
                if len(results) >= FEED_LIMIT: break
            if results:
                break  # 첫 번째 성공한 피드로 충분
        except Exception as e:
            print(f"[INTEL] KrCERT RSS 실패 ({rss_url}): {e}")
            continue

    # RSS 실패 시 → JSON API 시도
    if not results:
        try:
            resp = await _get("https://www.krcert.or.kr/krcert/secNoticeList.json?pageIndex=1&pageSize=10")
            if resp.status_code == 200:
                data = resp.json()
                items = data.get("list") or data.get("data") or []
                for item in items[:FEED_LIMIT]:
                    title = item.get("title","").strip()
                    if not title: continue
                    results.append({
                        "source":"KrCERT","source_tag":"KrCERT","title":title,
                        "summary":item.get("content","")[:300],
                        "url":f"https://www.krcert.or.kr{item.get('url','')}",
                        "severity":_classify_sev(title,"high"),
                        "published_at":datetime.now(),"affects_assets":False,
                    })
        except Exception as e:
            print(f"[INTEL] KrCERT JSON API 실패: {e}")

    print(f"[INTEL] KrCERT: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_kisa() -> list:
    """KISA 보호나라 — 보안 공지·취약점 RSS"""
    import feedparser
    results = []
    feeds = [
        ("https://www.boho.or.kr/rss/mediaBoardRss.do?menuNo=205020", "medium"),
        ("https://www.boho.or.kr/rss/vitiRss.do?menuNo=205023",       "high"),
        ("https://www.boho.or.kr/rss/atcRss.do",                      "medium"),
    ]
    for rss_url, base_sev in feeds:
        try:
            resp = await _get(rss_url)
            if resp.status_code != 200:
                continue
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","") or e.get("id","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"KISA","source_tag":"KISA","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary, base_sev),
                    "published_at":pub,"affects_assets":False,
                })
                if len(results) >= FEED_LIMIT: break
            if results:
                break
        except Exception as e:
            print(f"[INTEL] KISA RSS 실패 ({rss_url}): {e}")
            continue

    # RSS 실패 시 → 크롤링
    if not results:
        try:
            from bs4 import BeautifulSoup
            resp = await _get("https://www.boho.or.kr/kr/bbs/list.do?menuNo=205020")
            if resp.status_code == 200:
                soup = BeautifulSoup(resp.content, "html.parser")
                for a in soup.select("table a, .board-list a, td.title a"):
                    title = a.get_text(strip=True)
                    if len(title) < 8 or not any("가"<=c<="힣" for c in title): continue
                    href = a.get("href","")
                    url  = href if href.startswith("http") else "https://www.boho.or.kr"+href
                    results.append({
                        "source":"KISA","source_tag":"KISA","title":title[:500],
                        "summary":f"KISA 보호나라 — {title[:200]}",
                        "url":url,"severity":_classify_sev(title,"medium"),
                        "published_at":datetime.now(),"affects_assets":False,
                    })
                    if len(results) >= FEED_LIMIT: break
        except ImportError:
            print("[INTEL] KISA 크롤링: beautifulsoup4 필요 → pip install beautifulsoup4")
        except Exception as e:
            print(f"[INTEL] KISA 크롤링 실패: {e}")

    print(f"[INTEL] KISA: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_fsec() -> list:
    """금융보안원 — 보안 공지 크롤링"""
    results = []
    urls = [
        "https://www.fsec.or.kr/user/bbs/fsec/163/315/bbsList.do",
        "https://www.fsec.or.kr/bbs/list?id=B0000024",
        "https://www.fsec.or.kr/user/bbs/fsec/64/259/bbsList.do",
    ]
    for url in urls:
        try:
            from bs4 import BeautifulSoup
            resp = await _get(url)
            if resp.status_code != 200:
                continue
            soup = BeautifulSoup(resp.content, "html.parser")
            for a in soup.select("table a, .board-list a, td.subject a, .title a, td a[href*='bbs']"):
                title = a.get_text(strip=True)
                if len(title) < 8 or not any("가"<=c<="힣" for c in title): continue
                href = a.get("href","")
                full = href if href.startswith("http") else "https://www.fsec.or.kr"+href
                results.append({
                    "source":"금융보안원","source_tag":"금융보안원","title":title[:500],
                    "summary":f"금융보안원 보안공지 — {title[:200]}",
                    "url":full,"severity":_classify_sev(title,"high"),
                    "published_at":datetime.now(),"affects_assets":False,
                })
                if len(results) >= FEED_LIMIT: break
            if results:
                break
        except ImportError:
            print("[INTEL] 금융보안원: beautifulsoup4 필요 → pip install beautifulsoup4")
            break
        except Exception as e:
            print(f"[INTEL] 금융보안원 실패 ({url}): {e}")
            continue

    print(f"[INTEL] 금융보안원: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_cisa_rss() -> list:
    """CISA Advisories RSS"""
    import feedparser
    results = []
    try:
        resp = await _get("https://www.cisa.gov/cybersecurity-advisories/all.xml")
        if resp.status_code == 200:
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"CISA","source_tag":"CISA","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary,"high"),
                    "published_at":pub,"affects_assets":False,
                })
    except Exception as e:
        print(f"[INTEL] CISA RSS 실패: {e}")
    print(f"[INTEL] CISA: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_bleeping() -> list:
    """BleepingComputer Security RSS"""
    import feedparser
    results = []
    try:
        resp = await _get("https://www.bleepingcomputer.com/feed/")
        if resp.status_code == 200:
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"BleepingComputer","source_tag":"BleepingComputer","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary,"medium"),
                    "published_at":pub,"affects_assets":False,
                })
    except Exception as e:
        print(f"[INTEL] BleepingComputer RSS 실패: {e}")
    print(f"[INTEL] BleepingComputer: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_sans() -> list:
    """SANS ISC RSS"""
    import feedparser
    results = []
    try:
        resp = await _get("https://isc.sans.edu/rssfeed_full.xml")
        if resp.status_code == 200:
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"SANS","source_tag":"SANS","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary,"medium"),
                    "published_at":pub,"affects_assets":False,
                })
    except Exception as e:
        print(f"[INTEL] SANS RSS 실패: {e}")
    print(f"[INTEL] SANS: {len(results)}건")
    return results[:FEED_LIMIT]




async def _fetch_boannews() -> list:
    """보안뉴스 (www.boannews.com) — RSS + 크롤링 fallback"""
    import feedparser
    results = []
    # RSS 시도
    try:
        resp = await _get("https://www.boannews.com/media/boannews_rss.xml")
        if resp.status_code == 200:
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"보안뉴스","source_tag":"보안뉴스","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary,"medium"),
                    "published_at":pub,"affects_assets":False,
                })
    except Exception as e:
        print(f"[INTEL] 보안뉴스 RSS 실패: {e}")

    # RSS 실패 시 크롤링
    if not results:
        try:
            from bs4 import BeautifulSoup
            resp = await _get("https://www.boannews.com/media/t_list.asp")
            if resp.status_code == 200:
                # EUC-KR 인코딩 처리
                try: html = resp.content.decode("euc-kr")
                except: html = resp.content.decode("utf-8", errors="ignore")
                soup = BeautifulSoup(html, "html.parser")
                for a in soup.select("a[href*='view.asp'], a[href*='media/view']"):
                    title = a.get_text(strip=True)
                    if len(title) < 8: continue
                    href = a.get("href","")
                    url = href if href.startswith("http") else "https://www.boannews.com"+href
                    results.append({
                        "source":"보안뉴스","source_tag":"보안뉴스","title":title[:500],
                        "summary":f"보안뉴스 — {title[:200]}","url":url,
                        "severity":_classify_sev(title,"medium"),
                        "published_at":datetime.now(),"affects_assets":False,
                    })
                    if len(results) >= FEED_LIMIT: break
        except Exception as e:
            print(f"[INTEL] 보안뉴스 크롤링 실패: {e}")
    print(f"[INTEL] 보안뉴스: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_dailysecu() -> list:
    """데일리시큐 (www.dailysecu.com) — RSS"""
    import feedparser
    results = []
    try:
        resp = await _get("https://www.dailysecu.com/rss/allArticle.xml")
        if resp.status_code == 200:
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"데일리시큐","source_tag":"데일리시큐","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary,"medium"),
                    "published_at":pub,"affects_assets":False,
                })
    except Exception as e:
        print(f"[INTEL] 데일리시큐 RSS 실패: {e}")
    print(f"[INTEL] 데일리시큐: {len(results)}건")
    return results[:FEED_LIMIT]


async def _fetch_hackernews() -> list:
    """The Hacker News — RSS"""
    import feedparser
    results = []
    try:
        resp = await _get("https://feeds.feedburner.com/TheHackersNews")
        if resp.status_code == 200:
            parsed = feedparser.parse(resp.content)
            for e in parsed.entries[:FEED_LIMIT]:
                title   = _clean(e.get("title",""))
                summary = _clean(e.get("summary","") or e.get("description",""))
                url     = e.get("link","")
                if not title: continue
                pub = None
                for attr in ("published_parsed","updated_parsed"):
                    t = e.get(attr)
                    if t:
                        try: pub = datetime(*t[:6]); break
                        except: pass
                pub = pub or datetime.now()
                results.append({
                    "source":"TheHackerNews","source_tag":"TheHackerNews","title":title,
                    "summary":summary,"url":url,
                    "severity":_classify_sev(title+" "+summary,"medium"),
                    "published_at":pub,"affects_assets":False,
                })
    except Exception as e:
        print(f"[INTEL] TheHackerNews RSS 실패: {e}")
    print(f"[INTEL] TheHackerNews: {len(results)}건")
    return results[:FEED_LIMIT]
# ── 소스 → 수집 함수 매핑 ─────────────────────────────────────────
SOURCE_FETCHERS = {
    # 국내 공식 보안기관
    "KrCERT":           _fetch_krcert,
    "KISA":             _fetch_kisa,
    "금융보안원":        _fetch_fsec,
    # 국내 보안 미디어
    "보안뉴스":          _fetch_boannews,
    "데일리시큐":        _fetch_dailysecu,
    # 해외
    "CISA":             _fetch_cisa_rss,
    "BleepingComputer": _fetch_bleeping,
    "SANS":             _fetch_sans,
    "TheHackerNews":    _fetch_hackernews,
}

# 기본 수집 설정
DEFAULT_CONFIG = {
    # 국내 공식기관
    "KrCERT":           True,
    "KISA":             True,
    "금융보안원":        True,
    # 국내 보안 미디어 (보안뉴스, 데일리시큐)
    "보안뉴스":          True,
    "데일리시큐":        True,
    # 해외
    "CISA":             False,
    "BleepingComputer": False,
    "SANS":             False,
    "TheHackerNews":    False,
    # CVE
    "NVD":              True,
}


# ═══════════════════════════════════════════════════════════════════
# NVD CVE 수집
# ═══════════════════════════════════════════════════════════════════
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

async def _fetch_nvd_cves(days: int = 3, min_cvss: float = 7.0) -> list:
    results = []
    try:
        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=days)
        params = {
            "pubStartDate":   start.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "pubEndDate":     end.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "cvssV3Severity": "CRITICAL",
            "resultsPerPage": 30,
        }
        import requests as req, urllib.parse, warnings
        warnings.filterwarnings("ignore")
        url = NVD_API + "?" + urllib.parse.urlencode(params)
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: req.get(url, headers=BROWSER_HEADERS, timeout=TIMEOUT, verify=False)
        )
        data = resp.json()
        for item in data.get("vulnerabilities",[]):
            cve_data = item.get("cve",{})
            cve_id   = cve_data.get("id","")
            descs    = cve_data.get("descriptions",[])
            desc_en  = next((d["value"] for d in descs if d.get("lang")=="en"), "")
            metrics  = cve_data.get("metrics",{})
            cvss_v31 = metrics.get("cvssMetricV31",[])
            cvss_v30 = metrics.get("cvssMetricV30",[])
            cvss_v2  = metrics.get("cvssMetricV2",[])
            score, vec = 0.0, ""
            if cvss_v31:
                score = cvss_v31[0]["cvssData"].get("baseScore",0)
                vec   = cvss_v31[0]["cvssData"].get("vectorString","")
            elif cvss_v30:
                score = cvss_v30[0]["cvssData"].get("baseScore",0)
            elif cvss_v2:
                score = cvss_v2[0]["cvssData"].get("baseScore",0)
            if score < min_cvss: continue
            weaknesses = cve_data.get("weaknesses",[])
            cwe = ",".join(d.get("value","") for d in (weaknesses[0].get("description",[]) if weaknesses else [])[:2])
            configs = cve_data.get("configurations",[])
            affected = []
            for cfg in configs[:2]:
                for node in cfg.get("nodes",[])[:3]:
                    for m in node.get("cpeMatch",[])[:3]:
                        cpe = m.get("criteria","")
                        if cpe:
                            parts = cpe.split(":")
                            if len(parts)>=5: affected.append(f"{parts[3]} {parts[4]}")
            pub_str = cve_data.get("published","")
            try: pub_dt = datetime.fromisoformat(pub_str.replace("Z","+00:00")).replace(tzinfo=None)
            except: pub_dt = datetime.now()
            results.append({
                "id":               cve_id,
                "cvss_score":       score,
                "cvss_vector":      vec,
                "severity":         "critical" if score>=9 else "high" if score>=7 else "medium",
                "description":      desc_en,
                "affected_products":json.dumps(list(set(affected))[:10]),
                "patch_info":       "",
                "is_kev":           False,
                "published_date":   pub_dt,
            })
    except Exception as e:
        print(f"[INTEL] NVD API 수집 실패: {e}")
    return results


async def _fetch_cisa_kev() -> list:
    results = []
    try:
        import requests as req, warnings
        warnings.filterwarnings("ignore")
        resp = await asyncio.get_event_loop().run_in_executor(
            None, lambda: req.get(
                "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
                headers=BROWSER_HEADERS, timeout=TIMEOUT, verify=False
            )
        )
        data   = resp.json()
        kevs   = sorted(data.get("vulnerabilities",[]),
                        key=lambda x: x.get("dateAdded",""), reverse=True)[:30]
        for v in kevs:
            added_str = v.get("dateAdded","")
            try: added = datetime.strptime(added_str,"%Y-%m-%d")
            except: added = datetime.now()
            results.append({
                "id":               v.get("cveID",""),
                "cvss_score":       9.0,
                "severity":         "critical",
                "description":      f"[{v.get('vendorProject','')} {v.get('product','')}] {v.get('shortDescription','')}",
                "affected_products":json.dumps([f"{v.get('vendorProject','')} {v.get('product','')}"]),
                "patch_info":       v.get("requiredAction",""),
                "is_kev":           True,
                "kev_added_date":   added,
                "published_date":   added,
            })
    except Exception as e:
        print(f"[INTEL] CISA KEV 수집 실패: {e}")
    return results


# ═══════════════════════════════════════════════════════════════════
# 메인 수집 함수
# ═══════════════════════════════════════════════════════════════════

async def collect_news(config: dict = None):
    """뉴스/공지 수집 — config로 소스 ON/OFF 제어"""
    from db.schema import NewsItem
    db    = SessionLocal()
    saved = 0
    # config=None → 전체, config={} → 전체, config={...} → 설정 적용
    active_config = config if config else DEFAULT_CONFIG

    # 활성화된 소스만 수집
    tasks = {
        src: fetcher()
        for src, fetcher in SOURCE_FETCHERS.items()
        if active_config.get(src, False)
    }
    if not tasks:
        print("[INTEL] 활성화된 수집 소스 없음")
        db.close()
        return

    print(f"[INTEL] 뉴스 수집 소스: {', '.join(tasks.keys())}")
    results = dict(zip(tasks.keys(), await asyncio.gather(*tasks.values())))

    try:
        for src, items in results.items():
            for item in items:
                try: save_news(db, item); saved += 1
                except: pass
            # 소스별 FEED_LIMIT 초과분 정리
            try:
                rows = (db.query(NewsItem).filter(NewsItem.source==src)
                        .order_by(NewsItem.published_at.desc()).all())
                for old in rows[FEED_LIMIT:]: db.delete(old)
                db.commit()
            except: db.rollback()
        print(f"[INTEL] 뉴스 수집 완료: {saved}건")
    finally:
        db.close()


async def collect_cve(config: dict = None):
    """CVE 수집"""
    active_config = config if config else DEFAULT_CONFIG
    nvd_on  = active_config.get("NVD", True)
    kev_on  = active_config.get("NVD", True)  # KEV는 NVD 설정과 동일하게 (NVD ON이면 KEV도 수집)
    db = SessionLocal(); saved = 0
    try:
        tasks = []
        if nvd_on:  tasks.append(_fetch_nvd_cves(days=3, min_cvss=7.0))
        if kev_on:  tasks.append(_fetch_cisa_kev())
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, list):
                for cve in r:
                    try: upsert_cve(db, cve); saved += 1
                    except: pass
        db.commit()
        print(f"[INTEL] CVE 수집 완료: {saved}건")
    finally:
        db.close()


async def collect_all(config: dict = None):
    """뉴스 + CVE 동시 수집"""
    await asyncio.gather(collect_news(config), collect_cve(config))


async def collect_all_with_progress(config: dict = None, progress: dict = None):
    """진행 상태를 추적하며 수집"""
    if progress is None:
        await collect_all(config)
        return

    active_config = config if config else DEFAULT_CONFIG

    def upd(step, done=None, total=None, saved=None, error=None):
        progress["step"] = step
        progress["steps"].append({"ts": datetime.now().strftime("%H:%M:%S"), "msg": step})
        if done  is not None: progress["done"]  = done
        if total is not None: progress["total"] = total
        if saved is not None: progress["saved"] = saved
        if error is not None: progress["error"] = error
        if len(progress["steps"]) > 50:
            progress["steps"] = progress["steps"][-50:]

    progress.update({
        "running": True, "step": "수집 준비 중...",
        "steps": [], "total": 0, "done": 0, "saved": 0,
        "started_at": datetime.now().isoformat(),
        "finished_at": None, "error": None,
    })

    enabled_news = [s for s in SOURCE_FETCHERS if active_config.get(s, False)]
    do_nvd       = active_config.get("NVD", True)  # NVD OFF 시 KEV도 건너뜀
    total        = len(enabled_news) + (2 if do_nvd else 0)  # NVD + KEV (NVD ON 시)

    upd(f"수집 소스 확인: 뉴스 {len(enabled_news)}개", total=total, done=0)

    from db.schema import NewsItem
    db = SessionLocal(); saved = 0; done = 0

    try:
        # 뉴스 소스별 순차 수집
        for src in enabled_news:
            upd(f"📡 {src} 수집 중...", done=done)
            try:
                items = await SOURCE_FETCHERS[src]()
                for item in items:
                    try: save_news(db, item); saved += 1
                    except: pass
                rows = (db.query(NewsItem).filter(NewsItem.source==src)
                        .order_by(NewsItem.published_at.desc()).all())
                for old in rows[FEED_LIMIT:]: db.delete(old)
                db.commit()
                done += 1
                upd(f"✅ {src}: {len(items)}건", done=done, saved=saved)
            except Exception as e:
                done += 1
                upd(f"❌ {src} 실패: {str(e)[:60]}", done=done)
        db.close()

        # CVE 수집 — NVD 설정이 ON일 때만
        nvd_list, kev_list = [], []
        if do_nvd:
            upd("🔴 NVD CVE 수집 중...", done=done)
            try:
                nvd_list = await _fetch_nvd_cves(days=3)
                done += 1
                upd(f"✅ NVD CVE: {len(nvd_list)}건", done=done)
            except Exception as e:
                done += 1
                upd(f"❌ NVD 실패: {str(e)[:50]}", done=done)

            upd("⚠ CISA KEV 수집 중...", done=done)
            try:
                kev_list = await _fetch_cisa_kev()
                done += 1
                upd(f"✅ CISA KEV: {len(kev_list)}건", done=done)
            except Exception as e:
                done += 1
                upd(f"❌ CISA KEV 실패: {str(e)[:50]}", done=done)
        else:
            upd("⏭ CVE 수집 건너뜀 (NVD OFF)", done=done)

        if nvd_list or kev_list:
            db2 = SessionLocal(); cve_saved = 0
            for cve in nvd_list + kev_list:
                try: upsert_cve(db2, cve); cve_saved += 1
                except: pass
            db2.commit(); db2.close()
            saved += cve_saved

        upd(f"🎉 완료 — 뉴스 {saved}건 저장", done=total, saved=saved)
    except Exception as e:
        upd(f"❌ 오류: {e}", error=str(e))
    finally:
        progress["running"]     = False
        progress["finished_at"] = datetime.now().isoformat()
