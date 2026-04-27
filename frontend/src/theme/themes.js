// theme/themes.js
// 엔터프라이즈 보안 플랫폼 전용 테마
// 원칙: 색은 '의미'에만 사용. 배경/레이아웃은 무채색.
// 참고: Tenable One, CrowdStrike Falcon, Splunk SIEM, IBM QRadar

export const THEMES = [
  {
    id: "oracle",
    label: "Oracle",
    labelKo: "오라클 (기본)",
    labelJa: "オラクル",
    desc: "흰 배경 + 진회색 사이드바 + 레드 포인트 — 담백하고 명확",
    preview: ["#F5F5F5", "#2B2B2B", "#C74634"],
  },
  {
    id: "splunk",
    label: "Splunk Dark",
    labelKo: "스플렁크 다크 ★AI추천",
    labelJa: "スプランクダーク",
    desc: "Splunk SIEM 공식 다크 — 글로벌 보안 관제 1위 솔루션 UI",
    preview: ["#1A1C20", "#212428", "#65A637"],
  },
  {
    id: "light",
    label: "Light",
    labelKo: "라이트",
    labelJa: "ライト",
    desc: "밝은 배경 — 보고서 출력 최적화",
    preview: ["#F4F5F7", "#FFFFFF", "#1E3A5F"],
  },
  {
    id: "corporate",
    label: "Corporate",
    labelKo: "코퍼레이트",
    labelJa: "コーポレート",
    desc: "흰 배경 + 네이비 사이드바 — 임원 보고용",
    preview: ["#F8F9FA", "#FFFFFF", "#1E3A8A"],
  },
];

// ── CSS 변수 정의 ─────────────────────────────────────────────────
// 규칙:
//   --bg-*   : 배경색 (무채색 계열)
//   --txt-*  : 텍스트 (배경 대비 충분한 명도)
//   --bdr-*  : 테두리 (극도로 얇고 미묘하게)
//   --accent : 단 하나의 포인트 색상 (파란색 계열)
//   --danger/--warn/--ok : 상태 전달 목적에만 사용

export const themeVars = {

  // ── 오라클: 흰 배경 + 진회색 사이드바 + 레드 포인트 ──────────
  // Oracle 설치 마법사처럼 담백하고 명확. 군더더기 없음.
  oracle: {
    "--bg-base":      "#F5F5F5",   // 페이지 배경
    "--bg-nav":       "#2B2B2B",   // 사이드바 — 오라클 진회색
    "--bg-card":      "#FFFFFF",   // 카드
    "--bg-card2":     "#F0F0F0",   // 중첩 카드
    "--bg-input":     "#F5F5F5",   // 입력 필드
    "--bg-hover":     "#383838",   // 호버 — 사이드바 안에서 밝게
    "--bg-active":    "#3D1E18",   // 활성 — 레드 계열 어둡게 (진회색 배경 대비)
    "--bdr":          "rgba(0,0,0,.09)",
    "--bdr2":         "rgba(0,0,0,.16)",
    "--bdr-nav":      "rgba(255,255,255,.10)",  // 사이드바 내부 구분선 — 밝게
    "--txt":          "#1A1A1A",   // 본문
    "--txt2":         "#3D3D3D",   // 보조
    "--txt3":         "#7A7A7A",   // 힌트
    "--accent":       "#C74634",   // 오라클 레드
    "--accent-dim":   "#3D1E18",
    "--accent-text":  "#E86040",   // 밝은 레드 (진회색 배경 대비)
    "--nav-text":     "#C8C8C8",   // 사이드바 메뉴 텍스트 — 밝게
    "--topbar-bg":    "#FFFFFF",
    "--section-text": "#888888",   // Sec 그룹 레이블
    "--logo-text":    "#FFFFFF",
    "--shadow":       "0 1px 3px rgba(0,0,0,.10)",
  },

  // ── 스플렁크 다크: Splunk SIEM 공식 UI 스타일 ★AI추천 ──────────
  // 글로벌 보안 관제 솔루션 1위 Splunk의 실제 다크 테마.
  // 진한 회색 + 연두빛 녹색 포인트. 눈에 편하고 데이터가 명확히 읽힘.
  // IBM QRadar, CrowdStrike 등 엔터프라이즈 SIEM의 공통 언어.
  splunk: {
    "--bg-base":      "#1A1C20",   // Splunk 메인 배경 — 짙은 회색
    "--bg-nav":       "#16181C",   // 사이드바 — 한 단계 더 어둡게
    "--bg-card":      "#212428",   // 카드 — 배경보다 살짝 밝게
    "--bg-card2":     "#1A1C20",   // 중첩 카드
    "--bg-input":     "#2A2D33",   // 입력 필드
    "--bg-hover":     "#2E3138",   // 호버
    "--bg-active":    "#1E2B1A",   // 활성 — 녹색 아주 연하게
    "--bdr":          "rgba(255,255,255,.07)",
    "--bdr2":         "rgba(255,255,255,.13)",
    "--bdr-nav":      "rgba(255,255,255,.09)",
    "--txt":          "#D8DEE9",   // 본문 — Splunk 특유의 따뜻한 흰색
    "--txt2":         "#A8B0BC",   // 보조
    "--txt3":         "#6B7585",   // 힌트
    "--accent":       "#65A637",   // Splunk 그린 — 로고 공식 색상
    "--accent-dim":   "#1E2B1A",
    "--accent-text":  "#80C050",   // 밝은 녹색
    "--nav-text":     "#6B7585",
    "--topbar-bg":    "#16181C",
    "--section-text": "#3D4450",
    "--logo-text":    "#D8DEE9",
    "--shadow":       "none",
  },

  // ── 라이트: 완전한 밝은 테마. 보고서 출력용. ──────────────────
  light: {
    "--bg-base":      "#F4F5F7",
    "--bg-nav":       "#FFFFFF",
    "--bg-card":      "#FFFFFF",
    "--bg-card2":     "#F8F9FA",
    "--bg-input":     "#F4F5F7",
    "--bg-hover":     "#EFF1F4",
    "--bg-active":    "#E8EFF9",
    "--bdr":          "rgba(0,0,0,.08)",
    "--bdr2":         "rgba(0,0,0,.14)",
    "--txt":          "#0D1117",
    "--txt2":         "#1F2937",
    "--txt3":         "#6B7280",
    "--accent":       "#1D4ED8",
    "--accent-dim":   "#E8EFF9",
    "--accent-text":  "#1D4ED8",
    "--nav-text":     "#6B7280",
    "--topbar-bg":    "#FFFFFF",
    "--section-text": "#9CA3AF",
    "--logo-text":    "#111827",
    "--shadow":       "0 1px 2px rgba(0,0,0,.06)",
  },

  // ── 코퍼레이트: 흰 배경 + 네이비 사이드바. 임원 보고용. ────────
  corporate: {
    "--bg-base":      "#F0F2F5",
    "--bg-nav":       "#1E3A5F",
    "--bg-card":      "#FFFFFF",
    "--bg-card2":     "#F8F9FA",
    "--bg-input":     "#F0F2F5",
    "--bg-hover":     "#E8EDF4",
    "--bg-active":    "#2A4F7A",
    "--bdr":          "rgba(0,0,0,.07)",
    "--bdr2":         "rgba(0,0,0,.12)",
    "--txt":          "#0D1117",
    "--txt2":         "#1F2937",
    "--txt3":         "#6B7280",
    "--accent":       "#1E3A5F",
    "--accent-dim":   "#E8EDF4",
    "--accent-text":  "#1E3A5F",
    "--nav-text":     "#93C5FD",
    "--topbar-bg":    "#FFFFFF",
    "--section-text": "#93C5FD",
    "--logo-text":    "#FFFFFF",
    "--shadow":       "0 1px 3px rgba(0,0,0,.08)",
  },
};

// ── 상태 색상 (테마와 무관하게 일정) ─────────────────────────────
// 전세계 공통 의미: 빨강=위험, 주황=경고, 초록=안전
// 채도를 낮춰서 차분하게 유지
export const STATUS_COLORS = {
  critical: { bg:"#2D1515", border:"#5C2626", text:"#F87171" },
  high:     { bg:"#2D1E0F", border:"#5C3A1A", text:"#FB923C" },
  medium:   { bg:"#2D2810", border:"#5C4F1A", text:"#FBBF24" },
  low:      { bg:"#122D1A", border:"#1F5C32", text:"#4ADE80" },
  info:     { bg:"#111E30", border:"#1E3A5F", text:"#60A5FA" },
  ok:       { bg:"#122D1A", border:"#1F5C32", text:"#4ADE80" },
};

export function applyTheme(themeId) {
  const vars = themeVars[themeId] || themeVars.oracle;
  const root = document.documentElement;
  Object.entries(vars).forEach(([k, v]) => root.style.setProperty(k, v));
  localStorage.setItem("ssk_theme", themeId);
}

export function getStoredTheme() {
  return localStorage.getItem("ssk_theme") || "oracle";
}
