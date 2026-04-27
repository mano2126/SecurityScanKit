/**
 * 자산 등록 프리셋 설정
 * 경로: frontend/src/config/assetPresets.js
 *
 * ─ 사용법 ──────────────────────────────────────────────────────
 * group  : 셀렉트박스에 표시되는 그룹명 (optgroup)
 * items  : 해당 그룹의 선택 항목 목록
 * pcGroup: true 로 표시된 그룹의 items 는
 *          담당자 이름이 앞에 자동으로 붙습니다.
 *          예) 담당자 "최만호" + "외부망_업무용 PC"
 *           → 시스템명: "최만호_외부망_업무용 PC"
 *
 * ─ 항목 추가 예시 ────────────────────────────────────────────────
 * { group: "새 그룹", items: ["항목1", "항목2"] }
 * ────────────────────────────────────────────────────────────────
 */

export const SYSTEM_NAME_PRESETS = [
  {
    group: "PC/단말기",
    pcGroup: true,   // ← true: 담당자 이름 자동 앞에 붙음
    items: [
      "외부망_업무용 PC",
      "내부망_업무용 PC",
      "외부개발자_외부망_업무용 PC",
      "외부개발자_내부망_업무용 PC",
      "개발자 PC",
      "서버 관리 PC",
      "운영자 노트북",
    ],
  },
  {
    group: "웹/앱 서버",
    items: [
      "운영 웹서버",
      "개발 웹서버",
      "WAS 서버",
      "API 게이트웨이",
      "로드밸런서",
      "리버스 프록시",
    ],
  },
  {
    group: "데이터베이스",
    items: [
      "운영 DB(Oracle)",
      "운영 DB(MySQL)",
      "운영 DB(MSSQL)",
      "운영 DB(PostgreSQL)",
      "DB 이중화 서버",
      "백업 DB 서버",
    ],
  },
  {
    group: "인프라/네트워크",
    items: [
      "방화벽",
      "IPS/IDS",
      "웹방화벽(WAF)",
      "코어 스위치",
      "L4 스위치",
      "라우터",
      "VPN 게이트웨이",
    ],
  },
  {
    group: "파일/스토리지",
    items: [
      "NAS 서버",
      "백업 서버",
      "파일 서버",
      "FTP 서버",
    ],
  },
  {
    group: "보안 시스템",
    items: [
      "보안 관제 서버",
      "SIEM 서버",
      "취약점 스캐너",
      "NAC 서버",
      "DLP 서버",
    ],
  },
  {
    group: "기타/직접입력",
    items: [
      "기타 (직접 입력)",
    ],
  },
];

/** PC 그룹 항목 목록 (담당자 자동 붙임 대상) */
export const PC_ITEMS = SYSTEM_NAME_PRESETS
  .filter(g => g.pcGroup)
  .flatMap(g => g.items);
