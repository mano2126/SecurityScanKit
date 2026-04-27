"""
AI 취약점 분석기 - Claude API 활용
- 스캔 결과를 바탕으로 금융권 맞춤 보안 권고사항 생성
- 우선순위 조치 계획 수립
- ISMS-P, 금융보안원 기준 매핑
"""
import os
import json
import aiohttp
from typing import Dict


SYSTEM_PROMPT = """당신은 대한민국 금융회사 전담 보안 컨설턴트입니다.
ISMS-P 인증, 금융보안원 취약점 점검 가이드, 전자금융감독규정에 정통한 전문가입니다.

주어진 보안 스캔 결과를 분석하여 다음을 제공하십시오:
1. 전반적인 보안 위험 평가 (경영진 보고용)
2. 긴급/중요/일반 조치 사항 분류
3. 각 취약점에 대한 금융규제 연관성 (ISMS-P 통제항목, 전자금융감독규정 등)
4. 구체적인 조치 방법 및 우선순위
5. 재발 방지를 위한 보안 강화 방안

반드시 JSON 형식으로만 응답하고, 코드블록 없이 순수 JSON만 반환하십시오."""


class AIAnalyzer:
    def __init__(self):
        self.api_url = "https://api.anthropic.com/v1/messages"
        self.model = "claude-sonnet-4-20250514"

    async def analyze(self, findings: dict) -> dict:
        """Claude API를 이용한 취약점 AI 분석"""

        # 취약점 요약 생성
        all_vulns = []
        for scan_type, data in findings.items():
            if isinstance(data, dict) and "vulnerabilities" in data:
                for v in data["vulnerabilities"]:
                    all_vulns.append({
                        "scan_type": scan_type,
                        "id": v.get("id"),
                        "title": v.get("title"),
                        "severity": v.get("severity"),
                        "description": v.get("description", "")[:200]
                    })

        prompt = f"""다음은 금융회사 서버 보안 취약점 스캔 결과입니다. 분석해 주십시오.

발견된 취약점 목록 ({len(all_vulns)}개):
{json.dumps(all_vulns, ensure_ascii=False, indent=2)}

다음 JSON 구조로만 응답하십시오:
{{
  "executive_summary": "경영진용 위험 요약 (3-5문장, 한국어)",
  "risk_assessment": {{
    "overall_risk": "위험/경고/주의/양호",
    "key_risks": ["주요 위험 1", "주요 위험 2", "주요 위험 3"]
  }},
  "immediate_actions": [
    {{
      "priority": 1,
      "title": "조치 제목",
      "vuln_ids": ["관련 취약점 ID"],
      "action": "구체적 조치 방법",
      "deadline": "즉시/1주일 이내/1개월 이내"
    }}
  ],
  "regulatory_mapping": [
    {{
      "vuln_id": "취약점 ID",
      "regulation": "해당 규정/통제항목",
      "risk": "미준수 시 위험"
    }}
  ],
  "security_enhancement": {{
    "short_term": ["단기 개선사항 (1-3개월)"],
    "mid_term": ["중기 개선사항 (3-6개월)"],
    "long_term": ["장기 개선사항 (6개월 이상)"]
  }},
  "compliance_checklist": [
    {{
      "item": "점검 항목",
      "standard": "근거 기준",
      "status": "조치 필요/권고/양호"
    }}
  ]
}}"""

        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "model": self.model,
                    "max_tokens": 1000,
                    "system": SYSTEM_PROMPT,
                    "messages": [{"role": "user", "content": prompt}]
                }
                async with session.post(
                    self.api_url,
                    headers={"Content-Type": "application/json"},
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=60)
                ) as resp:
                    data = await resp.json()

                    if data.get("content") and len(data["content"]) > 0:
                        text = data["content"][0].get("text", "{}")
                        # 코드블록 제거
                        text = text.strip()
                        if text.startswith("```"):
                            text = text.split("```")[1]
                            if text.startswith("json"):
                                text = text[4:]
                        return json.loads(text.strip())
                    return self._fallback_analysis(all_vulns)

        except Exception as e:
            return self._fallback_analysis(all_vulns)

    def _fallback_analysis(self, vulns: list) -> dict:
        """API 실패 시 기본 분석 결과"""
        critical = [v for v in vulns if v.get("severity") == "critical"]
        high = [v for v in vulns if v.get("severity") == "high"]

        return {
            "executive_summary": f"총 {len(vulns)}개의 취약점이 발견되었습니다. "
                                  f"그 중 치명적(Critical) {len(critical)}개, "
                                  f"고위험(High) {len(high)}개가 포함되어 있어 즉각적인 조치가 필요합니다.",
            "risk_assessment": {
                "overall_risk": "위험" if critical else ("경고" if high else "주의"),
                "key_risks": [v["title"] for v in (critical + high)[:3]]
            },
            "immediate_actions": [
                {
                    "priority": i + 1,
                    "title": v["title"],
                    "vuln_ids": [v["id"]],
                    "action": "전문가 검토 및 즉시 조치 필요",
                    "deadline": "즉시"
                }
                for i, v in enumerate(critical[:5])
            ],
            "regulatory_mapping": [],
            "security_enhancement": {
                "short_term": ["취약점 패치 적용", "방화벽 규칙 검토"],
                "mid_term": ["보안 정책 수립", "정기 점검 체계 구축"],
                "long_term": ["ISMS-P 인증 준비", "보안 아키텍처 개선"]
            },
            "compliance_checklist": []
        }
