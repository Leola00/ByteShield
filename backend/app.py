"""ByteShield Enterprise SOC Incident Response report generator (OpenAI)."""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from openai import OpenAI

BACKEND_DIR = Path(__file__).resolve().parent
load_dotenv(BACKEND_DIR / ".env")

SOC_INCIDENT_PROMPT = """You are ByteShield SOC — an enterprise Security Operations Center incident response analyst.

Generate a professional cyber incident report JSON aligned with NIST SP 800-61 Rev.2, SANS IR workflow, and MITRE ATT&CK v14.

Rules:
- Use real MITRE ATT&CK technique IDs where applicable (e.g. T1566.001, T1566.002, T1078, T1204.002).
- Extract all observable IoCs from the evidence (URLs, domains, emails, phones, IPs, filenames).
- Containment playbook steps must be actionable for a Tier-1/Tier-2 SOC analyst.
- Severity mapping: Critical (active fraud/credential harvest), High (confirmed phishing), Medium (suspicious), Low/Informational (benign).
- Write technical fields in English. Include a brief Arabic executive summary in incident.executiveSummaryAr.
- Be precise — do not invent IoCs not present in the evidence.

Return ONLY valid JSON matching this schema:
{
  "reportId": "BS-IR-YYYYMMDD-XXXX",
  "generatedAt": "ISO-8601 UTC",
  "reportVersion": "1.0",
  "frameworks": ["NIST SP 800-61", "MITRE ATT&CK", "SANS PICERL"],
  "incident": {
    "title": "Concise incident title",
    "executiveSummary": "2-3 sentence analyst summary",
    "executiveSummaryAr": "Arabic executive summary",
    "severity": "Critical | High | Medium | Low | Informational",
    "status": "Open | Triaging | Contained | Closed",
    "classification": "Phishing | Spearphishing | BEC | Banking Fraud | Smishing | Vishing | Malware | Credential Harvesting | Social Engineering | Benign",
    "confidence": 0,
    "riskScore": 0,
    "attackVector": "Primary vector description",
    "impactAssessment": "Business/technical impact",
    "affectedAssets": ["asset or data type"],
    "timeline": [
      {"phase": "Reconnaissance | Delivery | Exploitation | Actions on Objectives", "timestamp": "Estimated or N/A", "description": "..."}
    ]
  },
  "mitreAttack": {
    "tactics": ["Initial Access", "..."],
    "techniques": [
      {
        "id": "T1566.002",
        "name": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "description": "How this technique applies",
        "confidence": "High | Medium | Low"
      }
    ],
    "killChainPhase": "Delivery | Exploitation | ..."
  },
  "indicatorsOfCompromise": {
    "urls": [{"value": "...", "severity": "critical | high | medium | low", "context": "..."}],
    "domains": [{"value": "...", "severity": "...", "context": "..."}],
    "ipAddresses": [{"value": "...", "severity": "...", "context": "..."}],
    "emailAddresses": [{"value": "...", "severity": "...", "context": "..."}],
    "phoneNumbers": [{"value": "...", "severity": "...", "context": "..."}],
    "fileHashes": [],
    "other": [{"value": "...", "type": "...", "severity": "...", "context": "..."}]
  },
  "containmentPlaybook": {
    "priority": "P1 | P2 | P3 | P4",
    "immediateActions": [
      {"step": 1, "action": "...", "owner": "SOC Analyst | IR Lead | Network Team", "estimatedTime": "15 min"}
    ],
    "shortTermActions": [{"step": 1, "action": "...", "owner": "...", "estimatedTime": "..."}],
    "longTermActions": [{"step": 1, "action": "...", "owner": "...", "estimatedTime": "..."}],
    "escalationCriteria": ["When to escalate to IR manager / CISO"],
    "communicationPlan": "Stakeholder notification guidance"
  },
  "detectionAndResponse": {
    "detectionRules": [{"name": "...", "logic": "SIEM/SOAR rule logic", "dataSource": "Email Gateway | EDR | Proxy"}],
    "recommendedTools": ["Tool or control"],
    "huntingQueries": ["Hypothesis-driven hunt query"]
  },
  "references": ["Relevant standards or threat intel refs"],
  "analystNotes": "Additional SOC analyst commentary"
}
"""


def _default_report_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d")
    suffix = uuid.uuid4().hex[:6].upper()
    return f"BS-IR-{stamp}-{suffix}"


def generate_soc_report(payload: dict) -> dict:
    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY not configured in backend/.env")

    text = str(payload.get("text") or "").strip()
    if not text:
        raise ValueError("No evidence text provided")

    content_type = str(payload.get("contentType") or "Message")
    triage = payload.get("triage") or {}

    triage_block = ""
    if triage:
        triage_block = f"""
Prior triage assessment (from ByteShield detector):
- Risk score: {triage.get('riskScore', 'N/A')}/100
- Classification: {triage.get('classification', 'N/A')}
- Threat type: {triage.get('threatType', 'N/A')}
- Key findings: {', '.join(triage.get('reasoning', [])[:6]) or 'N/A'}
"""

    user_message = f"""Content type: {content_type}
{triage_block}
--- Evidence ---
{text[:14000]}
"""

    model = os.environ.get("OPENAI_SOC_MODEL") or os.environ.get("OPENAI_MODEL") or "gpt-4o-mini"
    client = OpenAI(api_key=api_key)

    completion = client.chat.completions.create(
        model=model,
        temperature=0,
        messages=[
            {"role": "system", "content": SOC_INCIDENT_PROMPT},
            {"role": "user", "content": user_message},
        ],
        response_format={"type": "json_object"},
    )

    content = completion.choices[0].message.content
    if not content:
        raise RuntimeError("Empty response from OpenAI")

    report = json.loads(content)
    report.setdefault("reportId", _default_report_id())
    report.setdefault("generatedAt", datetime.now(timezone.utc).isoformat())
    report.setdefault("reportVersion", "1.0")
    return report


def main() -> int:
    try:
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8")

        raw = sys.stdin.read()
        payload = json.loads(raw) if raw.strip() else {}
        data = generate_soc_report(payload)
        print(json.dumps({"success": True, "data": data}, ensure_ascii=False))
        return 0
    except Exception as exc:  # noqa: BLE001 — CLI boundary
        print(json.dumps({"success": False, "error": str(exc)}, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    sys.exit(main())