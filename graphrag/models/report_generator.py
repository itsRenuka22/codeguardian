"""
Shared prompt builder for all LLM clients.
"""

SYSTEM = (
    "You are an expert cybersecurity engineer writing professional code security review reports. "
    "Be technical, concise, and actionable. Use markdown formatting."
)


def build_prompt(analysis: dict, code: str) -> str:
    verdict    = analysis.get("verdict", "unknown").upper()
    confidence = analysis.get("confidence", 0)
    language   = analysis.get("language_detected", "unknown")
    vulns      = ", ".join(analysis.get("vulnerability_types", [])) or "none detected"
    severity   = analysis.get("top_severity") or "unknown"
    matches    = analysis.get("total_matches", 0)

    ev_lines = []
    for e in analysis.get("evidence", [])[:3]:
        cwes = ", ".join(c["id"] for c in e.get("cwes", []))
        dist = e.get("similarity_distance", 1.0)
        ev_lines.append(
            f"  • {e.get('code_id')} | {e.get('severity')} severity "
            f"| similarity dist={dist:.3f} | CWEs: {cwes or 'N/A'}"
        )

    fix_lines = []
    for f in analysis.get("fix_guidance", [])[:3]:
        fix_lines.append(f"  • [{f.get('vuln_type', '?').replace('_', ' ')}] {f.get('description', '')}")

    code_snippet = code[:600] + ("…" if len(code) > 600 else "")

    return f"""Code under review ({language}):
```
{code_snippet}
```

Automated GraphRAG analysis:
- Verdict    : {verdict}  (confidence {confidence:.0%})
- Vulns found: {vulns}
- Top severity: {severity}
- Similar patterns in knowledge base: {matches}

Top evidence matches:
{chr(10).join(ev_lines) or "  (none found)"}

Recommended fixes from knowledge base:
{chr(10).join(fix_lines) or "  (none available)"}

Write a professional security report with exactly these four sections:
## Executive Summary
One paragraph on the overall security posture.

## Vulnerability Analysis
Explain each vulnerability, how it can be exploited, and the business impact.

## Remediation
Specific, code-level fix instructions with before/after examples where possible.

## Risk Rating
Severity level, estimated CVSS score range, and remediation priority.

Keep the report under 450 words. Be specific and actionable."""
