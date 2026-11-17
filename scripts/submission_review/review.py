#!/usr/bin/env python3
"""
Pre-submission review for VDP/bug-bounty reports.
Uses an LLM judge to check for quality, completeness, and policy compliance
before submitting a finding to a program.

Usage: python3 review.py <report.md> [--model MODEL] [--api-key KEY]
"""
import argparse
import asyncio
import json
import pathlib
import sys

try:
    import httpx
except ImportError:
    sys.exit("httpx required: pip install httpx")

REVIEW_PROMPT = """\
You are a senior security researcher reviewing a vulnerability report before submission to a bug bounty or VDP program.

Evaluate the report on these dimensions and return a JSON object:

{
  "verdict": "SUBMIT" | "REVISE" | "WITHHOLD",
  "score": 0-100,
  "issues": ["list of specific issues"],
  "suggestions": ["list of concrete improvements"],
  "summary": "one paragraph executive summary of your assessment"
}

Criteria:
1. **Impact clarity**: Is the security impact clearly described with a measured severity?
2. **Reproducibility**: Does the report include step-by-step reproduction instructions?
3. **Evidence**: Is there proof (screenshots, request/response, curl commands)?
4. **Scope compliance**: Does the target appear to be in scope? No clearly out-of-scope claims?
5. **Completeness**: Title, description, impact, steps, evidence, remediation recommendation?
6. **Professionalism**: Clear writing, no inflammatory language, no exaggerated claims?
7. **Ethical compliance**: No data exfiltration beyond what's needed to prove the issue?

Verdict guide:
- SUBMIT: Score >= 75, no blocking issues
- REVISE: Score 50-74, fixable issues before submission
- WITHHOLD: Score < 50, or scope/ethical issues

Report to review:
---
{report}
---

Return only valid JSON."""


async def review(report_text: str, endpoint: str, model: str, api_key: str) -> dict:
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"
    prompt = REVIEW_PROMPT.replace("{report}", report_text)
    body = {
        "model": model,
        "max_tokens": 1024,
        "messages": [{"role": "user", "content": prompt}],
    }
    async with httpx.AsyncClient() as client:
        r = await client.post(endpoint, json=body, headers=headers, timeout=120)
        r.raise_for_status()
        data = r.json()
        if "choices" in data:
            content = data["choices"][0]["message"]["content"]
        elif "content" in data:
            content = data["content"][0]["text"]
        else:
            content = json.dumps(data)
    # Parse JSON from response (may be wrapped in ```json fences)
    content = content.strip()
    if content.startswith("```"):
        content = content.split("```")[1]
        if content.startswith("json"):
            content = content[4:]
    return json.loads(content)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("report", help="Path to the report file (Markdown)")
    parser.add_argument("--endpoint", default="http://localhost:11434/v1/chat/completions")
    parser.add_argument("--model", default="llama3.2")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()

    report_path = pathlib.Path(args.report)
    if not report_path.exists():
        sys.exit(f"error: {args.report} not found")

    report_text = report_path.read_text()

    result = asyncio.run(review(report_text, args.endpoint, args.model, args.api_key))

    print(f"\nVerdict : {result.get('verdict', '?')}")
    print(f"Score   : {result.get('score', '?')}/100")
    print(f"\nSummary : {result.get('summary', '')}")

    issues = result.get("issues", [])
    if issues:
        print("\nIssues:")
        for i in issues:
            print(f"  - {i}")

    suggestions = result.get("suggestions", [])
    if suggestions:
        print("\nSuggestions:")
        for s in suggestions:
            print(f"  - {s}")

    verdict = result.get("verdict", "REVISE")
    sys.exit(0 if verdict == "SUBMIT" else 1)


if __name__ == "__main__":
    main()
