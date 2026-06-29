import os
import json
import requests

GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")
GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

SYSTEM_PROMPT = """You are a security analyst reviewing static analysis (SAST) findings.
For each finding you are given, you must:
1. Classify the TRUE severity as one of: Critical, High, Medium, Low, Informational
   (the raw SAST tool severity is often noisy — use your judgement based on real exploitability)
2. Write a short, clear explanation (2-3 sentences) of what the vulnerability is and why it matters
3. Suggest a concrete fix (1-3 sentences)

Respond ONLY with valid JSON in this exact format, nothing else, no markdown fences:
{"severity": "...", "explanation": "...", "fix_suggestion": "..."}
"""


def classify_finding(finding: dict, language: str) -> dict:
    """
    Sends one finding (with its code snippet/context) to Gemini and returns
    the enriched result: severity, explanation, fix_suggestion.
    Falls back to safe defaults if the API call fails.
    """
    user_prompt = f"""Language: {language}
Rule triggered: {finding['rule']}
Tool's raw severity: {finding['raw_severity']}
Tool's message: {finding['message']}
Line number: {finding['line']}

Code context:
```
{finding['snippet']}
```
"""

    full_prompt = SYSTEM_PROMPT + "\n\n" + user_prompt

    try:
        response = requests.post(
            f"{GEMINI_URL}?key={GEMINI_API_KEY}",
            json={
                "contents": [{"parts": [{"text": full_prompt}]}],
                "generationConfig": {"temperature": 0.2},
            },
            timeout=30,
        )
        response.raise_for_status()
        data = response.json()
        raw_text = data["candidates"][0]["content"]["parts"][0]["text"].strip()

        # Gemini sometimes wraps JSON in ```json fences despite instructions — strip them
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()

        parsed = json.loads(raw_text)
        return {
            "line": finding["line"],
            "rule": finding["rule"],
            "snippet": finding["snippet"],
            "severity": parsed.get("severity", "Medium"),
            "explanation": parsed.get("explanation", ""),
            "fix_suggestion": parsed.get("fix_suggestion", ""),
        }
    except Exception as e:
        # If the LLM call fails for any reason, don't crash the whole scan —
        # just return the finding with a fallback severity.
        return {
            "line": finding["line"],
            "rule": finding["rule"],
            "snippet": finding["snippet"],
            "severity": "Medium",
            "explanation": f"Automated analysis unavailable: {str(e)}",
            "fix_suggestion": "Review this finding manually.",
        }


def analyze_findings(findings: list, language: str) -> list:
    """Runs classify_finding on every finding from the scan."""
    return [classify_finding(f, language) for f in findings]
