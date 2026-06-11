"""
rule_validator.py
Syntactic validation of LLM-generated Snort 3 rules.
Receives already-extracted rule list from rule_extractor.py.

Used by pipeline.py:
    from rule_validator import validate_rules
"""

import re
import subprocess
import tempfile
import os


# ── Semantic safety patterns ──────────────────────────────────────────────────

DANGEROUS_PATTERNS = [
    # Block all traffic without any condition
    r"(alert|drop)\s+ip\s+any\s+any\s+->\s+any\s+any\s+\(",
    # Rate limit count 0
    r"detection_filter\s*:.*count\s+0\s*,",
]


# ── Public API ────────────────────────────────────────────────────────────────

def validate_rules(snort_rules: list[str]) -> dict:
    """
    Validate extracted Snort 3 rules syntactically and semantically.

    Parameters
    ----------
    snort_rules : list[str]
        Already-extracted Snort rule lines from rule_extractor.py.

    Returns
    -------
    dict with keys:
        valid  : bool
        errors : list[str]
    """
    errors = []

    if not snort_rules:
        return {"valid": False, "errors": ["[snort] No rules to validate"]}

    # Semantic checks
    for rule in snort_rules:
        errors += _semantic_check(rule)

    # Syntactic check via snort -T
    errors += _validate_snort_binary(snort_rules)

    return {
        "valid":  len(errors) == 0,
        "errors": errors,
    }


# ── Validators ────────────────────────────────────────────────────────────────

def _validate_snort_binary(snort_rules: list[str]) -> list:
    """Test rules with snort -T, fall back to regex."""
    errors = []

    with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False) as f:
        f.write("\n".join(snort_rules) + "\n")
        tmp_path = f.name

    try:
        result = subprocess.run(
            ["snort", "-T", "-c", tmp_path],
            capture_output=True, text=True, timeout=15
        )
        if result.returncode != 0:
            errors.append(
                f"[snort] Syntax error: {result.stderr.strip()[:300]}"
            )
    except FileNotFoundError:
        errors += _validate_snort_regex(snort_rules)
    except subprocess.TimeoutExpired:
        errors.append("[snort] Validation timed out")
    finally:
        os.unlink(tmp_path)

    return errors


def _validate_snort_regex(snort_rules: list[str]) -> list:
    """Lightweight regex fallback — checks mandatory fields."""
    errors = []
    required = [r"\bsid:\d+", r"\bmsg:\"", r"\brev:\d+"]
    for rule in snort_rules:
        for pattern in required:
            if not re.search(pattern, rule):
                errors.append(
                    f"[snort-regex] Missing field '{pattern}' in: {rule[:80]}"
                )
    return errors


def _semantic_check(rule: str) -> list:
    """Safety checks per rule."""
    errors = []
    for pattern in DANGEROUS_PATTERNS:
        if re.search(pattern, rule, re.IGNORECASE):
            errors.append(
                f"[semantic] Dangerous pattern in rule: '{rule[:80]}'"
            )
    return errors


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    test_cases = [
        {
            "name": "SYN Flood — valid",
            "rules": [
                'alert tcp 172.16.0.5 any -> $HOME_NET any (msg:"SYN Flood"; flags:S,12; detection_filter:track by_src,count 1000,seconds 1; sid:9000001; rev:1;)'
            ],
        },
        {
            "name": "Missing sid — invalid",
            "rules": [
                'alert tcp any any -> $HOME_NET any (msg:"Test"; flags:S;)'
            ],
        },
        {
            "name": "Empty list — invalid",
            "rules": [],
        },
    ]

    for tc in test_cases:
        result = validate_rules(tc["rules"])
        status = "PASS" if result["valid"] else "FAIL"
        print(f"[{status}] {tc['name']}")
        for err in result["errors"]:
            print(f"       {err}")
