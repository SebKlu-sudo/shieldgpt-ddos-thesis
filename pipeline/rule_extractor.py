"""
rule_extractor.py
Parses the raw LLM response into structured fields.
Extracts Snort 3 rules as a list — handles single-line and multi-line rules.

Used by pipeline.py and run_ddos2019.py:
    from rule_extractor import extract_rules
"""

import re

DELIMITER = "---RULES---"


def extract_rules(response: str) -> dict:
    """
    Split LLM response at ---RULES--- delimiter.
    Extract Snort 3 rules as a list.

    Returns dict with keys:
        analysis    : str       — analysis text before delimiter
        rules       : str       — raw rule text after delimiter
        snort_rules : list[str] — extracted Snort rule lines
        valid       : bool      — True if delimiter present AND rules found
        rule_type   : str       — "snort" or "unknown"
    """
    if DELIMITER in response:
        parts    = response.split(DELIMITER, 1)
        analysis = parts[0].strip()
        rules    = parts[1].strip()
        valid    = True
    else:
        analysis = ""
        rules    = response.strip()
        valid    = False

    snort_rules = _extract_snort_rules(rules)
    rule_type   = "snort" if snort_rules else "unknown"

    if valid and not snort_rules:
        valid = False

    return {
        "analysis":    analysis,
        "rules":       rules,
        "snort_rules": snort_rules,
        "valid":       valid,
        "rule_type":   rule_type,
    }


def _extract_snort_rules(text: str) -> list[str]:
    """Extract Snort rules — handles both single-line and multi-line rules."""
    lines        = []
    current_rule = ""
    in_rule      = False

    for line in text.splitlines():
        line_stripped = line.strip()

        if re.match(r"^(alert|drop|reject|pass)\s+", line_stripped):
            if current_rule:
                lines.append(current_rule.strip())
            current_rule = line_stripped
            in_rule      = True
            if line_stripped.endswith(")") or line_stripped.endswith(";)"):
                lines.append(current_rule.strip())
                current_rule = ""
                in_rule      = False

        elif in_rule:
            current_rule += " " + line_stripped
            if line_stripped.endswith(")") or line_stripped.endswith(";)"):
                lines.append(current_rule.strip())
                current_rule = ""
                in_rule      = False

    if current_rule:
        lines.append(current_rule.strip())

    return lines
