"""
rule_extractor.py
Parses the raw LLM response into structured fields.
Extracts Snort 3 rules as a list for rule_validator.py and rule_deployer.py

Used by pipeline.py:
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

    # valid only if delimiter present AND at least one Snort rule found
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
    """Extract lines that look like Snort rules."""
    lines = []
    for line in text.splitlines():
        line = line.strip()
        if re.match(r"^(alert|drop|reject|pass)\s+", line):
            lines.append(line)
    return lines


# ── Quick self-test ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    sample = """
The traffic profile indicates a SYN Flood attack.
---RULES---
alert tcp 172.16.0.5 any -> $HOME_NET any (msg:"SYN Flood"; flags:S,12; detection_filter:track by_src,count 1000,seconds 1; sid:9000001; rev:1;)
alert tcp 172.16.0.5 any -> $HOME_NET any (msg:"SYN Flood rate"; detection_filter:track by_src,count 5000,seconds 5; sid:9000002; rev:1;)
"""
    result = extract_rules(sample)
    print(f"valid       : {result['valid']}")
    print(f"rule_type   : {result['rule_type']}")
    print(f"snort_rules : {result['snort_rules']}")
    print(f"analysis    : {result['analysis'][:60]}...")
