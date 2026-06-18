"""
rule_validator.py
Syntactic validation of LLM-generated Snort 3 rules.
Receives already-extracted rule list from rule_extractor.py.

Validation runs on klusids (10.34.0.28) via SSH — the actual IPS VM —
using a minimal snort_validate.lua without any rule includes, so only
the newly generated rule is validated in isolation.

Used by pipeline.py:
    from rule_validator import validate_rules
"""

import re
import subprocess
import tempfile
import os


SNORT_CONFIG_VALIDATE = "/tmp/snort_validate.lua"
IDS_VM_HOST           = "luser@10.34.0.28"
SSH_PORT              = "2222"
SSH_TIMEOUT           = 30

# ── Semantic safety patterns ──────────────────────────────────────────────────

DANGEROUS_PATTERNS = [
    r"(alert|drop)\s+ip\s+any\s+any\s+->\s+any\s+any\s+\(",
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

    # Syntactic check via snort -T on klusids over SSH
    errors += _validate_snort_ssh(snort_rules)

    return {
        "valid":  len(errors) == 0,
        "errors": errors,
    }


# ── Validators ────────────────────────────────────────────────────────────────

def _ensure_validate_config():
    """
    Ensure /tmp/snort_validate.lua exists on klusids.
    Uses Python to replace only the rules = [[ ... ]] block with an empty
    one, keeping the full Lua structure intact.
    Only creates the file if it does not already exist.
    """
    # Check if already exists
    result = subprocess.run(
        ["ssh", "-p", SSH_PORT, IDS_VM_HOST,
         "test -f /tmp/snort_validate.lua && echo exists"],
        capture_output=True, text=True, timeout=5
    )
    if "exists" in result.stdout:
        return

    # Create it via Python on klusids
    subprocess.run(
        [
            "ssh", "-p", SSH_PORT, IDS_VM_HOST,
            (
                "python3 -c \""
                "import re; "
                "c = open('/usr/local/etc/snort/snort.lua').read(); "
                "c = re.sub("
                "r'rules\\\\s*=\\\\s*\\\\[\\\\[.*?\\\\]\\\\]', "
                "'rules = [[]]', c, flags=re.DOTALL"
                "); "
                "open('/tmp/snort_validate.lua', 'w').write(c)"
                "\""
            ),
        ],
        capture_output=True, timeout=SSH_TIMEOUT
    )


def _validate_snort_ssh(snort_rules: list[str]) -> list:
    """
    Validate rules on klusids via SSH:
        1. Ensure /tmp/snort_validate.lua exists (no rule includes)
        2. Clean up old temp rule files
        3. Write rules to a temp file locally
        4. scp temp file to klusids /tmp/
        5. Run: snort -T -c /tmp/snort_validate.lua --rule-path /tmp/<tmpfile>
        6. Return errors from output
    Falls back to regex if SSH fails.
    """
    errors = []

    # Step 1: ensure minimal validate config exists on klusids
    _ensure_validate_config()

    # Step 2: clean up any leftover temp rule files
    subprocess.run(
        ["ssh", "-p", SSH_PORT, IDS_VM_HOST,
         "rm -f /tmp/llm_val_*.rules"],
        capture_output=True, timeout=5
    )

    with tempfile.NamedTemporaryFile(
            mode="w", suffix=".rules", delete=False, prefix="llm_val_") as f:
        f.write("\n".join(snort_rules) + "\n")
        tmp_local = f.name

    tmp_remote = f"/tmp/{os.path.basename(tmp_local)}"

    try:
        # Step 3: copy rules to klusids
        scp_result = subprocess.run(
            [
                "scp",
                "-P", SSH_PORT,
                tmp_local,
                f"{IDS_VM_HOST}:{tmp_remote}",
            ],
            capture_output=True, text=True, timeout=SSH_TIMEOUT
        )
        if scp_result.returncode != 0:
            errors.append(
                f"[snort-ssh] scp failed: {scp_result.stderr.strip()[:200]}"
            )
            return errors

        # Step 4: validate on klusids using isolated config
        ssh_result = subprocess.run(
            [
                "ssh",
                "-p", SSH_PORT,
                IDS_VM_HOST,
                (
                    f"cd /usr/local/etc/snort && "
                    f"sudo /usr/local/bin/snort -T "
                    f"-c {SNORT_CONFIG_VALIDATE} "
                    f"--daq afpacket "
                    f"--daq-dir /usr/local/lib/daq "
                    f"--plugin-path /usr/local/lib/snort "
                    f"--rule-path {tmp_remote} "
                    f"2>&1 | grep -E 'ERROR|FATAL|successfully' | head -20"
                ),
            ],
            capture_output=True, text=True, timeout=SSH_TIMEOUT
        )

        output = ssh_result.stdout.strip()

        if "Snort successfully validated" in output:
            pass  # valid
        elif "ERROR" in output or "FATAL" in output:
            for line in output.splitlines():
                if "ERROR" in line or "FATAL" in line:
                    errors.append(f"[snort-ssh] {line.strip()[:200]}")
        else:
            if ssh_result.returncode != 0:
                errors.append(
                    f"[snort-ssh] Validation failed (rc={ssh_result.returncode}): "
                    f"{output[:200]}"
                )

        # Step 5: cleanup remote temp file
        subprocess.run(
            ["ssh", "-p", SSH_PORT, IDS_VM_HOST,
             f"rm -f {tmp_remote}"],
            capture_output=True, timeout=5
        )

    except subprocess.TimeoutExpired:
        errors.append("[snort-ssh] Validation timed out")
    except Exception as e:
        errors += _validate_snort_regex(snort_rules)
    finally:
        os.unlink(tmp_local)

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
                'alert tcp 172.16.0.5 any -> $HOME_NET any (msg:"SYN Flood"; flags:S; detection_filter:track by_src, count 1000, seconds 1; sid:9000001; rev:1;)'
            ],
        },
        {
            "name": "depth old syntax — should fail",
            "rules": [
                'alert udp any any -> any any (msg:"Test"; content:"|30|"; offset:0; depth:1; detection_filter:track by_src, count 3, seconds 60; sid:9000002; rev:1;)'
            ],
        },
        {
            "name": "depth new syntax — should pass",
            "rules": [
                'alert udp any any -> any any (msg:"Test"; content:"|30|", offset 0, depth 1; detection_filter:track by_src, count 3, seconds 60; sid:9000003; rev:1;)'
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