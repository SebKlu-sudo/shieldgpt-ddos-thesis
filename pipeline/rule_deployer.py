"""
rule_deployer.py
Deploys validated Snort 3 rules to klusids (IDS-VM) via SSH.
Receives already-extracted rule list from rule_extractor.py.

kllums  (10.34.0.29) — this script runs here
klusids (10.34.0.28) — rules are deployed here via SSH

Used by pipeline.py:
    from rule_deployer import deploy_rules
"""

import re
import subprocess
import time
import logging

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

IDS_VM_HOST      = "luser@10.34.0.28"
SNORT_RULES_FILE = "/usr/local/etc/snort/rules/llm_generated.rules"
SNORT_PID_FILE   = "/var/run/snort/snort.pid"
SSH_TIMEOUT      = 10  # seconds


# ── SSH helper ────────────────────────────────────────────────────────────────

def _ssh(cmd: str) -> subprocess.CompletedProcess:
    """Run a shell command on klusids via SSH."""
    return subprocess.run(
        ["ssh", "-p", "2222",
         "-o", "StrictHostKeyChecking=no",
         "-o", "BatchMode=yes",
         IDS_VM_HOST, cmd],
        capture_output=True, text=True, timeout=SSH_TIMEOUT
    )


# ── Public API ────────────────────────────────────────────────────────────────

def deploy_rules(snort_rules: list[str]) -> dict:
    """
    Deploy validated Snort 3 rules to klusids via SSH.

    Parameters
    ----------
    snort_rules : list[str]
        Already-extracted Snort rule lines from rule_extractor.py.

    Returns
    -------
    dict with keys:
        success  : bool
        deployed : list[str]
        errors   : list[str]
        t_deploy : float
    """
    deployed = []
    errors   = []

    if not snort_rules:
        return {
            "success":  False,
            "deployed": [],
            "errors":   ["[snort] No rules to deploy"],
            "t_deploy": time.time(),
        }

    # Append each rule to llm_generated.rules on klusids
    for rule in snort_rules:
        escaped = rule.replace("'", "'\\''")
        cmd     = f"echo '{escaped}' | sudo -n tee -a {SNORT_RULES_FILE}"
        try:
            result = _ssh(cmd)
            if result.returncode == 0:
                deployed.append(rule[:80])
                logger.info(f"[snort] Appended: {rule[:80]}")
            else:
                errors.append(
                    f"[snort] Write failed: {result.stderr.strip()[:200]}"
                )
        except subprocess.TimeoutExpired:
            errors.append("[snort] SSH timeout writing rule")
        except Exception as e:
            errors.append(f"[snort] SSH exception: {e}")

    # Reload Snort via SIGHUP
    if not errors:
        errors += _reload_snort()

    return {
        "success":  len(errors) == 0,
        "deployed": deployed,
        "errors":   errors,
        "t_deploy": time.time(),
    }


def _reload_snort() -> list:
    """Send SIGHUP to Snort on klusids to reload rules."""
    errors = []
    cmd = (
        f"sudo -n kill -SIGHUP $(cat {SNORT_PID_FILE} 2>/dev/null) "
        f"2>/dev/null && echo OK || echo FAIL"
    )
    try:
        result = _ssh(cmd)
        if "OK" in result.stdout:
            logger.info("[snort] Reloaded successfully")
        else:
            errors.append(
                f"[snort] Reload failed: {result.stdout.strip()[:200]}"
            )
    except subprocess.TimeoutExpired:
        errors.append("[snort] SSH timeout during reload")
    except Exception as e:
        errors.append(f"[snort] Reload exception: {e}")
    return errors


# ── SSH connectivity test ─────────────────────────────────────────────────────

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    print("=== rule_deployer.py — SSH connectivity test ===\n")

    try:
        result = _ssh("echo 'SSH OK' && hostname")
        if result.returncode == 0:
            print(f"[OK] Connected to klusids: {result.stdout.strip()}")
        else:
            print(f"[FAIL] SSH error: {result.stderr.strip()}")
    except Exception as e:
        print(f"[FAIL] Exception: {e}")
