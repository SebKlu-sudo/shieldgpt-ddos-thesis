"""
attack_descriptions.py
Shared attack metadata for CIC-DDoS2019.
Imported by gen_prompt_ddos2019.py, run_ddos2019.py and prompt_builder.py.
"""

ATTACK_DICT = {
    "Syn": {
        "name": "SYN Flood",
        "description": (
            "a TCP SYN flood attack. The attacker sends a large number of SYN "
            "packets to the target without completing the three-way handshake, "
            "exhausting the server connection table with half-open entries."
        ),
    },
    "LDAP": {
        "name": "LDAP Amplification",
        "description": (
            "a LDAP amplification DDoS attack. The attacker sends spoofed LDAP "
            "requests to publicly accessible LDAP servers, which respond with "
            "much larger replies directed at the victim."
        ),
    },
    "MSSQL": {
        "name": "MSSQL Amplification",
        "description": (
            "a MSSQL amplification DDoS attack. The attacker exploits Microsoft "
            "SQL Server response mechanism by sending small spoofed queries "
            "that generate disproportionately large responses toward the victim."
        ),
    },
    "NetBIOS": {
        "name": "NetBIOS Amplification",
        "description": (
            "a NetBIOS amplification DDoS attack. The attacker sends spoofed "
            "NetBIOS name service requests to open resolvers, which return "
            "amplified responses to the victim IP address."
        ),
    },
    "Portmap": {
        "name": "Portmap Amplification",
        "description": (
            "a Portmap amplification DDoS attack. The attacker abuses the ONC "
            "RPC portmapper service by sending small spoofed requests that "
            "trigger large responses directed at the victim."
        ),
    },
    "UDP": {
        "name": "UDP Flood",
        "description": (
            "a UDP flood attack. The attacker sends a high volume of UDP packets "
            "to random ports on the target, exhausting bandwidth and processing "
            "resources."
        ),
    },
    "UDPLag": {
        "name": "UDP-Lag",
        "description": (
            "a UDP-Lag attack targeting real-time services by inducing high "
            "latency through sustained UDP traffic at moderate rates."
        ),
    },
    "benign": {
        "name": "Benign",
        "description": "benign network traffic.",
    },
}

SYSTEM_PROMPT = (
"""You are a senior network security engineer responsible for \
defending a Linux server against DDoS attacks.
 
You have the following mitigation tool available on the server:
  1. Snort 3 rule — signature-based detection and inline blocking
 
Your task:
  Step 1 - Analysis: Analyse the traffic profile and explain in 2-3 sentences \
why it is indicative of the described attack.
  Step 2 - Mitigation: Write a Snort 3 rule that detects and blocks this \
specific attack based on the traffic characteristics above. The rule must \
include: action, protocol, src/dst IP/port, msg, sid, rev. Use \
detection_filter for rate-based detection where appropriate. \
Use $HOME_NET for the victim address. For the attacker address, use the \
specific source IP from the traffic profile if available, \
otherwise use $EXTERNAL_NET.
 
Always separate Step 1 and Step 2 with the delimiter: ---RULES---
 
Only provide Snort 3 rules.
)
