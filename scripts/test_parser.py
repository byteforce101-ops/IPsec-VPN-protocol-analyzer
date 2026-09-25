import os
import sys

# Add backend directory to module search path
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, backend_path)

from parser.pcap_parser import parse_pcap_file
from parser.config_parser import parse_config_file
from engine.rules import evaluate_rules
from engine.scorer import calculate_score

samples_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))

test_files = [
    ("ikev2_aes256_pfs_secure.pcap", "pcap"),
    ("ikev1_3des_no_pfs_vulnerable.pcap", "pcap"),
    ("ikev2_weak_dh_group2.pcap", "pcap"),
    ("ipsec_strongswan_secure.conf", "conf"),
    ("ipsec_strongswan_vulnerable.conf", "conf"),
    ("cisco_vpn_legacy.cfg", "conf"),
]

print("=" * 80)
print("  IPsec VPN PROTOCOL ANALYZER - AUTOMATED TEST SUITE")
print("=" * 80)
print()

for filename, ftype in test_files:
    filepath = os.path.join(samples_dir, filename)
    if not os.path.exists(filepath):
        continue

    print(f"FILE: {filename} [{ftype.upper()}]")
    print("-" * 80)

    if ftype == "pcap":
        parsed_data = parse_pcap_file(filepath, filename)
    else:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        parsed_data = parse_config_file(content, filename)

    params = parsed_data.get("parameters", {})
    print(f"  Key Exchange : {params.get('keyexchange', 'N/A').upper()}")
    print(f"  Ciphers      : {params.get('ciphers', [])}")
    print(f"  DH Groups    : {params.get('dh_groups', [])}")
    print(f"  PFS Enabled  : {params.get('pfs', 'Unknown')}")

    findings = evaluate_rules(parsed_data)
    score, grade, counts = calculate_score(findings)

    print(f"  Security Score: {score}/100 | Grade: {grade}")
    print(f"  Findings Count: {len(findings)} (Critical: {counts.get('Critical', 0)}, High: {counts.get('High', 0)}, Med: {counts.get('Medium', 0)}, Low: {counts.get('Low', 0)})")
    
    for f in findings:
        print(f"    * [{f['severity'].upper()}] {f['title']}")
        print(f"      Detected: {f['detected']}")
        print(f"      Recommendation: {f['recommended']}")
    print()
