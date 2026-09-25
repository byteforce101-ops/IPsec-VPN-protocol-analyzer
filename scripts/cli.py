"""
IPsec VPN Security Analyzer - Command Line Interface (CLI)
Allows running protocol analysis, NIST security rule auditing, AI traffic classification,
and PDF report generation directly from the command line by passing a file path.

Usage:
  python scripts/cli.py <path_to_file.pcap_or_conf>
"""

import argparse
import os
import sys

# Ensure backend modules can be imported
backend_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend"))
sys.path.insert(0, backend_path)

from parser.pcap_parser import parse_pcap_file
from parser.config_parser import parse_config_file
from engine.rules import evaluate_rules
from engine.scorer import calculate_score
from ai.explainer import generate_ai_assessment
from reports.pdf_generator import generate_pdf, REPORTS_DIR


def run_cli_analysis(filepath: str):
    abs_path = os.path.abspath(filepath)
    if not os.path.exists(abs_path):
        print(f"Error: File not found at '{abs_path}'")
        sys.exit(1)

    filename = os.path.basename(abs_path)
    ext = os.path.splitext(filename)[1].lower()
    allowed_exts = [".pcap", ".pcapng", ".conf", ".cfg", ".txt"]

    if ext not in allowed_exts:
        print(f"Error: Unsupported file extension '{ext}'. Allowed: {', '.join(allowed_exts)}")
        sys.exit(1)

    print("\n" + "=" * 80)
    print("  IPsec VPN PROTOCOL ANALYZER - COMMAND LINE INTERFACE (CLI)")
    print("=" * 80)
    print(f"Analyzing File : {abs_path}")
    print(f"File Format    : {ext.upper()}")
    print("-" * 80)

    # 1. Parse File
    if ext in [".pcap", ".pcapng"]:
        parsed_data = parse_pcap_file(abs_path, filename)
    else:
        with open(abs_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        parsed_data = parse_config_file(content, filename)

    # 2. Evaluate Security Rules
    findings = evaluate_rules(parsed_data)

    # 3. Calculate Score & Grade
    score, grade, severity_counts = calculate_score(findings)

    # 4. Generate AI Assessment
    ai_data = generate_ai_assessment(findings, filename, score, grade)
    ai_summary = ai_data.get("aiSummary", "")

    # 5. Format Output
    params = parsed_data.get("parameters", {})
    ai_traffic = parsed_data.get("aiTrafficAnalysis", {})

    print("\n[+] PROTOCOL & CRYPTOGRAPHIC PARAMETERS")
    print(f"    - Key Exchange Protocol : {params.get('keyexchange', 'N/A').upper()}")
    print(f"    - Encryption Ciphers    : {', '.join(params.get('ciphers', [])) or 'None detected'}")
    print(f"    - Hash Algorithms       : {', '.join(params.get('hashes', [])) or 'None detected'}")
    print(f"    - Diffie-Hellman Groups : {', '.join(params.get('dh_groups', [])) or 'None detected'}")
    print(f"    - PFS Status            : {'Enabled' if params.get('pfs') else 'Disabled / Unverified'}")

    if ai_traffic.get("predictedCategory"):
        print("\n[+] AI ENCRYPTED TRAFFIC CLASSIFICATION")
        print(f"    - Predicted Category    : {ai_traffic['predictedCategory']}")
        print(f"    - AI Confidence         : {ai_traffic.get('confidence', 0)}%")
        print(f"    - Analysis Detail       : {ai_traffic.get('explanation', 'N/A')}")

    print(f"\n[+] SECURITY AUDIT ASSESSMENT")
    print(f"    - Overall Security Score: {score}/100")
    print(f"    - Risk Rating Grade     : {grade}")
    print(f"    - Severity Summary      : {severity_counts.get('Critical', 0)} Critical, {severity_counts.get('High', 0)} High, {severity_counts.get('Medium', 0)} Medium, {severity_counts.get('Low', 0)} Low")

    print(f"\n[+] EXECUTIVE AI SUMMARY")
    print(f"    {ai_summary}")

    print("\n[+] FINDINGS & THREAT MATRIX")
    if not findings:
        print("    No security vulnerabilities identified. Configuration follows NIST SP 800-77 best practices.")
    else:
        for idx, f in enumerate(findings, 1):
            print(f"    {idx}. [{f['severity'].upper()}] {f['title']}")
            print(f"       Category       : {f.get('category', 'General')}")
            print(f"       Evidence       : {f['detected']}")
            print(f"       Explanation    : {f['explanation']}")
            print(f"       Recommendation : {f['recommended']}")
            print()

    # 6. Generate PDF Report
    import uuid
    report_id = f"cli_{uuid.uuid4().hex[:8]}"
    result_dict = {
        "reportId": report_id,
        "scanName": f"CLI Scan: {filename}",
        "fileName": filename,
        "score": score,
        "grade": grade,
        "severityCounts": severity_counts,
        "aiSummary": ai_summary,
        "findings": findings,
        "technicalDetails": parsed_data.get("technical_snippet", ""),
    }

    pdf_path = generate_pdf(report_id, result_dict)
    print("=" * 80)
    print(f"[SUCCESS] PDF Executive Report Generated: {pdf_path}")
    print("=" * 80 + "\n")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python scripts/cli.py <path_to_file.pcap_or_conf>")
        print("Example: python scripts/cli.py samples/ikev2_aes256_pfs_secure.pcap")
        sys.exit(1)

    target_file = sys.argv[1]
    run_cli_analysis(target_file)
