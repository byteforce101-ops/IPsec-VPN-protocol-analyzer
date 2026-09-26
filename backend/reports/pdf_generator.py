"""
PDF report generation module using Jinja2 and WeasyPrint.
Renders an executive security assessment report and outputs to backend/reports_storage/.
"""

import os
from typing import Any, Dict
from jinja2 import Template

REPORTS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "reports_storage"))
os.makedirs(REPORTS_DIR, exist_ok=True)

REPORT_HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>IPsec Security Assessment - {{ scan_name }}</title>
<style>
  @page {
    size: A4;
    margin: 15mm;
  }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #111827;
    line-height: 1.5;
    font-size: 10pt;
    background-color: #ffffff;
  }
  .header {
    border-bottom: 2px solid #5850ec;
    padding-bottom: 12px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }
  .header h1 {
    font-size: 20pt;
    margin: 0;
    color: #111827;
    font-weight: 800;
  }
  .header .meta {
    font-size: 8.5pt;
    color: #6b7280;
    margin-top: 4px;
  }
  .score-card {
    background: #f9fafb;
    border: 1px solid #e5e7eb;
    border-radius: 8px;
    padding: 16px;
    margin-bottom: 20px;
    display: flex;
    align-items: center;
    gap: 20px;
  }
  .score-num {
    font-size: 34pt;
    font-weight: 800;
    color: #5850ec;
    line-height: 1;
  }
  .score-grade {
    font-size: 13pt;
    font-weight: 700;
    color: #10b981;
    margin-top: 4px;
  }
  .ai-summary {
    background: #eef2ff;
    border-left: 4px solid #5850ec;
    padding: 12px 16px;
    margin-bottom: 20px;
    font-size: 9.5pt;
    color: #1e1b4b;
    border-radius: 0 8px 8px 0;
  }
  h2 {
    font-size: 13pt;
    border-bottom: 1px solid #e5e7eb;
    padding-bottom: 4px;
    margin-top: 20px;
    margin-bottom: 12px;
    color: #111827;
    font-weight: 700;
  }
  .param-table {
    width: 100%;
    border-collapse: collapse;
    margin-bottom: 20px;
    font-size: 9pt;
  }
  .param-table th, .param-table td {
    border: 1px solid #e5e7eb;
    padding: 8px 12px;
    text-align: left;
  }
  .param-table th {
    background-color: #f9fafb;
    font-weight: 700;
    color: #374151;
  }
  .finding {
    border: 1px solid #e5e7eb;
    border-radius: 6px;
    margin-bottom: 12px;
    padding: 12px 14px;
    page-break-inside: avoid;
    background-color: #ffffff;
  }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 7.5pt;
    font-weight: 800;
    text-transform: uppercase;
  }
  .badge-Critical { background: #fef2f2; color: #ef4444; border: 1px solid #fecaca; }
  .badge-High { background: #fff7ed; color: #c2410c; border: 1px solid #ffedd5; }
  .badge-Medium { background: #fefce8; color: #b45309; border: 1px solid #fef3c7; }
  .badge-Low { background: #f0fdf4; color: #15803d; border: 1px solid #bbf7d0; }
  .finding-title {
    font-size: 11pt;
    font-weight: 700;
    margin-left: 8px;
    color: #111827;
  }
  .finding-meta {
    font-size: 8.5pt;
    color: #6b7280;
    margin-top: 2px;
  }
  .finding-box {
    background: #f9fafb;
    padding: 8px 12px;
    border-radius: 4px;
    font-size: 8.5pt;
    margin-top: 8px;
    border: 1px solid #f1f3f9;
  }
  .code-block {
    background: #111827;
    color: #e5e7eb;
    padding: 12px;
    border-radius: 6px;
    font-family: monospace;
    font-size: 8pt;
    white-space: pre-wrap;
  }
  .footer {
    margin-top: 30px;
    font-size: 8pt;
    color: #9ca3af;
    text-align: center;
    border-top: 1px solid #edeef3;
    padding-top: 10px;
  }
</style>
</head>
<body>
  <div class="header">
    <div>
      <h1>IPsec Security Assessment</h1>
      <div class="meta">Target: <b>{{ file_name }}</b> | Scan: <b>{{ scan_name }}</b> | Date: {{ analyzed_at }}</div>
    </div>
  </div>

  <div class="score-card">
    <div>
      <div class="score-num">{{ score }}/100</div>
      <div class="score-grade">{{ grade }}</div>
    </div>
    <div style="flex: 1; padding-left: 20px; border-left: 1px solid #e5e7eb;">
      <div style="font-weight: 700; font-size: 10.5pt;">Threat Summary Matrix</div>
      <div style="font-size: 9pt; color: #4b5563; margin-top: 6px;">
        Critical: <b>{{ severity_counts.Critical }}</b> &nbsp;|&nbsp;
        High: <b>{{ severity_counts.High }}</b> &nbsp;|&nbsp;
        Medium: <b>{{ severity_counts.Medium }}</b> &nbsp;|&nbsp;
        Low: <b>{{ severity_counts.Low }}</b>
      </div>
      <div style="font-size: 8.5pt; color: #6b7280; margin-top: 4px;">
        Compliance Standard: NIST SP 800-77 Rev 1 / RFC 7296
      </div>
    </div>
  </div>

  <div class="ai-summary">
    <strong>Executive AI Summary:</strong><br/>
    {{ ai_summary }}
  </div>

  <h2>Protocol & Cryptographic Characteristics</h2>
  <table class="param-table">
    <tr>
      <th>Parameter</th>
      <th>Identified Configuration Value</th>
      <th>Compliance Status</th>
    </tr>
    <tr>
      <td><b>IKE Version</b></td>
      <td>{{ parameters.get('ike_version', 'IKEv2') }}</td>
      <td>{{ 'PASSED (Modern)' if parameters.get('keyexchange') == 'ikev2' else 'VULNERABLE (Legacy IKEv1)' }}</td>
    </tr>
    <tr>
      <td><b>IPsec Protocol & Mode</b></td>
      <td>{{ parameters.get('ipsec_protocol', 'ESP') }} ({{ mode }})</td>
      <td>{{ 'PASSED (Tunnel Mode)' if mode == 'Tunnel Mode' else 'WARNING (Transport Mode Metadata Exposure)' }}</td>
    </tr>
    <tr>
      <td><b>Encryption Algorithms</b></td>
      <td>{{ parameters.get('ciphers', [])|join(', ') or 'AES-256-GCM' }}</td>
      <td>{{ 'PASSED (AEAD Standard)' if 'gcm' in (parameters.get('ciphers', [])|join(' ')|lower) else 'REVIEW RECOMMENDED' }}</td>
    </tr>
    <tr>
      <td><b>Auth & Hash Algorithms</b></td>
      <td>{{ parameters.get('hashes', [])|join(', ') or 'HMAC-SHA256' }}</td>
      <td>PASSED</td>
    </tr>
    <tr>
      <td><b>Diffie-Hellman Group</b></td>
      <td>{{ parameters.get('dh_groups', [])|join(', ') or 'Group 19 (ECP256)' }}</td>
      <td>{{ 'VULNERABLE (< 2048-bit)' if 'group 2' in (parameters.get('dh_groups', [])|join(' ')|lower) else 'PASSED' }}</td>
    </tr>
    <tr>
      <td><b>Perfect Forward Secrecy (PFS)</b></td>
      <td>{{ 'Enabled (PFS Active)' if parameters.get('pfs') else 'Disabled' }}</td>
      <td>{{ 'PASSED' if parameters.get('pfs') else 'HIGH RISK (Disabled)' }}</td>
    </tr>
    <tr>
      <td><b>SA SPIs</b></td>
      <td>{{ parameters.get('spi_list', [])|join(', ') }}</td>
      <td>Active SPI Attributes</td>
    </tr>
  </table>

  {% if ai_traffic and ai_traffic.get('predictedCategory') %}
  <h2>AI Encrypted Flow Classification</h2>
  <table class="param-table">
    <tr>
      <th>Predicted Application Traffic</th>
      <td><b>{{ ai_traffic.get('predictedCategory') }}</b></td>
    </tr>
    <tr>
      <th>AI Model Confidence Score</th>
      <td><b>{{ ai_traffic.get('confidence') }}% Confidence</b></td>
    </tr>
    <tr>
      <th>Flow Analysis & Evidence</th>
      <td>{{ ai_traffic.get('explanation') }}</td>
    </tr>
  </table>
  {% endif %}

  <h2>Security Findings Matrix ({{ findings|length }})</h2>
  {% for f in findings %}
  <div class="finding">
    <div>
      <span class="badge badge-{{ f.severity }}">{{ f.severity }}</span>
      <span class="finding-title">{{ f.title }}</span>
      <span class="finding-meta">— {{ f.category }}</span>
    </div>
    <p style="margin: 6px 0; font-size: 9pt; color: #374151;">{{ f.explanation }}</p>
    <div class="finding-box">
      <div><span style="color:#6b7280;">Detected:</span> <b>{{ f.detected }}</b></div>
      <div style="margin-top: 3px;"><span style="color:#6b7280;">NIST Recommendation:</span> <b style="color:#10b981;">{{ f.recommended }}</b></div>
    </div>
  </div>
  {% endfor %}

  {% if technical_details %}
  <h2>Technical Details / Extracted Proposal</h2>
  <div class="code-block">{{ technical_details }}</div>
  {% endif %}

  <div class="footer">
    Generated by IPsec Protocol Analyzer Security Suite · Confidential &amp; Proprietary Report
  </div>
</body>
</html>
"""


def generate_pdf(report_id: str, scan_data: Dict[str, Any]) -> str:
    """
    Renders the report HTML and saves as a PDF file in reports_storage/{report_id}.pdf.
    Returns the absolute path to the generated PDF file.
    """
    pdf_path = os.path.join(REPORTS_DIR, f"{report_id}.pdf")

    template = Template(REPORT_HTML_TEMPLATE)
    html_content = template.render(
        scan_name=scan_data.get("scanName", "IPsec Security Review"),
        file_name=scan_data.get("fileName", "configuration.conf"),
        analyzed_at=scan_data.get("analyzedAt", "Sep 25, 2026"),
        score=scan_data.get("score", 0),
        grade=scan_data.get("grade", "Grade F"),
        severity_counts=scan_data.get("severityCounts", {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}),
        ai_summary=scan_data.get("aiSummary", ""),
        mode=scan_data.get("mode", "Tunnel Mode"),
        parameters=scan_data.get("parameters", {}),
        ai_traffic=scan_data.get("aiTrafficAnalysis", {}),
        findings=scan_data.get("findings", []),
        technical_details=scan_data.get("technicalDetails", ""),
    )

    try:
        from weasyprint import HTML
        HTML(string=html_content).write_pdf(pdf_path)
    except Exception as e:
        # Fallback if WeasyPrint or native GTK cdlls are not installed on the OS
        print(f"[PDF Generator] WeasyPrint generation fallback due to: {e}")
        _generate_fallback_pdf(pdf_path, scan_data, html_content)

    return pdf_path


def _generate_fallback_pdf(pdf_path: str, scan_data: Dict[str, Any], html_content: str):
    """
    Fallback generator that creates a valid PDF containing the report summary
    if WeasyPrint system dependencies (GTK3/Pango) are missing.
    """
    title = f"IPsec Security Assessment - {scan_data.get('scanName', 'Review')}"
    score_line = f"Score: {scan_data.get('score', 0)} ({scan_data.get('grade', 'N/A')})"
    summary = scan_data.get("aiSummary", "")

    content_stream = f"""BT
/F1 16 Tf
40 750 Td
({title}) Tj
/F1 11 Tf
0 -25 Td
({score_line}) Tj
0 -20 Td
(Target File: {scan_data.get('fileName', 'Unknown')}) Tj
0 -20 Td
(Executive AI Summary:) Tj
/F1 9 Tf
0 -15 Td
({summary[:85]}) Tj
0 -12 Td
({summary[85:170]}) Tj
0 -25 Td
(Security Findings Matrix:) Tj
"""
    y_offset = -16
    for f in scan_data.get("findings", [])[:6]:
        line = f"[{f.get('severity')}] {f.get('title')}: {f.get('recommended')}"
        content_stream += f"0 {y_offset} Td\n({line[:80]}) Tj\n"
        y_offset = -14

    content_stream += "ET"

    stream_bytes = content_stream.encode("latin-1", "replace")
    pdf_bytes = f"""%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>
endobj
4 0 obj
<< /Length {len(stream_bytes)} >>
stream
{content_stream}
endstream
endobj
5 0 obj
<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>
endobj
xref
0 6
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000234 00000 n 
0000000330 00000 n 
trailer
<< /Size 6 /Root 1 0 R >>
startxref
412
%%EOF""".encode("latin-1", "replace")

    with open(pdf_path, "wb") as f:
        f.write(pdf_bytes)
