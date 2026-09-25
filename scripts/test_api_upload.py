import os
import requests

API_URL = "http://127.0.0.1:8000/api/analyze"
SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))

test_files = [
    "ikev2_aes256_pfs_secure.pcap",
    "ikev1_3des_no_pfs_vulnerable.pcap",
    "ipsec_strongswan_vulnerable.conf",
    "ipsec_strongswan_secure.conf",
]

print("=" * 80)
print("  TESTING FASTAPI BACKEND API: POST /api/analyze")
print("=" * 80)
print()

for filename in test_files:
    filepath = os.path.join(SAMPLES_DIR, filename)
    if not os.path.exists(filepath):
        continue

    print(f"UPLOADING TO API: {filename}")
    with open(filepath, "rb") as f:
        files = {"file": (filename, f)}
        response = requests.post(API_URL, files=files)

    if response.status_code == 200:
        data = response.json()
        print(f"  Status       : SUCCESS (200 OK)")
        print(f"  Report ID    : {data.get('reportId')}")
        print(f"  Scan Name    : {data.get('scanName')}")
        print(f"  Score/Grade  : {data.get('score')}/100 ({data.get('grade')})")
        print(f"  AI Summary   : {data.get('aiSummary')}")
        print(f"  Findings     : {len(data.get('findings', []))} findings detected")
    else:
        print(f"  Status       : FAILED ({response.status_code})")
        print(f"  Error Detail : {response.text}")
    print("-" * 80)
