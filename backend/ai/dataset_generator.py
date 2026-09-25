"""
Dataset Generator for IPsec Encrypted Traffic Classification using Standard Python CSV.
Generates structured training data based on flow statistics (packet size distributions,
burst dynamics, packet counts, and flow duration) across 5 traffic categories:
- Web (HTTP/HTTPS browsing)
- Video (Streaming media e.g. YouTube/Netflix)
- VoIP (Voice over IP calls e.g. Zoom/Teams audio)
- FileTransfer (FTP/SFTP/Large downloads)
- ICMP (Ping/Keep-alive control traffic)
"""

import csv
import math
import os
import random

DATASET_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "dataset"))
os.makedirs(DATASET_DIR, exist_ok=True)
DATASET_CSV = os.path.join(DATASET_DIR, "vpn_traffic_dataset.csv")

FIELDNAMES = [
    "flow_duration",
    "packet_count",
    "bytes_total",
    "avg_pkt_size",
    "std_pkt_size",
    "max_pkt_size",
    "min_pkt_size",
    "packets_per_sec",
    "bytes_per_sec",
    "traffic_category",
]


def generate_flow_features(traffic_type: str) -> dict:
    """Generates realistic statistical features for a specific traffic category."""
    if traffic_type == "Web":
        packet_count = random.randint(15, 120)
        sizes = [random.randint(64, 200) for _ in range(int(packet_count * 0.4))] + \
                [random.randint(800, 1460) for _ in range(int(packet_count * 0.6))]
        duration = random.uniform(1.5, 15.0)

    elif traffic_type == "Video":
        packet_count = random.randint(200, 1500)
        sizes = [random.randint(1100, 1480) for _ in range(packet_count)]
        duration = random.uniform(10.0, 120.0)

    elif traffic_type == "VoIP":
        packet_count = random.randint(100, 800)
        sizes = [random.randint(140, 260) for _ in range(packet_count)]
        duration = random.uniform(5.0, 60.0)

    elif traffic_type == "FileTransfer":
        packet_count = random.randint(300, 3000)
        sizes = [random.randint(1400, 1500) for _ in range(packet_count)]
        duration = random.uniform(5.0, 90.0)

    elif traffic_type == "ICMP":
        packet_count = random.randint(5, 50)
        sizes = [random.randint(64, 128) for _ in range(packet_count)]
        duration = random.uniform(1.0, 20.0)

    else:
        packet_count = random.randint(10, 100)
        sizes = [random.randint(100, 1000) for _ in range(packet_count)]
        duration = random.uniform(2.0, 30.0)

    bytes_total = sum(sizes)
    mean_size = bytes_total / max(len(sizes), 1)
    variance = sum((x - mean_size) ** 2 for x in sizes) / max(len(sizes), 1)
    std_size = math.sqrt(variance)

    return {
        "flow_duration": round(duration, 3),
        "packet_count": packet_count,
        "bytes_total": bytes_total,
        "avg_pkt_size": round(mean_size, 2),
        "std_pkt_size": round(std_size, 2),
        "max_pkt_size": max(sizes),
        "min_pkt_size": min(sizes),
        "packets_per_sec": round(packet_count / max(duration, 0.1), 2),
        "bytes_per_sec": round(bytes_total / max(duration, 0.1), 2),
        "traffic_category": traffic_type,
    }


def generate_dataset(num_samples: int = 1500) -> str:
    categories = ["Web", "Video", "VoIP", "FileTransfer", "ICMP"]
    rows = []

    for _ in range(num_samples):
        cat = random.choice(categories)
        rows.append(generate_flow_features(cat))

    with open(DATASET_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=FIELDNAMES)
        writer.writeheader()
        writer.writerows(rows)

    print(f"Generated {len(rows)} samples dataset saved to: {DATASET_CSV}")
    return DATASET_CSV


if __name__ == "__main__":
    generate_dataset()
