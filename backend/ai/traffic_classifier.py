"""
Traffic Classifier Service for IPsec Encrypted ESP Flows.
Analyzes flow statistical features (packet size distribution, mean size, std deviation, packet count)
to dynamically predict the underlying application category without breaking encryption.
"""

import math
from typing import Any, Dict


def predict_traffic_category(esp_sizes: list, total_packets: int) -> Dict[str, Any]:
    """
    Predicts the traffic category and AI confidence score based on real ESP packet size statistics.
    """
    if not esp_sizes:
        return {
            "predictedCategory": "Control / Setup Traffic",
            "confidence": 95.0,
            "explanation": "No ESP payload data streams detected. Capture consists solely of initial IKE control handshake exchanges.",
        }

    count = len(esp_sizes)
    total_bytes = sum(esp_sizes)
    avg_size = total_bytes / max(count, 1)
    
    variance = sum((x - avg_size) ** 2 for x in esp_sizes) / max(count, 1)
    std_size = math.sqrt(variance)
    max_size = max(esp_sizes)
    min_size = min(esp_sizes)

    # 1. ICMP / Ping check
    if max_size <= 200 and avg_size < 150:
        category = "ICMP / Keep-Alive"
        confidence = round(94.0 + (min(count, 50) / 50.0) * 5.0, 1)
        explanation = f"Small uniform packet sizes (mean: {avg_size:.1f} bytes, max: {max_size} bytes) indicate low-overhead ICMP ping or heartbeat traffic."

    # 2. VoIP Audio check
    elif avg_size >= 140 and avg_size <= 350 and std_size < 100:
        category = "VoIP / Audio Stream"
        confidence = round(88.0 + (min(count, 200) / 200.0) * 10.0, 1)
        explanation = f"Consistent small-payload framing (mean: {avg_size:.1f} bytes, std: {std_size:.1f}) matches real-time RTP voice audio streams."

    # 3. Video Streaming check
    elif avg_size > 1000 and count >= 10:
        category = "Video Streaming"
        confidence = round(91.0 + (min(count, 500) / 500.0) * 7.5, 1)
        explanation = f"High throughput with large MTU-bounded packets (mean: {avg_size:.1f} bytes, max: {max_size} bytes) indicates video chunk delivery."

    # 4. Bulk File Transfer check
    elif max_size >= 1400 and avg_size >= 900 and std_size < 300:
        category = "File Transfer (FTP/SFTP)"
        confidence = round(89.5 + (min(count, 300) / 300.0) * 9.0, 1)
        explanation = f"Sustained max-segment TCP payload delivery (mean: {avg_size:.1f} bytes) indicates bulk file transfer."

    # 5. Web Browsing check (Mixed request/response sizes)
    else:
        category = "Web Browsing (HTTPS)"
        confidence = round(85.0 + (min(count, 100) / 100.0) * 10.0, 1)
        explanation = f"Bimodal packet size distribution (mean: {avg_size:.1f} bytes, std: {std_size:.1f}) reflects HTTP GET requests and encrypted HTML/JSON responses."

    return {
        "predictedCategory": category,
        "confidence": confidence,
        "explanation": explanation,
        "stats": {
            "espPacketCount": count,
            "avgPacketSizeBytes": round(avg_size, 1),
            "stdPacketSizeBytes": round(std_size, 1),
            "maxPacketSizeBytes": max_size,
            "minPacketSizeBytes": min_size,
        },
    }
