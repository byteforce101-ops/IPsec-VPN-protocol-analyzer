"""
Security rule engine for IPsec/IKE configurations and packet captures.
Audits configuration parameters against NIST SP 800-77 Rev 1, NSA CNSA, and RFC standards.
Evaluates Cryptographic Strength, Compliance, SA Parameters, Key Lifetime, Replay Protection,
PFS Configuration, Cipher Suite Strength, Metadata Exposure, and Operating Modes.
"""

from typing import Any, Dict, List


def evaluate_rules(parsed_data: Dict[str, Any]) -> List[Dict[str, str]]:
    """
    Evaluates parsed IPsec parameters and produces structured findings.
    Each finding matches the frontend schema:
    {
      "severity": "Critical" | "High" | "Medium" | "Low",
      "title": str,
      "category": str,
      "explanation": str,
      "detected": str,
      "recommended": str
    }
    """
    params = parsed_data.get("parameters", {})
    mode = parsed_data.get("mode", params.get("mode", "Tunnel Mode"))
    file_type = parsed_data.get("file_type", "config")
    findings: List[Dict[str, str]] = []

    # 1. Authentication Security & PSK Entropy Audit
    auth_method = params.get("auth_method", "preshared_key")
    psk = params.get("psk")
    
    if auth_method == "preshared_key":
        if psk:
            weak_words = ["vpn", "key", "secret", "admin", "123", "cisco", "pass"]
            if len(psk) < 20 or any(common in psk.lower() for common in weak_words):
                findings.append({
                    "severity": "Critical",
                    "title": "Weak or predictable pre-shared key detected",
                    "category": "Authentication",
                    "explanation": "The configured pre-shared key is short or predictable, leaving the tunnel vulnerable to offline dictionary & rainbow table attacks.",
                    "detected": psk if len(psk) <= 24 else f"{psk[:10]}...",
                    "recommended": "Use a 32+ character high-entropy random secret or PKI certificates (NIST SP 800-77)",
                })
        elif file_type == "config":
            # For configuration files, unconfigured or blank PSK string is critical
            findings.append({
                "severity": "Critical",
                "title": "Pre-shared key authentication with low entropy",
                "category": "Authentication",
                "explanation": "Pre-shared key authentication is configured without verifiable entropy guarantees or automated rotation.",
                "detected": "Pre-Shared Key (PSK)",
                "recommended": "Migrate to X.509 RSA/ECDSA certificates (NIST SP 800-77 Rev 1)",
            })

    # 2. IKE Protocol Version & Metadata Exposure (Aggressive Mode ID Leakage)
    keyexchange = params.get("keyexchange", "ikev2").lower()
    aggressive = params.get("aggressive_mode", False)
    
    if aggressive or keyexchange in ["ikev1", "ike"]:
        findings.append({
            "severity": "High",
            "title": "Aggressive mode or legacy IKEv1 enabled (Metadata Leakage)",
            "category": "IKE Negotiation & Metadata",
            "explanation": "IKEv1 Aggressive Mode transmits user identity hashes in cleartext during initial handshake packets, making them susceptible to active interception and offline password cracking.",
            "detected": "IKEv1 Aggressive Mode",
            "recommended": "Enforce IKEv2 Main Mode with cryptographic identity protection (RFC 7296)",
        })

    # 3. Encryption Algorithm & Cipher Suite Strength Audit
    ciphers = [c.lower() for c in params.get("ciphers", [])]
    detected_weak_cipher = None
    for c in ciphers:
        if "3des" in c or "des" in c or "blowfish" in c:
            detected_weak_cipher = c
            break

    if detected_weak_cipher:
        findings.append({
            "severity": "High",
            "title": "Legacy 64-bit block cipher proposal enabled",
            "category": "Cryptography",
            "explanation": "3DES and 64-bit block ciphers are deprecated due to Sweet32 collision attacks (CVE-2016-2183) and low throughput performance.",
            "detected": detected_weak_cipher.upper(),
            "recommended": "Enforce AES-256-GCM or ChaCha20-Poly1305 with AEAD (NIST SP 800-77 Rev 1)",
        })
    else:
        has_gcm = any("gcm" in c or "chacha" in c for c in ciphers)
        if not has_gcm and ciphers:
            is_aes_256 = any("256" in c for c in ciphers)
            if is_aes_256:
                findings.append({
                    "severity": "Low",
                    "title": "Non-AEAD cipher mode configured (AES-256-CBC + HMAC)",
                    "category": "Cryptography",
                    "explanation": "AES-256-CBC provides strong 256-bit encryption confidentiality, but lacks integrated AEAD authentication.",
                    "detected": ciphers[0] if ciphers else "aes-256-cbc",
                    "recommended": "Upgrade cipher proposal to AEAD mode: AES-256-GCM (RFC 4106 / NIST SP 800-77)",
                })
            else:
                findings.append({
                    "severity": "Medium",
                    "title": "Non-AEAD 128-bit cipher mode configured (AES-128-CBC + HMAC)",
                    "category": "Cryptography",
                    "explanation": "128-bit CBC cipher suites separate encryption and message authentication, increasing latency and vulnerability to padding oracle attacks.",
                    "detected": ciphers[0] if ciphers else "aes-128-cbc",
                    "recommended": "Upgrade cipher proposal to AEAD mode: AES-256-GCM (RFC 4106 / NIST SP 800-77)",
                })

    # 4. Diffie-Hellman Key Exchange Group Strength
    dh_groups = [str(g).lower() for g in params.get("dh_groups", [])]
    weak_dh = None
    for dh in dh_groups:
        if any(w in dh for w in ["modp1024", "modp768", "group1", "group2", "group5"]):
            weak_dh = dh
            break

    if weak_dh:
        findings.append({
            "severity": "High",
            "title": "Weak Diffie-Hellman group (< 2048-bit)",
            "category": "Key Exchange",
            "explanation": "Diffie-Hellman Groups 1, 2, and 5 offer less than 112 bits of security margin and are vulnerable to pre-computed Logjam attacks.",
            "detected": weak_dh,
            "recommended": "Enforce DH Group 14 (2048-bit MODP), Group 19 (256-bit ECP), or Group 21",
        })

    # 5. Perfect Forward Secrecy (PFS) Configuration
    pfs_enabled = params.get("pfs", True)
    if not pfs_enabled:
        findings.append({
            "severity": "High",
            "title": "Perfect Forward Secrecy (PFS) disabled",
            "category": "Key Lifetime & PFS",
            "explanation": "Without PFS, compromising a long-term gateway private key allows retrospective decryption of all recorded past session traffic.",
            "detected": "PFS Disabled",
            "recommended": "Enable PFS (pfs=yes) to generate ephemeral Diffie-Hellman keys per Phase 2 rekey",
        })

    # 6. VPN Operating Mode Evaluation (Tunnel Mode vs Transport Mode Metadata Exposure)
    if mode == "Transport Mode":
        findings.append({
            "severity": "Medium",
            "title": "Transport Mode deployed on public WAN (Metadata Exposure)",
            "category": "Operating Mode Security",
            "explanation": "Transport Mode encrypts only upper-layer payloads, leaving original IP packet headers exposed. Over public networks, this exposes endpoint metadata and inner communication topology.",
            "detected": "Transport Mode",
            "recommended": "Deploy Tunnel Mode for gateway-to-gateway or site-to-site WAN communication to encapsulate inner IP headers.",
        })

    # 7. Protocol Assessment (AH vs ESP)
    ipsec_protocol = params.get("ipsec_protocol", "ESP")
    if "AH" in ipsec_protocol:
        findings.append({
            "severity": "Medium",
            "title": "AH (Authentication Header) protocol enabled without payload encryption",
            "category": "Protocol Characteristics",
            "explanation": "AH protocol provides packet integrity and authentication but does NOT provide payload confidentiality/encryption. AH also fails through NAT routers.",
            "detected": "AH (Authentication Header)",
            "recommended": "Migrate to ESP (IP Protocol 50) with AEAD authenticated encryption.",
        })

    # 8. Dead Peer Detection (DPD) & Tunnel Availability Audit
    dpd_delay = params.get("dpd_delay")
    if dpd_delay:
        digits = "".join(filter(str.isdigit, str(dpd_delay)))
        delay_sec = int(digits) if digits else 120
        if delay_sec > 90:
            findings.append({
                "severity": "Low",
                "title": "DPD interval is conservative",
                "category": "Availability",
                "explanation": f"The Dead Peer Detection interval ({delay_sec}s) may delay recovery when a tunnel peer unexpectedly disconnects.",
                "detected": f"{delay_sec} seconds",
                "recommended": "Set DPD interval between 30 and 60 seconds with dpdaction=restart",
            })
    elif file_type == "config":
        findings.append({
            "severity": "Low",
            "title": "DPD interval unverified or default",
            "category": "Availability",
            "explanation": "Explicit Dead Peer Detection parameters should be configured to prevent blackholing VPN traffic when peers fail.",
            "detected": "Unconfigured / Default",
            "recommended": "Specify dpddelay=30s and dpdaction=restart",
        })

    return findings
