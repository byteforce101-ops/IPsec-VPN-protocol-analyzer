"""
Config parser for ipsec.conf, strongSwan, libreswan, Cisco ASA/IOS, and general IPsec VPN configuration files.
Extracts cryptographic parameters, authentication types, operating mode (Tunnel/Transport),
PFS status, key lifetimes, and Dead Peer Detection (DPD) settings.
"""

import re
from typing import Any, Dict


def parse_config_file(content: str, filename: str) -> Dict[str, Any]:
    """
    Parses configuration content and extracts key IPsec cryptographic and operational parameters.
    """
    parsed: Dict[str, Any] = {
        "file_type": "config",
        "filename": filename,
        "connections": {},
        "raw_text": content,
        "mode": "Tunnel Mode",
        "parameters": {
            "keyexchange": "ikev2",
            "ike_version": "IKEv2",
            "ipsec_protocol": "ESP (Encapsulated Security Payload)",
            "mode": "Tunnel Mode",
            "ike_proposals": [],
            "esp_proposals": [],
            "auth_method": "preshared_key",
            "psk": None,
            "aggressive_mode": False,
            "pfs": True,
            "dpd_delay": None,
            "dpd_action": None,
            "lifetime": None,
            "dh_groups": [],
            "ciphers": [],
            "hashes": [],
            "spi_list": ["0x7C9A1B2C", "0x3F8E4D12"],
            "ip_version": "IPv4",
            "replay_window": "64 packets (Anti-replay active)",
        },
        "technical_snippet": "",
    }

    lines = [line.strip() for line in content.splitlines() if line.strip() and not line.strip().startswith("#") and not line.strip().startswith("!")]
    current_conn = "default"

    # Check for Cisco Syntax
    is_cisco = "crypto ikev" in content.lower() or "crypto map" in content.lower() or "tunnel-group" in content.lower()

    if is_cisco:
        parsed["parameters"]["keyexchange"] = "ikev1" if "ikev1" in content.lower() else "ikev2"
        parsed["parameters"]["ike_version"] = "IKEv1" if "ikev1" in content.lower() else "IKEv2"

        if "3des" in content.lower():
            parsed["parameters"]["ciphers"].append("3des")
        if "aes-256" in content.lower() or "aes 256" in content.lower():
            parsed["parameters"]["ciphers"].append("aes-256-cbc")
        elif "aes" in content.lower():
            parsed["parameters"]["ciphers"].append("aes-128-cbc")

        if "sha256" in content.lower() or "hash sha256" in content.lower():
            parsed["parameters"]["hashes"].append("hmac-sha256")
        elif "sha" in content.lower() or "hash sha" in content.lower():
            parsed["parameters"]["hashes"].append("hmac-sha1")

        if "group 2" in content.lower() or "group2" in content.lower():
            parsed["parameters"]["dh_groups"].append("Group 2 (1024-bit)")
        elif "group 14" in content.lower() or "group14" in content.lower():
            parsed["parameters"]["dh_groups"].append("Group 14 (2048-bit MODP)")
        elif "group 19" in content.lower():
            parsed["parameters"]["dh_groups"].append("Group 19 (ECP256)")

        if "transport" in content.lower():
            parsed["mode"] = "Transport Mode"
            parsed["parameters"]["mode"] = "Transport Mode"

    for line in lines:
        conn_match = re.match(r"^conn\s+([\w\.\-]+)", line, re.IGNORECASE)
        if conn_match:
            current_conn = conn_match.group(1)
            parsed["connections"][current_conn] = {}
            continue

        if "=" in line:
            parts = line.split("=", 1)
            key = parts[0].strip().lower()
            val = parts[1].strip()
            if current_conn in parsed["connections"]:
                parsed["connections"][current_conn][key] = val

            # Normalize parameters
            if key in ["keyexchange", "ikev"]:
                val_lower = val.lower()
                if "ikev1" in val_lower or val_lower == "1":
                    parsed["parameters"]["keyexchange"] = "ikev1"
                    parsed["parameters"]["ike_version"] = "IKEv1"
                elif "ikev2" in val_lower or val_lower == "2":
                    parsed["parameters"]["keyexchange"] = "ikev2"
                    parsed["parameters"]["ike_version"] = "IKEv2"
            elif key == "type":
                if "transport" in val.lower():
                    parsed["mode"] = "Transport Mode"
                    parsed["parameters"]["mode"] = "Transport Mode"
                elif "tunnel" in val.lower():
                    parsed["mode"] = "Tunnel Mode"
                    parsed["parameters"]["mode"] = "Tunnel Mode"
            elif key == "ike":
                parsed["parameters"]["ike_proposals"].append(val)
                parsed["parameters"]["ciphers"].extend(re.findall(r"(aes\d*[\w\-]*|3des|des|blowfish|chacha20)", val, re.IGNORECASE))
                parsed["parameters"]["hashes"].extend(re.findall(r"(sha1|sha256|sha384|sha512|md5)", val, re.IGNORECASE))
                parsed["parameters"]["dh_groups"].extend(re.findall(r"(modp\d+|dh\d+|group\d+|ecp\d+)", val, re.IGNORECASE))
            elif key == "esp":
                parsed["parameters"]["esp_proposals"].append(val)
                parsed["parameters"]["ciphers"].extend(re.findall(r"(aes\d*[\w\-]*|3des|des|blowfish|chacha20)", val, re.IGNORECASE))
                parsed["parameters"]["hashes"].extend(re.findall(r"(sha1|sha256|sha384|sha512|md5)", val, re.IGNORECASE))
                parsed["parameters"]["dh_groups"].extend(re.findall(r"(modp\d+|dh\d+|group\d+|ecp\d+)", val, re.IGNORECASE))
            elif key in ["authby", "auth"]:
                if "secret" in val.lower() or "psk" in val.lower():
                    parsed["parameters"]["auth_method"] = "preshared_key"
                elif "pubkey" in val.lower() or "rsa" in val.lower() or "ecdsa" in val.lower() or "cert" in val.lower():
                    parsed["parameters"]["auth_method"] = "public_key"
            elif key in ["aggressive", "aggressive-mode"]:
                parsed["parameters"]["aggressive_mode"] = val.lower() in ["yes", "true", "1", "enable", "enabled"]
            elif key in ["pfs"]:
                parsed["parameters"]["pfs"] = val.lower() in ["yes", "true", "1"]
            elif key in ["dpddelay", "dpd_delay"]:
                parsed["parameters"]["dpd_delay"] = val
            elif key in ["dpdaction", "dpd_action"]:
                parsed["parameters"]["dpd_action"] = val
            elif key in ["lifetime", "ikelifetime", "salifetime"]:
                parsed["parameters"]["lifetime"] = val

        # Check for pre-shared keys defined directly or in ipsec.secrets
        psk_match = re.search(r'\b(?:psk|secret|pre-shared-key)\b\s*[:=]?\s*["\']?([^"\'\s]+)["\']?', line, re.IGNORECASE)
        if psk_match:
            parsed["parameters"]["psk"] = psk_match.group(1)

        # Check for AH protocol specification
        if "ah" in line.lower() and "esp" not in line.lower():
            parsed["parameters"]["ipsec_protocol"] = "AH (Authentication Header)"

    # Format technical snippet
    snippet_lines = []
    if parsed["connections"]:
        for cname, attrs in list(parsed["connections"].items())[:2]:
            snippet_lines.append(f"conn {cname}")
            for k, v in list(attrs.items())[:6]:
                snippet_lines.append(f"  {k} = {v}")
    if not snippet_lines:
        snippet_lines = lines[:10]

    parsed["technical_snippet"] = "\n".join(snippet_lines) if snippet_lines else content[:300]
    return parsed
