import os
from scapy.all import IP, IPv6, UDP, Raw, wrpcap

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples"))
os.makedirs(SAMPLES_DIR, exist_ok=True)


def build_ikev2_secure_packet():
    """Generates a synthetic secure IKEv2 SA negotiation packet payload containing modern ciphers."""
    payload_str = (
        "IKEv2_SA_INIT_REQ "
        "Encr: AES-256-GCM, Hash: HMAC-SHA256, DH_Group: Group 19 (ECP256), PFS: Enabled, Auth: Certificate, Mode: Tunnel"
    )
    raw_payload = payload_str.encode("utf-8")
    
    header = bytearray(28)
    header[0:8] = b"\x01\x02\x03\x04\x05\x06\x07\x08"
    header[8:16] = b"\x00" * 8
    header[16] = 0x20  # Version 2.0
    header[18] = 34    # Exchange Type IKE_SA_INIT
    header[19] = 0x08
    
    full_payload = bytes(header) + raw_payload
    return IP(src="192.168.1.10", dst="192.168.1.1") / UDP(sport=500, dport=500) / Raw(load=full_payload)


def build_ikev1_vulnerable_packet():
    """Generates a synthetic IKEv1 Aggressive Mode packet payload containing legacy/weak ciphers and transport mode."""
    payload_str = (
        "IKEv1_Aggressive_Mode "
        "Encr: 3DES, Hash: HMAC-SHA1, DH_Group: Group 2 (1024-bit), PFS: Disabled, PSK: vpn123, Mode: Transport"
    )
    raw_payload = payload_str.encode("utf-8")
    
    header = bytearray(28)
    header[0:8] = b"\xaa\xbb\xcc\xdd\xee\xff\x00\x11"
    header[8:16] = b"\x00" * 8
    header[16] = 0x10  # Version 1.0
    header[18] = 4     # Aggressive Mode
    header[19] = 0x08
    
    full_payload = bytes(header) + raw_payload
    return IP(src="10.0.0.5", dst="10.0.0.1") / UDP(sport=500, dport=500) / Raw(load=full_payload)


def build_ikev2_weak_dh_packet():
    """Generates IKEv2 with weak DH Group 2."""
    payload_str = (
        "IKEv2_SA_INIT_REQ "
        "Encr: AES-256-CBC, Hash: HMAC-SHA1, DH_Group: Group 2 (1024-bit), PFS: Disabled, Mode: Tunnel"
    )
    raw_payload = payload_str.encode("utf-8")
    
    header = bytearray(28)
    header[0:8] = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    header[8:16] = b"\x00" * 8
    header[16] = 0x20
    header[18] = 34
    
    full_payload = bytes(header) + raw_payload
    return IP(src="172.16.0.2", dst="172.16.0.1") / UDP(sport=500, dport=500) / Raw(load=full_payload)


def build_ikev2_ipv6_ah_packet():
    """Generates IKEv2 IPv6 packet with AH and AES-128-CBC."""
    payload_str = (
        "IKEv2_SA_INIT_REQ "
        "Protocol: AH + ESP, Encr: AES-128-CBC, Hash: HMAC-SHA256, DH_Group: Group 14 (2048-bit MODP), PFS: Enabled, IP: IPv6"
    )
    raw_payload = payload_str.encode("utf-8")
    
    header = bytearray(28)
    header[0:8] = b"\x66\x77\x88\x99\xaa\xbb\xcc\xdd"
    header[8:16] = b"\x00" * 8
    header[16] = 0x20
    header[18] = 34
    
    full_payload = bytes(header) + raw_payload
    return IPv6(src="2001:db8::10", dst="2001:db8::1") / UDP(sport=500, dport=500) / Raw(load=full_payload)


def build_esp_packets(src_ip, dst_ip, count=20, spi=0x12345678, payload_type="video", is_ipv6=False):
    """Generates synthetic ESP packets (IP protocol 50) simulating encrypted tunnel traffic."""
    esp_packets = []
    for seq in range(1, count + 1):
        esp_header = spi.to_bytes(4, byteorder="big") + seq.to_bytes(4, byteorder="big")
        
        # Vary payload size based on simulated traffic type
        if payload_type == "video":
            payload_len = 1200 + (seq % 4) * 60
        elif payload_type == "voip":
            payload_len = 160 + (seq % 3) * 20
        elif payload_type == "whatsapp":
            payload_len = 80 + (seq % 5) * 40
        elif payload_type == "icmp":
            payload_len = 64
        else:
            payload_len = 800 + (seq % 10) * 50

        # Inner packet header simulation for Tunnel Mode (0x45 for IPv4 inner IP header)
        inner_ip_header = b"\x45\x00\x00\x20\x00\x01\x00\x00\x40\x06\x00\x00\x0a\x00\x00\x02\x0a\x00\x00\x03"
        dummy_encrypted_data = inner_ip_header + os.urandom(max(0, payload_len - len(inner_ip_header)))
        
        if is_ipv6:
            pkt = IPv6(src=src_ip, dst=dst_ip, nh=50) / Raw(load=esp_header + dummy_encrypted_data)
        else:
            pkt = IP(src=src_ip, dst=dst_ip, proto=50) / Raw(load=esp_header + dummy_encrypted_data)
        
        esp_packets.append(pkt)
    return esp_packets


def build_ah_packets(src_ip, dst_ip, count=10, spi=0x99AABBCC, is_ipv6=False):
    """Generates synthetic AH packets (IP protocol 51)."""
    ah_packets = []
    for seq in range(1, count + 1):
        ah_header = b"\x32\x04\x00\x00" + spi.to_bytes(4, byteorder="big") + seq.to_bytes(4, byteorder="big") + os.urandom(12)
        dummy_payload = os.urandom(100)
        
        if is_ipv6:
            pkt = IPv6(src=src_ip, dst=dst_ip, nh=51) / Raw(load=ah_header + dummy_payload)
        else:
            pkt = IP(src=src_ip, dst=dst_ip, proto=51) / Raw(load=ah_header + dummy_payload)
        
        ah_packets.append(pkt)
    return ah_packets


def create_config_files():
    """Generates sample IPsec configuration files (.conf and .cfg)."""
    
    # 1. Vulnerable strongSwan config
    vulnerable_conf = """# Sample Vulnerable strongSwan IPsec Configuration
config setup
    charondebug="ike 2, knl 2, cfg 2"

conn vulnerable-site-to-site
    keyexchange=ikev1
    type=transport
    aggressive=yes
    authby=secret
    left=192.168.1.1
    right=203.0.113.50
    ike=3des-sha1-modp1024!
    esp=3des-sha1!
    pfs=no
    auto=start
"""
    vulnerable_conf_path = os.path.join(SAMPLES_DIR, "ipsec_strongswan_vulnerable.conf")
    with open(vulnerable_conf_path, "w", encoding="utf-8") as f:
        f.write(vulnerable_conf)
    print(f"Created: {vulnerable_conf_path}")

    # 2. Secure strongSwan config
    secure_conf = """# Sample Highly Secure strongSwan IPsec Configuration (NIST SP 800-77 Compliant)
config setup
    charondebug="ike 1, knl 1, cfg 1"

conn secure-cloud-tunnel
    keyexchange=ikev2
    type=tunnel
    authby=pubkey
    leftcert=gatewayCert.pem
    left=192.168.1.1
    right=198.51.100.25
    ike=aes256gcm16-sha256-ecp256!
    esp=aes256gcm16-ecp256!
    pfs=yes
    dpddelay=30s
    dpdaction=restart
    auto=start
"""
    secure_conf_path = os.path.join(SAMPLES_DIR, "ipsec_strongswan_secure.conf")
    with open(secure_conf_path, "w", encoding="utf-8") as f:
        f.write(secure_conf)
    print(f"Created: {secure_conf_path}")

    # 3. Cisco Legacy ASA IPsec config
    cisco_cfg = """! Legacy Cisco ASA IPsec Configuration
crypto ikev1 policy 10
 authentication pre-share
 encryption 3des
 hash sha
 group 2
 lifetime 86400

crypto map mymap 10 ipsec-isakmp
 set peer 203.0.113.10
 set transform-set ESP-3DES-SHA
 match address 101

tunnel-group 203.0.113.10 type ipsec-l2l
tunnel-group 203.0.113.10 ipsec-attributes
 ikev1 pre-shared-key vpnsecret123
"""
    cisco_cfg_path = os.path.join(SAMPLES_DIR, "cisco_vpn_legacy.cfg")
    with open(cisco_cfg_path, "w", encoding="utf-8") as f:
        f.write(cisco_cfg)
    print(f"Created: {cisco_cfg_path}")


def main():
    print("Generating complete suite of test files (.pcap, .conf, .cfg)...")

    # 1. Secure IKEv2 PCAP (Tunnel Mode, AES-256-GCM, DH Group 19, Video Streaming)
    ikev2_pkt = build_ikev2_secure_packet()
    esp_pkts_1 = build_esp_packets("192.168.1.10", "192.168.1.1", count=30, spi=0xABCDEF01, payload_type="video")
    secure_pcap = os.path.join(SAMPLES_DIR, "ikev2_aes256_pfs_secure.pcap")
    wrpcap(secure_pcap, [ikev2_pkt] + esp_pkts_1)
    print(f"Created: {secure_pcap}")

    # 2. Vulnerable IKEv1 PCAP (Transport Mode, 3DES, DH Group 2, Aggressive Mode, WhatsApp traffic)
    ikev1_pkt = build_ikev1_vulnerable_packet()
    esp_pkts_2 = build_esp_packets("10.0.0.5", "10.0.0.1", count=25, spi=0x99887766, payload_type="whatsapp")
    vulnerable_pcap = os.path.join(SAMPLES_DIR, "ikev1_3des_no_pfs_vulnerable.pcap")
    wrpcap(vulnerable_pcap, [ikev1_pkt] + esp_pkts_2)
    print(f"Created: {vulnerable_pcap}")

    # 3. IKEv2 Weak DH Group 2 PCAP (AES-256-CBC, DH Group 2, VoIP Traffic)
    weak_dh_pkt = build_ikev2_weak_dh_packet()
    esp_pkts_voip = build_esp_packets("172.16.0.2", "172.16.0.1", count=40, spi=0x44556677, payload_type="voip")
    weak_dh_pcap = os.path.join(SAMPLES_DIR, "ikev2_weak_dh_group2.pcap")
    wrpcap(weak_dh_pcap, [weak_dh_pkt] + esp_pkts_voip)
    print(f"Created: {weak_dh_pcap}")

    # 4. IPv6 AH + ESP PCAP (IKEv2 IPv6, AH + ESP, AES-128-CBC, ICMP Traffic)
    ipv6_pkt = build_ikev2_ipv6_ah_packet()
    esp_pkts_ipv6 = build_esp_packets("2001:db8::10", "2001:db8::1", count=20, spi=0x77889900, payload_type="icmp", is_ipv6=True)
    ah_pkts_ipv6 = build_ah_packets("2001:db8::10", "2001:db8::1", count=10, spi=0x11223344, is_ipv6=True)
    ipv6_pcap = os.path.join(SAMPLES_DIR, "ikev2_aes128_cbc_ah_esp_ipv6.pcap")
    wrpcap(ipv6_pcap, [ipv6_pkt] + ah_pkts_ipv6 + esp_pkts_ipv6)
    print(f"Created: {ipv6_pcap}")

    # 5. ESP Tunnel Traffic PCAP
    esp_traffic_pcap = os.path.join(SAMPLES_DIR, "esp_tunnel_mode_traffic.pcap")
    wrpcap(esp_traffic_pcap, esp_pkts_1 + esp_pkts_2)
    print(f"Created: {esp_traffic_pcap}")

    # 6. Config files
    create_config_files()

    print("\nAll sample test files successfully generated!")


if __name__ == "__main__":
    main()
