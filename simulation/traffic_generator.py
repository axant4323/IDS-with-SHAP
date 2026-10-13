#!/usr/bin/env python3
"""
X-NIDS Realistic Network Traffic Generator
Generates multi-vector enterprise network traffic:
- Legitimate Web (HTTP), DNS, and Session transfers
- DoS (HTTP Connection Saturation & TCP SYN Flood)
- Reconnaissance (Sequential Port Scanning)
- Generic Attacks (High-Rate UDP Storms)
- Fuzzers (Malformed TCP Payloads)
"""

import os
import time
import random
from scapy.all import Ether, IP, TCP, UDP, Raw, wrpcap, conf
conf.verb = 0
ETH_CLIENT = "02:00:00:00:00:01"
ETH_SERVER = "02:00:00:00:00:02"

def generate_network_traffic(output_pcap="simulated_traffic.pcap"):
    print("[*] Generating realistic multi-vector network traffic...")
    packets = []
    
    server_ip = "10.1.2.50"
    benign_clients = ["10.1.1.10", "10.1.1.11", "10.1.1.12"]
    attacker_dos = "10.1.3.100"
    attacker_scan = "10.1.3.101"
    attacker_fuzz = "10.1.3.102"
    
    current_time = time.time()
    
    # -------------------------------------------------------------------------
    # 1. Benign Traffic (HTTP & DNS)
    # -------------------------------------------------------------------------
    print("  [+] Synthesizing Legitimate Enterprise Traffic...")
    for client in benign_clients:
        for s in range(10):
            sport = random.randint(35000, 60000)
            seq = random.randint(10000, 80000)
            
            # 3-Way Handshake
            current_time += random.uniform(0.01, 0.04)
            p1 = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=client, dst=server_ip) / TCP(sport=sport, dport=80, flags="S", seq=seq)
            p1.time = current_time
            packets.append(p1)
            
            current_time += random.uniform(0.001, 0.004) # Normal low RTT
            s_seq = random.randint(20000, 90000)
            p2 = Ether(src=ETH_SERVER, dst=ETH_CLIENT) / IP(src=server_ip, dst=client) / TCP(sport=80, dport=sport, flags="SA", seq=s_seq, ack=seq+1)
            p2.time = current_time
            packets.append(p2)
            
            current_time += random.uniform(0.001, 0.003)
            p3 = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=client, dst=server_ip) / TCP(sport=sport, dport=80, flags="A", seq=seq+1, ack=s_seq+1)
            p3.time = current_time
            packets.append(p3)
            
            # HTTP Request
            current_time += random.uniform(0.01, 0.03)
            req = b"GET /index.html HTTP/1.1\r\nHost: server.local\r\n\r\n"
            p4 = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=client, dst=server_ip) / TCP(sport=sport, dport=80, flags="PA", seq=seq+1, ack=s_seq+1) / Raw(load=req)
            p4.time = current_time
            packets.append(p4)
            
            # HTTP Response
            current_time += random.uniform(0.02, 0.05)
            resp = b"HTTP/1.1 200 OK\r\nContent-Length: 1200\r\n\r\n" + (b"DATA" * 300)
            p5 = Ether(src=ETH_SERVER, dst=ETH_CLIENT) / IP(src=server_ip, dst=client) / TCP(sport=80, dport=sport, flags="PA", seq=s_seq+1, ack=seq+1+len(req)) / Raw(load=resp)
            p5.time = current_time
            packets.append(p5)
            
            # Teardown
            current_time += random.uniform(0.01, 0.03)
            p6 = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=client, dst=server_ip) / TCP(sport=sport, dport=80, flags="FA", seq=seq+1+len(req), ack=s_seq+1+len(resp))
            p6.time = current_time
            packets.append(p6)
            
            p7 = Ether(src=ETH_SERVER, dst=ETH_CLIENT) / IP(src=server_ip, dst=client) / TCP(sport=80, dport=sport, flags="FA", seq=s_seq+1+len(resp), ack=seq+2+len(req))
            p7.time = current_time + 0.002
            packets.append(p7)

    # -------------------------------------------------------------------------
    # 2. Attack: DoS (Connection Exhaustion & Multi-Packet Saturation)
    # -------------------------------------------------------------------------
    print("  [!] Injecting Attack 1: DoS (Connection Exhaustion & Request Flood)...")
    for session_id in range(30):
        attacker_sport = random.randint(40000, 65000)
        atk_seq = random.randint(1000, 50000)
        
        # Fast handshake
        current_time += random.uniform(0.001, 0.003)
        p1 = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=attacker_dos, dst=server_ip) / TCP(sport=attacker_sport, dport=80, flags="S", seq=atk_seq)
        p1.time = current_time
        packets.append(p1)
        
        current_time += 0.001
        p2 = Ether(src=ETH_SERVER, dst=ETH_CLIENT) / IP(src=server_ip, dst=attacker_dos) / TCP(sport=80, dport=attacker_sport, flags="SA", seq=1000, ack=atk_seq+1)
        p2.time = current_time
        packets.append(p2)
        
        current_time += 0.001
        p3 = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=attacker_dos, dst=server_ip) / TCP(sport=attacker_sport, dport=80, flags="A", seq=atk_seq+1, ack=1001)
        p3.time = current_time
        packets.append(p3)
        
        # Heavy repeating attack payloads (Slowloris / HTTP Flood)
        for req_num in range(8):
            current_time += random.uniform(0.002, 0.008)
            flood_req = f"GET /heavy_query?id={req_num}&flood=true HTTP/1.1\r\nHost: target\r\nX-Attack: DoS\r\n\r\n".encode()
            atk_p = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=attacker_dos, dst=server_ip) / TCP(sport=attacker_sport, dport=80, flags="PA", seq=atk_seq+1+req_num*len(flood_req), ack=1001) / Raw(load=flood_req)
            atk_p.time = current_time
            packets.append(atk_p)

    # -------------------------------------------------------------------------
    # 3. Attack: Generic (High-Rate UDP Storm with Zero Responses)
    # -------------------------------------------------------------------------
    print("  [!] Injecting Attack 2: Generic UDP Storm (High Packet Rate)...")
    for _ in range(300):
        current_time += random.uniform(0.0001, 0.0005)
        u_sport = random.randint(20000, 60000)
        udp_payload = b"GENERIC_ATTACK_STORM_PAYLOAD_" * 4
        u_pkt = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=attacker_dos, dst=server_ip) / UDP(sport=u_sport, dport=53) / Raw(load=udp_payload)
        u_pkt.time = current_time
        packets.append(u_pkt)

    # -------------------------------------------------------------------------
    # 4. Attack: Reconnaissance (Port Scanning)
    # -------------------------------------------------------------------------
    print("  [!] Injecting Attack 3: Reconnaissance (Sequential Port Probe)...")
    for probe_port in range(21, 100):
        current_time += random.uniform(0.003, 0.01)
        probe_sport = random.randint(50000, 62000)
        prb = Ether(src=ETH_CLIENT, dst=ETH_SERVER) / IP(src=attacker_scan, dst=server_ip) / TCP(sport=probe_sport, dport=probe_port, flags="S", seq=random.randint(100, 10000))
        prb.time = current_time
        packets.append(prb)
        
        # Closed port RST response
        if probe_port not in [80, 53]:
            current_time += 0.002
            rst = Ether(src=ETH_SERVER, dst=ETH_CLIENT) / IP(src=server_ip, dst=attacker_scan) / TCP(sport=probe_port, dport=probe_sport, flags="R", seq=0, ack=0)
            rst.time = current_time
            packets.append(rst)

    # Sort strictly by timestamp
    packets.sort(key=lambda p: p.time)
    
    print(f"[*] Writing {len(packets)} packets to {output_pcap}...")
    wrpcap(output_pcap, packets)
    print(f"[✓] Successfully generated {output_pcap} ({os.path.getsize(output_pcap):,} bytes).")
    return output_pcap

if __name__ == "__main__":
    generate_network_traffic()
