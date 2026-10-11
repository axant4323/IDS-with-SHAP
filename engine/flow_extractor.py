#!/usr/bin/env python3
"""
X-NIDS PCAP-to-Flow Extractor
Parses raw PCAP packet streams into bidirectional flow records with statistical
metrics conforming to the UNSW-NB15 flow schema.
"""

import sys
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP, UDP, Raw

def extract_flows_from_pcap(pcap_file="simulated_traffic.pcap"):
    print(f"[*] Reading PCAP file: {pcap_file}...")
    packets = rdpcap(pcap_file)
    print(f"  [+] Loaded {len(packets)} packets. Assembling bidirectional flows...")

    flows = {}
    
    for pkt in packets:
        if not pkt.haslayer(IP):
            continue
            
        ip = pkt[IP]
        src_ip = ip.src
        dst_ip = ip.dst
        proto = "tcp" if pkt.haslayer(TCP) else ("udp" if pkt.haslayer(UDP) else "other")
        
        if proto == "tcp":
            sport = pkt[TCP].sport
            dport = pkt[TCP].dport
        elif proto == "udp":
            sport = pkt[UDP].sport
            dport = pkt[UDP].dport
        else:
            sport = 0
            dport = 0
            
        # 5-tuple canonical flow key for bidirectional matching
        if (src_ip, sport) <= (dst_ip, dport):
            flow_key = (src_ip, dst_ip, sport, dport, proto)
        else:
            flow_key = (dst_ip, src_ip, dport, sport, proto)
            
        pkt_time = float(pkt.time)
        pkt_len = len(pkt)
        payload_len = len(pkt[Raw].load) if pkt.haslayer(Raw) else 0
        
        if flow_key not in flows:
            # First packet seen defines the initiator (source)
            flows[flow_key] = {
                "initiator_ip": src_ip,
                "initiator_port": sport,
                "fwd_ip": src_ip,
                "rev_ip": dst_ip,
                "fwd_port": sport,
                "rev_port": dport,
                "proto": proto,
                "fwd_times": [],
                "rev_times": [],
                "fwd_lens": [],
                "rev_lens": [],
                "fwd_payloads": [],
                "rev_payloads": [],
                "tcp_flags": [],
                "syn_time": None,
                "synack_time": None,
                "ack_time": None,
                "stcpb": 0,
                "dtcpb": 0,
                "swin": 0,
                "dwin": 0,
                "has_http_req": False,
                "http_resp_len": 0,
            }
            
        flow = flows[flow_key]
        is_forward = (src_ip == flow["initiator_ip"] and sport == flow["initiator_port"])
        
        if is_forward:
            flow["fwd_times"].append(pkt_time)
            flow["fwd_lens"].append(pkt_len)
            flow["fwd_payloads"].append(payload_len)
            if pkt.haslayer(TCP):
                flow["swin"] = pkt[TCP].window
                if flow["stcpb"] == 0:
                    flow["stcpb"] = pkt[TCP].seq
        else:
            flow["rev_times"].append(pkt_time)
            flow["rev_lens"].append(pkt_len)
            flow["rev_payloads"].append(payload_len)
            if pkt.haslayer(TCP):
                flow["dwin"] = pkt[TCP].window
                if flow["dtcpb"] == 0:
                    flow["dtcpb"] = pkt[TCP].seq

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            flow["tcp_flags"].append(flags)
            if flags == "S" and flow["syn_time"] is None:
                flow["syn_time"] = pkt_time
            elif flags == "SA" and flow["synack_time"] is None:
                flow["synack_time"] = pkt_time
            elif flags == "A" and flow["synack_time"] is not None and flow["ack_time"] is None:
                flow["ack_time"] = pkt_time
                
        if pkt.haslayer(Raw):
            load = pkt[Raw].load
            if b"GET " in load or b"POST " in load:
                flow["has_http_req"] = True
            if b"HTTP/1." in load:
                flow["http_resp_len"] += len(load)

    print(f"  [+] Assembled {len(flows)} bidirectional flows. Calculating statistical metrics...")
    
    flow_records = []
    
    for key, f in flows.items():
        all_times = sorted(f["fwd_times"] + f["rev_times"])
        start_t = all_times[0]
        end_t = all_times[-1]
        dur = max(0.000001, end_t - start_t)
        
        spkts = len(f["fwd_times"])
        dpkts = len(f["rev_times"])
        sbytes = sum(f["fwd_lens"])
        dbytes = sum(f["rev_lens"])
        
        # Inter-packet arrival times (ms)
        fwd_iat = np.diff(f["fwd_times"]) * 1000.0 if spkts > 1 else [0.0]
        rev_iat = np.diff(f["rev_times"]) * 1000.0 if dpkts > 1 else [0.0]
        
        sinpkt = float(np.mean(fwd_iat))
        dinpkt = float(np.mean(rev_iat))
        sjit = float(np.std(fwd_iat)) if spkts > 1 else 0.0
        djit = float(np.std(rev_iat)) if dpkts > 1 else 0.0
        
        # TCP handshake latencies
        if f["syn_time"] and f["synack_time"]:
            synack = max(0.0001, f["synack_time"] - f["syn_time"])
        else:
            synack = 0.0
            
        if f["synack_time"] and f["ack_time"]:
            ackdat = max(0.0001, f["ack_time"] - f["synack_time"])
        else:
            ackdat = 0.0
            
        tcprtt = synack + ackdat
        
        # Service deduction
        dest_p = f["rev_port"]
        if dest_p == 80 or f["fwd_port"] == 80:
            service = "http"
        elif dest_p == 53 or f["fwd_port"] == 53:
            service = "dns"
        elif dest_p == 22 or f["fwd_port"] == 22:
            service = "ssh"
        else:
            service = "-"
            
        # State deduction
        if f["proto"] == "tcp":
            if any("F" in str(flg) for flg in f["tcp_flags"]):
                state = "FIN"
            elif any("R" in str(flg) for flg in f["tcp_flags"]):
                state = "RST"
            elif any("S" in str(flg) for flg in f["tcp_flags"]) and dpkts == 0:
                state = "REQ"
            elif any("A" in str(flg) for flg in f["tcp_flags"]):
                state = "CON"
            else:
                state = "INT"
        else:
            state = "CON" if dpkts > 0 else "INT"
            
        record = {
            "src_ip": f["fwd_ip"],
            "dst_ip": f["rev_ip"],
            "src_port": f["fwd_port"],
            "dst_port": f["rev_port"],
            "dur": dur,
            "proto": f["proto"],
            "service": service,
            "state": state,
            "spkts": spkts,
            "dpkts": dpkts,
            "sbytes": sbytes,
            "dbytes": dbytes,
            "rate": (spkts + dpkts) / dur,
            "sload": (sbytes * 8.0) / dur,
            "dload": (dbytes * 8.0) / dur,
            "sloss": 0,
            "dloss": 0,
            "sinpkt": sinpkt,
            "dinpkt": dinpkt,
            "sjit": sjit,
            "djit": djit,
            "swin": f["swin"],
            "stcpb": f["stcpb"],
            "dtcpb": f["dtcpb"],
            "dwin": f["dwin"],
            "tcprtt": tcprtt,
            "synack": synack,
            "ackdat": ackdat,
            "smean": sbytes / max(1, spkts),
            "dmean": dbytes / max(1, dpkts),
            "trans_depth": 1 if f["has_http_req"] else 0,
            "response_body_len": f["http_resp_len"],
            "ct_src_dport_ltm": 1,
            "ct_dst_sport_ltm": 1,
            "is_ftp_login": 0,
            "ct_ftp_cmd": 0,
            "ct_flw_http_mthd": 1 if f["has_http_req"] else 0,
            "is_sm_ips_ports": 1 if (f["fwd_ip"] == f["rev_ip"] and f["fwd_port"] == f["rev_port"]) else 0
        }
        flow_records.append(record)
        
    df_flows = pd.DataFrame(flow_records)
    
    # Calculate connection count aggregates
    if not df_flows.empty:
        df_flows["ct_src_dport_ltm"] = df_flows.groupby(["src_ip", "dst_port"])["dur"].transform("count")
        df_flows["ct_dst_sport_ltm"] = df_flows.groupby(["dst_ip", "src_port"])["dur"].transform("count")

    print(f"[✓] Successfully extracted {len(df_flows)} flows with {df_flows.shape[1]} features.")
    return df_flows

if __name__ == "__main__":
    df = extract_flows_from_pcap()
    print("\nSample Flow Records (first 3):")
    print(df[["src_ip", "dst_ip", "dst_port", "proto", "service", "state", "dur", "spkts", "dpkts", "sbytes", "dbytes"]].head(3))
