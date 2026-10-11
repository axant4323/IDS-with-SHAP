#!/usr/bin/env python3
"""
X-NIDS End-to-End Simulation & Explainability Demo Runner
Runs the full pipeline:
  [1] Packet Simulation (ns-3 / Scapy)
  [2] PCAP Flow Extraction
  [3] Live Ensemble Inference (XGBoost + LightGBM)
  [4] Flow-Level SHAP Interpretability
"""

import os
import sys
import time

from simulation.traffic_generator import generate_network_traffic
from engine.flow_extractor import extract_flows_from_pcap
from engine.nids_detector import XNidsDetector

def main():
    print("=" * 76)
    print("    X-NIDS: EXPLAINABLE NETWORK INTRUSION DETECTION SYSTEM & SIMULATOR    ")
    print("=" * 76)
    print("Pipeline Stages:")
    print("  [Stage 1] Discrete Network Packet Simulation & Attack Injection")
    print("  [Stage 2] Bidirectional 5-Tuple NetFlow Statistical Extraction")
    print("  [Stage 3] Calibrated Soft-Voting Ensemble Classification")
    print("  [Stage 4] Flow-Level Explainable AI (SHAP TreeExplainer Attribution)")
    print("=" * 76 + "\n")
    
    t_start = time.time()
    
    # Stage 1: Traffic Simulation
    pcap_file = "simulated_traffic.pcap"
    generate_network_traffic(output_pcap=pcap_file)
    print()
    
    # Stage 2: Flow Extraction
    flows = extract_flows_from_pcap(pcap_file)
    print()
    
    # Stage 3 & 4: Detection & SHAP Explainability
    detector = XNidsDetector(artifacts_dir="model_artifacts", alerts_dir="shap_alerts")
    results = detector.detect_and_explain(flows, explain_samples=3)
    
    t_total = time.time() - t_start
    print("=" * 76)
    print(f"[✓] End-to-End Simulation & NIDS Execution Completed in {t_total:.2f}s")
    print(f"    - Simulated PCAP      : {os.path.abspath(pcap_file)}")
    print(f"    - SHAP Alerts Directory: {os.path.abspath(detector.alerts_dir)}")
    print("=" * 76)

if __name__ == "__main__":
    main()
