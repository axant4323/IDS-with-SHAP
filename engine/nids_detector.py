import sys, os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
#!/usr/bin/env python3
"""
X-NIDS Real-Time Detector & SHAP Explainability Engine
Ingests extracted network flow records, performs ensemble inference,
measures detection latency, and generates real-time SHAP attribution cards and plots.
"""

import os
import time
import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import shap
from engine.train_and_save_model import build_network_features

class XNidsDetector:
    def __init__(self, artifacts_dir="model_artifacts", alerts_dir="shap_alerts"):
        print(f"[*] Initializing X-NIDS Detection Engine from {artifacts_dir}...")
        self.xgb = joblib.load(os.path.join(artifacts_dir, "xgb_multi.joblib"))
        self.lgb = joblib.load(os.path.join(artifacts_dir, "lgb_multi.joblib"))
        self.preprocessor = joblib.load(os.path.join(artifacts_dir, "preprocessor.joblib"))
        self.le = joblib.load(os.path.join(artifacts_dir, "label_encoder.joblib"))
        self.freq_maps = joblib.load(os.path.join(artifacts_dir, "freq_maps.joblib"))
        
        self.class_names = list(self.le.classes_)
        self.normal_idx = self.class_names.index("Normal") if "Normal" in self.class_names else -1
        self.alerts_dir = alerts_dir
        os.makedirs(self.alerts_dir, exist_ok=True)
        
        # Initialize SHAP TreeExplainer on LightGBM for speed
        print("  [+] Initializing SHAP TreeExplainer for flow-level attribution...")
        self.explainer = shap.TreeExplainer(self.lgb)
        self.feature_names = self.preprocessor.get_feature_names_out()
        print("[✓] X-NIDS Detector ready for live traffic inference.")

    def preprocess_flows(self, df_flows):
        df_fe = build_network_features(df_flows)
        
        # Map frequency encodings
        cat_cols = ["proto", "service", "state"]
        for c in cat_cols:
            df_fe[f"{c}_freq"] = df_fe[c].map(self.freq_maps.get(c, {})).fillna(0.0)
            
        # Ensure categorical columns exist and match
        for c in cat_cols:
            df_fe[c] = df_fe[c].astype(str)
            
        drop_cols = ["src_ip", "dst_ip", "src_port", "dst_port", "label", "attack_cat"]
        X_df = df_fe.drop(columns=[col for col in drop_cols if col in df_fe.columns])
        
        X_proc = self.preprocessor.transform(X_df)
        return X_proc, df_fe

    def detect_and_explain(self, df_flows, explain_samples=3):
        print(f"\n[*] Inspecting {len(df_flows)} extracted flow records...")
        start_t = time.time()
        
        X_proc, df_fe = self.preprocess_flows(df_flows)
        
        # Soft-Voting Ensemble Inference
        infer_start = time.time()
        p_xgb = self.xgb.predict_proba(X_proc)
        p_lgb = self.lgb.predict_proba(X_proc)
        ensemble_probs = 0.5 * p_xgb + 0.5 * p_lgb
        preds = np.argmax(ensemble_probs, axis=1)
        confidences = np.max(ensemble_probs, axis=1)
        infer_end = time.time()
        
        total_latency_ms = (infer_end - infer_start) * 1000.0
        per_flow_latency_us = (total_latency_ms / max(1, len(df_flows))) * 1000.0
        
        df_flows = df_flows.copy()
        df_flows["prediction_idx"] = preds
        df_flows["predicted_class"] = [self.class_names[idx] for idx in preds]
        df_flows["confidence"] = confidences
        df_flows["is_malicious"] = df_flows["prediction_idx"] != self.normal_idx
        
        # SOC Traffic Breakdown
        malicious_count = df_flows["is_malicious"].sum()
        benign_count = len(df_flows) - malicious_count
        
        print("\n" + "="*70)
        print("          X-NIDS SECURITY OPERATIONS CENTER (SOC) REPORT          ")
        print("="*70)
        print(f"Total Flows Inspected : {len(df_flows):,}")
        print(f"Legitimate Flows (OK) : {benign_count:,} ({benign_count/len(df_flows)*100:.1f}%)")
        print(f"Threat Alerts Triggered: {malicious_count:,} ({malicious_count/len(df_flows)*100:.1f}%)")
        print(f"Ensemble Inference Time: {total_latency_ms:.2f} ms")
        print(f"Throughput Processing : {per_flow_latency_us:.2f} µs per flow (Sub-millisecond)")
        print("-"*70)
        print("Threat Breakdown by Attack Category:")
        attack_summary = df_flows[df_flows["is_malicious"]]["predicted_class"].value_counts()
        for cat, count in attack_summary.items():
            print(f"  • {cat:18s}: {count:5d} flows ({count/malicious_count*100:5.1f}% of threats)")
        print("="*70 + "\n")
        
        # SHAP Explainability on Malicious Alerts
        if malicious_count > 0:
            print("[*] Generating SHAP Explainability Cards for Flagged Threats...")
            malicious_indices = df_flows[df_flows["is_malicious"]].index.tolist()
            sample_alert_indices = malicious_indices[:explain_samples]
            
            for rank, idx in enumerate(sample_alert_indices, 1):
                row = df_flows.loc[idx]
                target_cls_idx = row["prediction_idx"]
                target_cls_name = row["predicted_class"]
                flow_vector = X_proc[idx:idx+1]
                
                # Compute SHAP for flow
                shap_vals = self.explainer.shap_values(flow_vector)
                if isinstance(shap_vals, list):
                    flow_shap = shap_vals[target_cls_idx][0]
                elif shap_vals.ndim == 3:
                    flow_shap = shap_vals[0, :, target_cls_idx]
                else:
                    flow_shap = shap_vals[0]
                    
                # Find top positive contributing features
                top_indices = np.argsort(flow_shap)[::-1][:4]
                
                src_ip = row["src_ip"]
                dst_ip = row["dst_ip"]
                src_port = row["src_port"]
                dst_port = row["dst_port"]
                proto = str(row["proto"]).upper()
                dur = float(row["dur"])
                spkts = int(row["spkts"])
                dpkts = int(row["dpkts"])
                sbytes = int(row["sbytes"])
                dbytes = int(row["dbytes"])
                conf = float(row["confidence"]) * 100.0

                print(f"[ALERT #{rank}] Threat Detected: {target_cls_name.upper()} (Confidence: {conf:.1f}%)")
                print(f"  Flow: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({proto})")
                print(f"  Duration: {dur:.5f}s | Packets: {spkts}->{dpkts} | Bytes: {sbytes}->{dbytes}")
                print("  Top Explainability Drivers (SHAP Attribution):")
                for f_idx in top_indices:
                    fname = self.feature_names[f_idx].replace("remainder__", "").replace("cat__", "")
                    fval = flow_vector[0, f_idx]
                    impact = flow_shap[f_idx]
                    print(f"    - {fname:25s}: Val={fval:10.4f} | Contribution=+{impact:.4f}")
                print()
                
            # Generate and save a summary plot for the malicious sample
            print(f"[*] Exporting SHAP Visual Plots to {self.alerts_dir}/...")
            mal_sample_proc = X_proc[malicious_indices[:min(200, len(malicious_indices))]]
            shap_sample = self.explainer.shap_values(mal_sample_proc)
            
            # Use most common attack class
            top_attack_class = attack_summary.index[0]
            top_attack_idx = self.class_names.index(top_attack_class)
            
            if isinstance(shap_sample, list):
                plot_shap = shap_sample[top_attack_idx]
            elif shap_sample.ndim == 3:
                plot_shap = shap_sample[:, :, top_attack_idx]
            else:
                plot_shap = shap_sample
                
            clean_feature_names = [f.replace("remainder__", "").replace("cat__", "") for f in self.feature_names]
            
            plt.figure(figsize=(10, 8))
            shap.summary_plot(
                plot_shap,
                mal_sample_proc,
                feature_names=clean_feature_names,
                max_display=15,
                show=False
            )
            plot_path = os.path.join(self.alerts_dir, f"{top_attack_class.lower()}_shap_summary.png")
            plt.title(f"X-NIDS SHAP Attribution — {top_attack_class} Attack Vectors", fontsize=12, pad=15)
            plt.tight_layout()
            plt.savefig(plot_path, dpi=200)
            plt.close()
            print(f"[✓] Saved SHAP Attribution Plot: {plot_path}")

        return df_flows

if __name__ == "__main__":
    from engine.flow_extractor import extract_flows_from_pcap
    flows = extract_flows_from_pcap("simulated_traffic.pcap")
    detector = XNidsDetector()
    results = detector.detect_and_explain(flows)
