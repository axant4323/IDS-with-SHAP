#!/usr/bin/env python3
"""
X-NIDS Security Operations Center (SOC) REST API & Web Dashboard Server
Serves real-time intrusion detection metrics, NetFlow telemetry, and interactive SHAP explainability.
"""

import os
import sys
import time
import json
import numpy as np
import pandas as pd

# Add repository root to Python path
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from flask import Flask, jsonify, request, send_from_directory, render_template_string

from simulation.traffic_generator import generate_network_traffic
from engine.flow_extractor import extract_flows_from_pcap
from engine.nids_detector import XNidsDetector

app = Flask(__name__, static_folder=".", static_url_path="")

# Global in-memory cache for state
STATE = {
    "detector": None,
    "last_run_time": None,
    "pcap_file": os.path.join(REPO_ROOT, "simulated_traffic.pcap"),
    "flows_df": None,
    "flows_list": [],
    "metrics": {
        "total_flows": 0,
        "benign_count": 0,
        "threat_count": 0,
        "threat_ratio_pct": 0.0,
        "latency_ms": 0.0,
        "throughput_us": 0.0,
        "category_breakdown": {},
        "status": "INITIALIZING"
    },
    "alerts": [],
    "shap_plots": [],
    "X_proc": None,
    "feature_names": []
}

def get_detector():
    if STATE["detector"] is None:
        artifacts_dir = os.path.join(REPO_ROOT, "model_artifacts")
        alerts_dir = os.path.join(REPO_ROOT, "shap_alerts")
        STATE["detector"] = XNidsDetector(artifacts_dir=artifacts_dir, alerts_dir=alerts_dir)
        STATE["feature_names"] = [f.replace("remainder__", "").replace("cat__", "") for f in STATE["detector"].feature_names]
    return STATE["detector"]

def process_pipeline():
    """Executes traffic generation, NetFlow extraction, and ensemble inference + SHAP."""
    detector = get_detector()
    start_total = time.time()
    
    pcap_path = os.path.join(REPO_ROOT, "simulated_traffic.pcap")
    generate_network_traffic(output_pcap=pcap_path)
    
    flows = extract_flows_from_pcap(pcap_path)
    
    # Process flows through detector
    X_proc, df_fe = detector.preprocess_flows(flows)
    STATE["X_proc"] = X_proc
    
    infer_start = time.time()
    p_xgb = detector.xgb.predict_proba(X_proc)
    p_lgb = detector.lgb.predict_proba(X_proc)
    ensemble_probs = 0.5 * p_xgb + 0.5 * p_lgb
    preds = np.argmax(ensemble_probs, axis=1)
    confidences = np.max(ensemble_probs, axis=1)
    infer_end = time.time()
    
    total_latency_ms = (infer_end - infer_start) * 1000.0
    per_flow_latency_us = (total_latency_ms / max(1, len(flows))) * 1000.0
    
    flows = flows.copy()
    flows["flow_id"] = np.arange(len(flows))
    flows["prediction_idx"] = preds
    flows["predicted_class"] = [detector.class_names[idx] for idx in preds]
    flows["confidence"] = confidences
    flows["is_malicious"] = flows["prediction_idx"] != detector.normal_idx
    
    # Attack breakdown
    malicious_mask = flows["is_malicious"]
    threat_count = int(malicious_mask.sum())
    benign_count = int(len(flows) - threat_count)
    cat_counts = flows[malicious_mask]["predicted_class"].value_counts().to_dict()
    
    # Precompute SHAP attributions for top threats
    alerts = []
    if threat_count > 0:
        mal_indices = flows[malicious_mask].index.tolist()
        sample_indices = mal_indices[:min(10, len(mal_indices))]
        
        for idx in sample_indices:
            row = flows.loc[idx]
            target_cls_idx = row["prediction_idx"]
            target_cls = row["predicted_class"]
            flow_vector = X_proc[idx:idx+1]
            
            shap_vals = detector.explainer.shap_values(flow_vector)
            if isinstance(shap_vals, list):
                flow_shap = shap_vals[target_cls_idx][0]
            elif shap_vals.ndim == 3:
                flow_shap = shap_vals[0, :, target_cls_idx]
            else:
                flow_shap = shap_vals[0]
                
            top_f_indices = np.argsort(flow_shap)[::-1][:5]
            drivers = []
            for fi in top_f_indices:
                drivers.append({
                    "feature": STATE["feature_names"][fi],
                    "value": float(flow_vector[0, fi]),
                    "shap_impact": float(flow_shap[fi])
                })
                
            alerts.append({
                "flow_id": int(row["flow_id"]),
                "src_ip": str(row["src_ip"]),
                "src_port": int(row["src_port"]),
                "dst_ip": str(row["dst_ip"]),
                "dst_port": int(row["dst_port"]),
                "proto": str(row["proto"]).upper(),
                "predicted_class": target_cls,
                "confidence": round(float(row["confidence"]) * 100.0, 1),
                "dur": round(float(row["dur"]), 5),
                "sbytes": int(row["sbytes"]),
                "dbytes": int(row["dbytes"]),
                "spkts": int(row["spkts"]),
                "dpkts": int(row["dpkts"]),
                "top_drivers": drivers
            })
            
        # Export SHAP summary plot
        clean_names = STATE["feature_names"]
        top_cat = list(cat_counts.keys())[0] if cat_counts else "Exploits"
        top_cat_idx = detector.class_names.index(top_cat) if top_cat in detector.class_names else 0
        
        sample_for_plot = X_proc[mal_indices[:min(100, len(mal_indices))]]
        shap_for_plot = detector.explainer.shap_values(sample_for_plot)
        if isinstance(shap_for_plot, list):
            plot_vals = shap_for_plot[top_cat_idx]
        elif shap_for_plot.ndim == 3:
            plot_vals = shap_for_plot[:, :, top_cat_idx]
        else:
            plot_vals = shap_for_plot
            
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        import shap
        
        plt.figure(figsize=(9, 6))
        shap.summary_plot(plot_vals, sample_for_plot, feature_names=clean_names, max_display=12, show=False)
        plot_filename = f"{top_cat.lower()}_shap_summary.png"
        plot_path = os.path.join(detector.alerts_dir, plot_filename)
        plt.title(f"X-NIDS SHAP Global Feature Impact — {top_cat}", fontsize=11, pad=12)
        plt.tight_layout()
        plt.savefig(plot_path, dpi=180)
        plt.close()
        STATE["shap_plots"] = [f"/shap_alerts/{plot_filename}"]

    # Convert flows to clean serializable dicts
    flows_list = []
    for _, r in flows.iterrows():
        flows_list.append({
            "flow_id": int(r["flow_id"]),
            "src_ip": str(r["src_ip"]),
            "src_port": int(r["src_port"]),
            "dst_ip": str(r["dst_ip"]),
            "dst_port": int(r["dst_port"]),
            "proto": str(r["proto"]).upper(),
            "service": str(r.get("service", "-")),
            "state": str(r.get("state", "-")),
            "dur": round(float(r["dur"]), 5),
            "sbytes": int(r["sbytes"]),
            "dbytes": int(r["dbytes"]),
            "spkts": int(r["spkts"]),
            "dpkts": int(r["dpkts"]),
            "rate": round(float(r.get("rate", 0)), 1),
            "sload": round(float(r.get("sload", 0)), 1),
            "dload": round(float(r.get("dload", 0)), 1),
            "predicted_class": str(r["predicted_class"]),
            "confidence": round(float(r["confidence"]) * 100.0, 1),
            "is_malicious": bool(r["is_malicious"])
        })
        
    STATE["flows_df"] = flows
    STATE["flows_list"] = flows_list
    STATE["alerts"] = alerts
    STATE["last_run_time"] = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    STATE["metrics"] = {
        "total_flows": len(flows),
        "benign_count": benign_count,
        "threat_count": threat_count,
        "threat_ratio_pct": round((threat_count / max(1, len(flows))) * 100.0, 1),
        "latency_ms": round(total_latency_ms, 2),
        "throughput_us": round(per_flow_latency_us, 2),
        "category_breakdown": cat_counts,
        "execution_time_s": round(time.time() - start_total, 2),
        "status": "ONLINE"
    }
    return STATE["metrics"]

# -----------------------------------------------------------------------------
# REST API Endpoints
# -----------------------------------------------------------------------------

@app.route("/")
def index():
    return send_from_directory(os.path.dirname(__file__), "index.html")

@app.route("/shap_alerts/<path:filename>")
def serve_shap_alerts(filename):
    alerts_dir = os.path.join(REPO_ROOT, "shap_alerts")
    return send_from_directory(alerts_dir, filename)

@app.route("/api/status", methods=["GET"])
def get_status():
    return jsonify({
        "status": "ready" if STATE["flows_df"] is not None else "standby",
        "last_run": STATE["last_run_time"],
        "metrics": STATE["metrics"]
    })

@app.route("/api/run-simulation", methods=["POST"])
def run_simulation():
    try:
        metrics = process_pipeline()
        return jsonify({
            "success": True,
            "message": "Simulation and SHAP analysis completed successfully",
            "metrics": metrics,
            "alerts_count": len(STATE["alerts"]),
            "plots": STATE["shap_plots"]
        })
    except Exception as e:
        import traceback
        return jsonify({"success": False, "error": str(e), "traceback": traceback.format_exc()}), 500

@app.route("/api/metrics", methods=["GET"])
def get_metrics():
    if STATE["flows_df"] is None:
        # Load automatically if pcap exists
        if os.path.exists(STATE["pcap_file"]):
            process_pipeline()
    return jsonify(STATE["metrics"])

@app.route("/api/flows", methods=["GET"])
def get_flows():
    if STATE["flows_df"] is None:
        if os.path.exists(STATE["pcap_file"]):
            process_pipeline()
            
    flows = STATE["flows_list"]
    
    # Query parameters
    search = request.args.get("search", "").strip().lower()
    category = request.args.get("category", "").strip()
    status_filter = request.args.get("status", "all").strip().lower() # all, threat, benign
    threshold = float(request.args.get("threshold", 0.50))
    limit = int(request.args.get("limit", 100))
    offset = int(request.args.get("offset", 0))
    
    filtered = []
    for f in flows:
        # Apply threshold dynamic evaluation
        is_mal = f["is_malicious"]
        if f["confidence"] / 100.0 < threshold and is_mal:
            # If below threshold, consider borderline or re-evaluated
            pass
            
        if status_filter == "threat" and not f["is_malicious"]:
            continue
        if status_filter == "benign" and f["is_malicious"]:
            continue
            
        if category and category != "All" and f["predicted_class"].lower() != category.lower():
            continue
            
        if search:
            searchable = f"{f['src_ip']} {f['dst_ip']} {f['src_port']} {f['dst_port']} {f['proto']} {f['predicted_class']}".lower()
            if search not in searchable:
                continue
                
        filtered.append(f)
        
    total_matching = len(filtered)
    paginated = filtered[offset:offset + limit]
    
    return jsonify({
        "total": total_matching,
        "offset": offset,
        "limit": limit,
        "flows": paginated
    })

@app.route("/api/shap-alerts", methods=["GET"])
def get_shap_alerts():
    if STATE["flows_df"] is None:
        if os.path.exists(STATE["pcap_file"]):
            process_pipeline()
            
    return jsonify({
        "alerts": STATE["alerts"],
        "plots": STATE["shap_plots"]
    })

@app.route("/api/explain-flow/<int:flow_id>", methods=["GET"])
def explain_flow(flow_id):
    if STATE["flows_df"] is None or STATE["X_proc"] is None:
        return jsonify({"error": "No simulation data loaded"}), 400
        
    if flow_id < 0 or flow_id >= len(STATE["flows_list"]):
        return jsonify({"error": "Flow ID out of range"}), 404
        
    detector = get_detector()
    row = STATE["flows_df"].iloc[flow_id]
    flow_dict = STATE["flows_list"][flow_id]
    flow_vector = STATE["X_proc"][flow_id:flow_id+1]
    target_cls_idx = int(row["prediction_idx"])
    
    # Calculate SHAP values
    shap_vals = detector.explainer.shap_values(flow_vector)
    if isinstance(shap_vals, list):
        flow_shap = shap_vals[target_cls_idx][0]
    elif shap_vals.ndim == 3:
        flow_shap = shap_vals[0, :, target_cls_idx]
    else:
        flow_shap = shap_vals[0]
        
    # Get top 8 drivers (positive and negative)
    sorted_indices = np.argsort(flow_shap)[::-1]
    drivers = []
    for fi in sorted_indices[:10]:
        val = float(flow_vector[0, fi])
        impact = float(flow_shap[fi])
        drivers.append({
            "feature": STATE["feature_names"][fi],
            "value": round(val, 4),
            "impact": round(impact, 4),
            "direction": "malicious" if impact > 0 else "benign"
        })
        
    return jsonify({
        "flow": flow_dict,
        "class_name": str(row["predicted_class"]),
        "confidence": round(float(row["confidence"]) * 100.0, 1),
        "drivers": drivers
    })

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print("=" * 76)
    print("       X-NIDS SECURITY OPERATIONS CENTER (SOC) DASHBOARD SERVER       ")
    print("=" * 76)
    print(f"[*] Dashboard URL : http://localhost:{port}")
    print(f"[*] Working Dir   : {os.path.abspath(REPO_ROOT)}")
    print(f"[*] Initializing pipeline cache on startup...")
    try:
        process_pipeline()
        print(f"[✓] Initial data loaded: {STATE['metrics']['total_flows']} flows ready.")
    except Exception as e:
        print(f"[!] Warmup failed (will trigger on demand): {e}")
        
    print(f"[*] Launching HTTP Server on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
