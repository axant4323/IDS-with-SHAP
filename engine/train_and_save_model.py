#!/usr/bin/env python3
"""
X-NIDS Model Trainer & Serializer
Trains tuned XGBoost and LightGBM models with 48 engineered features and power class weights,
then exports the models and preprocessors to model_artifacts/ for live inference.
"""

import os
import joblib
import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, LabelEncoder
from sklearn.compose import ColumnTransformer
from xgboost import XGBClassifier
import lightgbm as lgb

def build_network_features(df_in):
    d = df_in.copy()
    
    # Volumes & Totals
    d["tot_bytes"] = d["sbytes"] + d["dbytes"]
    d["tot_pkts"] = d["spkts"] + d["dpkts"]
    d["tot_loss"] = d["sloss"] + d["dloss"]
    d["byte_diff"] = np.abs(d["sbytes"] - d["dbytes"])
    d["pkt_diff"] = np.abs(d["spkts"] - d["dpkts"])
    
    # Asymmetric Flow Ratios
    d["bytes_ratio"] = (d["sbytes"] + 1.0) / (d["dbytes"] + 1.0)
    d["pkts_ratio"] = (d["spkts"] + 1.0) / (d["dpkts"] + 1.0)
    d["sbytes_per_pkt"] = d["sbytes"] / (d["spkts"] + 1.0)
    d["dbytes_per_pkt"] = d["dbytes"] / (d["dpkts"] + 1.0)
    d["loss_ratio"] = d["tot_loss"] / (d["tot_pkts"] + 1.0)
    d["sloss_rate"] = d["sloss"] / (d["spkts"] + 1.0)
    d["dloss_rate"] = d["dloss"] / (d["dpkts"] + 1.0)
    
    # Rate and Load Dynamics
    d["byte_rate"] = d["tot_bytes"] / (d["dur"] + 1e-5)
    d["pkt_rate"] = d["tot_pkts"] / (d["dur"] + 1e-5)
    d["sload_to_rate"] = d["sload"] / (d["rate"] + 1e-5)
    d["dload_to_rate"] = d["dload"] / (d["rate"] + 1e-5)
    d["load_ratio"] = (d["sload"] + 1.0) / (d["dload"] + 1.0)
    
    # TCP Handshake, Jitter, Timing
    d["tcprtt_to_dur"] = d["tcprtt"] / (d["dur"] + 1e-5)
    d["synack_to_ackdat"] = (d["synack"] + 1e-5) / (d["ackdat"] + 1e-5)
    d["tcprtt_synack_ratio"] = d["synack"] / (d["tcprtt"] + 1e-5)
    d["syn_ack_diff"] = np.abs(d["synack"] - d["ackdat"])
    d["dinpkt_to_sinpkt"] = (d["dinpkt"] + 1e-4) / (d["sinpkt"] + 1e-4)
    d["jit_diff"] = np.abs(d["sjit"] - d["djit"])
    d["jit_ratio"] = (d["sjit"] + 1.0) / (d["djit"] + 1.0)
    d["jit_sum"] = d["sjit"] + d["djit"]
    d["dinpkt_dload_ratio"] = d["dinpkt"] / (d["dload"] + 1e-4)
    d["mean_size_ratio"] = (d["smean"] + 1.0) / (d["dmean"] + 1.0)
    
    # Connection Metrics
    d["ct_ratio"] = (d["ct_src_dport_ltm"] + 1.0) / (d["ct_dst_sport_ltm"] + 1.0)
    d["swin_dwin_ratio"] = (d["swin"] + 1.0) / (d["dwin"] + 1.0)
    d["stcpb_dtcpb_diff"] = np.abs(d["stcpb"] - d["dtcpb"])
    
    # Indicators
    d["has_tcp_handshake"] = (d["tcprtt"] > 0).astype(int)
    d["is_slow_handshake"] = (d["tcprtt"] > 0.05).astype(int)
    d["zero_dbytes"] = (d["dbytes"] == 0).astype(int)
    d["zero_dur"] = (d["dur"] == 0).astype(int)
    
    # Log transforms
    skew_cols = ["sbytes", "dbytes", "tot_bytes", "sload", "dload", "rate", "dur", "sinpkt", "dinpkt", "sjit", "djit"]
    for c in skew_cols:
        d[f"log_{c}"] = np.log1p(np.maximum(0, d[c]))
        
    return d

def train_and_export():
    print("[*] Loading UNSW-NB15 dataset (output.csv)...")
    df = pd.read_csv("output.csv")
    
    # Conflict & duplicate filtering
    feature_cols = [c for c in df.columns if c not in ["label", "attack_cat"]]
    conflict_mask = df.groupby(feature_cols, dropna=False)["label"].transform("nunique") > 1
    df_clean = df.loc[~conflict_mask].copy()
    df_model = df_clean.drop_duplicates().copy()
    print(f"  [+] Cleaned records: {len(df_model)} rows.")
    
    # Feature engineering
    print("  [+] Applying 48 domain network feature transformations...")
    df_fe = build_network_features(df_model)
    
    cat_cols = ["proto", "service", "state"]
    freq_maps = {}
    for c in cat_cols:
        fmap = df_fe[c].value_counts(normalize=True).to_dict()
        df_fe[f"{c}_freq"] = df_fe[c].map(fmap)
        freq_maps[c] = fmap
        
    # Multiclass setup
    df_multi = df_fe.copy()
    df_multi["attack_cat"] = df_multi["attack_cat"].astype("string").str.strip()
    df_multi = df_multi.dropna(subset=["attack_cat"]).copy()
    
    X = df_multi.drop(columns=["label", "attack_cat"])
    y_text = df_multi["attack_cat"]
    
    le = LabelEncoder()
    y = le.fit_transform(y_text)
    class_names = list(le.classes_)
    
    # Split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    # ColumnTransformer
    ct = ColumnTransformer(
        transformers=[("cat", OneHotEncoder(min_frequency=50, handle_unknown="ignore", sparse_output=False), cat_cols)],
        remainder="passthrough"
    )
    X_train_proc = ct.fit_transform(X_train)
    
    # Power Class Weights (alpha=0.40)
    classes_arr, counts_arr = np.unique(y_train, return_counts=True)
    n_total = len(y_train)
    n_cls = len(classes_arr)
    weights_power = (n_total / (n_cls * counts_arr)) ** 0.40
    weight_map = dict(zip(classes_arr, weights_power))
    sw = np.array([weight_map[c] for c in y_train])
    
    # 1. Train Multiclass XGBoost
    print("  [+] Training Tuned Multiclass XGBoost Classifier...")
    xgb_multi = XGBClassifier(
        n_estimators=350, max_depth=7, learning_rate=0.05,
        subsample=0.8, colsample_bytree=0.8, objective="multi:softprob",
        num_class=n_cls, eval_metric="mlogloss",
        random_state=42, n_jobs=-1, tree_method="hist"
    )
    xgb_multi.fit(X_train_proc, y_train, sample_weight=sw)
    
    # 2. Train Multiclass LightGBM
    print("  [+] Training Tuned Multiclass LightGBM Classifier...")
    lgb_multi = lgb.LGBMClassifier(
        n_estimators=400, learning_rate=0.05, num_leaves=95,
        subsample=0.8, colsample_bytree=0.8, min_child_samples=15,
        random_state=42, n_jobs=-1, verbose=-1
    )
    lgb_multi.fit(X_train_proc, y_train, sample_weight=sw)
    
    # Export artifacts
    os.makedirs("model_artifacts", exist_ok=True)
    print("[*] Serializing trained models and preprocessors to model_artifacts/...")
    
    joblib.dump(xgb_multi, "model_artifacts/xgb_multi.joblib")
    joblib.dump(lgb_multi, "model_artifacts/lgb_multi.joblib")
    joblib.dump(ct, "model_artifacts/preprocessor.joblib")
    joblib.dump(le, "model_artifacts/label_encoder.joblib")
    joblib.dump(freq_maps, "model_artifacts/freq_maps.joblib")
    
    print("[✓] Model artifacts saved successfully:")
    for f in os.listdir("model_artifacts"):
        p = os.path.join("model_artifacts", f)
        print(f"    - {f} ({os.path.getsize(p):,} bytes)")

if __name__ == "__main__":
    train_and_export()
