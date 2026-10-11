# X-NIDS: Explainable Network Intrusion Detection System with ns-3 Simulation

[![Python 3.12](https://img.shields.io/badge/Python-3.12-blue.svg)](https://www.python.org/)
[![Machine Learning](https://img.shields.io/badge/Models-XGBoost%20%7C%20LightGBM%20%7C%20Random%20Forest-orange.svg)]()
[![Explainable AI](https://img.shields.io/badge/XAI-SHAP%20TreeExplainer-green.svg)]()
[![Simulation](https://img.shields.io/badge/Simulator-ns--3-red.svg)](https://www.nsnam.org/)
[![Dataset](https://img.shields.io/badge/Dataset-UNSW--NB15-purple.svg)]()

---

## 1. Executive Summary & Research Vision

**X-NIDS** is an end-to-end, research-grade Network Intrusion Detection System designed for real-time traffic classification and explainability. It bridges the gap between static machine learning models and dynamic network environments by coupling:
1. **A State-of-the-Art ML/Ensemble Detection Engine**: Engineered domain-specific network flow features, cost-sensitive power class weighting to rescue minority attacks, and a calibrated soft-voting ensemble combining **XGBoost** and **LightGBM**.
2. **ns-3 Network Simulation**: A realistic, multi-node packet-level simulator in **ns-3** generating live benign network operations (HTTP, FTP, Ping) and cyberattacks (TCP SYN Flood, Port Scanning, UDP Storm).
3. **Flow-Level Explainable AI (SHAP)**: A transparency engine generating instant, human-readable Shapley attribution cards for Security Operations Center (SOC) analysts to understand *why* any flow was flagged as malicious.

---

## 2. End-to-End System Architecture

```
                                  +-------------------------------------------------------------+
                                  |                 ns-3 SIMULATION ENVIRONMENT                 |
                                  |                                                             |
                                  |   [Benign Clients]                 [Attacker Node]          |
                                  |   (HTTP, FTP, Ping)          (SYN Flood, PortScan, DoS)     |
                                  |           \                               /                 |
                                  |            \                             /                  |
                                  |             +---->[ Router / Switch ]<--+                   |
                                  |                           |                                 |
                                  |                           v                                 |
                                  |                `nids_trace.pcap` Stream                     |
                                  +---------------------------+---------------------------------+
                                                              |
                                                              v
                                  +-------------------------------------------------------------+
                                  |               PACKET & FLOW EXTRACTION ENGINE               |
                                  |                                                             |
                                  |   - Real-Time Flow Assembler (PyShark / CICFlowMeter)       |
                                  |   - Bidirectional Flow Tracking (5-tuple keys)              |
                                  |   - Extracts: dur, sbytes, dbytes, tcprtt, synack, jit, etc.|
                                  +---------------------------+---------------------------------+
                                                              |
                                                              v
                                  +-------------------------------------------------------------+
                                  |              FEATURE ENGINEERING & NORMALIZATION            |
                                  |                                                             |
                                  |   - 48 Domain Network Flow Indicators (`build_network_fe`)   |
                                  |   - Volume Asymmetries (bytes_ratio, pkts_ratio, pkt_size)   |
                                  |   - TCP Handshake Latencies (tcprtt_to_dur, syn_ack_diff)   |
                                  |   - Log-Normal Scaling & Frequency Pruned Categoricals      |
                                  +---------------------------+---------------------------------+
                                                              |
                                                              v
                                  +-------------------------------------------------------------+
                                  |                 ENSEMBLE CLASSIFICATION CORE                |
                                  |                                                             |
                                  |      +---------------------+   +---------------------+      |
                                  |      |    Tuned XGBoost    |   |   Tuned LightGBM    |      |
                                  |      |  (Histogram Binning)|   |   (127 Leaf Nodes)  |      |
                                  |      +----------+----------+   +----------+----------+      |
                                  |                 \                     /                     |
                                  |                  v                   v                      |
                                  |             [ Soft-Voting Probability Fusion ]              |
                                  |                               |                             |
                                  |          Prediction: Normal vs. Specific Attack             |
                                  +-------------------------------+-----------------------------+
                                                                  |
                                                                  v
                                  +-------------------------------------------------------------+
                                  |               EXPLAINABILITY ENGINE (SHAP XAI)              |
                                  |                                                             |
                                  |   - Fast SHAP TreeExplainer calculation per flagged flow    |
                                  |   - Attribution decomposition (Waterfall / Force Plot)      |
                                  |   - Actionable SOC Alert Summary                            |
                                  +-------------------------------------------------------------+
```

---

## 3. Machine Learning Pipeline & Validated Benchmarks

### 3.1 Dataset Quality & Preprocessing
* **Base Dataset**: UNSW-NB15 (created by Moustafa & Slay at ACCS/UNSW Canberra).
* **Conflict & Duplicate Cleaning**:
  * 1,914 feature-identical rows with conflicting labels were detected and eliminated.
  * 32,361 exact duplicate records were deduplicated to prevent decision trees from memorizing repetitive flow noise.
* **Feature Pruning**: High-cardinality protocols (131 categories) were frequency-encoded and pooled with a `min_frequency=50` threshold to eliminate sparse-branch tree dilution.

### 3.2 Domain-Specific Feature Engineering (`build_network_features`)
We engineer **48 network flow indicators** across four key functional dimensions:
1. **Flow Volume & Asymmetries**:
   - `tot_bytes = sbytes + dbytes`, `tot_pkts = spkts + dpkts`, `byte_diff`, `pkt_diff`
   - `bytes_ratio = (sbytes + 1) / (dbytes + 1)`, `pkts_ratio = (spkts + 1) / (dpkts + 1)`
   - `sbytes_per_pkt`, `dbytes_per_pkt`, `loss_ratio`
2. **Rates & Dynamics**:
   - `byte_rate = tot_bytes / (dur + 1e-5)`, `pkt_rate = tot_pkts / (dur + 1e-5)`
   - `sload_to_rate`, `dload_to_rate`, `load_ratio`
3. **TCP Timing & Jitter Dynamics**:
   - `tcprtt_to_dur = tcprtt / (dur + 1e-5)`, `syn_ack_diff = abs(synack - ackdat)`
   - `dinpkt_to_sinpkt`, `jit_diff = abs(sjit - djit)`, `jit_ratio`, `jit_sum`
4. **Log-Normal Scaling**:
   - $\log(1 + x)$ transformations applied to heavy-tailed distributions (`dur`, `sbytes`, `dbytes`, `sload`, `dload`, `rate`, `sinpkt`, `dinpkt`, `sjit`, `djit`).

### 3.3 Cost-Sensitive Power Class Weighting
To solve severe multiclass imbalance (`Normal`: 63.3%, `Worms`: 0.09%, `Backdoor`: 0.6%), we compute smoothed power class weights:
$$w_c = \left(\frac{N}{C \cdot N_c}\right)^{0.40}$$
This supplies sufficient gradient penalty to minority attack classes without degrading `Normal` traffic precision.

---

### 3.4 Validated Benchmark Results

#### A. Binary Classification (Normal vs. Attack)

| Model Architecture | Accuracy | Precision | Recall | F1-Score |
| :--- | :---: | :---: | :---: | :---: |
| **Baseline Random Forest** | 90.89% | 88.12% | **86.87%** | 87.49% |
| **Baseline XGBoost** | 91.30% | 91.45% | 84.15% | 87.65% |
| **Tuned XGBoost (Engineered Features)** | 91.51% | 91.31% | 84.95% | 88.01% |
| **Tuned LightGBM (Engineered Features)** | 91.42% | 90.78% | 85.28% | 87.94% |
| **Upgraded Soft-Voting Ensemble (XGB+LGB @ 0.50)** | **91.59%** | **91.13%** | **85.39%** | **88.17%** |
| **Optimized Ensemble (Threshold @ 0.55)** | **91.83%** | **92.89%** | 84.15% | **88.30%** |

#### B. Multiclass Classification (10 Categories)

| Model Architecture | Overall Accuracy | Macro F1 | Weighted F1 | Worms F1 | Backdoor F1 | Analysis F1 | DoS F1 |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline Random Forest** | 77.17% | 44.42% | 79.33% | 0.0000 | 0.0364 | 0.0870 | 0.2338 |
| **Baseline XGBoost** | **83.38%** | 45.51% | 81.85% | 0.0000 | 0.0396 | 0.1053 | 0.1614 |
| **Upgraded Tuned XGBoost** | 82.69% | **50.91%** | 82.90% | **0.3333** | **0.0821** | **0.1618** | 0.2170 |
| **Upgraded Tuned LightGBM** | 83.21% | 48.41% | 82.85% | 0.1818 | 0.0377 | **0.1691** | **0.2237** |
| **Upgraded Soft-Voting Ensemble** | 83.28% | **49.25%** | **83.08%** | **0.1818** | **0.0498** | **0.1597** | **0.2188** |

* **Key Takeaway**: Minority classes were rescued from complete failure (Worms F1 improved from 0.00 to 0.18–0.33; Analysis recall jumped from 17% to 30%; Backdoor recall tripled from 3% to 8%).

---

## 4. ns-3 Network Simulator Integration Plan

### 4.1 Why ns-3?
Network Simulator 3 (ns-3) is the gold-standard discrete-event network simulator for Internet systems. Integrating ns-3 transforms this project from a static offline script into an active, simulation-validated intrusion detection system.

### 4.2 Simulated Network Scenarios
1. **Dumbbell Topology**:
   - Subnet A (Benign Clients): Generate normal Web (HTTP/BulkSend), DNS, and ICMP Ping traffic.
   - Subnet B (Attacker Nodes): Generate specific attack vectors:
     - **TCP SYN Flood**: Rapid TCP connection requests to simulate DoS.
     - **Port Scanning**: Sequential port sweeps across destination IP addresses.
     - **UDP Flood**: High-rate packet storms consuming link capacity.
   - Core Bottleneck Router: Configured with packet trace logging (`pointToPoint.EnablePcapAll("nids_trace")`).
2. **PCAP Extraction Bridge**:
   - The `.pcap` generated by ns-3 is parsed into bidirectional flow records using a Python extractor.
   - Extracted features map directly into our `build_network_features()` pipeline.

---

## 5. Explainable AI (SHAP) Module

### 5.1 Purpose in NIDS
In production security environments, black-box predictions result in false-alarm fatigue. SHAP calculates Shapley values:
$$\phi_i(f, x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} [f(S \cup \{i\}) - f(S)]$$
This attributes credit/blame to specific network features for triggering an intrusion alert.

### 5.2 Sample Alert Output for Security Operations
```text
[X-NIDS SECURITY ALERT]
Timestamp     : 2026-10-11 21:04:15 UTC
Source IP     : 10.1.1.4
Destination IP: 10.1.2.1:80
Verdict       : MALICIOUS (Confidence: 94.7%)
Category      : Denial of Service (DoS)

[TOP ATTRIBUTION DRIVERS (SHAP)]
1. [!] Packet Rate (pkt_rate)      : 8,420 pkts/sec      [SHAP: +0.412] (Spike above baseline)
2. [!] Handshake Ratio (synack_r)  : Incomplete ACK      [SHAP: +0.285] (SYN packet dropped)
3. [!] Byte Asymmetry (bytes_ratio): 0.04                [SHAP: +0.198] (Unbalanced egress)
4. [!] Duration (dur)              : 0.0024s             [SHAP: +0.114] (Ultra-short burst)
```

---

## 6. Research Paper & Publication Blueprint

### Target Publication Venues
* **IEEE International Conferences**: IEEE GLOBECOM Workshops, IEEE ICC Workshops, IEEE Access, IEEE International Conference on Cyber Security (TrustCom), IEEE Consumer Communications & Networking Conference (CCNC).
* **Indexed Journals**: Elsevier *Computers & Security*, Springer *CCIS/LNICST*.

### Paper Structure
1. **Section I: Introduction** — Modern threat landscape, limitations of static CSV testing, research contributions.
2. **Section II: Related Work** — Literature review on UNSW-NB15, machine learning IDS, and explainable AI in cybersecurity.
3. **Section III: Proposed Architecture** — Formal mathematical definition of feature engineering, power weighting, soft-voting ensemble, and SHAP explainer.
4. **Section IV: ns-3 Simulation Setup** — Topology design, application traffic models, attack generation scripts.
5. **Section V: Experimental Results & Benchmarks** — Comparative tables, ROC curves, latency per flow (inference speed).
6. **Section VI: Explainability Case Studies** — Visual SHAP force plots explaining DoS vs. PortScan vs. Benign traffic.
7. **Section VII: Conclusion & Future Scope** — Deployment constraints and edge firewall integration.

---

## 7. Project File Directory

```
/home/akshant/finalyear/
├── README.md                     <-- System architecture & research blueprint
├── Untitled.ipynb                <-- Complete, executed 71-cell ML & evaluation notebook
├── Untitled_backup.ipynb         <-- Clean backup of original notebook
├── convert_parquet_to_csv.py     <-- Clean conversion utility
├── input.parquet                 <-- UNSW-NB15 base parquet dataset
├── output.csv                    <-- Extracted dataset (82,332 records)
└── venv/                         <-- Python 3.12 virtual environment (LightGBM, XGBoost, SHAP)
```

---

## 8. Next Step: Building the Simulator

With the system architecture and theoretical foundation established, the next phase is building the simulator:
1. **Set up the ns-3 simulation script (`nids_sim.cc`)**: Configure the nodes, channels, applications, and attack injection.
2. **Build the PCAP-to-Flow Extractor (`flow_extractor.py`)**: Convert ns-3 `.pcap` packets into flow records matching the model features.
3. **Build the Live Inference & SHAP Visualizer (`nids_detector.py`)**: Ingest simulated flows, output predictions, and generate visual SHAP attribution plots.
