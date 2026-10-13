# X-NIDS: Master Project Roadmap & Implementation Tracker

> **Project Name**: X-NIDS (Explainable Network Intrusion Detection System)  
> **Repository**: [https://github.com/axant4323/IDS-with-SHAP](https://github.com/axant4323/IDS-with-SHAP)  
> **Language**: 100% Pure Python  
> **Tracker Version**: 1.0.0  
> **Last Updated**: October 2026

---

## 📊 Overall Project Status

| Phase | Description | Status | Completion | Lead Assignee |
| :--- | :--- | :---: | :---: | :--- |
| **Phase 1** | Data Cleaning & Dataset Conflict Sanitization | ✅ Completed | 100% | Core Team |
| **Phase 2** | 48-Feature Engineering & Ensemble Model Tuning | ✅ Completed | 100% | Core Team |
| **Phase 3** | Pure-Python Simulation, NetFlow Extractor & SHAP XAI | ✅ Completed | 100% | Core Team |
| **Phase 4** | Web-Based SOC Security Dashboard (JavaScript + Tailwind CSS) | ✅ Completed | 100% | Partner 1 |
| **Phase 5** | Extended Attack Scenarios & Multi-Topology Simulation | 🚀 Ready to Implement | 0% | Partner 2 |
| **Phase 6** | Real-Time Live Network Sniffing (Socket / Promiscuous) | 🚀 Ready to Implement | 0% | Partner 3 |
| **Phase 7** | IEEE Research Paper Manuscript & Overleaf LaTeX | 🚀 Ready to Implement | 0% | Partner 4 / All |

---

## ⚡ Quick Progress Check

Run this single command anytime in your terminal to see real-time progress:
```bash
python check_progress.py
```

---

## 📌 Detailed Implementation Checklist

### Phase 1: Data Cleaning & Conflict Sanitization (100% Completed)
- [x] Fix namespace collision with `csv.py` by renaming to `convert_parquet_to_csv.py`
- [x] Profile all 36 original columns in UNSW-NB15 dataset (`input.parquet` / `output.csv`)
- [x] Identify and remove 1,914 feature-identical rows with conflicting labels
- [x] Deduplicate 32,361 identical records to prevent decision tree memorization
- [x] Establish verified baseline benchmarks for Random Forest and XGBoost

---

### Phase 2: Feature Engineering & Model Optimization (100% Completed)
- [x] Implement 48 domain network features in `build_network_features()`:
  - [x] Volume & Asymmetry ratios (`bytes_ratio`, `pkts_ratio`, `sbytes_per_pkt`, `dbytes_per_pkt`)
  - [x] Rate & Dynamics (`byte_rate`, `pkt_rate`, `sload_to_rate`, `dload_to_rate`, `load_ratio`)
  - [x] TCP handshake latencies & jitter (`tcprtt_to_dur`, `syn_ack_diff`, `jit_diff`, `jit_sum`)
  - [x] Log-normal transformations on heavy-tailed distributions (`dur`, `sbytes`, `dbytes`, `sload`)
- [x] Implement categorical frequency encoding and `min_frequency=50` pruning
- [x] Implement Cost-Sensitive Power Class Weighting ($w_c = (N/(C \cdot N_c))^{0.40}$) to rescue minority attacks
- [x] Train tuned XGBoost (`max_depth=7`, `learning_rate=0.04`, histogram binning)
- [x] Train tuned LightGBM (`num_leaves=127`, `min_child_samples=20`)
- [x] Build and calibrate Soft-Voting Ensemble (XGBoost + LightGBM)
- [x] Evaluate Decision Threshold scanning (0.35–0.65) reaching 91.83% accuracy and 88.30% F1
- [x] Serialize trained models, encoders, and transformers to `model_artifacts/`

---

### Phase 3: Pure-Python Simulation, NetFlow Extractor & SHAP XAI (100% Completed)
- [x] Create standalone Python network traffic synthesizer (`simulation/traffic_generator.py`)
- [x] Create Python ns-3 API simulation script with fallback (`simulation/nids_sim.py`)
- [x] Build bidirectional 5-tuple NetFlow extractor from PCAP traces (`engine/flow_extractor.py`)
- [x] Implement sub-millisecond line-rate inference engine (`engine/nids_detector.py`)
- [x] Integrate `shap.TreeExplainer` on flagged attack flows
- [x] Export automated SHAP attribution cards and visual summary plots to `shap_alerts/`
- [x] Build unified orchestrator (`run_simulation_demo.py`) running the entire pipeline in ~7.3 seconds

---

### Phase 4: Web-Based SOC Security Dashboard (JavaScript + Tailwind CSS) (Completed)
*Goal: Build a sleek, modern, glassmorphic dark-mode web application using Vanilla/Modern JavaScript and Tailwind CSS, backed by a lightweight Python REST server (`dashboard/server.py`). Enables evaluators to trigger simulations, inspect live detection feeds, and view interactive SHAP attribution cards in real time.*

- [x] **Task 4.1**: Set up lightweight Python backend API server (`dashboard/server.py` using Flask / FastAPI):
  - [x] Implement `POST /api/run-simulation`: Triggers `run_simulation_demo.py` and returns structured JSON output
  - [x] Implement `GET /api/metrics`: Serves live SOC statistics (total flows, benign count, attack count, mean inference latency)
  - [x] Implement `GET /api/flows`: Serves extracted NetFlow records with prediction labels and confidence scores
  - [x] Implement `GET /api/shap-alerts`: Serves generated SHAP attribution feature drivers and alert plot image paths
- [x] **Task 4.2**: Build modern frontend layout (`dashboard/index.html` styled with Tailwind CSS):
  - [x] Create sleek dark-mode glassmorphic navbar with live status pill and threat alert counters
  - [x] Implement KPI summary cards (Total Inspected Flows, Threat Ratio, Line-Rate Throughput µs/flow)
  - [x] Implement Attack Category Distribution Donut / Bar chart using Chart.js styled with Tailwind CSS
  - [x] Implement Live Threat Feed Table with color-coded severity badges (Normal, Exploits, DoS, Reconnaissance, Generic)
- [x] **Task 4.3**: Implement interactive frontend logic (`dashboard/app.js` in JavaScript):
  - [x] Add "Trigger Simulation & AI Detection" button with real-time animated loading state
  - [x] Add interactive slide-over drawer / modal to inspect SHAP Explainability cards and visual plots for any selected flow
  - [x] Add client-side search, IP filtering, and decision threshold slider (0.35–0.65) to dynamically re-evaluate classifications
- [x] **Task 4.4**: Document dashboard launch instructions (`python dashboard/server.py` -> opens `http://localhost:8000`)


---

### Phase 5: Extended Attack Scenarios & Multi-Topology Simulation (Ready to Implement - Partner 2)
*Goal: Broaden the simulated attack variety to demonstrate comprehensive detection of all 9 UNSW-NB15 attack types.*

- [ ] **Task 5.1**: Extend `simulation/traffic_generator.py` with additional attack signatures:
  - [ ] **Backdoor**: Periodic beaconing packets at regular intervals (C2 traffic)
  - [ ] **Worms**: Rapid multi-host infection propagation across synthetic IP ranges
  - [ ] **Analysis / Web Exploits**: SQL injection / Path traversal payloads inside HTTP Raw loads
  - [ ] **Shellcode**: Small executable binary payloads over raw TCP sockets
- [ ] **Task 5.2**: Add multi-subnet network simulation topology (Enterprise DMZ + Internal LAN)
- [ ] **Task 5.3**: Benchmark detection accuracy across the expanded attack set

---

### Phase 6: Real-Time Live Network Sniffing Mode (Ready to Implement - Partner 3)
*Goal: Allow the NIDS to listen on a real physical/virtual network interface (e.g., `eth0` or `wlan0`) in real time.*

- [ ] **Task 6.1**: Create `engine/live_sniffer.py`:
  - [ ] Use Scapy packet sniffer or raw sockets to capture live network interface packets
  - [ ] Maintain an in-memory sliding time window (e.g., 2-second windows) for active flows
  - [ ] Expire inactive TCP/UDP flows after configurable timeout (e.g., 5 seconds)
- [ ] **Task 6.2**: Stream completed flows directly into `XNidsDetector.detect_and_explain()`
- [ ] **Task 6.3**: Implement alert notification logging to a rotating JSON log file (`alerts.log`)
- [ ] **Task 6.4**: Test live capture against legitimate browsing and curl commands

---

### Phase 7: IEEE Conference Paper & Documentation (Ready to Implement - Partner 4 / All)
*Goal: Convert the experimental results, system architecture, and SHAP findings into a publishable academic paper.*

- [ ] **Task 7.1**: Download official IEEE two-column conference template (`IEEEtran.cls`)
- [ ] **Task 7.2**: Write **Section I: Introduction** (Modern cyber threats, SOC alert fatigue, explainability gap)
- [ ] **Task 7.3**: Write **Section II: Related Work** (Comparative literature review citing Moustafa & Slay, Sarhan, Kasongo)
- [ ] **Task 7.4**: Write **Section III: Proposed Architecture** (Mathematical formulation of 48 features, power weights, soft-voting ensemble)
- [ ] **Task 7.5**: Write **Section IV: Simulation & Flow Extraction** (ns-3 Python topology, 5-tuple flow aggregation)
- [ ] **Task 7.6**: Write **Section V: Results & Benchmarks** (Import tables from `Untitled.ipynb` and `Walkthrough.md`)
- [ ] **Task 7.7**: Write **Section VI: Explainability Case Studies** (Include SHAP summary plot and attribution case studies)
- [ ] **Task 7.8**: Format citations and prepare for submission to target IEEE conferences / Scopus journals

---

## 👥 Partner Onboarding Guide (How to Start Right Away)

If you are a project partner starting work on a pending phase:

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/axant4323/IDS-with-SHAP.git
   cd IDS-with-SHAP
   ```
2. **Set up Virtual Environment**:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt  # or: pip install lightgbm xgboost scapy shap pandas scikit-learn matplotlib
   ```
3. **Check Current Progress**:
   ```bash
   python check_progress.py
   ```
4. **Test the Existing Working Pipeline**:
   ```bash
   python run_simulation_demo.py
   ```
5. **Pick an Open Task from Phase 4, 5, 6, or 7**:
   - Check off completed items in `PROJECT_ROADMAP.md` as you finish them (`[ ]` -> `[x]`).
   - Commit and push your updates to the repository!
