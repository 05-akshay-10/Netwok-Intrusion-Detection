# Hybrid Network Intrusion Detection System (NIDS) Using Machine Learning and Rule-Based Detection

A Computer Networks and Cybersecurity capstone project combining **Supervised Machine Learning (Random Forest & Isolation Forest)** with **Heuristic Rule-Based Signatures** to detect malicious network intrusions, classify attack vectors, and generate real-time alerts.

---

## 📌 1. Problem Statement
Modern computer networks face sophisticated threats including Denial of Service (DoS/DDoS), Port Scans, Brute Force attacks, and Botnet activity. Traditional intrusion detection systems rely solely on static signatures, failing to catch zero-day anomalies, while pure machine learning models can act as black boxes with false positive risks. 

This project solves this challenge by developing a **Hybrid NIDS architecture** that fuses statistical machine learning with deterministic network traffic rules to maximize detection rate while maintaining low false-positive rates.

---

## 🎯 2. Objectives
1. **Machine Learning Engine**: Train Random Forest classifiers on the benchmark **CIC-IDS2017 dataset**: one for Benign vs Malicious, one to name the attack type (14 attack categories), plus an Isolation Forest anomaly signal.
2. **Rule-Based Engine**: Implement configurable, explainable signatures for Port Scans, DoS floods, slow-rate DoS, Brute Force on login ports, and TCP flag anomalies.
3. **Hybrid Integration**: A flow is Malicious if ML confidence >= the chosen threshold OR any rule fires; the alert records the source (`ML Only`, `Rules Only`, `Both ML & Rules`).
4. **Interactive Dashboard**: Build a dark-themed Streamlit control panel featuring telemetry KPIs, traffic dataset uploads, alert monitoring, and interactive Plotly visual charts.
5. **Local Packet Capture**: Support optional real-time packet capture on authorized network interfaces using Scapy.

---

## 🏗️ 3. System Architecture

```
                                  [ Input Network Data ]
                                 (CSV Dataset / Scapy Capture)
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │     Data Preprocessing &         │
                              │     Feature Alignment            │
                              └────────────────┬─────────────────┘
                                               │
                       ┌───────────────────────┴───────────────────────┐
                       │                                               │
                       ▼                                               ▼
     ┌──────────────────────────────────┐            ┌──────────────────────────────────┐
     │      Machine Learning Engine     │            │        Rule-Based Engine         │
     │  (2 Random Forests + IsolationFor)  │            │     (Heuristic Signatures)     │
     └─────────────────┬────────────────┘            └─────────────────┬────────────────┘
                       │                                               │
                       │ [Probability %]                               │ [Rule Alerts]
                       └───────────────────────┬───────────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │      Hybrid Decision Engine      │
                              │ (ML Only | Rules Only | Both)    │
                              └────────────────┬─────────────────┘
                                               │
                                               ▼
                              ┌──────────────────────────────────┐
                              │   Streamlit Dashboard Control    │
                              │    & SQLite Alert Persistence    │
                              └──────────────────────────────────┘
```

---

## 💻 4. Technologies Used
* **Programming Language**: Python 3.11+
* **Frontend UI**: Streamlit
* **Data Science & ML**: Scikit-Learn, Pandas, NumPy
* **Model Serialization**: Joblib
* **Data Visualization**: Plotly, Matplotlib
* **Alert Persistence**: SQLite3
* **Live Network Capture**: Scapy
* **Unit Testing**: Pytest

---

## 📊 5. Dataset Information
* **Dataset Name**: CIC-IDS2017 (Canadian Institute for Cybersecurity)
* **Dataset File**: `data/cicids2017.txt` (300,000 flow records, 67 columns)
* **Classes**: Benign (223,955) vs Malicious (76,045) across 14 attack types (15 classes including Benign) (DoS Hulk, DDoS, PortScan, FTP-Patator, SSH-Patator, Bot, Web Attacks, Infiltration, Heartbleed).

---

## 📁 6. Project Directory Structure
```
Network Intrusion Detection/
├── app.py                          # Streamlit main entry point
├── requirements.txt                # Python package dependencies
├── README.md                       # Comprehensive documentation
├── .gitignore                      # Git ignore file
├── .streamlit/config.toml          # Shared dark theme for every page
├── data/
│   ├── raw/                        # Raw dataset folder
│   ├── cicids2017.txt              # CIC-IDS2017 dataset file
│   └── alerts.db                   # Persistent SQLite alert database
├── models/
│   ├── random_forest_binary.joblib # Saved Binary RF model
│   ├── random_forest_multiclass.joblib # Saved Multiclass RF model
│   ├── isolation_forest.joblib     # Anomaly detector model
│   ├── feature_names.joblib        # Training feature list
│   ├── feature_scaler.joblib       # Fitted StandardScaler
│   └── metrics_summary.json        # Precomputed test evaluation stats
├── src/
│   ├── __init__.py
│   ├── data_loader.py              # Flexible CSV loading & normalization
│   ├── preprocessing.py           # Cleaning, scaling, leakage prevention
│   ├── train.py                    # Model training script
│   ├── predict.py                  # Model inference engine
│   ├── rules.py                    # Configurable Rule-Based engine
│   ├── hybrid_detector.py          # Combined ML + Rule decision engine
│   ├── alert_manager.py            # SQLite database interface
│   ├── live_capture.py             # Scapy live packet capture
│   ├── ui.py                       # Shared page setup, styling and sidebar status
│   └── metrics.py                  # Evaluation metrics & report writer
├── pages/
│   ├── 1_Dashboard.py              # Page 1: System overview & telemetry
│   ├── 2_Traffic_Analyzer.py       # Page 2: CSV dataset upload & analysis
│   ├── 3_Intrusion_Alerts.py       # Page 3: Alert log database manager
│   ├── 4_Model_Performance.py      # Page 4: Confusion matrix & ROC curve
│   └── 5_Network_Monitoring.py     # Page 5: Live network packet capture
├── tests/
│   ├── test_preprocessing.py       # Data loader, cleaning & split-alignment tests
│   ├── test_detection.py           # Rule engine, hybrid logic & end-to-end tests
│   └── test_metrics.py             # Evaluation metrics unit tests
└── reports/
    └── project_report.md           # College project submission report
```

---

## 🚀 7. Installation & Quick Start

### Step 1: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 2: Run Automated Unit Tests
```bash
python -m pytest
```

### Step 3: Train Machine Learning Models (Offline)
```bash
python -m src.train
```

### Step 4: Launch the Streamlit Dashboard
```bash
streamlit run app.py
```

---

## 🎬 8. College Project Demonstration Workflow

Follow these steps during your project viva or presentation:

1. **Step 1 - System Architecture (Home Page)**: Open `app.py`, show the sidebar status badges, the "How it works" text and the model snapshot.
2. **Step 2 - Dataset Inspection (Dashboard)**: Open `1_Dashboard.py`. Before any analysis it shows the real CIC-IDS2017 label counts; after analysis it shows your results.
3. **Step 3 - Model Training & Metrics (Model Performance)**: Open `4_Model_Performance.py` and explain the measured **99.84% Accuracy**, **99.68% F1-Score**, **0.13% False Positive Rate**, Confusion Matrix, ROC Curve, the ML vs Rules vs Hybrid table, and the Isolation Forest section.
4. **Step 4 - Traffic Analyzer Simulation**: Open `2_Traffic_Analyzer.py`, select a sample dataset slice or upload a CSV file, and click **Run Hybrid Detection**.
5. **Step 5 - Combined Results Table**: Review the output table showing `Final Prediction`, `Attack Category`, `Detection Method`, `Severity`, `ML Confidence %`, and the Isolation Forest flag. Filter results and download CSV.
6. **Step 6 - Intrusion Alert Logs**: Open `3_Intrusion_Alerts.py` to inspect the SQLite alert log. Expand an alert to explain the ML vs Rule root cause.
7. **Step 7 - Feature Importance**: Point out the top flow features (e.g. `DESTINATION_PORT`, `FLOW_DURATION`, `FLOW_PACKETS_S`) driving model decisions.
8. **Step 8 - Live Monitoring Demonstration**: Open `5_Network_Monitoring.py` and show packet capture on your local adapter (rules only; needs Npcap and administrator rights).

---

## 📈 9. Empirical Model Evaluation Results

| Metric | Measured Value | Explanation |
| :--- | :--- | :--- |
| **Accuracy** | **99.84%** | Total percentage of network flows correctly identified. |
| **Precision** | **99.61%** | Out of all flows flagged as attacks, 99.61% were actual attacks. |
| **Recall (TPR)** | **99.75%** | Out of all genuine attacks, 99.75% were successfully detected. |
| **F1-Score** | **99.68%** | Harmonic mean balancing precision and recall under class imbalance. |
| **False Positive Rate (FPR)** | **0.13%** | Fraction of benign network flows wrongly flagged as malicious. |
| **Inference Latency** | **~30 ms / 1k flows** | Time to classify 1,000 flows (single machine), fast enough for near real-time use. |

---

## 🖥️ 9b. The Dashboard Pages and the Models Behind Them

| Page | What it shows | Source |
| :--- | :--- | :--- |
| **Home** (`app.py`) | How the hybrid works, links to every page, model snapshot (accuracy, precision, recall, F1, FPR). | `models/metrics_summary.json` |
| **1 Dashboard** | KPI cards (flows, benign, malicious, alerts, attack categories), benign/malicious donut, attack-category bars, alert-severity pie, recent alerts. Shows your latest analysis; before any analysis it shows the CIC-IDS2017 training label counts, clearly marked as a baseline. | Session results, `alerts.db`, metrics file |
| **2 Traffic Analyzer** | Upload a CSV or load a slice of the dataset, set the ML threshold, run detection. Results table with prediction, attack category, detection method, severity, ML confidence, Isolation Forest flag, triggered rules and explanation; filters and CSV download. Malicious flows are saved to the alert database. | All models + rule engine |
| **3 Intrusion Alerts** | Saved alert log with severity/method filters, search, an inspector with the root-cause explanation, CSV export, clear history. | `data/alerts.db` |
| **4 Model Performance** | Test-set accuracy/precision/recall/F1/FPR, confusion matrix, ROC curve, **ML vs Rules vs Hybrid table**, multiclass per-class table, **Isolation Forest section**, top feature importances, downloadable report. | `models/metrics_summary.json` |
| **5 Network Monitoring** | Live Scapy capture: packet and flow counters and rule alerts. Rules only, because the ML models need full CIC-style flow features that live capture does not compute. | Rule engine |

### Why three models instead of one

| Model | Question it answers | Where you see it |
| :--- | :--- | :--- |
| **Binary Random Forest** | Is this flow Benign or Malicious, and how confident? | The decision itself: Final Prediction, ML Confidence %, severity, alerts, Home and Model Performance metrics, confusion matrix, ROC. |
| **Multiclass Random Forest** | If it is an attack, which of 14 types (DoS Hulk, PortScan, ...)? | Attack Category in the analyzer table, alerts and dashboard bars; per-class table on Model Performance. |
| **Isolation Forest** (unsupervised, trained on benign flows only) | Does this flow look statistically unusual, even without a label? | Anomaly count and column in the analyzer, a note in the alert explanation, and flag rates on Model Performance. It never decides Benign vs Malicious. |

One forest is not enough because naming the attack among 15 classes is a harder task than "attack or not". The binary model is tuned for the yes/no alert decision, while the multiclass model spends its capacity separating attack types (and is weaker on very rare classes such as Heartbleed or SQL Injection). Keeping them separate means a confusion between two attack types never turns into a missed attack. The Isolation Forest is a different kind of model and flags only about 5% of benign and 31% of attack flows, so it is shown as a secondary signal.

## ⚠️ 10. Limitations & Future Scope
* **Limitations**: High packet rate Live Capture with Scapy requires administrator privileges and Npcap driver on Windows. Heavy traffic volume (>10Gbps) requires hardware acceleration or C-based DPDK capture engines.
* **Future Scope**: Integrate Deep Learning (LSTM/Autoencoders) for sequential anomaly detection, deploy dynamic rule auto-generation based on threat intelligence feeds, and containerize using Docker for enterprise SOC deployment.

### Detection method comparison (held-out test set)

| Method | Recall | FPR | Notes |
| :--- | :--- | :--- | :--- |
| ML only (Random Forest) | 99.75% | 0.13% | Primary detector |
| Rules only | 33.87% | 0.49% | Explainable, but covers only port scans, brute force, slow DoS and zero-window floods |
| Hybrid (ML OR Rules) | 99.75% | 0.58% | Adds a human-readable reason to alerts at the cost of extra rule false positives |

Re-run `python -m src.train` to regenerate these; the Model Performance page shows them live.
