# ACADEMIC PROJECT REPORT

## PROJECT TITLE:
### Hybrid Network Intrusion Detection System Using Machine Learning and Rule-Based Detection

**Course**: Computer Networks & Cybersecurity Capstone  
**Implementation Platform**: Python 3.11+, Streamlit, Scikit-Learn, Scapy, SQLite  
**Dataset**: CIC-IDS2017 Network Traffic Benchmark  

---

### ABSTRACT
Modern computer network security faces escalating threats from Denial of Service (DoS/DDoS) attacks, Port Scanning, Brute Force attempts, and Botnet activity. Traditional Intrusion Detection Systems (IDS) rely on static signature matching, which fails to detect novel attack variants and zero-day anomalies. Conversely, pure Machine Learning (ML) approaches can behave as black-box classifiers that introduce unacceptable false-positive rates in enterprise environments.

This paper presents a **Hybrid Network Intrusion Detection System (NIDS)** that synergizes supervised machine learning (Random Forest Classifier & Isolation Forest Anomaly Detector) with configurable heuristic rule-based detection signatures. Evaluated on 300,000 network flows from the benchmark CIC-IDS2017 dataset, the ML component achieves a binary classification accuracy of **99.84%**, an F1-score of **99.68%**, and a False Positive Rate (FPR) of **0.13%**. The rule engine adds explainable alert reasons but, on this dataset, no extra recall. The system features a responsive Streamlit dashboard for real-time telemetry, dataset simulation, persistent SQLite alert logging, and optional local network packet capture via Scapy.

---

### 1. INTRODUCTION
As cloud infrastructure and Internet of Things (IoT) devices proliferate, network traffic volumes continue to grow exponentially. Intrusion Detection Systems play a critical defense-in-depth role by continuously monitoring network flows for policy violations and unauthorized activity. 

Intrusion detection methodologies are broadly categorized into:
1. **Signature-based / Rule-based Detection**: Compares traffic against known threat patterns. Offers zero false positives for known threats but fails against unknown attacks.
2. **Anomaly-based / Machine Learning Detection**: Learns statistical distributions of normal network behavior and identifies statistical deviations. Effective against novel attacks but prone to false alarms.

This project proposes a **Hybrid NIDS architecture** that unifies both approaches into a calibrated decision hierarchy, mitigating the weaknesses of individual engines.

---

### 2. PROBLEM STATEMENT & OBJECTIVES

#### 2.1 Problem Statement
Single-mechanism intrusion detection engines suffer from fundamental trade-offs: rule engines generate zero alerts for un-cataloged attacks, while ML models can produce spurious alerts for high-volume benign traffic bursts. A unified hybrid approach is needed to provide high detection sensitivity without overwhelming security operations center (SOC) analysts with false alarms.

#### 2.2 Project Objectives
* Develop a robust data preprocessing pipeline supporting raw CIC-IDS2017 network flow features, ensuring complete prevention of data leakage.
* Train and serialize a Random Forest classifier supporting binary (Benign vs Malicious) and multiclass (14 Attack Categories) classification.
* Implement a configurable Rule-Based Detection Engine targeting Port Scanning, DoS floods, Brute Force patterns, and TCP flag anomalies.
* Create a Hybrid Decision Engine that categorizes threats into `ML Only`, `Rules Only`, and `Both ML & Rules`.
* Build an interactive Streamlit dashboard featuring telemetry KPIs, CSV dataset uploads, persistent SQLite alert logging, and Plotly graphics.

---

### 3. METHODOLOGY & SYSTEM ARCHITECTURE

#### 3.1 Data Preprocessing Pipeline
The CIC-IDS2017 dataset contains 67 network flow features extracted using CICFlowMeter. Preprocessing steps include:
* **Feature Normalization**: Trimming whitespaces, mapping column name variations into standardized UPPERCASE schema.
* **Cleaning Infinite/NaN Values**: Replacing `np.inf` values with column medians and imputing missing data.
* **Data Leakage Prevention**: Splitting dataset into 70% Train, 15% Validation, and 15% Test sets *prior* to fitting the `StandardScaler`. Features and both label sets are split from the same row indices, so they stay aligned.

#### 3.2 Machine Learning Engine
* **Binary Classifier**: `RandomForestClassifier` (100 estimators, max depth 20, `class_weight='balanced'`) deciding Benign vs Malicious.
* **Attack-Type Classifier**: a second `RandomForestClassifier` (`class_weight='balanced_subsample'`) naming one of 14 attack categories. It is separate so that confusing two attack types can never turn an attack into a missed alert.
* **Unsupervised Anomaly Detector**: `IsolationForest` trained strictly on benign samples. On the test set it flags 5.25% of benign and 30.99% of attack flows, so it is a secondary signal and does not decide the verdict.

#### 3.3 Rule-Based Signature Engine
Configurable thresholds monitor network flow parameters:
Thresholds were tuned on the labelled dataset to keep benign false positives low:
1. **Port Scanning**: tiny payload-less probe (at most 2 forward packets, at most 1 reply, at most 6 bytes) answered with a zero window, lasting under 1,000 µs.
2. **DoS/DDoS Flooding**: more than 20,000 pkts/s with at least 100 forward packets (a short flow's packet rate alone is meaningless).
3. **Slow-Rate DoS**: web port (80/443/8080) held open over 60 s with no server data.
4. **Brute Force Authentication**: at least 8 forward packets with mean packet length under 100 bytes on ports 21, 22, 23 or 3389.
5. **TCP Flag Anomalies**: URG and PSH set together, or a zero initial window with more than 5 forward packets.

#### 3.4 Hybrid Fusion Hierarchy
Each analyzed flow is assigned a detection category:
A flow is Malicious when the ML confidence reaches the user-set threshold (default 0.5) **or** any rule fires. The alert records its source:
* **Both ML & Rules**: High severity.
* **ML Only**: attack found by the model, no rule matched.
* **Rules Only**: a signature matched while ML confidence was below the threshold.
* **Neither (Benign)**: severity is None.

---

### 4. EXPERIMENTAL RESULTS & PERFORMANCE EVALUATION

Evaluation was conducted on a held-out test set of 45,000 unseen network flows (15% of the data).

#### 4.1 Quantitative Performance Summary

| Metric | Formula / Description | Measured Value |
| :--- | :--- | :--- |
| **Accuracy** | $(TP + TN) / (TP + TN + FP + FN)$ | **99.84%** |
| **Precision** | $TP / (TP + FP)$ | **99.61%** |
| **Recall (Sensitivity)** | $TP / (TP + FN)$ | **99.75%** |
| **F1-Score** | $2 \cdot (Precision \cdot Recall) / (Precision + Recall)$ | **99.68%** |
| **False Positive Rate (FPR)** | $FP / (FP + TN)$ | **0.13%** |
| **ROC-AUC Score** | Area under ROC Curve | **0.9999** |
| **Prediction Latency** | Inference time per 1,000 samples (ms) | **~30 ms** |

#### 4.2 Confusion Matrix Analysis
* **True Negatives (TN)**: 33,548 benign flows correctly passed.
* **False Positives (FP)**: 45 benign flows incorrectly flagged (0.13% FPR).
* **False Negatives (FN)**: 28 attack flows missed.
* **True Positives (TP)**: 11,379 attack flows correctly caught.

#### 4.3 ML vs Rules vs Hybrid

| Method | Accuracy | Precision | Recall | F1 | FPR |
| :--- | :--- | :--- | :--- | :--- | :--- |
| ML only | 99.84% | 99.61% | 99.75% | 99.68% | 0.13% |
| Rules only | 82.87% | 95.88% | 33.87% | 50.05% | 0.49% |
| Hybrid (ML OR Rules) | 99.50% | 98.32% | 99.75% | 99.03% | 0.58% |

The rules alone catch about a third of attacks and add no recall on top of ML here, while raising the false positive rate. Their value is the human-readable reason attached to each alert.

#### 4.4 Attack-Type Classifier
The multiclass Random Forest reaches 99.26% accuracy and 89.8% macro F1. Very rare classes (Heartbleed: 11 samples, SQL Injection: 21, Infiltration: 36 in the whole dataset) are statistically unreliable.

---

### 5. LIMITATIONS & FUTURE WORK

#### 5.1 Limitations
* **Encrypted Payload Inspection**: Flow-based features analyze header telemetry rather than deep packet payload contents.
* **Live Capture Is Rules-Only**: the ML models need full CIC-style flow features that Scapy capture does not compute.
* **Dataset Scope**: results come from one benchmark dataset; the hybrid has not been validated on other traffic.
* **Live Capture Dependencies**: Real-time packet capture with Scapy on Windows requires Npcap driver installation and elevated administrator rights.

#### 5.2 Future Improvements
* Integration of Deep Learning models (LSTM / Transformer-based flow sequence models).
* Automated Threat Intelligence feed synchronization (STIX/TAXII).
* Containerized SOC deployment via Docker and Kubernetes.

---

### 6. CONCLUSION
The developed Hybrid Network Intrusion Detection System successfully demonstrates that combining supervised machine learning with heuristic rule-based detection provides explainable detection, 99.84% ML accuracy with a 0.13% false alarm rate, and explainable alerts from the rule engine. The Streamlit dashboard offers an intuitive interface for network security analysts, making this project an exemplary practical application of Computer Networks and Cybersecurity principles.

---

### REFERENCES
1. Sharafaldin, A., Lashkari, A. H., & Ghorbani, A. A. (2018). *Toward Generating a New Dataset for Intrusion Detection System (CIC-IDS2017)*. International Conference on Information Systems Security and Privacy (ICISSP).
2. Breiman, L. (2001). *Random Forests*. Machine Learning, 45(1), 5-32.
3. Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. IEEE International Conference on Data Mining (ICDM).
