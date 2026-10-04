# Step-by-Step College Project Demonstration Guide

This document provides a structured 7-step walkthrough for presenting and demonstrating the **"Hybrid Network Intrusion Detection System Using Machine Learning and Rule-Based Detection"** project during a college viva, evaluation, or practical demonstration.

---

### 📋 Pre-Demonstration Checklist
1. Open a terminal in the project directory: `c:\Users\Akshay\OneDrive\Documents\Network Intrusion Detection`
2. Ensure dependencies are installed: `pip install -r requirements.txt`
3. Launch the Streamlit application:
   ```bash
   streamlit run app.py
   ```
4. Open your web browser at `http://localhost:8501`.

---

## 🎬 7-Step Demonstration Walkthrough

### 📍 Step 1: System Overview & Architecture (`app.py`)
* **Action**: Open the main landing page (`app.py`).
* **What to Show**:
  * Point out the **System Status Badges** in the sidebar showing `ML Model Ready`, `Rule Engine Active`, and `Alert Database Ready`.
  * Explain the system architecture: A dual-engine hybrid approach fusing supervised machine learning (Random Forest) with heuristic rule-based signatures.
* **Viva Explanation**: *"Traditional IDS rely purely on fixed rules which fail against zero-day threats, whereas pure ML models can create false alarms. Our system combines both into a hybrid engine to maximize detection accuracy while keeping false positives under 0.15%."*

---

### 📍 Step 2: Dashboard Telemetry (`1_Dashboard.py`)
* **Action**: Click on **1_Dashboard** in the sidebar.
* **What to Show**:
  * **KPI Summary Cards**: Total network flows analyzed, Benign flows, Malicious flows, Logged alerts, and Attack categories.
  * **Interactive Plotly Charts**:
    * Donut chart showing Benign vs Malicious traffic ratio.
    * Horizontal bar chart showing the breakdown of attack vectors (DoS Hulk, DDoS, PortScan, FTP-Patator, SSH-Patator, Bot, etc.).
    * Alert severity distribution pie chart.
* **Viva Explanation**: *"The dashboard aggregates high-level telemetry from historical datasets and active intrusion logs, giving security analysts immediate situational awareness of attack volume and severity distribution."*

---

### 📍 Step 3: Traffic Analysis & Hybrid Engine (`2_Traffic_Analyzer.py`)
* **Action**: Click on **2_Traffic_Analyzer**, select a sample slice of `cicids2017.txt` or upload a CSV file, adjust the confidence slider (0.50), and click **⚡ Run Hybrid Detection**.
* **What to Show**:
  * The dataset preview (rows, columns, data types, missing values).
  * The progress indicator and generated **Interactive Results Table**.
  * Show the columns: `Predicted Class`, `Attack Category`, `Detection Method`, `Severity`, `ML Confidence %`, and `Triggered Rules`.
  * Demonstrate filtering by classification (Benign/Malicious) or detection method (`ML Only`, `Rules Only`, `Both ML & Rules`).
* **Viva Explanation**: *"Here, raw network flow records are passed through our preprocessed ML scaler and evaluated simultaneously by our Random Forest model and Rule-Based engine. Each flow is categorized based on whether ML, Rules, or both detected the anomaly."*

---

### 📍 Step 4: Persistent Intrusion Alert Logs (`3_Intrusion_Alerts.py`)
* **Action**: Click on **3_Intrusion_Alerts**.
* **What to Show**:
  * The SQLite alert history stored in `data/alerts.db`.
  * Filters for Severity (`High`, `Medium`, `Low`) and Detection Method.
  * Use the **Alert Deep-Dive Inspector** dropdown to select a specific alert ID and view its complete timestamp, IPs, ports, and root-cause explanation.
  * Point out the **Export Alert Log as CSV** button.
* **Viva Explanation**: *"All malicious records are automatically recorded in an embedded SQLite database. The Deep-Dive Inspector breaks down exactly why an alert was triggered—whether due to high ML confidence or specific rule signatures like Port Scanning or DoS packet floods."*

---

### 📍 Step 5: Model Evaluation & Performance (`4_Model_Performance.py`)
* **Action**: Click on **4_Model_Performance**.
* **What to Show**:
  * The top metric cards: **99.84% Accuracy**, **99.65% Precision**, **99.72% Recall**, **99.68% F1-Score**, and **0.12% False Positive Rate**.
  * The **Confusion Matrix Heatmap** evaluated on the held-out 15% test set (33,553 TN, 11,374 TP).
  * The **ROC Curve** (AUC = 0.9998).
  * The **Top 15 Feature Importances** chart (showing key flow features like `DESTINATION_PORT`, `FLOW_DURATION`, `FLOW_PACKETS_S`).
  * Click **Download Full Model Evaluation Report (TXT)**.
* **Viva Explanation**: *"All evaluation metrics were calculated on 45,000 unseen test samples using strict data leakage prevention (scaler fitted only on training set). Our model achieves high sensitivity with an ultra-low 0.12% false positive rate."*

---

### 📍 Step 6: Live Network Packet Capture (`5_Network_Monitoring.py`)
* **Action**: Click on **5_Network_Monitoring**.
* **What to Show**:
  * Select your local network adapter from the dropdown list.
  * Click **▶️ Start Monitoring** (or explain the Scapy packet capture background thread).
  * Show captured packet counter, active 5-tuple flow aggregator, and live rule-based alert table.
* **Viva Explanation**: *"For real-time defense, our Scapy module captures live packets on local network interfaces, aggregates them into 5-tuple IP flows, and evaluates heuristic rules live to catch scanning and flood attempts as they occur."*

---

### 📍 Step 7: Documentation & Academic Reports
* **Action**: Open [README.md](file:///c:/Users/Akshay/OneDrive/Documents/Network%20Intrusion%20Detection/README.md) and [reports/project_report.md](file:///c:/Users/Akshay/OneDrive/Documents/Network%20Intrusion%20Detection/reports/project_report.md) in your code editor or browser.
* **What to Show**:
  * Point out the full problem statement, technology stack, dataset citations (CIC-IDS2017), project folder structure, and formal academic paper format (Abstract, Introduction, Methodology, Results, Discussion, References).
* **Viva Explanation**: *"The repository includes comprehensive setup documentation, automated unit tests (`pytest`), and a complete formal academic project report ready for college submission."*
