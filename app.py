import os
import json
import streamlit as st

from src.ui import setup_page

setup_page(
    "Home", "🛡️", "Hybrid Network Intrusion Detection System",
    "**Network Traffic → Preprocessing → ML + Rules → Intrusion Detection → Alerts & Dashboard**",
)

col1, col2 = st.columns([3, 2])

with col1:
    st.markdown("""
    ### How it works
    Each network flow is checked by **two detection methods** and the result records which one raised the alert:

    - **Machine Learning**: a Random Forest trained on the CIC-IDS2017 dataset labels the flow Benign or Malicious and gives a confidence.
      A second Random Forest names the attack type, and an Isolation Forest adds an "unusual flow" signal.
    - **Rules**: readable signatures for port scans, DoS floods, slow-rate DoS, brute force on login ports and odd TCP flags.
      They give a plain-language reason for the alert.
    - **Hybrid decision**: a flow is **Malicious** if the ML confidence is at or above the chosen threshold *or* any rule fires.
      The alert is labelled **ML Only**, **Rules Only** or **Both ML & Rules**.
    """)

with col2:
    st.info("**Where to go**")
    st.page_link("pages/1_Dashboard.py", label="Dashboard: totals, attack mix, alert severity", icon="📊")
    st.page_link("pages/2_Traffic_Analyzer.py", label="Traffic Analyzer: upload CSV and run detection", icon="🔍")
    st.page_link("pages/3_Intrusion_Alerts.py", label="Intrusion Alerts: saved alert log", icon="🚨")
    st.page_link("pages/4_Model_Performance.py", label="Model Performance: accuracy, ROC, comparison", icon="📈")
    st.page_link("pages/5_Network_Monitoring.py", label="Network Monitoring: live rule-based capture", icon="📡")

summary_path = os.path.join("models", "metrics_summary.json")
if os.path.exists(summary_path):
    with open(summary_path, "r") as f:
        metrics_data = json.load(f)

    st.markdown("---")
    st.subheader("Trained Model Snapshot (held-out test set)")
    m_bin = metrics_data.get("binary") or {}

    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Accuracy", f"{m_bin.get('accuracy', 0)*100:.2f}%")
    c2.metric("Precision", f"{m_bin.get('precision', 0)*100:.2f}%")
    c3.metric("Recall", f"{m_bin.get('recall', 0)*100:.2f}%")
    c4.metric("F1-Score", f"{m_bin.get('f1_score', 0)*100:.2f}%")
    c5.metric("False Positive Rate", f"{m_bin.get('false_positive_rate', 0)*100:.2f}%")
else:
    st.warning("No trained models found. Run `python -m src.train` first.")
