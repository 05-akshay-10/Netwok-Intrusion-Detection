import os
import json
import streamlit as st
import pandas as pd

# Page configuration
st.set_page_config(
    page_title="Hybrid NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Cyber Dark Custom CSS
CUSTOM_CSS = """
<style>
    /* Dark Theme Base */
    .stApp {
        background-color: #0b0f19;
        color: #e2e8f0;
    }
    
    /* Card Styles */
    .metric-card {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 20px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.4);
        transition: transform 0.2s ease, border-color 0.2s ease;
    }
    .metric-card:hover {
        transform: translateY(-2px);
        border-color: #00f2fe;
    }
    
    .card-title {
        color: #9ca3af;
        font-size: 0.875rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.05em;
        margin-bottom: 8px;
    }
    
    .card-value {
        color: #f9fafb;
        font-size: 2.25rem;
        font-weight: 700;
        letter-spacing: -0.025em;
    }
    
    .card-subtitle {
        color: #6b7280;
        font-size: 0.75rem;
        margin-top: 4px;
    }
    
    /* Status Badges */
    .badge-success {
        background-color: rgba(16, 185, 129, 0.2);
        color: #10b981;
        border: 1px solid #10b981;
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    .badge-warning {
        background-color: rgba(245, 158, 11, 0.2);
        color: #f59e0b;
        border: 1px solid #f59e0b;
        padding: 4px 10px;
        border-radius: 9999px;
        font-size: 0.75rem;
        font-weight: 600;
    }
    
    /* Header Container */
    .header-container {
        border-bottom: 1px solid #1f2937;
        padding-bottom: 16px;
        margin-bottom: 24px;
    }
    
    /* Hide default Streamlit padding top */
    .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
    }
</style>
"""
st.markdown(CUSTOM_CSS, unsafe_allow_dict=True)

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/isometric/100/000000/shield.png", width=70)
    st.title("Hybrid NIDS")
    st.caption("Computer Networks & Cybersecurity Project")
    st.markdown("---")
    
    st.subheader("System Status")
    
    # Check ML model status
    model_ready = os.path.exists(os.path.join("models", "random_forest_binary.joblib"))
    if model_ready:
        st.markdown('<span class="badge-success">● ML Model Ready</span>', unsafe_allow_dict=True)
    else:
        st.markdown('<span class="badge-warning">▲ ML Model Not Trained</span>', unsafe_allow_dict=True)
        
    st.markdown('<span class="badge-success">● Rule Engine Active</span>', unsafe_allow_dict=True)
    st.markdown('<span class="badge-success">● Alert Database Ready</span>', unsafe_allow_dict=True)
    
    st.markdown("---")
    st.markdown("### Quick Navigation")
    st.markdown("""
    - 📊 **Dashboard**: System overview & stats
    - 🔍 **Traffic Analyzer**: Upload & evaluate CSV
    - 🚨 **Intrusion Alerts**: Persistent alert log
    - 📈 **Model Performance**: ML metrics & ROC
    - 📡 **Network Monitoring**: Live packet capture
    """)
    st.markdown("---")
    st.caption("CIC-IDS2017 Dataset • Scikit-Learn • Scapy")

# Main Page Welcome & Overview Banner
st.markdown('<div class="header-container">', unsafe_allow_dict=True)
st.title("🛡️ Hybrid Network Intrusion Detection System")
st.markdown("**Machine Learning (Random Forest) + Configurable Rule-Based Heuristics**")
st.markdown('</div>', unsafe_allow_dict=True)

col1, col2 = st.columns([2, 1])

with col1:
    st.markdown("""
    ### Welcome to the Hybrid NIDS Control Center
    
    This system combines **supervised Machine Learning** and **heuristic Rule-Based Detection** 
    to inspect network traffic flows, detect intrusions, identify attack categories, and generate real-time alerts.
    
    #### Key Capabilities:
    1. **Supervised ML Classification**: Trained on the benchmark **CIC-IDS2017 dataset** using Random Forest to classify benign vs malicious traffic.
    2. **Rule-Based Engine**: Configurable signatures for detecting **Port Scanning, DoS/DDoS floods, Brute Force attempts, and TCP flag anomalies**.
    3. **Hybrid Decision Integration**: Combines ML confidence probabilities with rule triggers to classify events as *ML Only*, *Rules Only*, or *Both*.
    4. **Offline Dataset Simulation & Live Capture**: Analyze historical CSV traffic dumps or capture live packets on authorized local interfaces using Scapy.
    """)

with col2:
    st.info("💡 **Getting Started**")
    st.markdown("""
    Use the sidebar menu to navigate between pages:
    - **1_Dashboard**: View overall network traffic distribution and alert summaries.
    - **2_Traffic_Analyzer**: Upload a CSV dataset file or load a sample to run hybrid detection.
    - **3_Intrusion_Alerts**: Search, filter, and inspect detailed security alerts.
    - **4_Model_Performance**: View exact accuracy, F1-score, FPR, and confusion matrix.
    - **5_Network_Monitoring**: Run packet capture on your local adapter.
    """)

# Load metrics summary if present
summary_path = os.path.join("models", "metrics_summary.json")
if os.path.exists(summary_path):
    with open(summary_path, "r") as f:
        metrics_data = json.load(f)
        
    st.markdown("---")
    st.subheader("Current Trained Model Snapshot")
    m_bin = metrics_data.get("binary", {})
    
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Accuracy", f"{m_bin.get('accuracy', 0)*100:.2f}%")
    c2.metric("Precision", f"{m_bin.get('precision', 0)*100:.2f}%")
    c3.metric("Recall", f"{m_bin.get('recall', 0)*100:.2f}%")
    c4.metric("F1-Score", f"{m_bin.get('f1_score', 0)*100:.2f}%")
