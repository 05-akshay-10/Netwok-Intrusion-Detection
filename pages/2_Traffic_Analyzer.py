import os
import streamlit as st
import pandas as pd
import numpy as np

from src.data_loader import find_dataset_files, load_dataset
from src.hybrid_detector import HybridDetector
from src.alert_manager import AlertManager

st.set_page_config(page_title="Traffic Analyzer | Hybrid NIDS", page_icon="🔍", layout="wide")

st.title("🔍 Network Traffic Analyzer")
st.markdown("Upload network flow CSV files or select sample dataset for hybrid machine learning and rule-based inspection.")

# Initialize Session State for Detector
if "hybrid_detector" not in st.session_state:
    st.session_state["hybrid_detector"] = HybridDetector()

alert_mgr = AlertManager()

# Data Source Selection Tabs
tab_upload, tab_sample = st.tabs(["📤 Upload CSV Dataset", "📁 Select Pre-loaded Sample"])

selected_df = None
data_source_name = ""

with tab_upload:
    uploaded_file = st.file_uploader("Upload Network Flow CSV or TXT file", type=["csv", "txt"])
    if uploaded_file is not None:
        try:
            df_upload = pd.read_csv(uploaded_file, low_memory=False)
            selected_df = df_upload
            data_source_name = uploaded_file.name
            st.success(f"File '{uploaded_file.name}' uploaded successfully ({len(df_upload):,} rows, {len(df_upload.columns)} columns).")
        except Exception as e:
            st.error(f"Error parsing uploaded file: {e}")

with tab_sample:
    dataset_files = find_dataset_files()
    if dataset_files:
        chosen_file = st.selectbox("Select dataset from disk:", dataset_files)
        sample_rows = st.slider("Select number of rows to analyze:", min_value=100, max_value=50000, value=2000, step=500)
        if st.button("Load Dataset Slice"):
            df_sample, meta = load_dataset(chosen_file, sample_size=sample_rows)
            selected_df = df_sample
            data_source_name = os.path.basename(chosen_file) + f" ({sample_rows} samples)"
            st.session_state["loaded_df"] = df_sample
            st.session_state["data_source_name"] = data_source_name
            st.success(f"Loaded {len(df_sample):,} rows from {chosen_file}")
    else:
        st.warning("No local dataset files found in data/ folder.")

# Use session state if loaded
if selected_df is None and "loaded_df" in st.session_state:
    selected_df = st.session_state["loaded_df"]
    data_source_name = st.session_state.get("data_source_name", "Loaded Data")

if selected_df is not None:
    st.markdown("---")
    st.subheader(f"Dataset Preview: {data_source_name}")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Rows", f"{len(selected_df):,}")
    col2.metric("Columns", f"{len(selected_df.columns)}")
    col3.metric("Missing Values", f"{selected_df.isna().sum().sum():,}")

    with st.expander("Inspect Raw Data & Columns", expanded=False):
        st.dataframe(selected_df.head(10), use_container_width=True)
        st.write("Column Names:", selected_df.columns.tolist())

    st.markdown("---")
    st.subheader("Hybrid Traffic Analysis Engine")
    
    c_thresh, c_btn = st.columns([2, 1])
    with c_thresh:
        ml_thresh = st.slider("ML Detection Sensitivity Threshold (Confidence Probability)", 0.10, 0.95, 0.50, 0.05)
    
    with c_btn:
        st.write("") # Padding
        run_analysis = st.button("⚡ Run Hybrid Detection", type="primary", use_container_width=True)

    if run_analysis:
        with st.spinner("Executing Random Forest ML inference and evaluating Rule-Based heuristics..."):
            detector: HybridDetector = st.session_state["hybrid_detector"]
            results_df = detector.analyze(selected_df, ml_threshold=ml_thresh)
            
            # Save results to session state
            st.session_state["analyzed_df"] = results_df
            
            # Persist alerts to SQLite database
            alerts_added = alert_mgr.save_alerts_from_df(results_df)
            st.success(f"Analysis complete! {len(results_df):,} flows processed. Logged {alerts_added} security alerts to database.")

    # Display Analysis Results
    if "analyzed_df" in st.session_state and not st.session_state["analyzed_df"].empty:
        res_df = st.session_state["analyzed_df"]
        
        st.markdown("### Analysis Results Summary")
        
        # Summary metrics
        m1, m2, m3, m4 = st.columns(4)
        m1.metric("Total Analyzed", f"{len(res_df):,}")
        m2.metric("Benign Flows", f"{(res_df['final_prediction']=='Benign').sum():,}")
        m3.metric("Malicious Flagged", f"{(res_df['final_prediction']=='Malicious').sum():,}")
        m4.metric("Both ML & Rules Flagged", f"{(res_df['detection_method']=='Both ML & Rules').sum():,}")

        st.markdown("---")
        st.subheader("Interactive Traffic Results Table")

        # Filters
        f1, f2, f3 = st.columns(3)
        with f1:
            pred_filter = st.multiselect("Filter by Classification", ["Benign", "Malicious"], default=["Benign", "Malicious"])
        with f2:
            method_filter = st.multiselect("Filter by Detection Method", ["ML Only", "Rules Only", "Both ML & Rules", "Neither (Benign)"], default=["ML Only", "Rules Only", "Both ML & Rules", "Neither (Benign)"])
        with f3:
            sev_filter = st.multiselect("Filter by Severity", ["High", "Medium", "Low", "None"], default=["High", "Medium", "Low", "None"])

        filtered_res = res_df[
            (res_df['final_prediction'].isin(pred_filter)) &
            (res_df['detection_method'].isin(method_filter)) &
            (res_df['severity'].isin(sev_filter))
        ]

        # Selected presentation columns
        cols_priority = [
            'final_prediction', 'attack_category', 'detection_method', 'severity',
            'ml_confidence_pct', 'triggered_rules', 'DESTINATION_PORT', 'FLOW_DURATION', 'FLOW_PACKETS_S', 'explanation'
        ]
        present_cols = [c for c in cols_priority if c in filtered_res.columns]

        st.dataframe(filtered_res[present_cols], use_container_width=True)

        # CSV Download Button
        csv_data = filtered_res.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download Analyzed Results as CSV",
            data=csv_data,
            file_name="hybrid_nids_analysis_results.csv",
            mime="text/csv"
        )
