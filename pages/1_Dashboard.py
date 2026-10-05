import os
import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go

from src.alert_manager import AlertManager
from src.ui import setup_page

setup_page("Dashboard", "📊", "Dashboard Overview", "Traffic distribution and intrusion alert summary for the most recent analysis.")

alert_mgr = AlertManager()
alerts_df = alert_mgr.get_all_alerts()

showing_baseline = False
baseline_attacks = {}

# Check if analysis results exist in session state
analyzed_df = st.session_state.get("analyzed_df", pd.DataFrame())

if not analyzed_df.empty:
    total_flows = len(analyzed_df)
    benign_count = (analyzed_df['final_prediction'] == 'Benign').sum()
    malicious_count = (analyzed_df['final_prediction'] == 'Malicious').sum()
    attack_categories_count = analyzed_df[analyzed_df['final_prediction'] == 'Malicious']['attack_category'].nunique()
    total_alerts = len(alerts_df)
else:
    # Try reading from metrics summary as fallback baseline
    summary_path = os.path.join("models", "metrics_summary.json")
    if os.path.exists(summary_path):
        with open(summary_path, "r") as f:
            summary = json.load(f)
        # Real label counts of the training dataset, recorded by src/train.py
        class_dist = summary.get("class_distribution", {})
        baseline_attacks = summary.get("attack_distribution", {})
        benign_count = class_dist.get("benign", 0)
        malicious_count = class_dist.get("malicious", 0)
        total_flows = benign_count + malicious_count
        attack_categories_count = len(baseline_attacks)
        total_alerts = len(alerts_df)
        showing_baseline = total_flows > 0
    else:
        total_flows = 0
        benign_count = 0
        malicious_count = 0
        attack_categories_count = 0
        total_alerts = len(alerts_df)

if showing_baseline:
    st.info("No traffic analyzed in this session yet. Showing the **labelled training dataset (CIC-IDS2017)** as a baseline. Run the Traffic Analyzer to see detection results.")

# KPI Cards Row
kpi1, kpi2, kpi3, kpi4, kpi5 = st.columns(5)

with kpi1:
    st.metric("Total Flows Analyzed", f"{total_flows:,}")
with kpi2:
    st.metric("Benign Flows", f"{benign_count:,}", delta=f"{benign_count/max(1,total_flows)*100:.1f}%")
with kpi3:
    st.metric("Malicious Flows", f"{malicious_count:,}", delta=f"-{malicious_count/max(1,total_flows)*100:.1f}%", delta_color="inverse")
with kpi4:
    st.metric("Total Alerts Logged", f"{total_alerts:,}")
with kpi5:
    st.metric("Attack Categories", f"{attack_categories_count}")

st.markdown("---")

if total_flows == 0 and alerts_df.empty:
    st.info("ℹ️ **No Traffic Analyzed Yet**")
    st.markdown("Head over to the **Traffic Analyzer** page to upload a network CSV file and execute hybrid detection.")
else:
    c1, c2 = st.columns(2)
    
    with c1:
        st.subheader("Traffic Class Distribution")
        pie_df = pd.DataFrame({
            "Classification": ["Benign", "Malicious"],
            "Count": [benign_count, malicious_count]
        })
        fig_donut = px.pie(
            pie_df,
            values="Count",
            names="Classification",
            color="Classification",
            color_discrete_map={"Benign": "#10b981", "Malicious": "#ef4444"},
            hole=0.55
        )
        fig_donut.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            margin=dict(t=30, b=30, l=30, r=30)
        )
        st.plotly_chart(fig_donut, width="stretch")
        st.caption("Distribution between safe benign network flows and flagged malicious intrusion attempts.")

    with c2:
        st.subheader("Detected Attack Categories Breakdown")
        if not analyzed_df.empty:
            attack_df = analyzed_df[analyzed_df['final_prediction'] == 'Malicious']['attack_category'].value_counts().reset_index()
            attack_df.columns = ['Attack Category', 'Count']
        else:
            attack_df = pd.DataFrame({
                'Attack Category': list(baseline_attacks.keys()),
                'Count': list(baseline_attacks.values())
            })

        fig_bar = px.bar(
            attack_df,
            x="Count",
            y="Attack Category",
            orientation="h",
            color="Count",
            color_continuous_scale="reds"
        )
        fig_bar.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            yaxis=dict(autorange="reversed"),
            margin=dict(t=30, b=30, l=30, r=30)
        )
        st.plotly_chart(fig_bar, width="stretch")
        st.caption("Top detected attack vectors ranked by occurrence volume.")

    st.markdown("---")
    
    r1, r2 = st.columns([1, 2])
    
    with r1:
        st.subheader("Alert Severity Profile")
        if not alerts_df.empty and 'severity' in alerts_df.columns:
            sev_df = alerts_df['severity'].value_counts().reset_index()
            sev_df.columns = ['Severity', 'Count']
        else:
            sev_df = pd.DataFrame(columns=['Severity', 'Count'])
            st.write("No alerts recorded yet.")
            
        fig_sev = px.pie(
            sev_df,
            values="Count",
            names="Severity",
            color="Severity",
            color_discrete_map={"High": "#ef4444", "Medium": "#f59e0b", "Low": "#3b82f6"}
        )
        fig_sev.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0")
        )
        if not sev_df.empty:
            st.plotly_chart(fig_sev, width="stretch")

    with r2:
        st.subheader("Recent Intrusion Alerts")
        if not alerts_df.empty:
            display_cols = ['timestamp', 'source_ip', 'destination_ip', 'destination_port', 'attack_category', 'detection_method', 'severity']
            cols_to_show = [c for c in display_cols if c in alerts_df.columns]
            st.dataframe(alerts_df[cols_to_show].head(8), width="stretch")
        else:
            st.write("No alerts recorded in persistent database yet.")
