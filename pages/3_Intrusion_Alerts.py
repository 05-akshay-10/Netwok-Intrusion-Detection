import streamlit as st
import pandas as pd
from src.alert_manager import AlertManager

st.set_page_config(page_title="Intrusion Alerts | Hybrid NIDS", page_icon="🚨", layout="wide")

st.title("🚨 Intrusion Alerts Monitor")
st.markdown("Persistent security alert logs recorded in SQLite database.")

alert_mgr = AlertManager()

# Controls & Filters Row
c1, c2, c3, c4 = st.columns([1, 1, 1, 1])

with c1:
    sev_filter = st.selectbox("Filter by Severity", ["All", "High", "Medium", "Low"])
with c2:
    method_filter = st.selectbox("Filter by Detection Method", ["All", "ML Only", "Rules Only", "Both ML & Rules"])
with c3:
    search_query = st.text_input("🔍 Search Alerts (IP, Port, Attack)", "")
with c4:
    st.write("") # Padding
    if st.button("🗑️ Clear Alert History", type="secondary"):
        alert_mgr.clear_alert_history()
        st.success("Alert history cleared successfully!")

alerts_df = alert_mgr.get_all_alerts(severity_filter=sev_filter, method_filter=method_filter)

if not alerts_df.empty and search_query:
    search_mask = alerts_df.astype(str).apply(lambda row: row.str.contains(search_query, case=False).any(), axis=1)
    alerts_df = alerts_df[search_mask]

# Summary KPI Header
a1, a2, a3, a4 = st.columns(4)
a1.metric("Total Logged Alerts", f"{len(alerts_df):,}")
high_count = (alerts_df['severity'] == 'High').sum() if not alerts_df.empty else 0
a2.metric("High Severity Alerts", f"{high_count:,}", delta_color="inverse")
both_count = (alerts_df['detection_method'] == 'Both ML & Rules').sum() if not alerts_df.empty else 0
a3.metric("Both ML & Rules Triggered", f"{both_count:,}")
categories_count = alerts_df['attack_category'].nunique() if not alerts_df.empty else 0
a4.metric("Unique Attack Vectors", f"{categories_count}")

st.markdown("---")

if alerts_df.empty:
    st.info("ℹ️ **No Alerts Match Current Filter Criteria**")
    st.markdown("Run analysis on a dataset in the **Traffic Analyzer** page to populate intrusion alerts.")
else:
    st.subheader("Alerts Log Table")
    
    # Table columns selection
    table_cols = ['id', 'timestamp', 'source_ip', 'destination_ip', 'destination_port', 'attack_category', 'detection_method', 'severity', 'ml_confidence', 'triggered_rules']
    show_cols = [c for c in table_cols if c in alerts_df.columns]
    
    st.dataframe(alerts_df[show_cols], use_container_width=True)

    # Detailed Alert Inspector Expander
    st.markdown("---")
    st.subheader("🔍 Alert Deep-Dive Inspector")
    
    selected_alert_id = st.selectbox("Select Alert ID to Inspect:", alerts_df['id'].tolist())
    
    if selected_alert_id:
        alert_row = alerts_df[alerts_df['id'] == selected_alert_id].iloc[0]
        
        with st.container():
            st.markdown(f"### Alert #{alert_row['id']} Details")
            
            d1, d2, d3 = st.columns(3)
            d1.markdown(f"**Timestamp**: `{alert_row.get('timestamp')}`")
            d1.markdown(f"**Source IP**: `{alert_row.get('source_ip')}`")
            d1.markdown(f"**Destination IP**: `{alert_row.get('destination_ip')}`")
            
            d2.markdown(f"**Attack Category**: `{alert_row.get('attack_category')}`")
            d2.markdown(f"**Detection Method**: `{alert_row.get('detection_method')}`")
            d2.markdown(f"**Severity**: `{alert_row.get('severity')}`")
            
            d3.markdown(f"**ML Confidence**: `{alert_row.get('ml_confidence')}%`")
            d3.markdown(f"**Target Port**: `{alert_row.get('destination_port')}`")
            d3.markdown(f"**Triggered Rules**: `{alert_row.get('triggered_rules')}`")

            st.markdown("#### Root Cause & Explanation:")
            st.info(alert_row.get('explanation', 'No explanation provided.'))

    # Export CSV Button
    st.markdown("---")
    csv_alerts = alerts_df.to_csv(index=False).encode('utf-8')
    st.download_button(
        label="📥 Export Alert Log as CSV",
        data=csv_alerts,
        file_name="nids_intrusion_alerts.csv",
        mime="text/csv"
    )
