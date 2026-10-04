import time
import streamlit as st
import pandas as pd

from src.live_capture import LivePacketCapturer, SCAPY_AVAILABLE

st.set_page_config(page_title="Network Monitoring | Hybrid NIDS", page_icon="📡", layout="wide")

st.title("📡 Live Network Packet Capture & Monitoring")
st.markdown("Monitor live network traffic on an authorized local network interface and run rule-based intrusion checks in real-time.")

if not SCAPY_AVAILABLE:
    st.warning("⚠️ **Scapy is unavailable or missing required driver support (Npcap/WinPcap).**")
    st.info("Live packet capture requires Scapy and an authorized network capture driver on Windows. Offline dataset simulation on the Traffic Analyzer page remains 100% operational.")
else:
    # Initialize Capturer in Session State
    if "live_capturer" not in st.session_state:
        st.session_state["live_capturer"] = LivePacketCapturer()

    capturer: LivePacketCapturer = st.session_state["live_capturer"]

    # Controls Row
    c1, c2, c3 = st.columns([2, 1, 1])

    with c1:
        ifaces = capturer.get_interfaces()
        selected_iface = st.selectbox("Select Authorized Local Network Adapter:", ifaces)

    with c2:
        st.write("") # Padding
        if not capturer.is_capturing:
            if st.button("▶️ Start Monitoring", type="primary", use_container_width=True):
                try:
                    capturer.start_capture(selected_iface)
                    st.success("Started live network packet monitoring!")
                    st.rerun()
                except Exception as e:
                    st.error(f"Could not start capture: {e}")
        else:
            if st.button("⏹️ Stop Monitoring", type="secondary", use_container_width=True):
                capturer.stop_capture()
                st.info("Stopped live network monitoring.")
                st.rerun()

    with c3:
        st.write("") # Padding
        if st.button("🔄 Refresh Telemetry", use_container_width=True):
            st.rerun()

    st.markdown("---")

    stats = capturer.get_stats()

    # Live Metrics Header
    m1, m2, m3, m4 = st.columns(4)
    status_text = "🟢 ACTIVE CAPTURE" if stats["is_capturing"] else "🔴 STOPPED"
    m1.metric("Capture Status", status_text)
    m2.metric("Total Captured Packets", f"{stats['total_packets']:,}")
    m3.metric("Active 5-Tuple Flows", f"{stats['active_flows']:,}")
    m4.metric("Live Rule Alerts", f"{stats['alert_count']:,}")

    st.markdown("---")

    st.subheader("Live Rule-Based Intrusion Alerts Log")
    live_alerts = stats["alerts"]

    if live_alerts:
        alerts_df = pd.DataFrame(live_alerts)
        st.dataframe(alerts_df, use_container_width=True)
    else:
        if stats["is_capturing"]:
            st.info("Monitoring network traffic... No rule-based intrusion alerts triggered yet.")
        else:
            st.write("Click **Start Monitoring** to begin capturing and analyzing live network packets.")
