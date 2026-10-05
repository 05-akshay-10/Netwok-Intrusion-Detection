import os
import streamlit as st

_CSS = """
<style>
    .block-container { padding-top: 2rem; padding-bottom: 2rem; }
    [data-testid="stMetric"] {
        background: linear-gradient(135deg, #111827 0%, #1f2937 100%);
        border: 1px solid #374151;
        border-radius: 12px;
        padding: 14px 16px;
    }
    .badge-success, .badge-warning {
        display: inline-block; padding: 4px 10px; margin-bottom: 6px;
        border-radius: 9999px; font-size: 0.75rem; font-weight: 600;
    }
    .badge-success { background: rgba(16,185,129,.2); color: #10b981; border: 1px solid #10b981; }
    .badge-warning { background: rgba(245,158,11,.2); color: #f59e0b; border: 1px solid #f59e0b; }
</style>
"""


def setup_page(title: str, icon: str, heading: str, subtitle: str = "") -> None:
    """Shared page setup: config, styling, sidebar status and page heading (same on every page)."""
    st.set_page_config(page_title=f"{title} | Hybrid NIDS", page_icon=icon, layout="wide")
    st.markdown(_CSS, unsafe_allow_html=True)

    with st.sidebar:
        st.subheader("System Status")
        if os.path.exists(os.path.join("models", "random_forest_binary.joblib")):
            st.markdown('<span class="badge-success">● ML Models Ready</span>', unsafe_allow_html=True)
        else:
            st.markdown('<span class="badge-warning">▲ Models Not Trained</span>', unsafe_allow_html=True)
        st.markdown('<span class="badge-success">● Rule Engine Active</span><br>'
                    '<span class="badge-success">● Alert Database Ready</span>', unsafe_allow_html=True)
        st.caption("CIC-IDS2017 • Scikit-Learn • Scapy")

    st.title(f"{icon} {heading}")
    if subtitle:
        st.markdown(subtitle)
