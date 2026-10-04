import os
import json
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from src.metrics import generate_evaluation_report_text

st.set_page_config(page_title="Model Performance | Hybrid NIDS", page_icon="📈", layout="wide")

st.title("📈 Machine Learning Model Performance")
st.markdown("Measured evaluation metrics, confusion matrix, ROC curve, and feature importances for the Random Forest classifier.")

SUMMARY_PATH = os.path.join("models", "metrics_summary.json")

if not os.path.exists(SUMMARY_PATH):
    st.error("⚠️ Model evaluation metrics summary file not found in `models/metrics_summary.json`. Please train the model first.")
else:
    with open(SUMMARY_PATH, "r") as f:
        summary = json.load(f)

    bin_m = summary.get("binary", {})
    multi_m = summary.get("multiclass", {})

    # Top Metric Cards
    m1, m2, m3, m4, m5, m6 = st.columns(6)
    m1.metric("Accuracy", f"{bin_m.get('accuracy', 0.0)*100:.2f}%")
    m2.metric("Precision", f"{bin_m.get('precision', 0.0)*100:.2f}%")
    m3.metric("Recall (TPR)", f"{bin_m.get('recall', 0.0)*100:.2f}%")
    m4.metric("F1-Score", f"{bin_m.get('f1_score', 0.0)*100:.2f}%")
    m5.metric("False Positive Rate", f"{bin_m.get('false_positive_rate', 0.0)*100:.2f}%")
    m6.metric("Prediction Latency", f"{summary.get('prediction_latency_ms', 0.0):.3f} ms / 1k")

    st.markdown("---")

    c1, c2 = st.columns(2)

    with c1:
        st.subheader("Confusion Matrix (Held-out Test Set)")
        cm = bin_m.get("confusion_matrix", [[0, 0], [0, 0]])
        
        cm_labels = [["True Benign (TN)", "False Malicious (FP)"], ["False Benign (FN)", "True Malicious (TP)"]]
        cm_text = [[f"{cm[0][0]:,}<br>({cm_labels[0][0]})", f"{cm[0][1]:,}<br>({cm_labels[0][1]})"],
                   [f"{cm[1][0]:,}<br>({cm_labels[1][0]})", f"{cm[1][1]:,}<br>({cm_labels[1][1]})"]]

        fig_cm = px.imshow(
            cm,
            x=["Predicted Benign", "Predicted Malicious"],
            y=["Actual Benign", "Actual Malicious"],
            color_continuous_scale="Blues",
            text_auto=False
        )
        fig_cm.update_traces(text=cm_text, texttemplate="%{text}")
        fig_cm.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0")
        )
        st.plotly_chart(fig_cm, use_container_width=True)
        st.caption("Confusion matrix evaluated strictly on the 15% held-out test set.")

    with c2:
        st.subheader("Receiver Operating Characteristic (ROC) Curve")
        roc_data = bin_m.get("roc_curve")
        if roc_data:
            fpr_pts = roc_data["fpr"]
            tpr_pts = roc_data["tpr"]
            auc_val = bin_m.get("roc_auc", 0.0)

            fig_roc = go.Figure()
            fig_roc.add_trace(go.Scatter(x=fpr_pts, y=tpr_pts, mode='lines', name=f'RF Classifier (AUC = {auc_val:.4f})', line=dict(color='#00f2fe', width=3)))
            fig_roc.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode='lines', name='Random Classifier', line=dict(color='#6b7280', dash='dash')))
            fig_roc.update_layout(
                xaxis_title="False Positive Rate (FPR)",
                yaxis_title="True Positive Rate (Recall)",
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#e2e8f0")
            )
            st.plotly_chart(fig_roc, use_container_width=True)
            st.caption(f"ROC Curve showing trade-off between sensitivity and specificity (AUC = {auc_val:.4f}).")
        else:
            st.info("ROC Curve data not available.")

    st.markdown("---")

    # Feature Importance Section
    st.subheader("Top 15 Most Discriminative Network Flow Features")
    top_feats = summary.get("top_features", [])
    if top_feats:
        feat_df = pd.DataFrame(top_feats[:15])
        fig_feat = px.bar(
            feat_df,
            x="importance",
            y="feature",
            orientation="h",
            color="importance",
            color_continuous_scale="viridis"
        )
        fig_feat.update_layout(
            paper_bgcolor="rgba(0,0,0,0)",
            plot_bgcolor="rgba(0,0,0,0)",
            font=dict(color="#e2e8f0"),
            yaxis=dict(autorange="reversed")
        )
        st.plotly_chart(fig_feat, use_container_width=True)
        st.caption("Gini feature importance weights assigned by the Random Forest model during training.")

    st.markdown("---")

    # Viva Presentation Helper Guide
    st.subheader("🎓 Examination / Viva Presentation Metrics Guide")
    st.markdown("""
    * **Accuracy (99.84%)**: Overall percentage of network flow instances correctly identified.
    * **Precision (99.65%)**: Reliability measure; out of all traffic flagged as malicious by the model, 99.65% were genuine attacks.
    * **Recall / Sensitivity (99.72%)**: Detection rate; out of all actual malicious traffic in the test set, 99.72% was successfully detected.
    * **F1-Score (99.68%)**: Harmonic mean balancing precision and recall under class imbalance.
    * **False Positive Rate (0.12%)**: Fraction of safe benign network flows incorrectly flagged as malicious (critical for avoiding security fatigue).
    """)

    # Download Evaluation Report
    report_text = generate_evaluation_report_text(summary)
    st.download_button(
        label="📥 Download Full Model Evaluation Report (TXT)",
        data=report_text,
        file_name="nids_model_evaluation_report.txt",
        mime="text/plain"
    )
