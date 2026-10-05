import os
import json
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go

from src.metrics import generate_evaluation_report_text
from src.ui import setup_page

setup_page("Model Performance", "📈", "Machine Learning Model Performance", "Measured results on the 15% held-out test set for the binary Random Forest, the multiclass Random Forest, the Isolation Forest, the rules and the hybrid combination.")

SUMMARY_PATH = os.path.join("models", "metrics_summary.json")

if not os.path.exists(SUMMARY_PATH):
    st.error("⚠️ Model evaluation metrics summary file not found in `models/metrics_summary.json`. Please train the model first.")
else:
    with open(SUMMARY_PATH, "r") as f:
        summary = json.load(f)

    bin_m = summary.get("binary") or {}
    multi_m = summary.get("multiclass") or {}

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
        st.plotly_chart(fig_cm, width="stretch")
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
            st.plotly_chart(fig_roc, width="stretch")
            st.caption(f"ROC Curve showing trade-off between sensitivity and specificity (AUC = {auc_val:.4f}).")
        else:
            st.info("ROC Curve data not available.")

    st.markdown("---")

    # ML vs Rules vs Hybrid comparison (all on the same held-out test set)
    rules_m = summary.get("rules") or {}
    hybrid_m = summary.get("hybrid") or {}
    if rules_m and hybrid_m:
        st.subheader("Detection Method Comparison (Held-out Test Set)")
        cmp_rows = []
        for name, m in [("ML Only (Random Forest)", bin_m), ("Rules Only", rules_m), ("Hybrid (ML OR Rules)", hybrid_m)]:
            cmp_rows.append({
                "Method": name,
                "Accuracy %": round(m.get("accuracy", 0.0) * 100, 2),
                "Precision %": round(m.get("precision", 0.0) * 100, 2),
                "Recall %": round(m.get("recall", 0.0) * 100, 2),
                "F1 %": round(m.get("f1_score", 0.0) * 100, 2),
                "False Positive Rate %": round(m.get("false_positive_rate", 0.0) * 100, 2),
            })
        st.dataframe(pd.DataFrame(cmp_rows), width="stretch", hide_index=True)
        st.caption("A flow is flagged by the hybrid system when either the ML model or any rule fires. Rules add explainable reasons to alerts; they also add their own false positives.")

    if multi_m:
        st.subheader("Attack Category Classifier (Multiclass Random Forest)")
        k1, k2, k3 = st.columns(3)
        k1.metric("Accuracy", f"{multi_m.get('accuracy', 0.0)*100:.2f}%")
        k2.metric("Macro F1-Score", f"{multi_m.get('f1_macro', 0.0)*100:.2f}%")
        k3.metric("Weighted F1-Score", f"{multi_m.get('f1_weighted', 0.0)*100:.2f}%")
        per_class = [
            {"Attack Category": c, "Precision %": round(v["precision"] * 100, 2), "Recall %": round(v["recall"] * 100, 2),
             "F1 %": round(v["f1-score"] * 100, 2), "Test Samples": int(v["support"])}
            for c, v in (multi_m.get("classification_report") or {}).items()
            if isinstance(v, dict) and c in (multi_m.get("classes") or [])
        ]
        if per_class:
            st.dataframe(pd.DataFrame(per_class), width="stretch", hide_index=True)
            st.caption("Per-class results. Categories with very few test samples (e.g. Heartbleed, SQL Injection) are statistically unreliable.")

    iso_m = summary.get("isolation_forest") or {}
    if iso_m:
        st.subheader("Anomaly Detector (Isolation Forest)")
        i1, i2, i3 = st.columns(3)
        i1.metric("Benign flows flagged anomalous", f"{iso_m.get('benign_flag_rate', 0.0)*100:.2f}%")
        i2.metric("Attack flows flagged anomalous", f"{iso_m.get('attack_flag_rate', 0.0)*100:.2f}%")
        i3.metric("Trained on", "Benign flows only")
        st.caption("Unsupervised: it never sees attack labels, so it is a secondary signal shown in the Traffic Analyzer and in alert explanations. It does not decide Benign vs Malicious.")

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
        st.plotly_chart(fig_feat, width="stretch")
        st.caption("Gini feature importance weights assigned by the Random Forest model during training.")

    st.markdown("---")

    # Viva Presentation Helper Guide
    st.subheader("🎓 Examination / Viva Presentation Metrics Guide")
    st.markdown("""
    * **Accuracy ({acc:.2f}%)**: Overall percentage of network flow instances correctly identified.
    * **Precision ({prec:.2f}%)**: Reliability measure; out of all traffic flagged as malicious by the model, {prec:.2f}% were genuine attacks.
    * **Recall / Sensitivity ({rec:.2f}%)**: Detection rate; out of all actual malicious traffic in the test set, {rec:.2f}% was successfully detected.
    * **F1-Score ({f1:.2f}%)**: Harmonic mean balancing precision and recall under class imbalance.
    * **False Positive Rate ({fpr:.2f}%)**: Fraction of safe benign network flows incorrectly flagged as malicious (critical for avoiding security fatigue).
    """.format(
        acc=bin_m.get('accuracy', 0.0) * 100,
        prec=bin_m.get('precision', 0.0) * 100,
        rec=bin_m.get('recall', 0.0) * 100,
        f1=bin_m.get('f1_score', 0.0) * 100,
        fpr=bin_m.get('false_positive_rate', 0.0) * 100,
    ))

    # Download Evaluation Report
    report_text = generate_evaluation_report_text(summary)
    st.download_button(
        label="📥 Download Full Model Evaluation Report (TXT)",
        data=report_text,
        file_name="nids_model_evaluation_report.txt",
        mime="text/plain"
    )
