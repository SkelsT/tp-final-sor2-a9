import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict

DIR_EXP = os.path.expanduser("~/experimentos")
DIR_CIC = os.path.join(DIR_EXP, "cic_flows")

def evaluar_dataset(ruta_csv, cols_excluir):
    df = pd.read_csv(ruta_csv)
    feature_cols = [c for c in df.columns if c not in cols_excluir and pd.api.types.is_numeric_dtype(df[c])]
    df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
    X = df[feature_cols].values
    y = df["label"].values

    # 5-Fold CV calibrado a FPR = 0.0%
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    probs_cv = np.zeros(len(df))
    for train_idx, test_idx in skf.split(X, y):
        clf = RandomForestClassifier(n_estimators=200, random_state=42)
        clf.fit(X[train_idx], y[train_idx])
        probs_cv[test_idx] = clf.predict_proba(X[test_idx])[:, 1]

    umbral_cv = probs_cv[df["escenario"] == "benigno"].max() + 1e-6
    df["pred_cv"] = (probs_cv >= umbral_cv).astype(int)

    # Zero-Day calibrado OOF sobre set base (FPR = 0.0%)
    train_esc = ["benigno", "estandar", "sqli_base"]
    df_train = df[df["escenario"].isin(train_esc)].copy()
    probs_oof = cross_val_predict(
        RandomForestClassifier(n_estimators=200, random_state=42),
        df_train[feature_cols].values,
        df_train["label"].values,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        method="predict_proba"
    )[:, 1]
    umbral_zd = probs_oof[df_train["escenario"] == "benigno"].max() + 1e-6

    clf_base = RandomForestClassifier(n_estimators=200, random_state=42)
    clf_base.fit(df_train[feature_cols].values, df_train["label"].values)
    df["pred_zd"] = (clf_base.predict_proba(X)[:, 1] >= umbral_zd).astype(int)

    clf_full = RandomForestClassifier(n_estimators=200, random_state=42).fit(X, y)
    imp = pd.Series(clf_full.feature_importances_, index=feature_cols).sort_values(ascending=True)
    return df, imp

df_scapy, imp_scapy = evaluar_dataset(
    os.path.join(DIR_EXP, "dataset_flujos.csv"),
    {"escenario", "label"}
)
df_cic, imp_cic = evaluar_dataset(
    os.path.join(DIR_CIC, "dataset_cic_unificado.csv"),
    {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "flow_id", "escenario", "label"}
)

escenarios = ["estandar", "sqli_base", "evasion_c3", "evasion_c4", "control_ua", "evasion_c7_v2"]
train_esc = {"estandar", "sqli_base"}
etiquetas = [
    "Estándar\n(Baseline)",
    "SQLi Base\n(SID 2006446)",
    "Evasión C3\n(Frag. IP 8B)",
    "Evasión C4\n(Seg. TCP 2B)",
    "Control UA\n(Spoofing Header)",
    "Evasión C7 v2\n(Padding >100B)"
]

suri_recall = [100.0, 100.0, 100.0, 100.0, 0.0, 0.0]
scapy_cv = [df_scapy[df_scapy["escenario"] == e]["pred_cv"].mean() * 100.0 for e in escenarios]
cic_cv = [df_cic[df_cic["escenario"] == e]["pred_cv"].mean() * 100.0 for e in escenarios]

scapy_zd = [np.nan if e in train_esc else df_scapy[df_scapy["escenario"] == e]["pred_zd"].mean() * 100.0 for e in escenarios]
cic_zd = [np.nan if e in train_esc else df_cic[df_cic["escenario"] == e]["pred_zd"].mean() * 100.0 for e in escenarios]

# --- GRÁFICO COMPARATIVO DE 3 ENFOQUES (2 PANELES) ---
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11.5, 11.0), sharex=True, constrained_layout=True)
x = np.arange(len(escenarios))
width = 0.27

# Panel A: 5-Fold CV
b1_a = ax1.bar(x - width, suri_recall, width, label="Suricata 7 (Firmas ET Open)", color="#2b5c8f")
b2_a = ax1.bar(x, scapy_cv, width, label="Random Forest — Scapy (19 features)", color="#2e8b57")
b3_a = ax1.bar(x + width, cic_cv, width, label="Random Forest — CICFlowMeter (76 features)", color="#6a5acd")

ax1.set_ylabel("Recall (%)", fontsize=11)
ax1.set_title("A. Detección sobre Tráfico Conocido (5-Fold CV | FPR HTTP = 0.0%)", fontsize=12, fontweight="bold", pad=38)
ax1.set_ylim(0, 118)
ax1.grid(axis="y", linestyle="--", alpha=0.5)
ax1.legend(bbox_to_anchor=(0.5, 1.12), loc="lower center", ncol=3, frameon=True, fontsize=9.5)

for bars in (b1_a, b2_a, b3_a):
    for bar in bars:
        h = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

# Panel B: Zero-Day
b1_b = ax2.bar(x - width, suri_recall, width, label="Suricata 7 (Firmas ET Open)", color="#2b5c8f")
b2_b = ax2.bar(x, scapy_zd, width, label="RF Zero-Day — Scapy (19 features)", color="#d97724")
b3_b = ax2.bar(x + width, cic_zd, width, label="RF Zero-Day — CICFlowMeter (76 features)", color="#c0392b")

ax2.set_ylabel("Recall (%)", fontsize=11)
ax2.set_title("B. Generalización Zero-Day ante Evasiones Inéditas (FPR HTTP = 0.0%)", fontsize=12, fontweight="bold", pad=38)
ax2.set_xticks(x)
ax2.set_xticklabels(etiquetas, fontsize=10)
ax2.set_ylim(0, 118)
ax2.grid(axis="y", linestyle="--", alpha=0.5)
ax2.legend(bbox_to_anchor=(0.5, 1.12), loc="lower center", ncol=3, frameon=True, fontsize=9.5)

for bars in (b1_b, b2_b, b3_b):
    for bar in bars:
        h = bar.get_height()
        if np.isnan(h):
            ax2.text(bar.get_x() + bar.get_width()/2, 3, "N/A\n(Train)", ha="center", va="bottom", fontsize=8, color="#555555")
        else:
            ax2.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

plt.savefig(os.path.join(DIR_EXP, "grafico_comparativa_3_enfoques.png"), dpi=300)
plt.close()

# --- GRÁFICO FEATURE IMPORTANCE CICFLOWMETER ---
fig, ax = plt.subplots(figsize=(8.8, 4.8))
imp_cic.tail(10).plot(kind="barh", ax=ax, color="#6a5acd")
ax.set_xlabel("Importancia Relativa (Gini Importance)", fontsize=11)
ax.set_title("Top 10 Variables Más Determinantes en CICFlowMeter (Random Forest)", fontsize=12, fontweight="bold")
ax.grid(axis="x", linestyle="--", alpha=0.5)

for i, v in enumerate(imp_cic.tail(10)):
    ax.text(v + 0.003, i, f"{v:.4f}", va="center", fontsize=9)

ax.set_xlim(0, imp_cic.tail(10).max() * 1.18)
plt.tight_layout()
plt.savefig(os.path.join(DIR_EXP, "grafico_feature_importance_cic.png"), dpi=300)
plt.close()

print("[+] Gráficos de 3 enfoques exportados en ~/experimentos/:")
print("    - grafico_comparativa_3_enfoques.png")
print("    - grafico_feature_importance_cic.png")
