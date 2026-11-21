import os
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict

DIR_EXP = os.path.expanduser("~/experimentos")
df = pd.read_csv(os.path.join(DIR_EXP, "dataset_flujos.csv"))

feature_cols = [c for c in df.columns if c not in ("escenario", "label")]
X = df[feature_cols].values
y = df["label"].values

# 1. Recalcular dinámicamente 5-Fold CV (FPR = 0.0%)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
probs_cv = np.zeros(len(df))
for train_idx, test_idx in skf.split(X, y):
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X[train_idx], y[train_idx])
    probs_cv[test_idx] = clf.predict_proba(X[test_idx])[:, 1]

df["prob_cv"] = probs_cv
umbral_cv = df[df["escenario"] == "benigno"]["prob_cv"].max() + 1e-6
df["pred_cv"] = (df["prob_cv"] >= umbral_cv).astype(int)

# 2. Recalcular dinámicamente Zero-Day (calibrado OOF sobre set base, FPR = 0.0%)
train_escenarios = ["benigno", "estandar", "sqli_base"]
df_train = df[df["escenario"].isin(train_escenarios)].copy()

probs_base_oof = cross_val_predict(
    RandomForestClassifier(n_estimators=200, random_state=42),
    df_train[feature_cols].values,
    df_train["label"].values,
    cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
    method="predict_proba"
)[:, 1]
umbral_zd = probs_base_oof[df_train["escenario"] == "benigno"].max() + 1e-6

clf_base = RandomForestClassifier(n_estimators=200, random_state=42)
clf_base.fit(df_train[feature_cols].values, df_train["label"].values)
df["pred_zd"] = (clf_base.predict_proba(X)[:, 1] >= umbral_zd).astype(int)

# --- GRÁFICO 1: Comparativa de Recall por escenario ---
escenarios = ["estandar", "sqli_base", "evasion_c3", "evasion_c4", "control_ua", "evasion_c7_v2"]
etiquetas = [
    "Estándar\n(Baseline)",
    "SQLi Base\n(SID 2006446)",
    "Evasión C3\n(Frag. IP 8B)",
    "Evasión C4\n(Seg. TCP 2B)",
    "Control UA\n(Spoofing Header)",
    "Evasión C7 v2\n(Padding >100B)"
]

suri_recall = [100.0, 100.0, 100.0, 100.0, 0.0, 0.0]
rf_cv_recall = [df[df["escenario"] == e]["pred_cv"].mean() * 100.0 for e in escenarios]
rf_zd_recall = [
    np.nan if e in train_escenarios else df[df["escenario"] == e]["pred_zd"].mean() * 100.0
    for e in escenarios
]

x = np.arange(len(escenarios))
width = 0.27

fig, ax = plt.subplots(figsize=(11, 5.5))
b1 = ax.bar(x - width, suri_recall, width, label="Suricata 7 (ET Open)", color="#2b5c8f")
b2 = ax.bar(x, rf_cv_recall, width, label="Random Forest (5-Fold CV)", color="#2e8b57")
b3 = ax.bar(x + width, rf_zd_recall, width, label="Random Forest (Zero-Day No Visto)", color="#d97724")

ax.set_ylabel("Recall / Tasa de Detección (%)", fontsize=11)
ax.set_title("Comparativa de Detección por Capa OSI (FPR HTTP = 0.0% | Global = 0.33%)", fontsize=12.5, fontweight="bold")
ax.set_xticks(x)
ax.set_xticklabels(etiquetas, fontsize=9.5)
ax.set_ylim(0, 116)
ax.grid(axis="y", linestyle="--", alpha=0.5)
ax.legend(loc="upper right", frameon=True)

for bars in (b1, b2, b3):
    for idx, bar in enumerate(bars):
        h = bar.get_height()
        if np.isnan(h):
            ax.text(bar.get_x() + bar.get_width()/2, 3, "N/A\n(Train)", ha="center", va="bottom", fontsize=8, color="#555555")
        else:
            ax.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

plt.tight_layout()
plt.savefig(os.path.join(DIR_EXP, "grafico_comparativa_recall.png"), dpi=300)
plt.close()

# --- GRÁFICO 2: Top 10 Feature Importance ---
clf_full = RandomForestClassifier(n_estimators=200, random_state=42).fit(X, y)
imp = pd.Series(clf_full.feature_importances_, index=feature_cols).sort_values(ascending=True).tail(10)

fig, ax = plt.subplots(figsize=(8.5, 4.8))
imp.plot(kind="barh", ax=ax, color="#3b6998")
ax.set_xlabel("Importancia Relativa (Gini Importance)", fontsize=11)
ax.set_title("Top 10 Variables Estadísticas de Flujo Más Determinantes (Random Forest)", fontsize=12, fontweight="bold")
ax.grid(axis="x", linestyle="--", alpha=0.5)

for i, v in enumerate(imp):
    ax.text(v + 0.004, i, f"{v:.4f}", va="center", fontsize=9)

ax.set_xlim(0, imp.max() * 1.18)
plt.tight_layout()
plt.savefig(os.path.join(DIR_EXP, "grafico_feature_importance.png"), dpi=300)
plt.close()

print("[+] Gráficos exportados correctamente en ~/experimentos/:")
print("    - grafico_comparativa_recall.png")
print("    - grafico_feature_importance.png")
