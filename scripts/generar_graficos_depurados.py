import os
import json
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier

DIR_DEP = os.path.expanduser("~/experimentos/depurado_c4")
RUTA_JSON = os.path.join(DIR_DEP, "metricas_desde_alertas.json")

with open(RUTA_JSON, "r", encoding="utf-8") as f:
    metricas = json.load(f)

# 1. Gráfico comparativo: Detección en variantes no vistas + FPR en benigno_eval
escenarios_plot = ["evasion_c3", "evasion_c4", "control_ua", "evasion_c7_v2", "benigno_eval"]
etiquetas_plot = [
    "Evasión C3\n(Ataque)",
    "Evasión C4 dep.\n(Ataque)",
    "Control UA\n(Ataque)",
    "Evasión C7 v2\n(Ataque)",
    "Benigno Eval\n(FPR / Benigno)"
]

suri_vals = [metricas["por_escenario"][e]["tasa_suricata"] * 100 for e in escenarios_plot]
scapy_vals = [metricas["por_escenario"][e]["tasa_rf_scapy"] * 100 for e in escenarios_plot]
cic_vals = [metricas["por_escenario"][e]["tasa_rf_cic"] * 100 for e in escenarios_plot]

x = np.arange(len(etiquetas_plot))
ancho = 0.25

fig, ax = plt.subplots(figsize=(10, 5.5))
b1 = ax.bar(x - ancho, suri_vals, ancho, label="Suricata (alertas eve.json)")
b2 = ax.bar(x, scapy_vals, ancho, label="RF - Scapy (19 features)")
b3 = ax.bar(x + ancho, cic_vals, ancho, label="RF - CICFlowMeter")

ax.axvline(3.5, color="gray", linestyle="--", linewidth=1)
ax.set_ylabel("Porcentaje de flujos marcados (%)")
ax.set_title("Generalización ante variantes no vistas vs. FPR en captura benigna independiente")
ax.set_xticks(x)
ax.set_xticklabels(etiquetas_plot)
ax.set_ylim(0, 112)
ax.legend()
ax.grid(axis="y", linestyle=":", alpha=0.6)

for barras in (b1, b2, b3):
    for bar in barras:
        h = bar.get_height()
        ax.annotate(f"{h:.1f}%",
                    xy=(bar.get_x() + bar.get_width() / 2, h),
                    xytext=(0, 3), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8)

plt.tight_layout()
out_comp = os.path.join(DIR_DEP, "comparativa_variantes_y_fpr.png")
plt.savefig(out_comp, dpi=150)
plt.close()

# 2. Gráfico de importancia de features en dataset depurado (Scapy y CIC)
df_scapy = pd.read_csv(os.path.join(DIR_DEP, "dataset_flujos_depurado.csv"))
cols_s = [c for c in df_scapy.columns if c not in ("escenario", "label")]
clf_s = RandomForestClassifier(n_estimators=200, random_state=42).fit(df_scapy[cols_s].values, df_scapy["label"].values)
imp_s = pd.Series(clf_s.feature_importances_, index=cols_s).sort_values(ascending=True).tail(8)

df_cic = pd.read_csv(os.path.join(DIR_DEP, "dataset_cic_unificado_depurado.csv"))
mapa_lbl = {"benigno": 0, "estandar": 1, "sqli_base": 1, "evasion_c3": 1, "evasion_c4": 1, "control_ua": 1, "evasion_c7_v2": 1}
df_cic = df_cic[df_cic["escenario"].isin(mapa_lbl)].copy()
y_c = df_cic["escenario"].map(mapa_lbl).values
non_c = {"escenario", "label", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "flow_id"}
cols_c = [c for c in df_cic.columns if c not in non_c and pd.api.types.is_numeric_dtype(df_cic[c])]
X_c = df_cic[cols_c].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
clf_c = RandomForestClassifier(n_estimators=200, random_state=42).fit(X_c, y_c)
imp_c = pd.Series(clf_c.feature_importances_, index=cols_c).sort_values(ascending=True).tail(8)

fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 4.8))
imp_s.plot(kind="barh", ax=ax1, title="Top 8 Features — Scapy (depurado)")
ax1.set_xlabel("Importancia relativa")
ax1.grid(axis="x", linestyle=":", alpha=0.6)

imp_c.plot(kind="barh", ax=ax2, title="Top 8 Features — CICFlowMeter (depurado)")
ax2.set_xlabel("Importancia relativa")
ax2.grid(axis="x", linestyle=":", alpha=0.6)

plt.tight_layout()
out_imp = os.path.join(DIR_DEP, "importancia_features_depurado.png")
plt.savefig(out_imp, dpi=150)
plt.close()

print("[+] Gráficos guardados en:", out_comp, "y", out_imp)
