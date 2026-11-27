"""
Matrices de confusión a partir de resultados ya calculados (sin nuevos experimentos).
Combina: 4 escenarios de variantes no vistas (E2, label=1) + benigno_eval (label=0, 150 flujos
independientes). Fuente: ~/experimentos/depurado_c4/tabla_eventos.csv.
"""
import os
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix

DIR_DEP = os.path.expanduser("~/experimentos/depurado_c4")
df = pd.read_csv(os.path.join(DIR_DEP, "tabla_eventos.csv"))

escenarios_e2_novistas = ["evasion_c3", "evasion_c4", "control_ua", "evasion_c7_v2"]
subset = df[df["escenario"].isin(escenarios_e2_novistas + ["benigno_eval"])].copy()
print("Flujos incluidos:", subset.shape[0], "( esperado 160 + 150 = 310 )")
print(subset["escenario"].value_counts())

y_true = subset["label_real"].values
modelos = [
    ("Suricata", "det_suricata"),
    ("RF - Scapy (19f)", "det_rf_scapy"),
    ("RF - CICFlowMeter (76f)", "det_rf_cic"),
]

fig, axes = plt.subplots(1, 3, figsize=(15, 4.8))
for ax, (nombre, col) in zip(axes, modelos):
    y_pred = subset[col].values
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0.0
    ax.imshow(cm, cmap="Blues")
    ax.set_title(f"{nombre}\n(Recall={recall:.1f}%, FPR={fpr:.1f}%)", fontsize=11)
    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Benigno", "Malicioso"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Benigno", "Malicioso"])
    ax.set_xlabel("Predicción")
    ax.set_ylabel("Etiqueta real")
    for i in range(2):
        for j in range(2):
            ax.text(
                j, i, str(cm[i, j]),
                ha="center", va="center",
                color="white" if cm[i, j] > cm.max() / 2 else "black",
                fontsize=14, fontweight="bold"
            )

fig.suptitle(
    "Matrices de confusión: variantes no vistas (evasion_c3, evasion_c4 dep., control_ua,\n"
    "evasion_c7_v2 — n=160, label=malicioso) + benigno_eval (n=150, label=benigno, independiente)",
    fontsize=11
)
plt.tight_layout(rect=[0, 0, 1, 0.90])
out = os.path.join(DIR_DEP, "matrices_confusion_e2_benigno_eval.png")
plt.savefig(out, dpi=150)
print("[+] Guardado:", out)

# Métricas numéricas de referencia, para citar en el texto
for nombre, col in modelos:
    y_pred = subset[col].values
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    recall = (tp / (tp + fn) * 100) if (tp + fn) > 0 else 0.0
    fpr = (fp / (fp + tn) * 100) if (fp + tn) > 0 else 0.0
    print(f"{nombre}: TP={tp} FN={fn} FP={fp} TN={tn} | Recall={recall:.2f}% FPR={fpr:.2f}%")
