import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import roc_auc_score

DIR_CIC = os.path.expanduser("~/experimentos/cic_flows")
VICTIM_IP = "192.168.56.20"

escenarios = [
    ("benigno", 0, "0.0% (FPR)"),
    ("estandar", 1, "100.0%"),
    ("sqli_base", 1, "100.0%"),
    ("evasion_c3", 1, "100.0%"),
    ("evasion_c4", 1, "100.0%"),
    ("control_ua", 1, "0.0%"),
    ("evasion_c7_v2", 1, "0.0%"),
]

dfs = []
for nombre, label, _ in escenarios:
    ruta = os.path.join(DIR_CIC, f"{nombre}_cic.csv")
    df_esc = pd.read_csv(ruta)
    # Normalizar nombres de columnas (minúsculas y guiones bajos)
    df_esc.columns = [c.strip().lower().replace(" ", "_") for c in df_esc.columns]

    # Filtrar solo tráfico HTTP puerto 80 hacia/desde la víctima (excluir SSH puerto 22)
    mask_http = (
        ((df_esc["dst_ip"] == VICTIM_IP) & (df_esc["dst_port"] == 80)) |
        ((df_esc["src_ip"] == VICTIM_IP) & (df_esc["src_port"] == 80))
    )
    df_esc = df_esc[mask_http].copy()
    df_esc["escenario"] = nombre
    df_esc["label"] = label
    print(f"[*] {nombre:<14}: {len(df_esc):>3} flujos HTTP extraídos por CICFlowMeter")
    dfs.append(df_esc)

df = pd.concat(dfs, ignore_index=True)

# Quedar solo con columnas numéricas válidas (excluir IPs, puertos, protocolo, timestamp)
cols_excluir = {"src_ip", "dst_ip", "src_port", "dst_port", "protocol", "timestamp", "flow_id", "escenario", "label"}
feature_cols = [c for c in df.columns if c not in cols_excluir and pd.api.types.is_numeric_dtype(df[c])]

df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0)
df.to_csv(os.path.join(DIR_CIC, "dataset_cic_unificado.csv"), index=False)

X = df[feature_cols].values
y = df["label"].values

# 1. Validación cruzada estratificada (5-Fold CV)
skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
probs_cv = np.zeros(len(df))
for train_idx, test_idx in skf.split(X, y):
    clf = RandomForestClassifier(n_estimators=200, random_state=42)
    clf.fit(X[train_idx], y[train_idx])
    probs_cv[test_idx] = clf.predict_proba(X[test_idx])[:, 1]

df["prob_cv"] = probs_cv
umbral_cv = df[df["escenario"] == "benigno"]["prob_cv"].max() + 1e-6
df["pred_cv"] = (df["prob_cv"] >= umbral_cv).astype(int)

# 2. Generalización Zero-Day (calibrado OOF sobre set base: benigno + estandar + sqli_base)
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

print(f"\n[+] Features numéricas CICFlowMeter usadas: {len(feature_cols)}")
print(f"[+] ROC-AUC Global (5-Fold CV): {roc_auc_score(y, probs_cv):.4f}")
print(f"[+] Umbral CV calibrado (FPR = 0.0%): {umbral_cv:.4f}")
print(f"[+] Umbral Zero-Day calibrado (FPR = 0.0%): {umbral_zd:.4f}\n")

print("=== TABLA COMPARATIVA: SURICATA vs. RF CON CICFLOWMETER (FPR = 0.0%) ===")
print(f"{'Escenario':<15} | {'Flujos':>6} | {'Suricata':<12} | {'RF-CIC (5-Fold)':<16} | {'RF-CIC (Zero-Day)':<22}")
print("-" * 82)
for nombre, label, suri_str in escenarios:
    sub = df[df["escenario"] == nombre]
    cv_str = f"{sub['pred_cv'].sum()}/{len(sub)} ({sub['pred_cv'].mean()*100:5.1f}%)"
    zd_str = "N/A (En Train)" if nombre in train_escenarios else f"{sub['pred_zd'].sum()}/{len(sub)} ({sub['pred_zd'].mean()*100:5.1f}%)"
    print(f"{nombre:<15} | {len(sub):>6} | {suri_str:<12} | {cv_str:<16} | {zd_str:<22}")

clf_full = RandomForestClassifier(n_estimators=200, random_state=42).fit(X, y)
importancias = pd.Series(clf_full.feature_importances_, index=feature_cols).sort_values(ascending=False)
print("\n=== TOP 10 FEATURES CICFLOWMETER MÁS DETERMINANTES ===")
for feat, val in importancias.head(10).items():
    print(f"  * {feat:<25}: {val:.4f}")
