import os
import json
import numpy as np
import pandas as pd
from scipy.stats import t as t_dist
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import confusion_matrix

DIR_EXP = os.path.expanduser("~/experimentos")
DIR_CIC = os.path.join(DIR_EXP, "cic_flows")
OUT_DIR = os.path.expanduser("~/tp_sor2/validacion_resultados")
os.makedirs(OUT_DIR, exist_ok=True)

SEMILLAS = [42, 7, 13, 21, 99, 123, 2024, 314, 777, 1337]
ESCENARIOS_EVAL = ["estandar", "sqli_base", "evasion_c3", "evasion_c4", "control_ua", "evasion_c7_v2"]
ESCENARIOS_NO_VISTOS = ["evasion_c4", "evasion_c3", "control_ua", "evasion_c7_v2"]
TRAIN_ZD = ["benigno", "estandar", "sqli_base"]


def calcular_metricas_binarias(y_true, y_pred):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0
    return {
        "TP": int(tp),
        "FP": int(fp),
        "FN": int(fn),
        "TN": int(tn),
        "Recall": round(recall * 100, 2),
        "Precision": round(precision * 100, 2),
        "FPR": round(fpr * 100, 2),
        "F1_score": round(f1 * 100, 2),
    }


def contar_alertas_suricata(dir_exp):
    conteo = {}
    for esc in ["benigno"] + ESCENARIOS_EVAL:
        ruta_eve = os.path.join(dir_exp, f"eve_{esc}.json")
        if not os.path.exists(ruta_eve):
            conteo[esc] = {"alertas_eve": None, "alertas_http": None}
            continue
        n_alerts = 0
        n_http_alerts = 0
        with open(ruta_eve, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("event_type") == "alert":
                    n_alerts += 1
                    if ev.get("app_proto") == "http" or "http" in ev:
                        n_http_alerts += 1
        conteo[esc] = {"alertas_eve": n_alerts, "alertas_http": n_http_alerts}
    return conteo


def evaluar_modelo(nombre_modelo, ruta_csv, cols_excluir, seed=42):
    df = pd.read_csv(ruta_csv)
    feature_cols = [
        c for c in df.columns
        if c not in cols_excluir and pd.api.types.is_numeric_dtype(df[c])
    ]
    X = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
    y = df["label"].astype(int).values
    mask_benigno = (df["escenario"] == "benigno").values

    # E1: 5-Fold CV (umbral fijado sobre población benigna out-of-fold)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=seed)
    probs_cv = np.zeros(len(df))
    for train_idx, test_idx in skf.split(X, y):
        clf = RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1)
        clf.fit(X[train_idx], y[train_idx])
        probs_cv[test_idx] = clf.predict_proba(X[test_idx])[:, 1]

    umbral_cv = probs_cv[mask_benigno].max() + 1e-6
    pred_cv = (probs_cv >= umbral_cv).astype(int)
    m_cv = calcular_metricas_binarias(y, pred_cv)

    # E2: Variantes no vistas (entrenamiento solo con benigno, estandar y sqli_base)
    mask_train_zd = df["escenario"].isin(TRAIN_ZD).values
    df_tr = df[mask_train_zd]
    X_tr = X[mask_train_zd]
    y_tr = y[mask_train_zd]
    mask_ben_tr = (df_tr["escenario"] == "benigno").values

    probs_oof_tr = cross_val_predict(
        RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1),
        X_tr,
        y_tr,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=seed),
        method="predict_proba",
    )[:, 1]
    umbral_zd = probs_oof_tr[mask_ben_tr].max() + 1e-6

    clf_zd = RandomForestClassifier(n_estimators=200, random_state=seed, n_jobs=-1)
    clf_zd.fit(X_tr, y_tr)
    probs_zd = clf_zd.predict_proba(X)[:, 1]
    pred_zd = (probs_zd >= umbral_zd).astype(int)

    # Evaluar E2 sobre variantes no vistas + benigno (para FPR global)
    mask_eval_zd = (~mask_train_zd) | mask_benigno
    m_zd = calcular_metricas_binarias(y[mask_eval_zd], pred_zd[mask_eval_zd])

    recall_por_esc_zd = {}
    for esc in ESCENARIOS_EVAL:
        m_esc = (df["escenario"] == esc).values
        if esc in ["estandar", "sqli_base"]:
            recall_por_esc_zd[esc] = None
        else:
            recall_por_esc_zd[esc] = round(float(pred_zd[m_esc].mean() * 100), 2)

    recall_por_esc_cv = {
        esc: round(float(pred_cv[(df["escenario"] == esc).values].mean() * 100), 2)
        for esc in ESCENARIOS_EVAL
    }

    return {
        "modelo": nombre_modelo,
        "seed": seed,
        "n_flujos": len(df),
        "n_features": len(feature_cols),
        "cv_metrics": m_cv,
        "zd_metrics": m_zd,
        "recall_cv": recall_por_esc_cv,
        "recall_zd": recall_por_esc_zd,
    }


def resumen_t_ic95(serie):
    vals = serie.dropna().astype(float)
    n = len(vals)
    media = float(vals.mean())
    desvio = float(vals.std(ddof=1)) if n > 1 else 0.0
    crit = float(t_dist.ppf(0.975, df=n - 1)) if n > 1 else 0.0
    ic95 = crit * desvio / np.sqrt(n) if n > 0 else 0.0
    return {
        "n": n,
        "media": round(media, 2),
        "std": round(desvio, 2),
        "min": round(float(vals.min()), 2),
        "max": round(float(vals.max()), 2),
        "t_crit": round(crit, 4),
        "ic95_low": round(media - ic95, 2),
        "ic95_high": round(media + ic95, 2),
    }


def main():
    ruta_scapy = os.path.join(DIR_EXP, "dataset_flujos.csv")
    ruta_cic = os.path.join(DIR_CIC, "dataset_cic_unificado.csv")

    res_scapy_42 = evaluar_modelo("RF_Scapy_19f", ruta_scapy, {"escenario", "label"}, seed=42)
    res_cic_42 = evaluar_modelo("RF_CIC_76f", ruta_cic, {
        "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
        "timestamp", "flow_id", "escenario", "label"
    }, seed=42)

    print("=== RESUMEN METRICAS GLOBALES (SEED=42) ===")
    for r in [res_scapy_42, res_cic_42]:
        print(f"\nModelo: {r['modelo']} (flujos={r['n_flujos']}, features={r['n_features']})")
        print("  E1 (5-Fold CV):", r["cv_metrics"])
        print("  E2 (No vistas + benigno):", r["zd_metrics"])
        print("  Recall por escenario (E2):", r["recall_zd"])

    # Multi-semilla para estabilidad en E2 en las 4 variantes no vistas
    filas_seeds = []
    for seed in SEMILLAS:
        rs = evaluar_modelo("RF_Scapy_19f", ruta_scapy, {"escenario", "label"}, seed=seed)
        rc = evaluar_modelo("RF_CIC_76f", ruta_cic, {
            "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
            "timestamp", "flow_id", "escenario", "label"
        }, seed=seed)
        for mod, res in [("RF_Scapy_19f", rs), ("RF_CIC_76f", rc)]:
            filas_seeds.append({
                "modelo": mod,
                "seed": seed,
                "c4_recall_zd": res["recall_zd"]["evasion_c4"],
                "c3_recall_zd": res["recall_zd"]["evasion_c3"],
                "ua_recall_zd": res["recall_zd"]["control_ua"],
                "c7_recall_zd": res["recall_zd"]["evasion_c7_v2"],
                "zd_precision": res["zd_metrics"]["Precision"],
                "zd_f1": res["zd_metrics"]["F1_score"],
                "zd_fpr": res["zd_metrics"]["FPR"],
            })

    df_seeds = pd.DataFrame(filas_seeds)
    df_seeds.to_csv(os.path.join(OUT_DIR, "estabilidad_multisimilla_e2.csv"), index=False)

    mapa_cols = {
        "evasion_c4": "c4_recall_zd",
        "evasion_c3": "c3_recall_zd",
        "control_ua": "ua_recall_zd",
        "evasion_c7_v2": "c7_recall_zd",
    }

    resumen_multisimilla = {}
    print(f"\n=== ESTABILIDAD MULTI-SEMILLA EN E2 ({len(SEMILLAS)} SEMILLAS | IC95% t-Student) ===")
    for mod, grp in df_seeds.groupby("modelo"):
        resumen_multisimilla[mod] = {}
        print(f"\nModelo: {mod}")
        for esc in ESCENARIOS_NO_VISTOS:
            col = mapa_cols[esc]
            st = resumen_t_ic95(grp[col])
            resumen_multisimilla[mod][esc] = st
            print(
                f"  {esc:14s} -> media={st['media']:6.2f}%, std={st['std']:5.2f}%, "
                f"min={st['min']:6.2f}%, max={st['max']:6.2f}%, "
                f"IC95%=[{st['ic95_low']:6.2f}%, {st['ic95_high']:6.2f}%] (t={st['t_crit']})"
            )

    suricata_counts = contar_alertas_suricata(DIR_EXP)
    salida_json = {
        "seed_42": {"RF_Scapy_19f": res_scapy_42, "RF_CIC_76f": res_cic_42},
        "multisimilla_e2": resumen_multisimilla,
        "suricata_eve_counts": suricata_counts,
    }
    with open(os.path.join(OUT_DIR, "metricas_consolidadas.json"), "w", encoding="utf-8") as f:
        json.dump(salida_json, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Archivos guardados en {OUT_DIR}")


if __name__ == "__main__":
    main()
