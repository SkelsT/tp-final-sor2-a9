import os
import json
from datetime import datetime
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict

DIR_EXP = os.path.expanduser("~/experimentos")
DIR_DEP = os.path.join(DIR_EXP, "depurado_c4")
DIR_EVAL = os.path.join(DIR_EXP, "eval_benigno")
VICTIM_IP = "192.168.56.20"

ESCENARIOS_BASE = [
    ("benigno", 0),
    ("estandar", 1),
    ("sqli_base", 1),
]

ESCENARIOS_NO_VISTOS = [
    ("evasion_c3", 1),
    ("evasion_c4", 1),
    ("control_ua", 1),
    ("evasion_c7_v2", 1),
]

FEATURE_COLS_SCAPY = [
    "duracion", "total_pkts", "fwd_pkts", "bwd_pkts", "ratio_pkts",
    "total_bytes", "pkt_len_mean", "pkt_len_std", "fwd_len_mean", "bwd_len_mean",
    "iat_mean", "iat_std", "iat_max", "n_psh", "n_syn", "n_fin", "n_rst",
    "n_frags", "pkts_per_sec"
]

META_COLS_SCAPY = [
    "evento_id", "escenario", "src_ip", "src_port", "dst_ip", "dst_port",
    "ts_inicio", "ts_fin", "label_real"
]

NON_FEAT_CIC = {
    "escenario", "label", "label_real", "src_ip", "dst_ip",
    "src_port", "dst_port", "protocol", "timestamp", "flow_id"
}


def parse_iso_ts(ts_str):
    if not ts_str:
        return None
    try:
        return datetime.fromisoformat(ts_str).timestamp()
    except ValueError:
        return None


def cargar_alertas_eve(ruta_eve):
    alertas = []
    if not os.path.exists(ruta_eve):
        return alertas
    with open(ruta_eve, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            if ev.get("event_type") == "alert":
                alertas.append({
                    "ts": parse_iso_ts(ev.get("timestamp")),
                    "src_ip": ev.get("src_ip"),
                    "src_port": int(ev.get("src_port")) if ev.get("src_port") is not None else None,
                    "dest_ip": ev.get("dest_ip"),
                    "dest_port": int(ev.get("dest_port")) if ev.get("dest_port") is not None else None,
                    "sid": ev.get("alert", {}).get("signature_id"),
                })
    return alertas


def extraer_flujos_con_meta(ruta_pcap, escenario, label_real):
    paquetes = rdpcap(ruta_pcap)
    flujos = {}

    for pkt in paquetes:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]

        if ip.dst == VICTIM_IP and int(tcp.dport) == 80:
            clave = (ip.src, int(tcp.sport), ip.dst, int(tcp.dport))
            direccion = "fwd"
        elif ip.src == VICTIM_IP and int(tcp.sport) == 80:
            clave = (ip.dst, int(tcp.dport), ip.src, int(tcp.sport))
            direccion = "bwd"
        else:
            continue

        flujos.setdefault(clave, []).append((
            float(pkt.time),
            direccion,
            len(pkt),
            int(ip.frag > 0 or (ip.flags & 1)),
            int(tcp.flags)
        ))

    filas = []
    for idx, (clave, lista) in enumerate(sorted(flujos.items(), key=lambda x: x[1][0][0])):
        lista.sort(key=lambda x: x[0])
        tiempos = [x[0] for x in lista]
        tamanos = [x[2] for x in lista]
        fwd_sizes = [x[2] for x in lista if x[1] == "fwd"]
        bwd_sizes = [x[2] for x in lista if x[1] == "bwd"]
        iats = np.diff(tiempos) if len(tiempos) > 1 else [0.0]

        flags_list = [x[4] for x in lista]
        n_psh = sum(1 for f in flags_list if f & 0x08)
        n_syn = sum(1 for f in flags_list if f & 0x02)
        n_fin = sum(1 for f in flags_list if f & 0x01)
        n_rst = sum(1 for f in flags_list if f & 0x04)
        n_frags = sum(x[3] for x in lista)

        duracion = tiempos[-1] - tiempos[0]
        total_pkts = len(lista)

        if escenario == "evasion_c4" and total_pkts <= 5:
            continue

        src_ip, src_port, dst_ip, dst_port = clave
        filas.append({
            "evento_id": f"{escenario}_{idx:04d}",
            "escenario": escenario,
            "src_ip": str(src_ip),
            "src_port": int(src_port),
            "dst_ip": str(dst_ip),
            "dst_port": int(dst_port),
            "ts_inicio": float(tiempos[0]),
            "ts_fin": float(tiempos[-1]),
            "label_real": int(label_real),
            "duracion": float(duracion),
            "total_pkts": int(total_pkts),
            "fwd_pkts": int(len(fwd_sizes)),
            "bwd_pkts": int(len(bwd_sizes)),
            "ratio_pkts": float(len(fwd_sizes) / max(len(bwd_sizes), 1)),
            "total_bytes": int(sum(tamanos)),
            "pkt_len_mean": float(np.mean(tamanos)),
            "pkt_len_std": float(np.std(tamanos)),
            "fwd_len_mean": float(np.mean(fwd_sizes)) if fwd_sizes else 0.0,
            "bwd_len_mean": float(np.mean(bwd_sizes)) if bwd_sizes else 0.0,
            "iat_mean": float(np.mean(iats)),
            "iat_std": float(np.std(iats)),
            "iat_max": float(np.max(iats)),
            "n_psh": int(n_psh),
            "n_syn": int(n_syn),
            "n_fin": int(n_fin),
            "n_rst": int(n_rst),
            "n_frags": int(n_frags),
            "pkts_per_sec": float(total_pkts / max(duracion, 1e-6)),
        })

    df_out = pd.DataFrame(filas)
    assert not df_out.duplicated(subset=["escenario", "src_ip", "src_port", "dst_ip", "dst_port"]).any(), (
        f"Duplicados de conexión detectados en {escenario}"
    )
    return df_out


def marcar_alertas_suricata(df_esc, alertas):
    detectado = []
    for _, row in df_esc.iterrows():
        hit = 0
        for al in alertas:
            if (
                al["src_ip"] == row["src_ip"]
                and al["src_port"] == int(row["src_port"])
                and al["dest_ip"] == row["dst_ip"]
                and al["dest_port"] == int(row["dst_port"])
            ):
                if al["ts"] is None or (row["ts_inicio"] - 1.0 <= al["ts"] <= row["ts_fin"] + 2.0):
                    hit = 1
                    break
        detectado.append(hit)
    return detectado


def asignar_pred_cic_por_metadatos(df_destino, df_cic_pred, incluir_escenario=True):
    """Asigna predicciones de CICFlowMeter mediante metadatos de conexión (sin usar posición de fila)."""
    claves_meta = ["src_ip", "src_port", "dst_ip", "dst_port"]
    if incluir_escenario:
        claves_meta = ["escenario"] + claves_meta

    work_cic = df_cic_pred[claves_meta + ["pred_cic"]].copy()
    work_cic["src_ip"] = work_cic["src_ip"].astype(str)
    work_cic["dst_ip"] = work_cic["dst_ip"].astype(str)
    work_cic["src_port"] = work_cic["src_port"].astype(int)
    work_cic["dst_port"] = work_cic["dst_port"].astype(int)
    if incluir_escenario:
        work_cic["escenario"] = work_cic["escenario"].astype(str)

    assert not work_cic.duplicated(subset=claves_meta).any(), (
        f"Claves duplicadas en CICFlowMeter para {claves_meta}"
    )

    merged = pd.merge(
        df_destino[claves_meta].copy(),
        work_cic,
        on=claves_meta,
        how="left",
        validate="one_to_one",
    )
    assert merged["pred_cic"].notna().all(), (
        "Existen flujos sin correspondencia exacta por metadatos en CICFlowMeter"
    )
    return merged["pred_cic"].astype(int).values


def calcular_metricas(y_true, y_pred):
    y_true = np.asarray(y_true, dtype=int)
    y_pred = np.asarray(y_pred, dtype=int)
    tp = int(np.sum((y_true == 1) & (y_pred == 1)))
    fp = int(np.sum((y_true == 0) & (y_pred == 1)))
    fn = int(np.sum((y_true == 1) & (y_pred == 0)))
    tn = int(np.sum((y_true == 0) & (y_pred == 0)))

    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    return {
        "TP": tp, "FP": fp, "FN": fn, "TN": tn,
        "recall": round(recall, 4),
        "precision": round(precision, 4),
        "fpr": round(fpr, 4),
    }


def main():
    os.makedirs(DIR_DEP, exist_ok=True)
    todos_escenarios = ESCENARIOS_BASE + ESCENARIOS_NO_VISTOS

    dfs_scapy = []
    for esc, lbl in todos_escenarios:
        pcap_path = os.path.join(DIR_EXP, f"{esc}.pcap")
        eve_path = os.path.join(DIR_EXP, f"eve_{esc}.json")
        df_e = extraer_flujos_con_meta(pcap_path, esc, lbl)
        alertas = cargar_alertas_eve(eve_path)
        df_e["det_suricata"] = marcar_alertas_suricata(df_e, alertas)
        dfs_scapy.append(df_e)

    df_main = pd.concat(dfs_scapy, ignore_index=True)
    assert len(df_main) == 540, f"Se esperaban 540 flujos depurados, se obtuvieron {len(df_main)}"

    # Conjunto benigno independiente para evaluación (nunca en train ni en calibración)
    df_ben_eval = extraer_flujos_con_meta(
        os.path.join(DIR_EVAL, "benigno_eval.pcap"),
        "benigno_eval",
        0
    )
    alertas_ben_eval = cargar_alertas_eve(os.path.join(DIR_EVAL, "eve_benigno_eval.json"))
    df_ben_eval["det_suricata"] = marcar_alertas_suricata(df_ben_eval, alertas_ben_eval)

    # Entrenar RF-Scapy SOLO en ESCENARIOS_BASE y calibrar umbral OOF en benigno base
    df_train_scapy = df_main[df_main["escenario"].isin([e for e, _ in ESCENARIOS_BASE])].copy()
    X_train_s = df_train_scapy[FEATURE_COLS_SCAPY].values
    y_train_s = df_train_scapy["label_real"].values

    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    probs_oof_s = cross_val_predict(
        RandomForestClassifier(n_estimators=200, random_state=42),
        X_train_s, y_train_s, cv=skf, method="predict_proba"
    )[:, 1]
    umbral_s = float(probs_oof_s[df_train_scapy["escenario"].values == "benigno"].max()) + 1e-6

    clf_scapy = RandomForestClassifier(n_estimators=200, random_state=42)
    clf_scapy.fit(X_train_s, y_train_s)

    df_main["det_rf_scapy"] = (clf_scapy.predict_proba(df_main[FEATURE_COLS_SCAPY].values)[:, 1] >= umbral_s).astype(int)
    df_ben_eval["det_rf_scapy"] = (clf_scapy.predict_proba(df_ben_eval[FEATURE_COLS_SCAPY].values)[:, 1] >= umbral_s).astype(int)

    # RF-CICFlowMeter (76 características exactas, excluyendo metadatos y protocol)
    cic_dep_path = os.path.join(DIR_DEP, "dataset_cic_unificado_depurado.csv")
    cic_eval_path = os.path.join(DIR_EVAL, "cic_flows", "benigno_eval_cic.csv")
    df_cic = pd.read_csv(cic_dep_path)
    df_cic_eval = pd.read_csv(cic_eval_path)

    feat_cols_cic = [
        c for c in df_cic.columns
        if c not in NON_FEAT_CIC and pd.api.types.is_numeric_dtype(df_cic[c])
    ]
    common_cic_cols = [c for c in feat_cols_cic if c in df_cic_eval.columns]
    assert len(common_cic_cols) == 76, f"Se esperaban 76 features en CIC, se obtuvieron {len(common_cic_cols)}"

    mapa_lbl = {e: l for e, l in todos_escenarios}
    df_cic["label_real"] = df_cic["escenario"].map(mapa_lbl)
    df_cic_train = df_cic[df_cic["escenario"].isin([e for e, _ in ESCENARIOS_BASE])].dropna(subset=["label_real"]).copy()

    X_train_c = df_cic_train[common_cic_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
    y_train_c = df_cic_train["label_real"].astype(int).values

    probs_oof_c = cross_val_predict(
        RandomForestClassifier(n_estimators=200, random_state=42),
        X_train_c, y_train_c, cv=skf, method="predict_proba"
    )[:, 1]
    umbral_c = float(probs_oof_c[df_cic_train["escenario"].values == "benigno"].max()) + 1e-6

    clf_cic = RandomForestClassifier(n_estimators=200, random_state=42)
    clf_cic.fit(X_train_c, y_train_c)

    df_cic = df_cic.copy()
    X_all_c = df_cic[common_cic_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
    df_cic["pred_cic"] = (clf_cic.predict_proba(X_all_c)[:, 1] >= umbral_c).astype(int)
    df_main["det_rf_cic"] = asignar_pred_cic_por_metadatos(df_main, df_cic, incluir_escenario=True)

    df_cic_eval = df_cic_eval.copy()
    X_ben_c = df_cic_eval[common_cic_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
    df_cic_eval["pred_cic"] = (clf_cic.predict_proba(X_ben_c)[:, 1] >= umbral_c).astype(int)
    df_ben_eval["det_rf_cic"] = asignar_pred_cic_por_metadatos(df_ben_eval, df_cic_eval, incluir_escenario=False)

    # Tabla evento por evento (metadatos + etiqueta + 3 detectores)
    cols_tabla = META_COLS_SCAPY + ["det_suricata", "det_rf_scapy", "det_rf_cic"]
    tabla_completa = pd.concat([df_main[cols_tabla], df_ben_eval[cols_tabla]], ignore_index=True)
    assert not tabla_completa.duplicated(subset=["escenario", "src_ip", "src_port", "dst_ip", "dst_port"]).any(), (
        "Existen filas duplicadas en tabla_eventos"
    )

    ruta_tabla = os.path.join(DIR_DEP, "tabla_eventos.csv")
    tabla_completa.to_csv(ruta_tabla, index=False)

    # Métricas calculadas automáticamente desde la tabla por evento
    no_vistos_names = [e for e, _ in ESCENARIOS_NO_VISTOS]
    sub_nv = df_main[df_main["escenario"].isin(no_vistos_names)]

    metricas = {
        "n_features_cic": len(common_cic_cols),
        "n_flujos_depurados_base": int(len(df_main)),
        "variantes_no_vistas_recall": {
            "suricata": calcular_metricas(sub_nv["label_real"], sub_nv["det_suricata"])["recall"],
            "rf_scapy": calcular_metricas(sub_nv["label_real"], sub_nv["det_rf_scapy"])["recall"],
            "rf_cic": calcular_metricas(sub_nv["label_real"], sub_nv["det_rf_cic"])["recall"],
        },
        "benigno_eval_independiente_fpr": {
            "suricata": calcular_metricas(df_ben_eval["label_real"], df_ben_eval["det_suricata"])["fpr"],
            "rf_scapy": calcular_metricas(df_ben_eval["label_real"], df_ben_eval["det_rf_scapy"])["fpr"],
            "rf_cic": calcular_metricas(df_ben_eval["label_real"], df_ben_eval["det_rf_cic"])["fpr"],
        },
        "por_escenario": {}
    }

    print(f"[+] Tabla evento por evento guardada en: {ruta_tabla} ({len(tabla_completa)} filas)")
    print(f"[+] Features CIC utilizadas: {len(common_cic_cols)} | Umbral RF-Scapy: {umbral_s:.4f} | Umbral RF-CIC: {umbral_c:.4f}\n")
    print(f"{'Escenario':<15} | {'N':>4} | {'Label':>5} | {'Suricata':>8} | {'RF-Scapy':>8} | {'RF-CIC':>8}")
    print("-" * 68)

    for esc, lbl in todos_escenarios + [("benigno_eval", 0)]:
        sub = tabla_completa[tabla_completa["escenario"] == esc]
        s_rate = sub["det_suricata"].mean()
        sc_rate = sub["det_rf_scapy"].mean()
        cc_rate = sub["det_rf_cic"].mean()
        metricas["por_escenario"][esc] = {
            "n": int(len(sub)),
            "label_real": int(lbl),
            "tasa_suricata": round(float(s_rate), 4),
            "tasa_rf_scapy": round(float(sc_rate), 4),
            "tasa_rf_cic": round(float(cc_rate), 4),
        }
        print(f"{esc:<15} | {len(sub):>4} | {lbl:>5} | {s_rate*100:>7.1f}% | {sc_rate*100:>7.1f}% | {cc_rate*100:>7.1f}%")

    print("\n=== MÉTRICAS CALCULADAS DESDE ALERTAS / PREDICCIONES ===")
    print("Recall en variantes no vistas (C3, C4, control_ua, C7_v2):", metricas["variantes_no_vistas_recall"])
    print("FPR en captura benigna independiente (benigno_eval):      ", metricas["benigno_eval_independiente_fpr"])

    ruta_json = os.path.join(DIR_DEP, "metricas_desde_alertas.json")
    with open(ruta_json, "w", encoding="utf-8") as f:
        json.dump(metricas, f, indent=2)
    print(f"\n[+] Métricas guardadas en: {ruta_json}")


if __name__ == "__main__":
    main()
