import os
import json
from datetime import datetime
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict

DIR_EXP = os.path.expanduser("~/experimentos")
DIR_DEP = os.path.join(DIR_EXP, "depurado_c4")
VICTIM_IP = "192.168.56.20"

COLS_EXCLUIR_SCAPY = {
    "escenario", "label", "label_real", "evento_id",
    "src_ip", "dst_ip", "src_port", "dst_port", "ts_inicio", "ts_fin"
}
COLS_EXCLUIR_CIC = {
    "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "timestamp", "flow_id", "escenario", "label", "label_real"
}
META_COLS_CONN = ["escenario", "src_ip", "src_port", "dst_ip", "dst_port"]


def resolver_ruta_cic_depurado():
    candidatas = [
        os.path.join(DIR_DEP, "cic_flows", "dataset_cic_unificado_depurado.csv"),
        os.path.join(DIR_DEP, "dataset_cic_unificado_depurado.csv"),
    ]
    for ruta in candidatas:
        if os.path.exists(ruta):
            return ruta
    raise FileNotFoundError(f"No se encontró dataset_cic_unificado_depurado.csv en: {candidatas}")


def obtener_columna_etiqueta(df):
    for col in ("label", "label_real"):
        if col in df.columns:
            return col
    raise KeyError("No se encontró columna de etiqueta ('label' o 'label_real').")


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
                })
    return alertas


def extraer_ventanas_flujos_pcap(ruta_pcap, escenario):
    """Extrae metadatos de conexión y ventana temporal de cada flujo depurado del PCAP."""
    paquetes = rdpcap(ruta_pcap)
    flujos = {}

    for pkt in paquetes:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]

        if ip.dst == VICTIM_IP and int(tcp.dport) == 80:
            clave = (str(ip.src), int(tcp.sport), str(ip.dst), int(tcp.dport))
        elif ip.src == VICTIM_IP and int(tcp.sport) == 80:
            clave = (str(ip.dst), int(tcp.dport), str(ip.src), int(tcp.sport))
        else:
            continue

        flujos.setdefault(clave, []).append(float(pkt.time))

    filas = []
    for clave, tiempos in sorted(flujos.items(), key=lambda x: min(x[1])):
        tiempos.sort()
        total_pkts = len(tiempos)
        if escenario == "evasion_c4" and total_pkts <= 5:
            continue
        src_ip, src_port, dst_ip, dst_port = clave
        filas.append({
            "escenario": escenario,
            "src_ip": src_ip,
            "src_port": src_port,
            "dst_ip": dst_ip,
            "dst_port": dst_port,
            "ts_inicio": tiempos[0],
            "ts_fin": tiempos[-1],
        })

    df_meta = pd.DataFrame(filas)
    assert not df_meta.duplicated(subset=META_COLS_CONN).any(), (
        f"Duplicados de conexión detectados en {escenario}"
    )
    return df_meta


def calcular_recall_suricata_desde_eve(escenarios):
    """Calcula programáticamente el recall de Suricata por escenario cruzando alertas de eve.json."""
    recalls = []
    for esc in escenarios:
        pcap_path = os.path.join(DIR_EXP, f"{esc}.pcap")
        eve_path = os.path.join(DIR_EXP, f"eve_{esc}.json")
        df_flujos = extraer_ventanas_flujos_pcap(pcap_path, esc)
        alertas = cargar_alertas_eve(eve_path)

        hits = []
        for _, row in df_flujos.iterrows():
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
            hits.append(hit)

        recalls.append(float(np.mean(hits)) * 100.0 if hits else 0.0)
    return recalls


def evaluar_dataset(ruta_csv, cols_excluir, df_meta_ref=None):
    df = pd.read_csv(ruta_csv)
    assert len(df) == 540, f"Se esperaban 540 flujos depurados en {ruta_csv}, se obtuvieron {len(df)}"

    col_label = obtener_columna_etiqueta(df)
    feature_cols = [
        c for c in df.columns
        if c not in cols_excluir and pd.api.types.is_numeric_dtype(df[c])
    ]

    # Si se pasa df_meta_ref (como en CICFlowMeter), asegurar correspondencia por metadatos sin depender del orden
    if df_meta_ref is not None:
        assert len(feature_cols) == 76, f"Se esperaban 76 features en CIC, se obtuvieron {len(feature_cols)}"
        work = df.copy()
        work["src_ip"] = work["src_ip"].astype(str)
        work["dst_ip"] = work["dst_ip"].astype(str)
        work["src_port"] = work["src_port"].astype(int)
        work["dst_port"] = work["dst_port"].astype(int)
        work["escenario"] = work["escenario"].astype(str)
        assert not work.duplicated(subset=META_COLS_CONN).any(), "Claves duplicadas en dataset CIC depurado"

        ref = df_meta_ref[META_COLS_CONN].copy()
        ref["src_ip"] = ref["src_ip"].astype(str)
        ref["dst_ip"] = ref["dst_ip"].astype(str)
        ref["src_port"] = ref["src_port"].astype(int)
        ref["dst_port"] = ref["dst_port"].astype(int)
        ref["escenario"] = ref["escenario"].astype(str)

        df = pd.merge(ref, work, on=META_COLS_CONN, how="left", validate="one_to_one")
        assert df[col_label].notna().all(), "Existen flujos sin correspondencia exacta por metadatos"

    X = df[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values
    y = df[col_label].astype(int).values

    # E1: 5-Fold CV calibrado OOF a FPR = 0.0% en benigno
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    probs_cv = np.zeros(len(df))
    for train_idx, test_idx in skf.split(X, y):
        clf = RandomForestClassifier(n_estimators=200, random_state=42)
        clf.fit(X[train_idx], y[train_idx])
        probs_cv[test_idx] = clf.predict_proba(X[test_idx])[:, 1]

    umbral_cv = probs_cv[df["escenario"] == "benigno"].max() + 1e-6
    df["pred_cv"] = (probs_cv >= umbral_cv).astype(int)

    # E2: Variantes no vistas calibrado OOF sobre set base (FPR = 0.0% en benigno base)
    train_esc = ["benigno", "estandar", "sqli_base"]
    df_train = df[df["escenario"].isin(train_esc)].copy()
    probs_oof = cross_val_predict(
        RandomForestClassifier(n_estimators=200, random_state=42),
        df_train[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values,
        df_train[col_label].astype(int).values,
        cv=StratifiedKFold(n_splits=5, shuffle=True, random_state=42),
        method="predict_proba"
    )[:, 1]
    umbral_zd = probs_oof[df_train["escenario"] == "benigno"].max() + 1e-6

    clf_base = RandomForestClassifier(n_estimators=200, random_state=42)
    clf_base.fit(
        df_train[feature_cols].replace([np.inf, -np.inf], np.nan).fillna(0.0).values,
        df_train[col_label].astype(int).values
    )
    df["pred_zd"] = (clf_base.predict_proba(X)[:, 1] >= umbral_zd).astype(int)

    return df


def main():
    os.makedirs(DIR_DEP, exist_ok=True)
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

    # Referencia de metadatos por conexión desde los PCAPs depurados
    meta_list = [
        extraer_ventanas_flujos_pcap(os.path.join(DIR_EXP, f"{e}.pcap"), e)
        for e in ["benigno"] + escenarios
    ]
    df_meta_ref = pd.concat(meta_list, ignore_index=True)

    df_scapy = evaluar_dataset(
        os.path.join(DIR_DEP, "dataset_flujos_depurado.csv"),
        COLS_EXCLUIR_SCAPY,
        df_meta_ref=None
    )
    df_cic = evaluar_dataset(
        resolver_ruta_cic_depurado(),
        COLS_EXCLUIR_CIC,
        df_meta_ref=df_meta_ref
    )

    suri_recall = calcular_recall_suricata_desde_eve(escenarios)
    scapy_cv = [df_scapy[df_scapy["escenario"] == e]["pred_cv"].mean() * 100.0 for e in escenarios]
    cic_cv = [df_cic[df_cic["escenario"] == e]["pred_cv"].mean() * 100.0 for e in escenarios]

    scapy_zd = [np.nan if e in train_esc else df_scapy[df_scapy["escenario"] == e]["pred_zd"].mean() * 100.0 for e in escenarios]
    cic_zd = [np.nan if e in train_esc else df_cic[df_cic["escenario"] == e]["pred_zd"].mean() * 100.0 for e in escenarios]

    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(11.5, 12.2), sharex=True)
    x = np.arange(len(escenarios))
    width = 0.27

    # Panel A: E1 (Tráfico conocido - 5-Fold CV)
    b1_a = ax1.bar(x - width, suri_recall, width, label="Suricata 7 (Firmas ET Open)", color="#2b5c8f")
    b2_a = ax1.bar(x, scapy_cv, width, label="Random Forest — Scapy (19 features)", color="#2e8b57")
    b3_a = ax1.bar(x + width, cic_cv, width, label="Random Forest — CICFlowMeter (76 features)", color="#6a5acd")

    ax1.set_ylabel("Recall (%)", fontsize=11)
    ax1.set_title("A. Detección sobre Tráfico Conocido — E1 (5-Fold CV | N=540)", fontsize=12, fontweight="bold", pad=34)
    ax1.set_ylim(0, 118)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)
    ax1.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=3, frameon=True, fontsize=9.5)

    for bars in (b1_a, b2_a, b3_a):
        for bar in bars:
            h = bar.get_height()
            ax1.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    # Panel B: E2 (Generalización ante variantes no vistas)
    b1_b = ax2.bar(x - width, suri_recall, width, label="Suricata 7 (Firmas ET Open)", color="#2b5c8f")
    b2_b = ax2.bar(x, scapy_zd, width, label="RF Variantes no vistas — Scapy (19 features)", color="#d97724")
    b3_b = ax2.bar(x + width, cic_zd, width, label="RF Variantes no vistas — CICFlowMeter (76 features)", color="#c0392b")

    ax2.set_ylabel("Recall (%)", fontsize=11)
    ax2.set_title("B. Generalización ante Variantes no Vistas — E2 (N=540 depurado)", fontsize=12, fontweight="bold", pad=34)
    ax2.set_xticks(x)
    ax2.set_xticklabels(etiquetas, fontsize=10)
    ax2.set_ylim(0, 118)
    ax2.grid(axis="y", linestyle="--", alpha=0.5)
    ax2.legend(loc="lower center", bbox_to_anchor=(0.5, 1.01), ncol=3, frameon=True, fontsize=9.5)

    for bars in (b1_b, b2_b, b3_b):
        for bar in bars:
            h = bar.get_height()
            if np.isnan(h):
                ax2.text(bar.get_x() + bar.get_width()/2, 3, "N/A\n(Train)", ha="center", va="bottom", fontsize=8, color="#555555")
            else:
                ax2.text(bar.get_x() + bar.get_width()/2, h + 1.5, f"{h:.1f}%", ha="center", va="bottom", fontsize=8.5, fontweight="bold")

    fig.subplots_adjust(top=0.91, bottom=0.08, hspace=0.30)
    os.makedirs(os.path.join(DIR_DEP, "results"), exist_ok=True)
    salida_img = os.path.join(DIR_DEP, "results", "grafico_comparativa_3_enfoques.png")
    plt.savefig(salida_img, dpi=300)
    plt.close()
    print(f"[+] Gráfico de 3 enfoques exportado en: {salida_img}")


if __name__ == "__main__":
    main()
