import os
import numpy as np
import pandas as pd
from scapy.all import rdpcap, IP, TCP
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import roc_auc_score

DIR_EXP = os.path.expanduser("~/experimentos")
VICTIM_IP = "192.168.56.20"

def extraer_flujos_pcap(ruta_pcap, escenario, etiqueta):
    paquetes = rdpcap(ruta_pcap)
    flujos = {}

    for pkt in paquetes:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            continue
        ip = pkt[IP]
        tcp = pkt[TCP]

        if ip.dst == VICTIM_IP and tcp.dport == 80:
            clave = (ip.src, tcp.sport, ip.dst, tcp.dport)
            direccion = "fwd"
        elif ip.src == VICTIM_IP and tcp.sport == 80:
            clave = (ip.dst, tcp.dport, ip.src, tcp.sport)
            direccion = "bwd"
        else:
            continue

        if clave not in flujos:
            flujos[clave] = []
        flujos[clave].append((
            float(pkt.time),
            direccion,
            len(pkt),
            int(ip.frag > 0 or (ip.flags & 1)),
            int(tcp.flags)
        ))

    filas = []
    for clave, lista in flujos.items():
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
        total_bytes = sum(tamanos)

        filas.append({
            "escenario": escenario,
            "label": etiqueta,
            "duracion": duracion,
            "total_pkts": total_pkts,
            "fwd_pkts": len(fwd_sizes),
            "bwd_pkts": len(bwd_sizes),
            "ratio_pkts": len(fwd_sizes) / max(len(bwd_sizes), 1),
            "total_bytes": total_bytes,
            "pkt_len_mean": np.mean(tamanos),
            "pkt_len_std": np.std(tamanos),
            "fwd_len_mean": np.mean(fwd_sizes) if fwd_sizes else 0.0,
            "bwd_len_mean": np.mean(bwd_sizes) if bwd_sizes else 0.0,
            "iat_mean": np.mean(iats),
            "iat_std": np.std(iats),
            "iat_max": np.max(iats),
            "n_psh": n_psh,
            "n_syn": n_syn,
            "n_fin": n_fin,
            "n_rst": n_rst,
            "n_frags": n_frags,
            "pkts_per_sec": total_pkts / max(duracion, 1e-6)
        })

    return pd.DataFrame(filas)

def main():
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
        ruta = os.path.join(DIR_EXP, f"{nombre}.pcap")
        df_esc = extraer_flujos_pcap(ruta, nombre, label)
        print(f"[*] {nombre:<14}: {len(df_esc):>3} flujos TCP extraídos")
        dfs.append(df_esc)

    df = pd.concat(dfs, ignore_index=True)
    df.to_csv(os.path.join(DIR_EXP, "dataset_flujos.csv"), index=False)

    feature_cols = [c for c in df.columns if c not in ("escenario", "label")]
    X = df[feature_cols].values
    y = df["label"].values

    # 1. Validación cruzada estratificada global (5-Fold CV)
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    probs_cv = np.zeros(len(df))
    for train_idx, test_idx in skf.split(X, y):
        clf = RandomForestClassifier(n_estimators=200, random_state=42)
        clf.fit(X[train_idx], y[train_idx])
        probs_cv[test_idx] = clf.predict_proba(X[test_idx])[:, 1]

    df["prob_cv"] = probs_cv
    umbral_cv = df[df["escenario"] == "benigno"]["prob_cv"].max() + 1e-6
    df["pred_cv"] = (df["prob_cv"] >= umbral_cv).astype(int)

    # 2. Generalización Zero-Day (Entrenado SOLO en benigno + estandar + sqli_base)
    train_escenarios = ["benigno", "estandar", "sqli_base"]
    mask_train = df["escenario"].isin(train_escenarios)
    df_train = df[mask_train].copy()

    # Calibrar umbral de clf_base usando probabilidades out-of-fold sobre el propio set base
    skf_base = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    probs_base_oof = cross_val_predict(
        RandomForestClassifier(n_estimators=200, random_state=42),
        df_train[feature_cols].values,
        df_train["label"].values,
        cv=skf_base,
        method="predict_proba"
    )[:, 1]
    df_train["prob_base_oof"] = probs_base_oof
    umbral_zd = df_train[df_train["escenario"] == "benigno"]["prob_base_oof"].max() + 1e-6

    # Entrenar clf_base definitivo sobre el set base y evaluar sobre los escenarios no vistos
    clf_base = RandomForestClassifier(n_estimators=200, random_state=42)
    clf_base.fit(df_train[feature_cols].values, df_train["label"].values)

    df["prob_zd"] = clf_base.predict_proba(X)[:, 1]
    df["pred_zd"] = (df["prob_zd"] >= umbral_zd).astype(int)

    print(f"\n[+] ROC-AUC Global (5-Fold CV): {roc_auc_score(y, probs_cv):.4f}")
    print(f"[+] Umbral CV calibrado (FPR = 0.0%): {umbral_cv:.4f}")
    print(f"[+] Umbral Zero-Day calibrado (OOF benigno base, FPR = 0.0%): {umbral_zd:.4f}\n")

    print("=== TABLA COMPARATIVA: SURICATA vs. RANDOM FOREST (FPR = 0.0%) ===")
    print(f"{'Escenario':<15} | {'Flujos':>6} | {'Suricata':<12} | {'RF (5-Fold CV)':<16} | {'RF (Zero-Day No Visto)':<22}")
    print("-" * 82)
    for nombre, label, suri_str in escenarios:
        sub = df[df["escenario"] == nombre]
        cv_str = f"{sub['pred_cv'].sum()}/{len(sub)} ({sub['pred_cv'].mean()*100:5.1f}%)"
        if nombre in train_escenarios:
            zd_str = "N/A (En Train)"
        else:
            zd_str = f"{sub['pred_zd'].sum()}/{len(sub)} ({sub['pred_zd'].mean()*100:5.1f}%)"
        print(f"{nombre:<15} | {len(sub):>6} | {suri_str:<12} | {cv_str:<16} | {zd_str:<22}")

    clf_full = RandomForestClassifier(n_estimators=200, random_state=42).fit(X, y)
    importancias = pd.Series(clf_full.feature_importances_, index=feature_cols).sort_values(ascending=False)
    print("\n=== TOP 8 FEATURES MÁS DETERMINANTES ===")
    for feat, val in importancias.head(8).items():
        print(f"  * {feat:<15}: {val:.4f}")

if __name__ == "__main__":
    main()
