# TP Final SOR2 — Tema A9: Evasión de Suricata y Mejora de Reglas con ML

**Alumno:** Emanuel Suárez (Legajo 41573744) — UNGS, Licenciatura en Sistemas  
**Materia:** Sistemas Operativos y Redes II — 2º Semestre 2026  
**Docente:** Benjamín Chuquimango

## Pregunta de investigación

¿En qué medida las variaciones controladas del tráfico malicioso afectan la capacidad de
detección de las reglas Emerging Threats en Suricata, y qué diferencias presenta un modelo
de Machine Learning al evaluar los mismos eventos bajo condiciones equivalentes de falsas
alarmas?

El objetivo no es demostrar que ML supera a Suricata, sino caracterizar experimentalmente
sus diferencias, limitaciones y condiciones de funcionamiento.

## Estructura del repositorio

```
tp-final-sor2-a9/
├── README.md
├── configs/     # Configuración de Suricata 
├── data/        # Datasets, capturas .pcap y manifiesto de escenarios (ver data/README.md)
│   ├── cic_flows/  # Datasets extraídos con CICFlowMeter (76 features)
│   └── README.md   # Diccionario de datos
├── scripts/     # Generación de tráfico, orquestación, extracción de features y evaluación ML
├── results/     # Métricas, tablas y gráficos generados
└── informe/     # Informe académico final (.docx) *a subir*
```
## Entorno

- 2 VMs en red Host-Only 192.168.56.0/24:
  - **Víctima** (192.168.56.20): servidor HTTP + Suricata 7.0.3 RELEASE (suricata-update 1.3.0) con reglas Emerging Threats Open (sin reglas custom propias; snapshot de reglas documentado en configs/).
  - **Atacante** (192.168.56.10): generación de tráfico benigno y de los 7 escenarios de ataque/variación sobre Python 3.12.3.
- Captura con tcpdump, análisis con Wireshark.
- Entornos y extracción de features:
  - venv (Scapy 2.8.0, scikit-learn 1.9.1, pandas 3.1.1, numpy 2.5.4, matplotlib 3.11.2): extractor propio de 19 features TCP/HTTP, cruce de alertas de Suricata, evaluación ML, tabla por evento y gráficos.
  - venv_cic (CICFlowMeter fork hieulw/cicflowmeter, 76 features): extractor alternativo/opcional de flujos desde capturas .pcap según la consigna.
- Clasificador: RandomForestClassifier (scikit-learn), calibrado a FPR≈0% sobre predicciones out-of-fold (OOF).

## Escenarios

| Escenario | Descripción |
|---|---|
| benigno | Tráfico HTTP normal (entrenamiento) |
| estandar | Ataque sin evasión (baseline) |
| sqli_base | Inyección SQL (SID 2006446) |
| evasion_c3 | Fragmentación IP (8 bytes) |
| evasion_c4 | Segmentación TCP (2 bytes) |
| control_ua | Spoofing de header User-Agent |
| evasion_c7_v2 | Padding de payload (>100 bytes) |
| benigno_eval | **Captura benigna independiente** (150 flujos), generada después de cerrado el entrenamiento, usada únicamente para medir la Tasa de Falsos Positivos (FPR) real fuera de la muestra de entrenamiento. Nunca se usa para entrenar ni para calibrar umbral. |

## Protocolo de evaluación

- **E1 — Tráfico conocido:** StratifiedKFold (5 folds) sobre benigno + estandar + sqli_base + evasion_c3 + evasion_c4 + control_ua + evasion_c7_v2.
- **E2 — Generalización ante variantes no vistas:** entrenamiento solo con benigno + estandar + sqli_base, evaluación en evasion_c3 / evasion_c4 / control_ua / evasion_c7_v2 (variantes excluidas por completo del entrenamiento).
- Umbral de decisión calibrado sobre probabilidades OOF del propio conjunto de entrenamiento (FPR≈0% en esa partición), nunca sobre el conjunto de prueba ni sobre benigno_eval.
- Métricas de Suricata obtenidas **programáticamente** por correlación de alertas (eve.json) contra cada flujo (4-tupla + ventana temporal), no por conteo manual de líneas de log (ver scripts/construir_tabla_eventos.py).
- Estabilidad: análisis multi-semilla (10 semillas) con intervalos de confianza 95% (t-Student) para los escenarios más sensibles.

## Cómo reproducir

1. **Laboratorio:** instalar Suricata 7.0.3 + ET Open en la Víctima (`configs/suricata.yaml`, con `HOME_NET` restringido a `192.168.56.20/32`).

2. **Generación de tráfico** (desde la Atacante):

   ```bash
   ~/tp_sor2/run_experimento.sh <modo>
   ```

   Modos disponibles: `benigno`, `estandar`, `sqli_base`, `evasion_c3`, `evasion_c4`, `control_ua`, `evasion_c7_v2`.
   El script orquesta `tcpdump` en la Víctima vía SSH junto con `generador_trafico.py` en la Atacante, y recupera `.pcap`, `eve.json` y `fast.log` de cada corrida.

   Para la captura benigna independiente de evaluación (150 flujos con User-Agents y rutas variadas, fuera de entrenamiento y calibración):

   ```bash
   python3 scripts/generador_benigno_eval.py
   ```

3. **Extracción de features:**
   * **Extractor propio (Scapy, 19 features, en entorno `venv`):** `scripts/evaluar_ml.py` y `scripts/construir_tabla_eventos.py`
   * **CICFlowMeter (76 features, en entorno `venv_cic`):**

     ```bash
     cicflowmeter -f <esc>.pcap -c cic_flows/<esc>_cic.csv
     ```

   * **Depuración de `evasion_c4`:** se filtran las 13 conexiones cortas e incompletas de 2 paquetes (`total_pkts <= 5` en Scapy y `tot_fwd_pkts + tot_bwd_pkts <= 5` en CICFlowMeter), dejando 40 flujos completos y registrando los descartados en `data/c4_flujos_descartados.csv`.

4. **Evaluación ML, tabla por evento y validación** (en entorno `venv`):

   ```bash
   python3 scripts/evaluar_ml.py                  # RF sobre features propias (Scapy)
   python3 scripts/evaluar_cic.py                 # RF sobre features CICFlowMeter
   python3 scripts/construir_tabla_eventos.py     # tabla por evento + métricas desde alertas reales + FPR en benigno_eval
   python3 scripts/validacion_fase1.py            # métricas completas + estabilidad multi-semilla
   python3 scripts/generar_graficos_depurados.py  # gráficos comparativos e importancia de features
   ```

## Resultados principales

- **Tráfico conocido (E1):** Suricata, RF-Scapy y RF-CIC detectan con Recall global de 96.67% (RF-Scapy) y 97.50% (RF-CIC) bajo validación cruzada estratificada (5 folds, N=540), y 100.0% en los escenarios con firma ET correspondiente para Suricata.
- **Generalización ante variantes no vistas (E2):** Suricata es evadido por completo (Recall 0.0%) en `control_ua` y `evasion_c7_v2`; ambos modelos de ML los detectan (Recall ≈90.0–100.0%). En `evasion_c4` (depurado, 40 flujos), al evaluar 10 semillas con 76 features en CICFlowMeter, RF-Scapy alcanza una media de 87.25% (std 18.39%, IC 95% [74.10%, 100.40%]) frente a 60.00% de RF-CIC (std 51.64%, IC 95% [23.06%, 96.94%]): la diferencia entre extractores resulta **estadísticamente no concluyente** por la superposición de intervalos de confianza, aunque RF-CIC exhibe una dispersión notablemente mayor entre semillas (oscilando entre 0.0% y 100.0%).
- **Evaluación benigna independiente (FPR):** la FPR medida sobre el propio conjunto de entrenamiento resulta ≈0.0% para ambos modelos sobre esa partición. Al medir la FPR sobre `benigno_eval` —una captura benigna genuinamente independiente de 150 flujos—, la FPR real resultó **70.67% (RF-Scapy) y 78.67% (RF-CIC)**, frente al **0.0%** de Suricata en tráfico HTTP al puerto 80. El análisis de la distribución de `total_bytes` muestra que el tráfico benigno de entrenamiento era homogéneo (~12.3–12.5 KB), lo que produjo límites de decisión estrechos que no generalizan a tráfico benigno más diverso. Esto se documenta como la limitación metodológica central del trabajo.
- **Depuración de `evasion_c4`:** 13 de los 53 flujos originalmente etiquetados como maliciosos correspondían a conexiones incompletas (2 paquetes, sin SYN, terminadas por RST) que no generan tráfico de aplicación real; se excluyeron y quedan documentados en `data/c4_flujos_descartados.csv`, dejando 40 flujos —coincidente con las 40 alertas reales que emite Suricata para ese escenario.

Ver `results/metricas_desde_alertas.json`, `results/tabla_eventos.csv` y `results/metricas_consolidadas.json` para el detalle completo por evento y por semilla.

## Herramientas

Linux, Python 3.12.3, Suricata 7.0.3 + suricata-update 1.3.0 + Emerging Threats Open (12/11/2026), Scapy 2.8.0, scikit-learn 1.9.1 (RandomForestClassifier, StratifiedKFold, cross_val_predict), pandas 3.1.1, numpy 2.5.4, matplotlib 3.11.2, scipy, tcpdump/Wireshark, CICFlowMeter (fork hieulw/cicflowmeter), entornos virtuales venv y venv_cic, Git/GitHub.

