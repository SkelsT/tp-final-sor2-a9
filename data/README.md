# Diccionario de datos

## Escenarios de captura

| Escenario | n (Scapy) | n (CIC) | Etiqueta verdadera | Condición |
| :--- | :--- | :--- | :--- | :--- |
| `benigno` | 300 | 300 | 0 (benigno) | Original — tráfico de entrenamiento |
| `estandar` | 40 | 40 | 1 (malicioso) | Original — ataque sin evasión |
| `sqli_base` | 40 | 40 | 1 | Original — SQLi, sin evasión |
| `evasion_c3` | 40 | 40 | 1 | Variante — fragmentación IP |
| `evasion_c4` (depurado) | 40 | 40 | 1 | Variante — segmentación TCP (ver nota de depuración) |
| `control_ua` | 40 | 40 | 1 | Variante — spoofing de User-Agent |
| `evasion_c7_v2` | 40 | 40 | 1 | Variante — padding de payload |
| `benigno_eval` | 150 | 150 | 0 | **Independiente** — nunca usado en entrenamiento ni calibración |

Las etiquetas (`label_real`) provienen directamente del script generador de tráfico que originó cada flujo (criterio independiente del sistema de detección), **nunca** de las alertas de Suricata, evitando así sesgar el etiquetado hacia los eventos que el IDS ya detecta por firma.

## Archivos

### Capturas y logs

* `*.pcap` — una captura por escenario (7 escenarios originales, `benigno_eval.pcap` y `benigno_train_backup.pcap`, respaldo del archivo `benigno.pcap` de entrenamiento original previo a cualquier procesamiento).
* `eve_*.json`, `fast_*.log` — salida de Suricata (EVE JSON y `fast.log`) por escenario, incluyendo `eve_benigno_eval.json` y `fast_benigno_eval.log` para la captura independiente. `fast_control_ua.log` y `fast_evasion_c7_v2.log` tienen tamaño 0 bytes **por diseño**, dado que ambas variantes evaden por completo las firmas evaluadas (0 alertas). En `eve_benigno_eval.json` y `fast_benigno_eval.log`, Suricata registra 0 alertas sobre el tráfico HTTP evaluado (puerto 80); la única alerta registrada corresponde a un escaneo externo (`ET SCAN Potential SSH Scan` hacia el puerto 22), fuera del tráfico bajo estudio.

### Datasets de features (Scapy, 19 features)

* `dataset_flujos.csv` — dataset original (incluye los 53 flujos de `evasion_c4` previos a la depuración). Se conserva para trazabilidad.
* `dataset_flujos_depurado.csv` — **versión final**, con `evasion_c4` depurado (`40` flujos en lugar de `53`).
* `flujos_benigno_eval.csv` — features extraídas de `benigno_eval` (conjunto independiente para evaluación de FPR).
* `c4_flujos_descartados.csv` — registro auditable de los `13` flujos de `evasion_c4` excluidos del dataset depurado. Corresponden a conexiones incompletas de 2 paquetes (`fwd_pkts = 1`, `bwd_pkts = 1`), sin flag `SYN` y terminadas mediante `RST`, propias de intentos abortados sin intercambio HTTP efectivo.

### Datasets de features (CICFlowMeter, 76 features) — `cic_flows/`

* `dataset_cic_unificado.csv` — dataset original sin depurar.
* `dataset_cic_unificado_depurado.csv` — versión final, alineada con el criterio de depuración aplicado en Scapy (`tot_fwd_pkts + tot_bwd_pkts > 5`, excluyendo los `13` flujos incompletos de `evasion_c4`).
* `benigno_eval_cic.csv` — features CICFlowMeter del conjunto `benigno_eval`.

## Columnas de metadatos (excluidas del entrenamiento)

`evento_id, escenario, src_ip, src_port, dst_ip, dst_port, ts_inicio, ts_fin, label_real` — se utilizan exclusivamente para trazabilidad y correlación programática con las alertas de Suricata (`det_suricata` en `results/tabla_eventos.csv`), nunca como variables predictoras del clasificador.

## Limitación metodológica: agrupamiento por sesión en E1

En el experimento **E1** (evaluación sobre tráfico conocido), cada escenario corresponde a una única sesión de captura continua (`benigno` constituye una sola campaña de `300` flujos). En consecuencia, aplicar una partición estricta agrupada por sesión (`GroupKFold` por escenario) colapsaría la totalidad de la clase negativa en un único fold, imposibilitando la validación cruzada estratificada de 5 folds. Para mitigar y acotar esta limitación:

1. Se documenta explícitamente esta restricción experimental en la sección de Metodología y Limitaciones del informe.
2. El experimento **E2** (*Generalización ante variantes no vistas*) garantiza aislamiento completo a nivel de escenario/sesión por diseño, excluyendo íntegramente del entrenamiento las variantes evaluadas.
3. Se incorpora un análisis multi-semilla (`10` semillas con intervalos de confianza del $95\%$ mediante distribución $t$-Student en `scripts/validacion_fase1.py`) para cuantificar la estabilidad de los modelos frente a variaciones de particionamiento.

## Evaluación de FPR en captura benigna independiente

La estimación de FPR obtenida sobre el propio conjunto de entrenamiento (calibrando y evaluando el umbral sobre la misma muestra) introduce circularidad metodológica y arroja valores cercanos a $0\%$. Al evaluar los mismos modelos con el umbral ya fijado sobre `benigno_eval` (`150` flujos benignos independientes), la FPR real asciende a **$70.67\%$ en RF-Scapy** y **$79.33\%$ en RF-CIC**, frente al **$0.0\%$ en Suricata** sobre tráfico HTTP (puerto 80).

El análisis exploratorio de `total_bytes` evidencia que el tráfico benigno de entrenamiento presenta una distribución altamente homogénea (rango intercuartílico entre $\approx 12.3\text{ KB}$ y $\approx 12.4\text{ KB}$), mientras que `benigno_eval` exhibe una distribución bimodal más representativa ($\approx 1.3\text{--}1.4\text{ KB}$ y $\approx 12.3\text{--}12.6\text{ KB}$). Como resultado, ambos clasificadores ajustaron fronteras de decisión excesivamente estrechas alrededor de la respuesta benigna observada durante el entrenamiento. El detalle numérico por evento se encuentra en `scripts/construir_tabla_eventos.py` y `results/metricas_desde_alertas.json`.
