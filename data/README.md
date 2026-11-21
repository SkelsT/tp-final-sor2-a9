# Diccionario de datos — datasets experimentales

## Escenarios (7, uno por sesión/campaña de captura)

| Escenario | Tipo de tráfico | Etiqueta verdadera | Condición |
|---|---|---|---|
| benigno | Navegación HTTP benigna | 0 (no malicioso) | Original |
| estandar | Nikto/sqlmap UA + /etc/passwd + UNION SELECT | 1 (malicioso) | Original (sin evasión) |
| sqli_base | SQLi sin ofuscar, UA benigna (SID 2006446) | 1 | Original (control de contenido) |
| evasion_c3 | Fragmentación IP 8 bytes (capa 3) | 1 | Variante — evasión |
| evasion_c4 | Segmentación TCP 2 bytes (capa 4) | 1 | Variante — evasión |
| control_ua | SQLi base + spoofing de User-Agent (capa 7) | 1 | Variante — evasión |
| evasion_c7_v2 | SQLi + padding /**/ >100B (capa 7) | 1 | Variante — evasión |

## Columnas de identificación (en cada CSV de flujos)

- Identificador del evento/flujo: índice de fila + (src_port, dst_port, timestamp)
  (excluidos como features del modelo, pero conservados en el CSV crudo para trazabilidad).
- Captura y escenario de procedencia: columna escenario — corresponde 1:1 con el
  .pcap/eve_<escenario>.json/fast_<escenario>.log del mismo nombre en esta carpeta.
- Tipo de tráfico y etiqueta verdadera: columna label (0 = benigno, 1 = malicioso).
  La etiqueta no proviene de las alertas de Suricata — se asigna en el momento de
  generación del tráfico (el script atacante controla qué escenario genera cada flujo),
  de forma independiente de si Suricata lo detectó o no. Esto es lo que permite medir falsos
  negativos de Suricata sin circularidad.
- Justificación independiente de la etiqueta: cada escenario corresponde a un único modo
  de generador_trafico.py ejecutado de forma aislada y verificada contra el .pcap crudo
  (ver scripts/generador_trafico.py); la etiqueta es anterior e independiente de cualquier
  alerta generada.
- Condición original o variante: ver tabla arriba (columna "Condición").
- Campaña o sesión de origen: cada escenario = una sesión de captura única (un .pcap
  por corrida de run_experimento.sh); no hay sesiones repetidas del mismo escenario en
  distintos momentos — limitación documentada: la partición 5-fold (E1) no puede agrupar
  por sesión sin colapsar en una sola campaña por clase (ver Metodología/Limitaciones del
  informe). El protocolo Zero-Day (E2) sí excluye sesiones completas del entrenamiento.

## Archivos por escenario

- <escenario>.pcap — captura cruda.
- eve_<escenario>.json — alertas de Suricata (formato EVE JSON).
- fast_<escenario>.log — alertas de Suricata (formato fast.log).
- cic_flows/<escenario>_cic.csv — features extraídas con CICFlowMeter (76 columnas).

## Datasets consolidados

- dataset_flujos.csv — 553 flujos, 19 features (extractor propio Scapy).
- cic_flows/dataset_cic_unificado.csv — 553 flujos, 76 features (CICFlowMeter), filtrado a
  tráfico HTTP puerto 80 (excluye ruido SSH de orquestación).

## Partición entrenamiento/validación/prueba

- E1 (tráfico conocido): StratifiedKFold de 5 particiones sobre todos los flujos,
  umbral calibrado con probabilidades out-of-fold sobre benigno (FPR objetivo = 0,0%).
- E2 (variantes no vistas): entrenamiento exclusivo sobre benigno+estandar+sqli_base;
  evaluación sobre evasion_c3, evasion_c4, control_ua, evasion_c7_v2 — excluidos por
  completo del entrenamiento y de la calibración del umbral.
