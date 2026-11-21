# TP Final SOR2 — Tema A9: Evasión de Suricata y Mejora de Reglas con ML

**Alumno:** Emanuel Suárez (Legajo 41573744) — UNGS, Licenciatura en Sistemas
**Materia:** Sistemas Operativos y Redes II — 2º Semestre 2026
**Docente:** Benjamín Chuquimango

## Pregunta de investigación

¿En qué medida las variaciones controladas del tráfico malicioso afectan la capacidad de
detección de las reglas Emerging Threats en Suricata, y qué diferencias presenta un modelo
de Machine Learning al evaluar los mismos eventos bajo condiciones equivalentes de falsas
alarmas?

## Estructura del repositorio

.
├── configs/     # Configuración de Suricata y reglas custom
├── data/        # Datasets, capturas .pcap y manifiesto de escenarios (ver data/README.md)
├── scripts/     # Generación de tráfico, orquestación, extracción de features y evaluación ML
├── results/     # Métricas, tablas y gráficos generados
└── informe/     # Informe académico final (.docx)

## Entorno

- 2 VMs en VirtualBox, red Host-Only aislada 192.168.56.0/24:
  - Víctima (192.168.56.20): Ubuntu/Debian, Apache2, Suricata 7.0.3 + ET Open.
  - Atacante (192.168.56.10): Python 3.12 (venv), Scapy 2.8.0, Nmap, tcpdump/tshark,
    scikit-learn 1.9.1, pandas, numpy, matplotlib, CICFlowMeter (fork hieulw/cicflowmeter).

## Cómo reproducir

1. Laboratorio: instalar Suricata + ET Open en la Víctima (configs/suricata.yaml,
   HOME_NET restringido a 192.168.56.20/32).
2. Generación de tráfico (desde la Atacante):
   ~/tp_sor2/run_experimento.sh <modo>   # modos: benigno, estandar, sqli_base,
                                          # evasion_c3, evasion_c4, control_ua, evasion_c7_v2
   Orquesta tcpdump en la Víctima vía SSH + generador_trafico.py en la Atacante,
   recupera .pcap, eve.json y fast.log de cada corrida.
3. Extracción de features:
   - Extractor propio (Scapy, 19 features): scripts/evaluar_ml.py
   - CICFlowMeter (76 features): cicflowmeter -f <esc>.pcap -c cic_flows/<esc>_cic.csv
4. Evaluación ML y validación:
   python3 scripts/evaluar_ml.py              # RF sobre features propias (Scapy)
   python3 scripts/evaluar_cic.py             # RF sobre features CICFlowMeter
   python3 scripts/validacion_fase1.py        # métricas completas + estabilidad multi-semilla
   python3 scripts/generar_graficos_3_enfoques.py

## Resultados principales

Ver results/metricas_consolidadas.json y results/estabilidad_multisimilla_e2.csv para el
detalle completo. Resumen: Suricata 100% en tráfico base y evasiones de capa 3/4 (reensambla
fragmentación y segmentación), 0% ante spoofing de User-Agent y padding de capa 7. Random
Forest detecta ambas evasiones de capa 7 con 90-100% de recall en Zero-Day; la generalización
en evasion_c4 es inestable en ambos extractores (validado con 10 semillas, IC95% solapados
entre Scapy y CICFlowMeter).

## Herramientas

Suricata 7.0.3, Scapy, Nmap (modos evasivos), CICFlowMeter, Python, scikit-learn, pandas,
matplotlib, scipy.
