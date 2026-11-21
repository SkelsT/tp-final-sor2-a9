# Configuración de Suricata

En este trabajo (Tema A9) se utiliza **Suricata 7.0.3** con el conjunto de reglas estándar **Emerging Threats Open** (sin reglas custom propias).

- `suricata.yaml`: archivo de configuración principal del motor Suricata en la VM Víctima (`192.168.56.20`), con `HOME_NET` restringido a `192.168.56.20/32` y salidas `eve.json` y `fast.log` habilitadas para el análisis de los escenarios.
