#!/bin/bash
# Uso: ./run_experimento.sh <modo>
# modos: benigno | estandar | evasion_c3 | evasion_c4 | evasion_c7

set -e
MODO="$1"
VICTIMA="vboxuser@192.168.56.20"
DIR_VICTIMA="/home/vboxuser/experimentos"
DIR_ATACANTE="$HOME/experimentos"

if [ -z "$MODO" ]; then
    echo "Uso: $0 [benigno|estandar|evasion_c3|evasion_c4|evasion_c7]"
    exit 1
fi

mkdir -p "$DIR_ATACANTE"
ssh "$VICTIMA" "mkdir -p $DIR_VICTIMA"

echo "[*] Limpiando logs de Suricata en la víctima..."
ssh "$VICTIMA" "sudo truncate -s 0 /var/log/suricata/eve.json /var/log/suricata/fast.log"

echo "[*] Arrancando tcpdump en la víctima (modo: $MODO)..."
ssh "$VICTIMA" "sudo nohup tcpdump -i enp0s8 -w $DIR_VICTIMA/${MODO}.pcap 'not port 22' > /dev/null 2>&1 &"
sleep 2   # darle tiempo a tcpdump a engancharse a la interfaz

echo "[*] Lanzando generador de tráfico ($MODO)..."
sudo ~/tp_sor2/venv/bin/python3 ~/tp_sor2/generador_trafico.py "$MODO"

sleep 2   # drenar los últimos paquetes antes de cortar

echo "[*] Deteniendo tcpdump en la víctima..."
ssh "$VICTIMA" "sudo pkill tcpdump" || true
sleep 1

echo "[*] Copiando logs y pcap..."
ssh "$VICTIMA" "sudo cp /var/log/suricata/eve.json $DIR_VICTIMA/eve_${MODO}.json
sudo cp /var/log/suricata/fast.log $DIR_VICTIMA/fast_${MODO}.log
sudo chmod 644 $DIR_VICTIMA/eve_${MODO}.json $DIR_VICTIMA/fast_${MODO}.log $DIR_VICTIMA/${MODO}.pcap"

scp "$VICTIMA:$DIR_VICTIMA/${MODO}.pcap" "$VICTIMA:$DIR_VICTIMA/eve_${MODO}.json" "$VICTIMA:$DIR_VICTIMA/fast_${MODO}.log" "$DIR_ATACANTE/"

N_ALERTAS=$(wc -l < "$DIR_ATACANTE/fast_${MODO}.log")
echo "[+] Experimento '$MODO' finalizado. Alertas Suricata: $N_ALERTAS"
echo "[+] Archivos en: $DIR_ATACANTE/{${MODO}.pcap, eve_${MODO}.json, fast_${MODO}.log}"
