import time
import random
import urllib.request
import urllib.error

TARGET_IP = "192.168.56.20"

def _http_get(url, user_agent):
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    try:
        with urllib.request.urlopen(req, timeout=2) as resp:
            resp.read()
    except urllib.error.HTTPError as e:
        e.read()
    except Exception:
        pass

def generar_benigno_eval(n=150):
    print(f"[*] Generando {n} flujos HTTP benignos INDEPENDIENTES para evaluación...")
    user_agents = [
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:130.0) Gecko/20100101 Firefox/130.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
    ]
    rutas = [
        "/",
        "/index.html",
        "/about",
        "/contact",
        "/?page=1",
        "/?page=2"
    ]
    for _ in range(n):
        url = f"http://{TARGET_IP}{random.choice(rutas)}"
        _http_get(url, random.choice(user_agents))
        time.sleep(random.uniform(0.05, 0.2))
    print("[+] Captura benigna independiente finalizada.")

if __name__ == "__main__":
    generar_benigno_eval(150)
