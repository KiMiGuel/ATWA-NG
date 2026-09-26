**For English, click [here](./README.md)**

<p align="center">
  <img src="docs/brand/atwa-ng-wordmark.png" alt="ATWA-NG" width="480">
</p>

<p align="center">
  <img src="docs/brand/icon-wifi.png" width="70" alt="">
  &nbsp;&nbsp;&nbsp;
  <img src="docs/brand/icon-earth.png" width="70" alt="">
  &nbsp;&nbsp;&nbsp;
  <img src="docs/brand/icon-air.png" width="70" alt="">
</p>

<h3 align="center">Una herramienta WiFi. Dos radios. Cero piedad para una contraseña débil.</h3>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.5.6-%2300c8ff?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Kali-compatible-purple?style=flat-square" alt="Kali">
  <img src="https://img.shields.io/badge/subcommands-24-00c8ff?style=flat-square" alt="24 subcomandos">
  <img src="https://img.shields.io/badge/tests-430%20passing-success?style=flat-square" alt="430 tests">
</p>

<p align="center">
  <b>Escanea · Captura · Crackea — una ventana, un flujo de trabajo.</b>
</p>

---

## 🛰️ Escaneo — mira toda la sala antes de tocar nada

Reconocimiento pasivo que aguanta un entorno RF saturado.

| | Función | Qué hace |
|---|---|---|
| 📡 | **Descubrimiento de APs en vivo** | El escaneo pasivo con salto de canal arma la lista de objetivos con beacons y respuestas a probe reales — BSSID, SSID, canal, seguridad, señal. |
| 👻 | **SSIDs ocultos** | Se desenmascaran en el instante en que un probe revela el nombre. |
| 🧑‍🤝‍🧑 | **Descubrimiento de clientes** | Cada estación que habla con un objetivo, mapeada a su AP para que sepas a quién apuntar. |
| 📶 | **Historial de señal** | Una gráfica en vivo por objetivo mientras lo mantienes fijado. |
| 🔐 | **Perfilado de seguridad** | WPA2 / WPA3 / OWE / WPS / PMF leídos del beacon, para saber qué funcionará antes de disparar. |
| 🦀 | **Escucha PINCER** | Una segunda radio se queda fija en el objetivo mientras la primera ataca — sin compartir canal, sin perder frames. |

```bash
atwa scan wlan0
```

---

## 💥 Ataque — elige la herramienta que le queda al objetivo

| | Ataque | Qué hace |
|---|---|---|
| 🎯 | **PMKID** | **Sin cliente.** Sin cliente ni deauth — un frame de auth y el AP te entrega el PMKID. Inmune a PMF. |
| 🤝 | **Captura de handshake** | Captura el 4-way y te dice si de verdad es crackeable antes de gastar una wordlist. |
| 💥 | **Deauth** | Ciclado de reason-codes, control de ráfagas y chequeo de potencia TX para que una radio muda no parezca un ataque roto. |
| 🌀 | **CHAOS** | Toda la suite de floods contra un objetivo — beacon, EAPOL, auth, deauth, redirección de canal y TKIP-MIC — escalando por niveles, reportando solo lo que tuvo efecto real. |
| 🕳️ | **WEP** | Fake-auth + ARP replay + recuperación de clave PTW nativa. |
| ☕ | **Caffe Latte / Hirte** | WEP directo desde un cliente — sin asociarse al AP. |
| 📶 | **WPS** | Pixie-Dust, Bruteforce, Null-PIN y reconocimiento que reemplaza a `wash`. Prueba un null-PIN gratis primero y se detiene si el AP está bloqueado. |
| 🕵️ | **Downgrade Twin** | Gemelo WPA2 falso contra un AP en transición a WPA3. Sin portal de credenciales. |
| 🛰️ | **OWE Downgrade** | Gemelo abierto falso para redes en transición a OWE. |
| 💥 | **PMF Bypass** | EAPOL malformado que fuerza una reconexión en un gemelo con PMF requerido — el deauth que PMF no puede bloquear. |
| 🐉 | **Dragonblood** | Poda por canal lateral de tiempos de SAE (CVE-2019-9494). Solo APs pre-2.10 sin parchear. |
| 🔑 | **Online Guess** | Intentos reales de 4-way por contraseña directamente contra el AP. |

> Cada ataque es accesible desde la CLI **y** la GUI.

---

## 🧠 Las cadenas — cuando prefieres no elegir

- **OMNI** — perfila el objetivo y recorre **PMKID → WPS → handshake → online guess → crack**, cortando en el momento en que algo cae.
- **SMART** — la vía rápida: PMKID primero, respaldo deauth+handshake, se detiene al primer éxito.
- **PINCER** 🦀 — dos radios a la vez. Una **escucha** (fija en el objetivo, compitiendo por un PMKID sin cliente), la otra **golpea** (deauth escalando: 8 → 16 → 32 → 64, apuntando a los dos clientes de mejor señal, respetando el límite de TX del canal).

```bash
atwa omni wlan0 <bssid> --wordlist rockyou.txt
atwa smart wlan0 <bssid>
atwa gui     # conecta dos adaptadores, elige un objetivo, pulsa PINCER
```

> PINCER necesita dos adaptadores Alfa detectados — el par **AWUS036ACHM** + **AWUS1900/RTL8814AU** se autodetecta por chipset.

---

## 🔓 Crackeo — captura y crackea, en la misma ventana

Sin malabares de formato. Apúntalo a una captura y déjalo correr.

| | Función | Qué hace |
|---|---|---|
| ⚙️ | **Dos motores** | **John the Ripper (jumbo)** principal, **aircrack-ng** alternativo. |
| 📁 | **Crackear una carpeta entera** | Apúntalo a un directorio — mergea, convierte y crackea todo sin supervisión. |
| 🔄 | **Conversión automática** | `.cap`/`.pcap` → `22000` → John, todo interno. |
| 🩹 | **Reparar una captura** | Repara un pcap malformado en vez de tirarlo. |
| ✅ | **Verifica primero** | Te dice si un handshake es usable *antes* de gastar una wordlist. |
| 💾 | **Los resultados caen** | Contraseña crackeada en pantalla y en `creds.json` junto a la captura. |

```bash
atwa crack-cap capture.cap --wordlist rockyou.txt
atwa crack hashes.22000 --wordlist rockyou.txt
```

---

## Instalación

```bash
git clone https://github.com/KiMiGuel/ATWA-NG.git
cd ATWA-NG
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

**El crackeo necesita John the Ripper *jumbo*** — el formato `wpapsk` no está en la build de la comunidad.

```bash
sudo apt install john
john --list=formats | grep -i wpapsk    # verificar
```

¿No lo tienes? Compila jumbo en `~/john` y ATWA-NG lo encuentra automáticamente:

```bash
git clone https://github.com/openwall/john -b bleeding-jumbo ~/john
cd ~/john/src && ./configure && make -s clean && make -sj$(nproc)
```

---

## Úsalo

```bash
atwa gui                      # la experiencia completa (necesita root)
atwa scan wlan0               # o pilótalo desde la terminal
atwa smart wlan0 <bssid>
atwa omni wlan0 <bssid> --wordlist rockyou.txt
```

<p align="center">
  <img src="docs/brand/gui-screenshot.png" alt="GUI de ATWA-NG — selección de adaptador, lista de escaneo, panel de objetivo, ataques y log" width="820">
</p>

- **Adapter → Start Monitor** lo pone en modo monitor. Un segundo adaptador desbloquea PINCER y los flujos de AP falso.
- **Start Scanning** → lista de APs en vivo.
- **Clic en un objetivo** → fija el canal, arranca la gráfica de señal, descubre clientes.
- **Attacks** → deauth, PMKID, handshake, SMART/OMNI/CHAOS, WEP, WPS, floods, AP falso.
- **Captures** → Inspect, Convert, Fix, Merge, Crack — un solo panel.

**Requisitos:** Linux, Python 3.10+, un adaptador con modo monitor + inyección. PINCER necesita dos adaptadores Alfa detectados.

Referencia completa de la CLI y checklist de dependencias: [USAGE.md](./USAGE.md).

---

¿Necesitas una wordlist? [Indepenlist-MX-wordlist](https://github.com/KiMiGuel/Indepenlist-MX-wordlist) — enfocada a México.

ATWA-NG busca actualizaciones en GitHub Releases — la GUI lo hace al arrancar sin bloquear, o ejecuta `atwa update-check`.

---

Solo para pruebas de seguridad autorizadas — contra redes y dispositivos que poseas o tengas autorización explícita para probar.

<p align="center">
  <sub>Por <b>KiMiGuEL</b> — <a href="https://github.com/KiMiGuel">INDEPENTEST</a></sub>
</p>
