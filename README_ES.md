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
  <img src="https://img.shields.io/badge/version-2.7.0-%2300c8ff?style=flat-square" alt="Versión">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Kali-compatible-purple?style=flat-square" alt="Kali">
  <img src="https://img.shields.io/badge/subcomandos-23-00c8ff?style=flat-square" alt="23 subcomandos CLI">
  <img src="https://img.shields.io/badge/tests-572%20passing-success?style=flat-square" alt="572 tests">
</p>

<p align="center">
  <b>Escanea · Captura · Crackea — una ventana, un solo flujo.</b>
</p>

---

## 🛰️ Escaneo — mira toda la sala antes de tocar nada

Reconocimiento pasivo que se mantiene al día en un RF saturado.

| | Función | Qué hace |
|---|---|---|
| 📡 | **Descubrimiento de APs en vivo** | El escaneo pasivo con salto de canal arma la lista de objetivos con beacons y probe-responses reales — BSSID, SSID, canal, seguridad y señal. |
| 👻 | **SSIDs ocultos** | Se desenmascaran en cuanto un probe revela el nombre. |
| 🧑‍🤝🧑 | **Descubrimiento de clientes** | Cada estación vista hablando con un objetivo, mapeada a su AP para que sepas a quién apuntar. |
| 📶 | **Historial de señal** | Una gráfica en vivo por objetivo mientras lo tienes fijado. |
| 🔐 | **Perfil de seguridad** | WPA2 / WPA3 / OWE / WPS / PMF leídos del beacon, para saber qué va a funcionar antes de disparar. |
| 🦀 | **Escucha PINCER** | Una segunda radio se queda quieta en el objetivo mientras la primera ataca — sin pelearse por el canal, sin frames perdidos. |

```bash
atwa scan wlan0
```

---

## 💥 Ataque — la herramienta correcta para cada objetivo

| | Ataque | Qué hace |
|---|---|---|
| 🎯 | **PMKID** | **Sin clientes.** Ni cliente ni deauth — un solo frame de auth y el AP te entrega el PMKID. Inmune a PMF. |
| 🤝 | **Captura de handshake** | Captura el 4-way y te dice si de verdad es crackeable antes de que quemes una wordlist. |
| 💥 | **Deauth** | Ciclado de reason-codes, control de ráfagas y chequeo de potencia TX, para que una radio callada no parezca un ataque descompuesto. |
| 🌀 | **CHAOS** | Toda la suite de floods contra un objetivo — beacon, EAPOL, auth, deauth, cambio de canal y TKIP-MIC — escalando por niveles y reportando solo lo que sí tuvo efecto. |
| 🕳️ | **WEP** | Fake-auth + ARP replay + recuperación nativa de la clave con PTW. |
| ☕ | **Caffe Latte / Hirte** | WEP directo desde un cliente — sin asociarse al AP. |
| 📶 | **WPS** | Pixie-Dust, Bruteforce, Null-PIN y reconocimiento que sustituye a `wash`. Prueba primero el null-PIN gratis y se frena si el AP está bloqueado. |
| 🕵️ | **Downgrade Twin** | Un gemelo WPA2 contra un AP en transición a WPA3. Sin portal de credenciales. |
| 🛰️ | **OWE Downgrade** | Un gemelo abierto para redes en transición a OWE. |
| 💥 | **PMF Bypass** | EAPOL malformado que fuerza una reconexión en un gemelo con PMF obligatorio — el deauth que PMF no puede detener. |
| 🐉 | **Dragonblood** | Poda de wordlist por canal lateral de tiempos SAE (CVE-2019-9494). Solo APs sin parchear anteriores a la 2.10. |
| 🔑 | **Online Guess** | Intentos reales de 4-way, contraseña por contraseña, directo contra el AP. |

> Cada ataque está en la CLI **y** en la GUI.

---

## 🧠 Las cadenas — para cuando no quieres elegir

- **OMNI** — perfila el objetivo y recorre **PMKID → WPS → handshake → online guess → crack**, cortando en cuanto algo cae.
- **SMART** — la vía rápida: PMKID primero, deauth+handshake como respaldo, y se detiene al primer éxito.
- **PINCER** 🦀 — dos radios a la vez. Una **escucha** (quieta en el objetivo, corriendo por un PMKID sin cliente), la otra **golpea** (deauth escalado: 8 → 16 → 32 → 64, contra los dos clientes de mejor señal, respetando el límite de TX del canal).

```bash
atwa omni wlan0 <bssid> --wordlist rockyou.txt
atwa smart wlan0 <bssid>
atwa gui     # conecta dos adaptadores, elige un objetivo y pulsa PINCER
```

> PINCER necesita dos adaptadores Alfa detectados — el par **AWUS036ACHM** + **AWUS1900/RTL8814AU** se autodetecta por chipset.

---

## 🔓 Crackeo — capturas y crackeas en la misma ventana

Sin batallas de formato. Apúntale a una captura y déjalo trabajar.

| | Función | Qué hace |
|---|---|---|
| ⚙️ | **Dos motores** | **John the Ripper (jumbo)** como principal, **aircrack-ng** como alterno. |
| 📁 | **Crackear una carpeta entera** | Apúntale a un directorio — unifica, convierte y crackea todo solo. |
| 🔄 | **Conversión automática** | `.cap`/`.pcap` → `22000` → John, sin que tú hagas nada. |
| 🩹 | **Repara capturas** | Arregla un pcap malformado en vez de tirarlo a la basura. |
| ✅ | **Verifica antes** | Te dice si un handshake sirve *antes* de gastar una wordlist. |
| 💾 | **Resultados a salvo** | La contraseña en pantalla y en `creds.json`, junto a la captura. |

```bash
atwa crack-cap capture.cap rockyou.txt
atwa crack hashes.22000 rockyou.txt
```

---

## Instalación

Linux (Kali recomendado), Python 3.10+ y un adaptador WiFi con modo monitor e inyección de paquetes. Con eso:

```bash
git clone https://github.com/KiMiGuel/ATWA-NG.git
cd ATWA-NG
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Eso te da el comando `atwa`. Dos cosas más vale instalar junto a él — ambas opcionales, pero las vas a querer:

**John the Ripper jumbo** (para `atwa crack`) — el formato `wpapsk` no viene en la build de comunidad.

```bash
sudo apt install john
john --list=formats | grep -i wpapsk    # verifica

# ¿no aparece? Compila jumbo en ~/john y ATWA-NG lo encuentra solo:
git clone https://github.com/openwall/john -b bleeding-jumbo ~/john
cd ~/john/src && ./configure && make -s clean && make -sj$(nproc)
```

**hcxtools** (para la conversión de capturas): `sudo apt install hcxtools`

La GUI puede auditar tu sistema por ti: **Help → Check Dependencies**.

---

## Úsalo

La GUI es la forma más fácil de entrar — se encarga del modo monitor y de los permisos por ti:

```bash
atwa gui
```

**Adapter → Start Monitor** pone el adaptador en modo monitor. **Start Scanning** llena la lista de APs. **Clic en un objetivo** fija su canal y arranca la gráfica de señal. El panel de **Attacks** de abajo lo tiene todo: deauth, PMKID, handshake, SMART/OMNI/CHAOS, WEP, WPS, floods y APs falsos. Un segundo adaptador desbloquea PINCER y los flujos de AP falso. La pestaña **Captures** es donde inspeccionas, conviertes, reparas, unificas y crackeas lo que atrapaste.

Desde la terminal también funciona. Dos cosas hay que saber: los comandos CLI van con root, y la interfaz tiene que estar en modo monitor primero (si no lo está, el propio error te da el comando exacto de `iw`):

```bash
sudo iw dev wlan0 set monitor        # una vez por sesión
sudo atwa scan wlan0                 # mira qué hay alrededor
sudo atwa smart wlan0 <bssid>        # ataque rápido: PMKID, luego deauth+handshake
sudo atwa omni wlan0 <bssid> --wordlist rockyou.txt   # la cadena completa
```

Todo lo que captures cae en `~/atwa-hs/<SSID>_<BSSID>/`, y las contraseñas crackeadas se guardan junto a la captura en `creds.json` — además de en pantalla.

<p align="center">
  <img src="docs/brand/gui-screenshot.png" alt="GUI de ATWA-NG — selección de adaptador, lista de escaneo, panel de objetivo, ataques y log" width="820">
</p>

Referencia completa de la CLI: [README.md](./README.md).

---

¿Necesitas una wordlist? [Indepenlist-MX-wordlist](https://github.com/KiMiGuel/Indepenlist-MX-wordlist) — enfocada a México.

ATWA-NG busca actualizaciones en GitHub Releases — la GUI lo hace al arrancar sin bloquear la interfaz, o ejecuta `atwa update`.

---

Solo para pruebas de seguridad autorizadas — contra redes y dispositivos que te pertenecen o para los que tengas autorización explícita.

<p align="center">
  <sub>Por <b>KiMiGuEL</b> — <a href="https://github.com/KiMiGuel">INDEPENTEST</a></sub>
</p>
