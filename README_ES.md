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

<p align="center">
  <b>Una herramienta WiFi. Dos radios. Cero piedad para una contraseña débil.</b>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-2.0.0-%2300c8ff?style=flat-square" alt="Version">
  <img src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square" alt="Python">
  <img src="https://img.shields.io/badge/Kali-compatible-purple?style=flat-square" alt="Kali">
  <img src="https://img.shields.io/badge/status-active--development-orange?style=flat-square" alt="Status">
</p>

---

## N2-NG acaba de ser REVAMPEADO. 🔥

Misma misión, motor completamente nuevo. **ATWA-NG** es la próxima generación — más rápido, más afilado, y hace algo que N2-NG nunca pudo: correr dos radios a la vez. El changelog completo está en el código; la versión corta es que **todo pega más duro ahora.**

La última versión estable de N2-NG se queda justo donde está — revisa [Releases](../../releases) para el historial completo y la rama `n2-ng` heredada.

---

## La última herramienta de pentesting WiFi que vas a necesitar

Cualquier otra herramienta te obliga a elegir: escanear *o* atacar. Escuchar *o* golpear. Un solo radio, haciendo un solo trabajo, mal, al mismo tiempo. Ya lo has sentido — el escaneo se traba justo cuando lanzas un deauth, la captura del handshake pierde un frame porque tu único adaptador se fue a otro canal a mandar un paquete. Eso no es un flujo de trabajo. Eso es un compromiso disfrazado de software.

ATWA-NG no hace compromisos. Escucha con un radio y golpea con el otro — simultáneamente, de forma nativa, sin repartir tiempo, sin frames perdidos. Cada ataque en esta herramienta — PMKID, captura de handshake, WPS, WEP, Evil Twin — corre sobre una implementación real, hecha desde cero, no un wrapper de shell rezando porque un subproceso no se caiga. Tienes una sola interfaz, retroalimentación real, y capturas en las que puedes confiar desde el momento en que caen al disco.

Si alguna vez perdiste un handshake porque tu único adaptador parpadeó en el momento equivocado — esta es la herramienta que le pone fin a eso.

---

## 🚩 Insignia: PINCER — Ataque Dual-WiFi

**Esta es la función que nadie más tiene.**

Requiere dos adaptadores Alfa específicos — un **AWUS036ACHM** (el que escucha) y un **AWUS1900** (el que ataca), detectados automáticamente por chipset. Conecta ambos. Fija un objetivo. Presiona **PINCER**. Desde ese instante:

- **El Radio A nunca deja de escuchar.** Fijo en el canal del objetivo, con los oídos abiertos, esperando el handshake — tiempo completo, sin compartirse con otros trabajos.
- **El Radio B nunca deja de golpear.** Rondas continuas de deauth contra el objetivo, tiempo completo, con su propio canal fijo separado.

Ningún radio pausa, salta de canal, ni comparte tiempo para hacer el trabajo del otro. Ese es todo el truco, y es la razón por la que PINCER captura handshakes que los ataques de un solo adaptador se pierden: el que escucha *siempre* está escuchando exactamente cuando el deauth realmente llega. Dos adaptadores, dos trabajos, cero compromiso — un pincer de verdad, cerrando por los dos lados a la vez.

---

## Todo lo demás en la caja

| Ataque | Qué hace realmente |
|---|---|
| **Smart Attack** | Se auto-dirige: PMKID primero, y si el objetivo es inmune a ataques sin cliente, cae a deauth+handshake |
| **OMNI Attack** | Cadena adaptativa completa — perfil → PMKID → handshake → intento en línea → crackeo, con un clic |
| **PMKID (sin cliente)** | No necesita cliente. Scapy nativo, consciente de PMF |
| **Captura de Handshake** | Sniff EAPOL nativo con una compuerta de verificación AUTHORIZED-vs-solo-challenge — ya no adivines si lo que capturaste realmente se puede crackear |
| **WPS** | Null-PIN, Pixie-Dust, y Bruteforce — Bruteforce prueba un null-PIN gratis primero y aborta de inmediato si el AP está bloqueado, en lugar de quemar 10,000 intentos en un callejón sin salida |
| **WEP** | Fake-auth + replay de ARP + recuperación de clave PTW nativa, más Caffe Latte para ataques solo-cliente |
| **Evil Twin** | AP falso real + portal cautivo, deauth automático a clientes reales hacia él |
| **Adivinanza de Contraseña en Línea** | Intentos reales de handshake de 4 vías, contraseña por contraseña, directo contra el AP |
| **Crackeo** | Miguel y aircrack-ng, ambos integrados — crackeo con un clic, o apúntalo a toda una carpeta de capturas y deja que las fusione, convierta, y crackee todo |
| **Desenmascarado de SSID oculto** | Automático, en cuanto una respuesta a un probe lo revele |

Cada uno de estos es un ataque real, nativo — no una apuesta con `subprocess.run()`.

---

## Instalación

```bash
git clone https://github.com/KiMiGuel/ATWA-NG.git
cd ATWA-NG
pip install -e .
```

## Cómo usarlo

```bash
atwa gui          # la experiencia completa — lanza la GUI (necesita root)
```

O manéjalo directo desde la terminal:

```bash
atwa --help
atwa scan wlan0
atwa smart wlan0 <bssid>
atwa omni wlan0 <bssid> --wordlist rockyou.txt
```

**Requisitos:** Linux, Python 3.10+, un adaptador WiFi capaz de modo monitor + inyección (un par AWUS036ACHM + AWUS1900 para desbloquear PINCER).

---

¿Necesitas un wordlist para apuntarle a esto? [Indepenlist-MX-wordlist](https://github.com/KiMiGuel/Indepenlist-MX-wordlist) — wordlists de contraseñas enfocados en México.

---

Solo para pruebas de seguridad autorizadas — contra redes y dispositivos que sean tuyos o para los que tengas autorización explícita.

<p align="center">
  <sub>Por <b>KiMiGuEL</b> — <a href="https://github.com/KiMiGuel">INDEPENTEST</a></sub>
</p>
