# Auditor-IA

Herramienta de línea de comandos que **audita la seguridad del código generado por
asistentes de IA** (ChatGPT, GitHub Copilot, Gemini, Claude).

La IA escribe código rápido, pero no siempre seguro. Esta herramienta revisa tu
proyecto y te dice **qué vulnerabilidades tiene, por qué son peligrosas y cómo
corregirlas**, en un reporte PDF en español.

> Desarrollada como parte de una monografía de grado en la Licenciatura en
> Informática del CRUBO, Universidad de Panamá.

---

## Paso 0: instala Python (una sola vez)

La herramienta es un programa de Python, así que tu computadora necesita tenerlo
instalado. Las demás dependencias (Bandit, Semgrep, etc.) se instalan solas; Python
es lo único que debes poner tú.

**¿Ya tienes Python?** Abre una terminal (en Windows: busca "cmd" o "PowerShell") y
escribe:
```bash
python --version
```
- Si ves algo como `Python 3.11.5`, ya lo tienes → salta al Paso 1.
- Si dice `'python' no se reconoce...`, instálalo así:

1. Entra a **https://www.python.org/downloads/** y descarga la última versión.
2. Abre el instalador y, en la **primera pantalla**, marca la casilla
   **☑ "Add Python to PATH"** antes de dar "Install Now".
   > ⚠️ Este paso es el que casi todos olvidan. Sin esa casilla, el comando
   > `python` no funcionará.
3. Cierra y vuelve a abrir la terminal, y comprueba de nuevo con `python --version`.

---

## Paso 1: obtén la herramienta

Hay dos formas. Elige **UNA**. Si no sabes qué es Git, usa la **Opción B (ZIP)**, es
la más sencilla.

### Opción A — con Git (`git clone`)

**A.1. ¿Tienes Git?** En una terminal escribe:
```bash
git --version
```
- Si ves algo como `git version 2.4x.x`, ya lo tienes → pasa al punto A.2.
- Si dice `'git' no se reconoce...`, instálalo primero:
  1. Entra a **https://git-scm.com/download/win** — la descarga empieza sola.
  2. Abre el instalador y ve dando **"Next"** en todas las pantallas (los valores por
     defecto están bien; no cambies nada).
  3. Al final pulsa **"Install"** y luego **"Finish"**.
  4. **Cierra y vuelve a abrir la terminal**, y comprueba con `git --version`.

**A.2. Clona la herramienta:**
```bash
git clone https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades.git
cd Herramienta-DetecVulnerabilidades
```
Ya estás dentro de la carpeta de la herramienta. Salta al **Paso 2**.

### Opción B — sin Git, descargando el ZIP (la más fácil)

1. Entra a la página del repositorio:
   **https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades**
2. Pulsa el botón verde **"< > Code"** y luego **"Download ZIP"**.
3. Ve a tu carpeta de **Descargas**. Verás un archivo
   `Herramienta-DetecVulnerabilidades-main.zip`.
4. **Descomprímelo:** clic derecho sobre el ZIP → **"Extraer todo..."** → **"Extraer"**.
   Se crea una carpeta con el mismo nombre.
5. **Abre esa carpeta** (entra hasta ver dentro `auditoria.py`).
6. **Abre una terminal DENTRO de esa carpeta** (este paso es el importante):
   - Haz clic en la **barra de direcciones** del Explorador (la que muestra la ruta,
     arriba), borra lo que diga, escribe **`cmd`** y pulsa **Enter**.
   - Se abre una ventana negra ya ubicada en la carpeta correcta. ✅

> ¿Cómo sé que la terminal está en el lugar correcto? Escribe `dir` (Enter) y debes
> ver `auditoria.py` en la lista.

---

## Paso 2: apúntala a tu proyecto

En la terminal (la que abriste en el Paso 1), escribe:
```bash
python auditoria.py --proyecto C:\ruta\a\mi-sistema
```
Cambia `C:\ruta\a\mi-sistema` por la carpeta de **tu** proyecto. Si la ruta tiene
espacios, ponla entre comillas: `--proyecto "C:\Mis Proyectos\sistema"`.

> Truco: puedes **arrastrar la carpeta de tu proyecto** desde el Explorador hasta la
> terminal y la ruta se escribe sola.

## Paso 3: abre el reporte

Se genera un PDF dentro de la carpeta de tu proyecto:
`reporte_auditoria_AAAA-MM-DD.pdf`

> **La primera vez tarda 2-3 minutos** instalando sus dependencias (Semgrep es
> grande). Es normal: **no cierres la terminal** aunque parezca que no pasa nada.
> Las siguientes veces arranca de inmediato. No necesitas ejecutar tu sistema ni
> tener la base de datos levantada: la herramienta solo lee el código.

### Requisitos
- **Python 3.8 o superior** (ver Paso 0)
- **Conexión a internet** la primera vez (para instalar las dependencias y para que
  Semgrep y OSV descarguen sus datos)

---

## Qué detecta

| Motor | Qué revisa | Lenguajes |
|---|---|---|
| Reglas propias | 10 patrones de código inseguro | Todos |
| Bandit | Análisis profundo de Python | Python, Django, Flask |
| Semgrep | Reglas del OWASP Top 10 | PHP, JavaScript, Java, TypeScript, C/C++ |
| OSV (Google) | Librerías con vulnerabilidades conocidas (CVE) | `requirements.txt` |
| Escáner de secretos | Claves y tokens expuestos | Todos |

Cada motor se activa **solo si tu proyecto lo necesita**: si no tienes archivos
Python, Bandit ni se ejecuta.

### Las reglas del protocolo

| ID | Vulnerabilidad | OWASP | Severidad |
|---|---|---|---|
| SEC-01 | Inyección SQL | A03:2021 | Alta |
| SEC-02 | Cross-Site Scripting (XSS) | A03:2021 | Alta |
| SEC-03 | Credencial quemada en el código | A07:2021 | Media-Alta |
| SEC-04 | Inyección de comandos del sistema | A03:2021 | Alta |
| SEC-05 | Path Traversal | A01:2021 | Alta |
| SEC-06 | Modo debug activo en producción | A05:2021 | Media |
| SEC-07 | Deserialización insegura | A08:2021 | Alta |
| SEC-08 | Uso de `eval()` con datos externos | A03:2021 | Alta |
| SEC-09 | Algoritmo criptográfico débil | A02:2021 | Media-Alta |
| SEC-10 | Secreto expuesto (AWS, GitHub, Stripe...) | A07:2021 | Alta |
| A06 | Dependencia con CVE conocidos | A06:2021 | Alta / Media-Alta |

---

## Qué te entrega el reporte

- **Nivel de riesgo del proyecto** (0-100): Bajo, Medio, Alto o Crítico
- **Resumen ejecutivo** con el conteo por severidad
- **Cada hallazgo** con: archivo y línea, el código señalado, el estándar
  (OWASP/CWE/CVSS), el **impacto real** explicado en lenguaje claro y **cómo
  corregirlo**
- Los hallazgos en **archivos sensibles** (login, config, db...) aparecen primero

---

## Probar que funciona

La herramienta trae pruebas automáticas que verifican que detecta correctamente:

```bash
python -m unittest test_auditoria -v
```

Si todas pasan (`OK`), la herramienta está lista para auditar tu proyecto.

---

## Problemas comunes

**`'python' no se reconoce como un comando...`**
Python no está instalado, o al instalarlo no marcaste "Add Python to PATH".
Reinstálalo siguiendo el Paso 0 y marca esa casilla. En algunas computadoras el
comando es `py` en vez de `python`.

**Se queda "pegado" un buen rato la primera vez**
Es normal: está descargando e instalando Bandit, Semgrep y las demás dependencias
(Semgrep es grande). Dale 2-3 minutos y no cierres la terminal.

**`error: no se encontró la carpeta '...'`**
La ruta que pusiste después de `--proyecto` no existe o está mal escrita. Si la ruta
tiene espacios, enciérrala entre comillas:
```bash
python auditoria.py --proyecto "C:\Mis Proyectos\sistema"
```

**Aparece un `[AVISO]` de que Semgrep no corrió**
Semgrep necesita internet la primera vez para descargar sus reglas. Revisa tu
conexión y vuelve a intentarlo. Los demás motores igual funcionan.

**`pip` falla al instalar**
Asegúrate de tener internet. Si sigue fallando, instala las dependencias a mano:
```bash
pip install fpdf2 bandit semgrep requests
```

---

## Lo que esta herramienta NO hace

Por transparencia, conviene saber su alcance:

- **No ejecuta ni ataca tu aplicación.** Hace análisis estático: lee el código. No
  reemplaza una prueba de penetración.
- **No revisa la configuración del servidor** ni la infraestructura.
- **Puede dar falsos positivos.** Revisa cada hallazgo con criterio; la herramienta
  señala, tú decides.
- **Un reporte limpio no garantiza que el sistema sea seguro.** Reduce riesgos
  conocidos, no todos.

---

## Licencia y uso

Proyecto académico de uso libre para fines educativos. Úsalo solo sobre código y
sistemas **de tu propiedad** o para los que tengas autorización.
