# Proyecto: Herramienta de Auditoría de Seguridad para Código Generado por IA

> Archivo de contexto para Claude Code. Léelo completo antes de ayudar.
> Autor: Eloy Karin Rivadeneira Miller, estudiante de Licenciatura en Informática del
> CRUBO (Universidad de Panamá). Esta herramienta es parte de su monografía de grado.

## Qué es este proyecto

Herramienta de línea de comandos (CLI) en Python que audita la seguridad del código
generado por asistentes de IA (GitHub Copilot, ChatGPT, Claude). Forma parte de una
monografía de grado titulada:

**"Diseño de un Protocolo de Auditoría de Seguridad para Código Generado por
Inteligencia Artificial en el Desarrollo de Aplicaciones"**

La idea: un estudiante clona esta herramienta desde GitHub, la apunta a su proyecto,
y la herramienta le dice qué vulnerabilidades tiene y cómo corregirlas. Se publicará
en GitHub para que cualquier estudiante del CRUBO la use.

## Filosofía de diseño (IMPORTANTE)

La herramienta NO reinventa motores de detección. Es un **orquestador**: aplica un
protocolo de auditoría propio y, más adelante, coordinará herramientas de análisis
ya existentes y gratuitas (Semgrep, Bandit, OWASP ZAP). El aporte original está en
CÓMO se organiza el análisis según el protocolo, no en el motor de detección en
bruto.

## Cómo trabajar con Eloy (MUY IMPORTANTE)

- Eloy tiene experiencia intermedia en Python ("algo, me defiendo"). Usa VS Code.
- Comunicar siempre en español.
- Trabajar SIEMPRE en pasos pequeños. Nada de tirar un programa gigante de golpe.
- Explicar el porqué de cada pieza de código. Eloy debe ENTENDER todo lo que escribe
  porque tiene que defenderlo ante un jurado. Si no lo entiende, no sirve.
- El código y la comprensión deben salir de Eloy. El rol del asistente es guiar,
  explicar, depurar juntos. NO escribir la tesis por él.
- Confirmar que cada paso funciona y se entiende antes de pasar al siguiente.
- Al final de cada sesión productiva, actualizar este CLAUDE.md con lo avanzado.

## El Protocolo de Auditoría (el corazón del proyecto)

Cada vulnerabilidad del checklist tiene esta anatomía de cinco partes:
ID, nombre, estándar (OWASP/CWE), severidad, señal de detección, corrección
recomendada.

Reglas definidas:

- **SEC-01 — Inyección SQL.** Severidad: Alta. OWASP A03:2021 / CWE-89.
  Detección: variable del usuario concatenada directamente en una consulta SQL.
  Corrección: usar consultas parametrizadas (prepared statements).

- **SEC-02 — Cross-Site Scripting (XSS).** Severidad: Alta. OWASP A03:2021 / CWE-79.
  Detección: datos del usuario insertados en HTML sin escapar/sanitizar.
  Corrección: escapar/sanitizar la salida, usar plantillas seguras del framework.

- **SEC-03 — Credenciales quemadas (hardcoded secrets).** Severidad: Media-Alta.
  OWASP A07:2021 / CWE-798.
  Detección: contraseñas, API keys o tokens escritos directamente en el código.
  Corrección: mover secretos a variables de entorno o gestor de secretos.

Reglas futuras: validación de entradas, manejo inseguro de sesiones, mensajes de
error reveladores, configuración insegura.

## Estado actual del código

**IMPORTANTE:** La herramienta está funcionando y probada con un sistema real
(Sistema_Inventario). Publicada en GitHub:
https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades

### Lo que ya funciona

La herramienta tiene CUATRO motores de detección que se activan según el proyecto:

- **Motor Regex:** 9 reglas propias (SEC-01 a SEC-09) con OWASP, CWE, CVSS,
  corrección e **impacto** (explicación del daño real en lenguaje claro). Corre
  siempre, en todos los lenguajes.
- **Motor Bandit:** análisis de Python/Django/Flask (se activa solo si hay .py).
- **Motor Semgrep:** PHP, JS, Java, TS, C/C++ (se activa solo si hay esos archivos).
- **Motor OSV (SCA):** lee `requirements.txt` y consulta la API gratuita de Google
  OSV para detectar librerías con vulnerabilidades conocidas (CVE reales). Cubre
  OWASP A06:2021. Se activa solo si hay `requirements.txt`. Requiere internet.

Otras capacidades:

- **Puntuación de riesgo del proyecto (0-100):** suma ponderada por severidad
  (Alta=10, Media-Alta=5, Media=2, Baja=1), acotada a 100, traducida a nivel
  (Bajo/Medio/Alto/Crítico). Se muestra en consola y en la portada del PDF.
- **Priorización de archivos sensibles:** los hallazgos en archivos con nombres
  críticos (login, auth, db, config, admin, usuario...) se marcan
  `[ARCHIVO SENSIBLE]` y se ordenan primero en el reporte.
- CLI con `--proyecto` apuntando a cualquier carpeta.
- Autoinstalación de dependencias: `fpdf2`, `bandit`, `semgrep`, `requests`.
- Reporte PDF en español: portada con nivel de riesgo + resumen ejecutivo +
  hallazgos detallados (con impacto y corrección).
- La herramienta se excluye a sí misma del escaneo automáticamente.
- Filtro de carpetas ignoradas (node_modules, venv, .git, etc.) y de comentarios.
- Casos de prueba en `ejemplos/`: `proyecto_vulnerable/` (requirements.txt con
  librerías vulnerables + login.py con SQL injection y credencial) y
  `ejemplo_vulne.py`.

### Flujo de uso (para el estudiante)
```
git clone https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades.git
cd Herramienta-DetecVulnerabilidades
python auditoria.py --proyecto ../mi-sistema
```
Primera vez instala dependencias sola. El PDF se guarda en la carpeta del proyecto auditado.

### Código de referencia — VERSIÓN HISTÓRICA v1 (NO usar como referencia actual)

> ADVERTENCIA: el bloque de abajo es la versión 1 (solo 3 reglas, sin motores
> externos). El código REAL y actual está en `auditoria.py` en el repo y tiene
> 4 motores (Regex, Bandit, Semgrep, OSV), puntuación de riesgo, priorización de
> archivos sensibles y campo de impacto. Para la arquitectura actual ver
> `docs/arquitectura.md`. Se conserva abajo solo como registro histórico.

```python
import argparse
import os
import re

# === Configuración ===
EXTENSIONES_CODIGO = (".py", ".php", ".js", ".java", ".ts")

def buscar_archivos_codigo(ruta):
    archivos_encontrados = []
    for carpeta_actual, subcarpetas, archivos in os.walk(ruta):
        for archivo in archivos:
            if archivo.endswith(EXTENSIONES_CODIGO):
                ruta_completa = os.path.join(carpeta_actual, archivo)
                archivos_encontrados.append(ruta_completa)
    return archivos_encontrados

def detectar_sql_injection(ruta_archivo):
    hallazgos = []
    patron = re.compile(
        r"(SELECT|INSERT|UPDATE|DELETE).*(\+|\.|%|f\"|f').*",
        re.IGNORECASE
    )
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for numero_linea, linea in enumerate(f, start=1):
                if patron.search(linea):
                    hallazgos.append({
                        "archivo": ruta_archivo, "linea": numero_linea,
                        "codigo": linea.strip(),
                        "regla": "SEC-01", "nombre": "Posible inyección SQL",
                        "severidad": "Alta",
                    })
    except Exception as e:
        print(f"  (No se pudo leer {ruta_archivo}: {e})")
    return hallazgos

def detectar_xss(ruta_archivo):
    hallazgos = []
    patron = re.compile(
        r"(echo|print|innerHTML|document\.write).*(\+|\.|\$_|f\"|f').*",
        re.IGNORECASE
    )
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for numero_linea, linea in enumerate(f, start=1):
                if patron.search(linea):
                    hallazgos.append({
                        "archivo": ruta_archivo, "linea": numero_linea,
                        "codigo": linea.strip(),
                        "regla": "SEC-02", "nombre": "Posible XSS (salida sin escapar)",
                        "severidad": "Alta",
                    })
    except Exception as e:
        print(f"  (No se pudo leer {ruta_archivo}: {e})")
    return hallazgos

def detectar_credenciales(ruta_archivo):
    hallazgos = []
    patron = re.compile(
        r"(password|passwd|api_key|apikey|secret|token)\s*[=:]\s*[\"'][^\"']+[\"']",
        re.IGNORECASE
    )
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for numero_linea, linea in enumerate(f, start=1):
                if patron.search(linea):
                    hallazgos.append({
                        "archivo": ruta_archivo, "linea": numero_linea,
                        "codigo": linea.strip(),
                        "regla": "SEC-03",
                        "nombre": "Posible credencial quemada en el código",
                        "severidad": "Media-Alta",
                    })
    except Exception as e:
        print(f"  (No se pudo leer {ruta_archivo}: {e})")
    return hallazgos

def main():
    parser = argparse.ArgumentParser(
        description="Herramienta de auditoría de seguridad para código generado por IA"
    )
    parser.add_argument("--proyecto", required=True,
                        help="Ruta a la carpeta del proyecto que se va a analizar")
    args = parser.parse_args()
    ruta = args.proyecto
    if not os.path.isdir(ruta):
        print(f"Error: no se encontró la carpeta '{ruta}'")
        return
    print(f"Proyecto encontrado en: {ruta}")
    archivos = buscar_archivos_codigo(ruta)
    print(f"Se encontraron {len(archivos)} archivos de código.\n")
    todos_los_hallazgos = []
    for archivo in archivos:
        todos_los_hallazgos.extend(detectar_sql_injection(archivo))
        todos_los_hallazgos.extend(detectar_xss(archivo))
        todos_los_hallazgos.extend(detectar_credenciales(archivo))
    if todos_los_hallazgos:
        print(f"Se encontraron {len(todos_los_hallazgos)} posibles vulnerabilidades:\n")
        for h in todos_los_hallazgos:
            print(f"[{h['severidad']}] {h['regla']} - {h['nombre']}")
            print(f"  Archivo: {h['archivo']} (línea {h['linea']})")
            print(f"  Código: {h['codigo']}\n")
    else:
        print("No se encontraron vulnerabilidades con las reglas actuales.")

if __name__ == "__main__":
    main()
```

Archivo de prueba `ejemplo_vulne.py`:

```python
nombre = input("Nombre: ")
consulta = "SELECT * FROM usuarios WHERE nombre = '" + nombre + "'"

api_key = "sk_live_1234567890abcdef"
password = "miClaveSuperSecreta123"

print("<div>" + nombre + "</div>")
```

Prueba con: `python auditoria.py --proyecto .`

## Próximos pasos de programación

1. [HECHO] Análisis SCA de dependencias (OSV), puntuación de riesgo, priorización
   de archivos sensibles y reporte educativo (campo `impacto`).
2. **AST para Python** — análisis estructural (no solo texto) para reducir falsos
   positivos en las reglas propias. Es el único pendiente de las 4 mejoras acordadas
   con Eloy para "sofisticar" la herramienta.
3. **README.md** — instrucciones claras para que los estudiantes clonen y usen la
   herramienta desde GitHub.
4. **Casos de estudio** — ejecutar la herramienta sobre sistemas reales para el
   Capítulo IV de la monografía.

## Limitaciones conocidas (material valioso para el Capítulo IV)

- La detección por Regex genera FALSOS POSITIVOS reales (marca texto sin entender el
  contexto). Mitigado con: filtro de comentarios, autoexclusión de la herramienta, y
  los motores Bandit/Semgrep que sí usan AST. El pendiente AST para las reglas propias
  reduciría aún más los falsos positivos.
- El motor OSV requiere conexión a internet (consulta la API de Google OSV en vivo).
- La puntuación de riesgo (0-100) es una heurística metodológica propia, inspirada en
  la escala CVSS; los pesos por severidad (10/5/2/1) son una decisión defendible, no
  una ley universal. Documentar esta justificación para la defensa.
- El AST solo aplicaría a Python; PHP/JS/Java/C dependen de Semgrep + Regex.
- No simula ataques: es análisis estático de código, no un pentest.

## Hoja de ruta (roadmap)

1. [HECHO] CLI básico + descubrimiento de archivos + reglas por Regex.
2. [HECHO] Mejoras de reducción de falsos positivos (comentarios, carpetas ignoradas).
3. [HECHO] Reporte presentable en PDF (portada, resumen ejecutivo, hallazgos).
4. [HECHO] Integrar Bandit y Semgrep como motores multi-lenguaje.
5. [HECHO] Análisis SCA de dependencias (OSV), scoring de riesgo, archivos sensibles
   y reporte educativo (impacto).
6. [PRÓXIMO] AST para Python (reducir falsos positivos en las reglas propias).
7. [PENDIENTE] README claro para que los estudiantes clonen la herramienta.
8. [PENDIENTE] Casos de estudio de validación para el Capítulo IV: caso principal web
   + un caso complementario. Comparar código auditado vs no auditado.

## Estructura de proyecto propuesta (a futuro)

```
auditor-ia/
  auditoria.py          # programa principal
  core/
    analizadores.py     # llamadas a Semgrep, Bandit, etc.
    protocolo.py        # aplica el checklist y los criterios
    reporte.py          # genera el informe final
  reglas/               # reglas de seguridad basadas en OWASP/CWE
  ejemplos/             # proyectos de prueba con vulnerabilidades
  README.md
  requirements.txt
```

## Estado del proyecto de monografía (más allá del código)

- **Capítulo I (El Problema):** borrador completo en Word.
- **Capítulo II (Marco Teórico):** borrador completo en Word con fuentes verificables
  (Pearce et al. 2022, OWASP, CWE, CSET 2024). El usuario debe verificar las citas.
- **Capítulo III (Marco Metodológico):** borrador completo en Word.
- **Capítulo IV (Resultados):** PENDIENTE, requiere ejecutar los casos de estudio.
- **Capítulo V (Conclusiones):** PENDIENTE, se escribe al final.
- **Ficha DI-F-001:** entregada al profesor por correo.
- **Ficha DI-F-003 (Informe de Progreso N° 01):** elaborada el 20/06/2026, reporta
  50% de avance real frente al 100% esperado, con atraso declarado honestamente.
- **Bitácora del proyecto:** en Word, con entradas históricas hasta el 20/06/2026.
- **Cronograma vivo:** en Excel, con seguimiento por fases y semanal.

## Recordatorio sobre la monografía

La herramienta es UNA pieza del Capítulo IV. NO es la monografía completa. El
documento académico (Capítulos I a V) es lo que se evalúa y defiende. Animar a Eloy
a documentar sobre la marcha cada hallazgo y decisión, porque es material directo
para la escritura.

## Plan de respaldo (recomendado, decisión de Eloy)

- Código de la herramienta → GitHub (es parte del entregable de la monografía).
- Documentos Word de los capítulos, fichas y bitácora → Google Drive.
- Hacer commit/sync con frecuencia para no volver a perder trabajo por un formateo.
