# Herramienta de Auditoría de Seguridad para Código Generado por IA

> Archivo de contexto para Claude Code. Léelo completo antes de ayudar.
> Autor: Eloy Karin Rivadeneira Miller, estudiante de Licenciatura en Informática del
> CRUBO (Universidad de Panamá).

## Qué es este proyecto

Herramienta de línea de comandos (CLI) en Python que audita la seguridad del código
generado por asistentes de IA (GitHub Copilot, ChatGPT, Claude).

**Flujo de uso (para el estudiante):**
```
git clone https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades.git
cd Herramienta-DetecVulnerabilidades
python auditoria.py --proyecto ../mi-sistema
```
La primera vez instala las dependencias sola. El PDF se guarda en la carpeta del
proyecto auditado.

## Los dos repositorios (IMPORTANTE)

| Repo | Carpeta local | Qué contiene | Para quién |
|---|---|---|---|
| `Herramienta-DetecVulnerabilidades` (público) | `c:\Users\eloyr\auditor-ia` | ESTE. Solo la herramienta | Los estudiantes del CRUBO |
| `monografia-auditoria-ia` (privado) | `c:\Users\eloyr\monografia-auditoria-ia` | La investigación: docs, casos de estudio, evidencia del Cap. IV | Eloy y el jurado |

**Regla de oro de este repo:** el estudiante que lo clona solo debe ver lo que
necesita para USAR la herramienta. Nada de documentación de tesis, bitácoras ni
casos de estudio. Si algo es material de la monografía, va al otro repo.

## Cómo trabajar con Eloy (MUY IMPORTANTE)

- Eloy tiene experiencia intermedia en Python ("algo, me defiendo"). Usa VS Code.
- Comunicar siempre en español.
- Trabajar SIEMPRE en pasos pequeños. Nada de tirar un programa gigante de golpe.
- Explicar el porqué de cada pieza de código. Eloy debe ENTENDER todo lo que escribe
  porque tiene que defenderlo ante un jurado. Si no lo entiende, no sirve.
- El código y la comprensión deben salir de Eloy. El rol del asistente es guiar,
  explicar, depurar juntos.
- Confirmar que cada paso funciona y se entiende antes de pasar al siguiente.
- Recordarle hacer commit cada vez que algo quede funcionando (ya perdió trabajo por
  un formateo).
- NO poner `Co-Authored-By: Claude` en los commits: la autoría del trabajo es suya.
- Al final de cada sesión productiva, actualizar este CLAUDE.md.

## Filosofía de diseño (IMPORTANTE)

La herramienta NO reinventa motores de detección. Es un **orquestador**: aplica un
protocolo de auditoría propio y coordina herramientas de análisis ya existentes y
gratuitas (Bandit, Semgrep, OSV). El aporte original está en CÓMO se organiza el
análisis según el protocolo, no en el motor de detección en bruto.

**Alcance:** es SAST (análisis estático) + SCA (dependencias). NO hace DAST: no
ejecuta la aplicación ni la ataca. Esa frontera es deliberada y defendible.

## El Protocolo de Auditoría (el corazón del proyecto)

Cada regla tiene: ID, nombre, estándar (OWASP/CWE), CVSS, severidad, señal de
detección, corrección e **impacto** (el daño real explicado en lenguaje claro).

| ID | Vulnerabilidad | OWASP | CWE | Severidad |
|---|---|---|---|---|
| SEC-01 | Inyección SQL | A03:2021 | CWE-89 | Alta |
| SEC-02 | Cross-Site Scripting (XSS) | A03:2021 | CWE-79 | Alta |
| SEC-03 | Credencial quemada | A07:2021 | CWE-798 | Media-Alta |
| SEC-04 | Inyección de comandos | A03:2021 | CWE-78 | Alta |
| SEC-05 | Path Traversal | A01:2021 | CWE-22 | Alta |
| SEC-06 | Modo debug activo | A05:2021 | CWE-489 | Media |
| SEC-07 | Deserialización insegura | A08:2021 | CWE-502 | Alta |
| SEC-08 | Uso de eval() con datos externos | A03:2021 | CWE-95 | Alta |
| SEC-09 | Algoritmo criptográfico débil | A02:2021 | CWE-327 | Media-Alta |
| SEC-10 | Secreto expuesto (formato real) | A07:2021 | CWE-798 | Alta |
| A06 | Dependencia vulnerable (CVE) | A06:2021 | CWE-1035 | Alta / Media-Alta |

La documentación completa del protocolo está en el repo de la monografía
(`docs/protocolo.md`).

## Estado actual del código

La herramienta funciona y está probada. Tiene CINCO motores que se activan según lo
que tenga el proyecto:

- **Regex:** 10 reglas propias (SEC-01 a SEC-10) con OWASP, CWE, CVSS, corrección e
  impacto. Corre siempre, en todos los lenguajes.
- **Bandit:** Python/Django/Flask (solo si hay `.py`).
- **Semgrep:** PHP, JS, Java, TS, C/C++ (solo si hay esos archivos).
- **OSV (SCA):** lee `requirements.txt` y consulta la API gratuita de Google OSV para
  detectar librerías con CVE conocidos (OWASP A06). Requiere internet.
- **Secretos (SEC-10):** claves de AWS, GitHub, Stripe, Google, Slack y PEM por su
  formato real. NO ignora comentarios (un secreto filtrado lo es igual).

Otras capacidades:

- **Puntuación de riesgo (0-100):** suma ponderada por severidad (Alta=10,
  Media-Alta=5, Media=2, Baja=1), acotada a 100, traducida a nivel
  (Bajo/Medio/Alto/Crítico). En consola y en la portada del PDF.
- **Priorización de archivos sensibles:** hallazgos en archivos con nombres críticos
  (login, auth, db, config, admin...) se marcan `[ARCHIVO SENSIBLE]` y van primero.
- Autoinstalación de dependencias: `fpdf2`, `bandit`, `semgrep`, `requests`.
- Reporte PDF en español: portada con nivel de riesgo + resumen ejecutivo + hallazgos
  detallados (con impacto y corrección).
- La herramienta se excluye a sí misma del escaneo automáticamente.
- Filtro de carpetas ignoradas (node_modules, venv, .git...) y de comentarios.
- **Pruebas unitarias:** `python -m unittest test_auditoria -v` (10 pruebas).

## Estructura del proyecto

```
auditor-ia/
  auditoria.py               # programa principal (los 5 motores, todo aquí)
  test_auditoria.py          # pruebas unitarias
  requirements.txt           # bandit, semgrep, fpdf2, requests
  README.md                  # instrucciones para el estudiante
  CLAUDE.md
  pruebas/
    proyecto_vulnerable/     # fixtures que usa test_auditoria.py
```

`auditoria.py` es monolítico a propósito. Dividirlo en `core/` no aporta a la
monografía y sí arriesga romper lo que ya funciona.

## Bugs importantes corregidos (material para el Cap. IV)

- **Crash por encoding (14/07/2026):** los símbolos ✓/✗ reventaban con
  `UnicodeEncodeError` en consolas Windows cp1252. Corregido forzando UTF-8 con
  `errors="replace"`. Les habría pasado a los compañeros del CRUBO.
- **Semgrep muerto en silencio (14/07/2026):** se invocaba con `python -m semgrep`,
  deprecado desde Semgrep 1.38; devolvía un aviso en vez de JSON y el motor de
  PHP/JS/Java no corría, reportando "0 vulnerabilidades" falsamente. Corregido con
  `ruta_semgrep()` (`shutil.which` + búsqueda junto al intérprete) y avisos `[AVISO]`
  explícitos.
- **Lección de diseño:** una herramienta de auditoría NUNCA debe fallar en silencio;
  un "todo está bien" falso es peor que un error visible.

## Limitaciones conocidas (material para el Cap. IV)

- La detección por Regex genera FALSOS POSITIVOS reales (marca texto sin entender el
  contexto). Mitigado con: filtro de comentarios, autoexclusión de la herramienta, y
  los motores Bandit/Semgrep que sí usan AST.
- El motor OSV requiere conexión a internet (consulta la API de Google OSV en vivo).
- OSV solo lee `requirements.txt` (PyPI). No lee `package.json` ni `composer.json`.
- La puntuación de riesgo (0-100) es una heurística metodológica propia, inspirada en
  la escala CVSS; los pesos (10/5/2/1) son una decisión defendible, no una ley.
- La priorización de sensibles se basa en el NOMBRE del archivo (heurística simple).
- No simula ataques: es análisis estático (SAST), no un pentest (DAST).

## Hoja de ruta

1. [HECHO] CLI + descubrimiento de archivos + reglas por Regex.
2. [HECHO] Reducción de falsos positivos (comentarios, carpetas ignoradas).
3. [HECHO] Reporte en PDF (portada, resumen ejecutivo, hallazgos).
4. [HECHO] Bandit y Semgrep como motores multi-lenguaje.
5. [HECHO] SCA de dependencias (OSV), scoring de riesgo, archivos sensibles e impacto.
6. [HECHO] Escaneo de secretos (SEC-10).
7. [HECHO] Pruebas unitarias (test_auditoria.py).
8. [HECHO] Separar la investigación a su propio repo.
9. [PRÓXIMO] README.md claro para que los estudiantes clonen y usen la herramienta.
10. [PENDIENTE] AST para Python (reducir falsos positivos en las reglas propias).
