# Bitácora de Desarrollo

---

## 2026-07-12 — Sesión "hacer la herramienta significativa"

Eloy planteó una inquietud de fondo: la herramienta se sentía "básica" frente a las
amenazas actuales y quería que fuera un aporte real, no solo una nota. Se acordó un
reencuadre importante y cuatro mejoras.

### Reencuadre metodológico (importante para la defensa)

La herramienta NO compite con Semgrep/Bandit en potencia de detección — no es su
aporte. Su aporte es el **ángulo**: auditar específicamente código generado por IA,
operacionalizando el hallazgo de Pearce et al. (2022) de que ~40% del código de
Copilot es vulnerable. El aporte es metodológico (el protocolo), no el motor en bruto.

### Las 4 mejoras acordadas (Eloy las eligió todas)

1. **SCA - Dependencias vulnerables (HECHO).** Nuevo motor OSV: lee `requirements.txt`
   y consulta la API gratuita de Google OSV (sin API key) para detectar librerías con
   CVE conocidos. Cubre OWASP A06:2021, una categoría entera que antes no se tocaba.
   Prueba real: 5 librerías viejas arrojaron 69 CVE reales. Se agrupan por librería
   (una tarjeta con conteo, no 69 tarjetas). Severidad dinámica: >10 CVE = Alta.
2. **Scoring + enfoque IA (HECHO).** Función `calcular_riesgo()`: suma ponderada por
   severidad (Alta=10, Media-Alta=5, Media=2, Baja=1), tope de 100, nivel
   Bajo/Medio/Alto/Crítico. Inspirado en CVSS. Se muestra en consola y en la portada
   del PDF con color.
3. **Reporte que educa + archivos sensibles (HECHO).** (a) Archivos con nombres
   críticos (login, auth, db, config, admin...) se marcan `[ARCHIVO SENSIBLE]` y van
   primero. (b) Campo `impacto` en cada hallazgo que explica el daño real en lenguaje
   claro; genérico por severidad para Bandit/Semgrep/OSV.
4. **AST para Python (PENDIENTE).** Único que queda. Análisis estructural para reducir
   falsos positivos en las reglas propias.

### Decisiones técnicas

- Se usó `requests` (no urllib) para la API OSV: código más legible y defendible.
  Se agregó a la autoinstalación de dependencias.
- El impacto va ANTES de la corrección (primero el porqué es peligroso, luego el remedio).
- La severidad por archivo sensible NO se altera (se descartó la opción B): se prioriza
  el orden pero no se distorsiona la metodología de severidad, para no complicar la
  defensa.

### Nueva rutina de trabajo

Eloy pidió que se le recuerde hacer commit después de cada cambio que funcione (ya
perdió trabajo antes por un formateo). Se hará de ahora en adelante.

### Casos de prueba creados

- `ejemplos/proyecto_vulnerable/requirements.txt` — librerías con CVE conocidos.
- `ejemplos/proyecto_vulnerable/login.py` — SQL injection + credencial en archivo
  con nombre sensible (para probar priorización).

---

## 2026-06-29 — Sesión de implementación completa

### Decisiones tomadas

**1. Arquitectura de tres motores confirmada**
- Bandit para Python (instalable por pip, 70+ reglas)
- Semgrep para PHP, JS, Java, TS, C/C++ (instalable por pip, reglas OWASP)
- Regex propio como complemento en todos los lenguajes
- Activación inteligente: cada motor solo corre si detecta archivos de su lenguaje

**2. Autoinstalación de dependencias**
La herramienta verifica al inicio si `fpdf2`, `bandit` y `semgrep` están instalados usando `importlib.util.find_spec()`. Solo instala lo que falta. El estudiante solo necesita `git clone` + `python auditoria.py`.

**3. Reglas como datos (REGLAS list)**
Se refactorizó de funciones separadas por regla a una lista de diccionarios con una función genérica `detectar_por_regex()`. Agregar reglas nuevas es solo agregar un diccionario.

**4. Reporte PDF en español con fpdf2**
- Portada: nombre, proyecto auditado, fecha, total de vulnerabilidades
- Resumen ejecutivo: tabla por severidad con colores
- Hallazgos detallados: OWASP/CWE/CVSS, archivo, línea, código, corrección
- Bugs resueltos: FPDFException por `multi_cell(0,...)`, UnicodeError por emojis en código, alineación con `new_x="LMARGIN"`

**5. La herramienta se excluye a sí misma**
`CARPETA_HERRAMIENTA = os.path.dirname(os.path.abspath(__file__))` detecta la carpeta donde vive `auditoria.py` y la excluye del walk. Evita que se audite a sí misma cuando está clonada dentro del proyecto del estudiante.

**6. Rama main unificada**
Se resolvió conflicto entre rama `master` (nuestros commits) y `main` (commit vacío inicial de GitHub). Se hizo force push de `master` sobre `main` y se eliminó `master`. El repo ahora tiene solo una rama: `main`.

### Bugs encontrados y resueltos en esta sesión

| Bug | Causa | Solución |
|---|---|---|
| Bandit escaneaba .venv | Sin filtro de exclusión | `--exclude` con CARPETAS_IGNORADAS |
| FPDFException (espacio insuficiente) | `multi_cell(0,...)` con `align="C"` | Usar `pdf.epw` como ancho |
| UnicodeEncodeError (emojis) | Fuente Courier no soporta Unicode | Función `limpiar_pdf()` |
| Texto desordenado en PDF | `multi_cell` no resetea X | Agregar `new_x="LMARGIN"` |
| Herramienta se auditaba a sí misma | Clonada dentro del proyecto | `CARPETA_HERRAMIENTA` autoexclusión |

### Estado al final de la sesión

- ✅ Herramienta funcional y probada con Sistema_Inventario real
- ✅ PDF generado correctamente con hallazgos reales
- ✅ Publicada en GitHub: https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades
- ⏳ Priorizar archivos sensibles (login, db, config, auth)
- ⏳ README.md para GitHub
- ⏳ Casos de estudio para Capítulo IV



Registro de decisiones tomadas y por qué. Material útil para la monografía.

---

## 2026-06-27 — Sesión de rediseño

### Decisiones tomadas

**1. Descartar Semgrep como dependencia externa**
Inicialmente se consideró llamar a Semgrep instalado por separado. Se descartó porque el estudiante tendría que instalarlo manualmente, rompiendo la experiencia de "clonar y ejecutar". Se decidió incluirlo en `requirements.txt` como dependencia pip, igual que Bandit.

**2. Adoptar arquitectura de tres motores**
- Bandit para Python (70+ reglas automáticas, instalable por pip)
- Semgrep para PHP/JS/Java/TS (miles de reglas OWASP, instalable por pip)
- Regex propio como complemento y respaldo

Esto convierte la herramienta en un orquestador real, que es la filosofía central de la monografía.

**3. Activación inteligente de motores**
Los motores no corren siempre — se activan según los lenguajes detectados en el proyecto:
- Proyecto Python → Bandit + Regex
- Proyecto PHP/JS → Semgrep + Regex
- Proyecto mixto → los tres

**4. Reglas como datos, no como funciones**
Se refactorizó la estructura: en vez de una función por regla, ahora hay una lista `REGLAS` de diccionarios y una sola función genérica `detectar_por_regex()`. Agregar una regla nueva es solo agregar un diccionario.

**5. Metadatos OWASP/CWE/CVSS estáticos**
Se evaluó consultar la API del NIST en tiempo real. Se descartó porque los metadatos de vulnerabilidades por categoría (SQL injection = CWE-89 = CVSS 9.8) no cambian. Consultar la API en vivo agrega complejidad y dependencia de internet innecesaria para este caso.

**6. Reporte en PDF con fpdf2**
El reporte final será en PDF (universal, no requiere software especial). Se usará `fpdf2` instalable por pip. Se descartó generar reportes en Markdown para Obsidian porque no todos los estudiantes tienen Obsidian instalado.

### Estado al final de la sesión

- ✅ 9 reglas regex con OWASP/CWE/CVSS (SEC-01 a SEC-09)
- ✅ Filtro de carpetas ignoradas
- ✅ Filtro de comentarios
- ✅ Función genérica de detección
- ⏳ Integración de Bandit (próximo paso)
- ⏳ Integración de Semgrep
- ⏳ Reporte PDF
- ⏳ README y publicación en GitHub

---

## Vínculos

- [[proyecto]] — Estado general
- [[arquitectura]] — Decisiones de diseño implementadas
- [[limitaciones]] — Lo que se decidió NO hacer y por qué
