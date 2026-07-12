# Limitaciones de la Herramienta

> Este archivo es material directo para el Capítulo IV de la monografía.

---

## 1. Falsos positivos con Regex

El motor de detección por expresiones regulares analiza texto, no código. Esto genera casos donde:

- Se marcan líneas que son comentarios (mitigado con `es_comentario()`)
- Se marca el propio código de `auditoria.py` porque contiene las palabras de los patrones (SELECT, password, etc.)
- Se marca código perfectamente seguro que coincide con el patrón textual

**Impacto:** El estudiante puede ver más vulnerabilidades de las reales y desconfiar del reporte.

**Mitigación actual:** Filtro de comentarios y carpetas ignoradas.

**Mitigación futura:** AST para Python (Bandit lo resuelve), Semgrep para otros lenguajes.

---

## 2. AST solo funciona en Python

El análisis por Árbol de Sintaxis Abstracta (AST) que provee Bandit solo funciona en archivos `.py`. Para PHP, JavaScript y Java seguimos dependiendo de regex.

---

## 3. Requiere conexión a internet (primera ejecución)

Semgrep descarga sus reglas desde internet la primera vez. Sin conexión, el motor Semgrep no estará disponible.

---

## 4. No simula ataques

La herramienta es un **analizador estático de código**. Analiza el texto del código sin ejecutarlo. No puede:
- Probar si una vulnerabilidad es explotable en la práctica
- Simular ataques reales (eso lo hacen Metasploit, Burp Suite)
- Detectar vulnerabilidades en tiempo de ejecución

Esto está fuera del alcance del proyecto y de cualquier trabajo de grado.

---

## 5. No consulta CVE en tiempo real

Los metadatos de OWASP, CWE y CVSS están definidos estáticamente en las reglas. La herramienta no consulta la base de datos del NIST/CVE en vivo. Esto significa que las puntuaciones son referencias generales, no específicas a versiones de software.

**Posible mejora futura:** Detectar versiones de librerías en requirements.txt y consultar la API del NIST para CVEs específicos.

---

## 6. Cobertura de lenguajes

| Lenguaje | Cobertura |
|---|---|
| Python / Django / Flask | Alta (Bandit + Regex) |
| PHP | Media (Semgrep + Regex) |
| JavaScript / TypeScript | Media (Semgrep + Regex) |
| Java | Media (Semgrep + Regex) |
| Otros lenguajes | No soportados |

---

## 7. El motor OSV requiere internet

El análisis de dependencias (SCA) consulta la API de Google OSV **en vivo** por cada
librería. Sin conexión, ese motor no genera hallazgos (los demás sí funcionan).

## 8. Solo lee dependencias de Python (requirements.txt)

El motor OSV hoy solo interpreta `requirements.txt` (ecosistema PyPI). No lee todavía
`package.json` (npm) ni `composer.json` (PHP). Mejora futura clara.

## 9. La puntuación de riesgo es una heurística

El puntaje 0-100 usa pesos por severidad (10/5/2/1) inspirados en CVSS. Es una
**decisión metodológica propia**, razonable y defendible, pero no una medida objetiva
universal. Debe documentarse como tal en la monografía.

## 10. La priorización de sensibles se basa en el NOMBRE del archivo

`es_archivo_sensible()` mira el nombre (login, db, config...). Un archivo crítico con
un nombre no convencional no se detectaría como sensible. Es una heurística simple.

---

## Vínculos

- [[proyecto]] — Visión general
- [[arquitectura]] — Cómo funciona la detección
- [[protocolo]] — Las reglas actuales
