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

## Vínculos

- [[proyecto]] — Visión general
- [[arquitectura]] — Cómo funciona la detección
- [[protocolo]] — Las reglas actuales
