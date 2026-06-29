# Bitácora de Desarrollo

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
