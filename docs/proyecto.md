# Auditor-IA — Visión General del Proyecto

## ¿Qué es?

Herramienta de línea de comandos (CLI) en Python que audita la seguridad del código generado por asistentes de IA (GitHub Copilot, ChatGPT, Claude).

Forma parte de la monografía de grado:
> **"Diseño de un Protocolo de Auditoría de Seguridad para Código Generado por Inteligencia Artificial en el Desarrollo de Aplicaciones"**

**Autor:** Eloy Karin Rivadeneira Miller
**Institución:** CRUBO — Universidad de Panamá
**Carrera:** Licenciatura en Informática

---

## ¿Para quién es?

Para estudiantes del CRUBO que usan IA para construir sistemas reales como:
- Sistemas de matrícula
- Sistemas de inventario
- Sistemas de facturación
- APIs y aplicaciones web

El argumento central: la IA genera código rápido pero inseguro. Esta herramienta lo demuestra.

---

## ¿Cómo se usa?

```bash
git clone https://github.com/eloy/auditor-ia
cd auditor-ia
pip install -r requirements.txt
python auditoria.py --proyecto ./mi-sistema
```

El estudiante recibe un reporte PDF con las vulnerabilidades encontradas y cómo corregirlas.

---

## Filosofía de diseño

La herramienta es un **orquestador**. No reinventa motores de detección — coordina herramientas existentes y aplica un protocolo de auditoría propio.

El aporte original está en **el protocolo**, no en el motor de detección en bruto.

---

## Motores de detección

| Motor | Lenguajes | Instalación |
|---|---|---|
| Bandit | Python, Django, Flask | `pip install bandit` |
| Semgrep | PHP, JavaScript, Java, TypeScript | `pip install semgrep` |
| Regex propio | Todos (complemento) | Incluido |

Los tres se instalan automáticamente con `pip install -r requirements.txt`.

---

## Estado actual

- [x] CLI básico con argparse
- [x] Descubrimiento de archivos por extensión
- [x] 9 reglas de detección por regex (SEC-01 a SEC-09) con OWASP/CWE/CVSS
- [x] Filtro de carpetas ignoradas (node_modules, venv, etc.)
- [x] Filtro de comentarios (es_comentario)
- [x] Integración de Bandit (Python/Django/Flask)
- [x] Integración de Semgrep (PHP, JS, Java, TS, C/C++)
- [x] Activación inteligente de motores según lenguajes del proyecto
- [x] Autoinstalación de dependencias (fpdf2, bandit, semgrep)
- [x] Reporte en PDF en español (portada, resumen ejecutivo, hallazgos)
- [x] La herramienta se excluye a sí misma del análisis automáticamente
- [x] Publicado en GitHub
- [ ] Priorizar archivos sensibles (login, db, config, auth)
- [ ] README para GitHub
- [ ] Casos de estudio (Capítulo IV)

---

## Vínculos

- [[protocolo]] — Las reglas de seguridad SEC-01 a SEC-09
- [[arquitectura]] — Cómo funciona internamente
- [[limitaciones]] — Material para el Capítulo IV
- [[bitacora]] — Registro de decisiones
