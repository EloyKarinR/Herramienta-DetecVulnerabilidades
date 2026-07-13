# Insumo para la tesis: Alcance y Limitaciones de la herramienta

> ⚠️ ESTO ES UN ANDAMIAJE, NO TEXTO FINAL. Son las ideas ordenadas y frases guía.
> Reescríbelo CON TU VOZ antes de pegarlo en el Word. El jurado espera tu redacción,
> no una copia. Donde diga [Eloy: ...] es una instrucción para ti, bórrala al final.

## ¿Dónde va esto en la monografía?

- **El ALCANCE (qué cubre y qué no):** encaja en el **Capítulo III (Marco Metodológico)**,
  en una sección tipo "Alcance de la herramienta" o "Delimitación del análisis".
  También puede reforzarse en la delimitación del **Capítulo I**.
- **Las LIMITACIONES:** van bien al final del **Capítulo IV (Resultados)** o en el
  **Capítulo V (Conclusiones)**, como "Limitaciones del estudio" y "Trabajo futuro".

---

## Idea central que debes transmitir

Un sistema puede ser vulnerable en varias **capas**, no solo en el código. Tu
herramienta cubre dos de esas capas de forma deliberada y bien definida; las demás
quedan explícitamente fuera de alcance. **Definir esa frontera es una fortaleza
metodológica, no una debilidad.**

## 1. El modelo de capas (puedes incluir esta tabla)

| Capa | Dónde vive la falla | ¿La herramienta la cubre? |
|---|---|---|
| Código propio | SQL, XSS, eval, comandos... | Sí (Regex, Bandit, Semgrep) |
| Dependencias | Librerías con CVE conocidos | Sí (OSV) |
| Configuración | DEBUG activo, CORS, permisos | Parcial |
| Secretos expuestos | API keys, contraseñas en el código | Parcial |
| Infraestructura / runtime | Servidor, puertos, app en ejecución | No (fuera de alcance) |

## 2. Las tres familias de análisis (concepto clave)

| Familia | Qué hace | ¿La herramienta? |
|---|---|---|
| SAST (estático) | Analiza el código sin ejecutarlo | Sí |
| SCA (composición) | Revisa las dependencias | Sí (OSV) |
| DAST (dinámico) | Ataca la aplicación en ejecución | No |

[Eloy: aquí explica con tus palabras que tu herramienta es SAST + SCA, y que DAST
—como OWASP ZAP o Burp Suite— requiere levantar la app y atacarla, lo cual excede
el alcance de un analizador estático.]

## 3. Mapeo con OWASP Top 10 (respaldo académico)

[Eloy: menciona que usaste el OWASP Top 10 como marco de referencia y muestra qué
categorías cubres. Cubres total o parcialmente: A02, A03, A05, A06, A08. No cubres:
A01, A04, A07, A09, A10, porque requieren análisis dinámico o de diseño.]

## 4. Declaración de alcance (frase plantilla para reescribir)

> "La herramienta desarrollada realiza análisis estático de seguridad (SAST) y
> análisis de composición de software (SCA). En consecuencia, detecta
> vulnerabilidades en el código fuente y en las dependencias de terceros, pero no
> evalúa la aplicación en tiempo de ejecución ni la configuración de la
> infraestructura, lo cual corresponde al análisis dinámico (DAST) y queda fuera del
> alcance de este estudio."

## 5. Limitaciones a declarar honestamente

- Los patrones Regex generan **falsos positivos** (analizan texto, no contexto).
  [Eloy: preséntalo como hallazgo metodológico, no como defecto oculto.]
- El motor OSV requiere **conexión a internet**.
- La puntuación de riesgo (0-100) es una **heurística propia** inspirada en CVSS, no
  una medida objetiva universal.
- La detección de dependencias hoy solo lee `requirements.txt` (Python).
- No se evalúa configuración de servidores ni comportamiento en ejecución.

## 6. Trabajo futuro (convierte las limitaciones en propuestas)

- Integrar análisis dinámico (DAST) con OWASP ZAP.
- Escaneo de secretos en todo el proyecto y en el historial de Git.
- Detección de configuraciones inseguras (`.env` expuesto, claves débiles).
- Soporte de dependencias en npm (`package.json`) y PHP (`composer.json`).

---

## Fuentes que puedes citar aquí

- OWASP Top 10 (2021) — para las categorías de vulnerabilidad. owasp.org
- Definiciones SAST / DAST / SCA — OWASP o NIST.
- Pearce et al. (2022) — ya en tu marco teórico, refuerza el "por qué" del código IA.

[Eloy: verifica cada cita en su fuente original antes de entregar.]

---

## Vínculos

- [[limitaciones]] — Limitaciones técnicas de la herramienta
- [[arquitectura]] — Los 4 motores y su alcance
- [[proyecto]] — Visión general
