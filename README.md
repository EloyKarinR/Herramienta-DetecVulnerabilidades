# Auditor-IA

Herramienta de línea de comandos que **audita la seguridad del código generado por
asistentes de IA** (ChatGPT, GitHub Copilot, Gemini, Claude).

La IA escribe código rápido, pero no siempre seguro. Esta herramienta revisa tu
proyecto y te dice **qué vulnerabilidades tiene, por qué son peligrosas y cómo
corregirlas**, en un reporte PDF en español.

> Desarrollada como parte de una monografía de grado en la Licenciatura en
> Informática del CRUBO, Universidad de Panamá.

---

## Cómo se usa (3 pasos)

**1. Clona la herramienta**
```bash
git clone https://github.com/EloyKarinR/Herramienta-DetecVulnerabilidades.git
cd Herramienta-DetecVulnerabilidades
```

**2. Apúntala a tu proyecto**
```bash
python auditoria.py --proyecto C:\ruta\a\mi-sistema
```

**3. Abre el reporte**

Se genera un PDF dentro de la carpeta de tu proyecto:
`reporte_auditoria_AAAA-MM-DD.pdf`

**No necesitas instalar nada más.** La primera vez, la herramienta instala sus
dependencias sola (tarda un par de minutos). Tampoco necesitas ejecutar tu sistema
ni tener la base de datos levantada: solo lee el código.

### Requisitos
- Python 3.8 o superior
- Conexión a internet (para analizar las dependencias)

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

El repositorio incluye un proyecto de prueba con vulnerabilidades a propósito:

```bash
python auditoria.py --proyecto pruebas/proyecto_vulnerable
```

Y las pruebas automáticas de la herramienta:

```bash
python -m unittest test_auditoria -v
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
