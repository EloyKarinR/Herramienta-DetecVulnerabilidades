# Arquitectura de la Herramienta

## Flujo general

```
python auditoria.py --proyecto ./mi-sistema
         │
         ▼
1. Descubrir archivos de código
   (.py, .php, .js, .java, .ts)
   Ignora: node_modules, venv, .git, __pycache__
         │
         ▼
2. Detectar qué tiene el proyecto
   ¿Hay .py?  → activar Bandit
   ¿Hay .php/.js/.java/.ts/.c/.cpp? → activar Semgrep
   ¿Hay requirements.txt? → activar OSV
   Siempre → activar Regex propio
         │
         ▼
3. Ejecutar motores activos
   ├── Bandit  → hallazgos Python
   ├── Semgrep → hallazgos PHP/JS/Java/TS/C
   ├── OSV     → dependencias vulnerables (CVE)
   └── Regex   → hallazgos complementarios
         │
         ▼
4. Unificar los hallazgos + marcar archivos sensibles
   + ordenar (sensibles primero, luego por severidad)
         │
         ▼
5. Calcular puntuación de riesgo (0-100 + nivel)
         │
         ▼
6. Generar reporte PDF
   con riesgo + impacto + correcciones
```

---

## Estructura de un hallazgo (formato interno)

```python
{
    "archivo":    "ruta/al/archivo.py",
    "linea":      12,
    "codigo":     "consulta = 'SELECT * FROM...' + nombre",
    "regla":      "SEC-01",
    "nombre":     "Inyección SQL",
    "severidad":  "Alta",
    "owasp":      "A03:2021",
    "cwe":        "CWE-89",
    "cvss":       9.8,
    "correccion": "Usar consultas parametrizadas.",
    "impacto":    "Un atacante podria leer o borrar toda la base de datos...",
    "motor":      "Regex",
    "sensible":   True   # True si el archivo tiene nombre critico (login, db...)
}
```

---

## Motores de detección

### Motor 1: Regex (propio)
- Analiza cada línea del archivo como texto
- Compara contra patrones (expresiones regulares)
- Funciona en todos los lenguajes
- Limitación: puede generar falsos positivos

### Motor 2: Bandit (Python)
- Analiza archivos `.py` usando AST (Árbol de Sintaxis Abstracta)
- Entiende la estructura real del código, no solo texto
- 70+ reglas de seguridad para Python
- Se activa solo si hay archivos `.py` en el proyecto

### Motor 3: Semgrep (multi-lenguaje)
- Analiza PHP, JavaScript, Java, TypeScript, C/C++
- Miles de reglas basadas en OWASP Top 10
- Se activa solo si hay archivos de esos lenguajes
- Requiere conexión a internet la primera vez

### Motor 4: OSV (dependencias vulnerables - SCA)
- Lee `requirements.txt` y extrae nombre + versión de cada librería
- Consulta la API gratuita de Google OSV (sin API key) por cada una
- Detecta librerías con CVE conocidos → cubre OWASP A06:2021
- Agrupa por librería (una tarjeta con el conteo de CVE, no una por CVE)
- Severidad dinámica: más de 10 CVE = Alta, de 1 a 10 = Media-Alta
- Se activa solo si hay `requirements.txt`. Requiere internet.

---

## Puntuación de riesgo (calcular_riesgo)

Suma ponderada por severidad, acotada a 100:

| Severidad | Peso |
|---|---|
| Alta | 10 |
| Media-Alta | 5 |
| Media | 2 |
| Baja | 1 |

`puntaje = min(100, suma)`. Luego se traduce a nivel:
- 0 = Sin riesgo · 1-25 = Bajo · 26-50 = Medio · 51-75 = Alto · 76-100 = Crítico

Los pesos se inspiran en la escala CVSS (0-10). Es una convención metodológica propia
y defendible, no una ley universal.

## Priorización de archivos sensibles

`es_archivo_sensible()` marca los hallazgos cuyo archivo tiene un nombre crítico
(login, auth, db, config, admin, usuario...). Esos hallazgos se etiquetan
`[ARCHIVO SENSIBLE]` y se ordenan primero, luego por severidad.

## Reporte que educa (campo impacto)

Cada hallazgo lleva una explicación del daño real en lenguaje claro. Las 9 reglas
Regex tienen su impacto propio; Bandit/Semgrep/OSV usan uno genérico según severidad
(`obtener_impacto()`).

---

## Autoexclusión de la herramienta

```python
CARPETA_HERRAMIENTA = os.path.dirname(os.path.abspath(__file__))
```

Cuando el estudiante clona la herramienta dentro de su proyecto y ejecuta `python auditoria.py --proyecto ..`, la herramienta detecta automáticamente su propia carpeta y la excluye del escaneo. Así nunca se audita a sí misma.

## Archivos del proyecto

```
auditor-ia/
  auditoria.py      ← programa principal (orquestador)
  ejemplo_vulne.py  ← archivo de prueba con vulnerabilidades
  requirements.txt  ← dependencias (bandit, semgrep, fpdf2)
  .gitignore        ← excluye venv, __pycache__, PDFs generados
  CLAUDE.md         ← contexto del proyecto para Claude Code
  docs/             ← esta carpeta (documentación en Obsidian)
  README.md         ← instrucciones para GitHub (pendiente)
```

---

## Vínculos

- [[proyecto]] — Visión general
- [[protocolo]] — Las reglas SEC-01 a SEC-09
- [[limitaciones]] — Lo que la herramienta NO puede hacer
