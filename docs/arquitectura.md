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
2. Detectar lenguajes presentes
   ¿Hay .py?  → activar Bandit
   ¿Hay .php/.js/.java/.ts? → activar Semgrep
   Siempre → activar Regex propio
         │
         ▼
3. Ejecutar motores activos
   ├── Bandit  → hallazgos Python
   ├── Semgrep → hallazgos PHP/JS/Java/TS
   └── Regex   → hallazgos complementarios
         │
         ▼
4. Unificar todos los hallazgos
   (mismo formato interno)
         │
         ▼
5. Generar reporte PDF
   con hallazgos + correcciones
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
    "motor":      "Regex"
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
- Analiza PHP, JavaScript, Java, TypeScript
- Miles de reglas basadas en OWASP Top 10
- Se activa solo si hay archivos de esos lenguajes
- Requiere conexión a internet la primera vez

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
