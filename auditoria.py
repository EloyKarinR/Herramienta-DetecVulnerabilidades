import argparse
import json
import os
import re
import subprocess
import sys

EXTENSIONES_CODIGO = (".py", ".php", ".js", ".java", ".ts", ".c", ".cpp", ".h")
CARPETAS_IGNORADAS = {"node_modules", "vendor", "venv", ".venv", ".git", "__pycache__"}

REGLAS = [
    {
        "id": "SEC-01",
        "nombre": "Inyección SQL",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "cvss": 9.8,
        "severidad": "Alta",
        "patron": r"(SELECT|INSERT|UPDATE|DELETE).*(\+|\.|%|f\"|f').*",
        "correccion": "Usar consultas parametrizadas (prepared statements).",
    },
    {
        "id": "SEC-02",
        "nombre": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "cvss": 8.8,
        "severidad": "Alta",
        "patron": r"(echo|print|innerHTML|document\.write).*(\+|\.|\$_|f\"|f').*",
        "correccion": "Escapar y sanitizar toda salida que incluya datos del usuario. Usar plantillas seguras del framework.",
    },
    {
        "id": "SEC-03",
        "nombre": "Credencial quemada en el código",
        "owasp": "A07:2021",
        "cwe": "CWE-798",
        "cvss": 7.5,
        "severidad": "Media-Alta",
        "patron": r"(password|passwd|api_key|apikey|secret|token)\s*[=:]\s*[\"'][^\"']+[\"']",
        "correccion": "Mover secretos a variables de entorno o a un gestor de secretos. Nunca escribir credenciales en el código fuente.",
    },
    {
        "id": "SEC-04",
        "nombre": "Inyección de comandos del sistema",
        "owasp": "A03:2021",
        "cwe": "CWE-78",
        "cvss": 9.8,
        "severidad": "Alta",
        "patron": r"(os\.system|subprocess\.call|subprocess\.run|popen)\s*\(.*(\+|f\"|f').*",
        "correccion": "No pasar datos del usuario a comandos del sistema. Usar listas de argumentos en subprocess sin shell=True.",
    },
    {
        "id": "SEC-05",
        "nombre": "Path Traversal (acceso a rutas arbitrarias)",
        "owasp": "A01:2021",
        "cwe": "CWE-22",
        "cvss": 7.5,
        "severidad": "Alta",
        "patron": r"open\s*\(.*(\+|f\"|f'|request\.|input\().*",
        "correccion": "Validar y normalizar rutas con os.path.abspath(). Verificar que la ruta resultante esté dentro del directorio permitido.",
    },
    {
        "id": "SEC-06",
        "nombre": "Modo debug activo en producción",
        "owasp": "A05:2021",
        "cwe": "CWE-489",
        "cvss": 5.3,
        "severidad": "Media",
        "patron": r"(DEBUG|debug)\s*=\s*True",
        "correccion": "Deshabilitar el modo debug en producción. Controlar esta configuración con variables de entorno.",
    },
    {
        "id": "SEC-07",
        "nombre": "Deserialización insegura",
        "owasp": "A08:2021",
        "cwe": "CWE-502",
        "cvss": 9.8,
        "severidad": "Alta",
        "patron": r"(pickle\.loads|yaml\.load\s*\()",
        "correccion": "No deserializar datos de fuentes no confiables. Reemplazar yaml.load() por yaml.safe_load().",
    },
    {
        "id": "SEC-08",
        "nombre": "Uso de eval() con datos externos",
        "owasp": "A03:2021",
        "cwe": "CWE-95",
        "cvss": 9.8,
        "severidad": "Alta",
        "patron": r"eval\s*\(.*(\+|f\"|f'|input\(|request\.).*",
        "correccion": "Evitar eval() con datos externos. Para datos simples usar ast.literal_eval().",
    },
    {
        "id": "SEC-09",
        "nombre": "Algoritmo criptográfico débil",
        "owasp": "A02:2021",
        "cwe": "CWE-327",
        "cvss": 7.5,
        "severidad": "Media-Alta",
        "patron": r"(hashlib\.md5|hashlib\.sha1)\s*\(",
        "correccion": "Usar SHA-256 o superior para integridad. Para contraseñas usar bcrypt, argon2 o PBKDF2.",
    },
]


def es_comentario(linea):
    limpia = linea.strip()
    return limpia.startswith(("#", "//", "*", "/*", "<!--"))


def buscar_archivos_codigo(ruta):
    archivos_encontrados = []
    for carpeta_actual, subcarpetas, archivos in os.walk(ruta):
        subcarpetas[:] = [s for s in subcarpetas if s not in CARPETAS_IGNORADAS]
        for archivo in archivos:
            if archivo.endswith(EXTENSIONES_CODIGO):
                ruta_completa = os.path.join(carpeta_actual, archivo)
                archivos_encontrados.append(ruta_completa)
    return archivos_encontrados


def detectar_por_regex(ruta_archivo, regla):
    hallazgos = []
    patron = re.compile(regla["patron"], re.IGNORECASE)
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for numero_linea, linea in enumerate(f, start=1):
                if not es_comentario(linea) and patron.search(linea):
                    hallazgos.append({
                        "archivo": ruta_archivo,
                        "linea": numero_linea,
                        "codigo": linea.strip(),
                        "regla": regla["id"],
                        "nombre": regla["nombre"],
                        "severidad": regla["severidad"],
                        "owasp": regla["owasp"],
                        "cwe": regla["cwe"],
                        "cvss": regla["cvss"],
                        "correccion": regla["correccion"],
                    })
    except Exception as e:
        print(f"  (No se pudo leer {ruta_archivo}: {e})")
    return hallazgos


SEVERIDAD_BANDIT = {
    "HIGH":   "Alta",
    "MEDIUM": "Media",
    "LOW":    "Baja",
}

SEVERIDAD_SEMGREP = {
    "ERROR":   "Alta",
    "WARNING": "Media",
    "INFO":    "Baja",
}


def detectar_con_bandit(ruta):
    hallazgos = []
    try:
        exclusiones = ",".join(CARPETAS_IGNORADAS)
        resultado = subprocess.run(
            [sys.executable, "-m", "bandit", "-r", ruta, "-f", "json", "-q",
             "--exclude", exclusiones],
            capture_output=True,
            text=True,
            timeout=120,
        )
        datos = json.loads(resultado.stdout)
        for r in datos.get("results", []):
            hallazgos.append({
                "archivo": r["filename"],
                "linea": r["line_number"],
                "codigo": r["code"].strip(),
                "regla": r["test_id"],
                "nombre": r["issue_text"],
                "severidad": SEVERIDAD_BANDIT.get(r["issue_severity"], r["issue_severity"]),
                "owasp": "Ver https://bandit.readthedocs.io",
                "cwe": "",
                "cvss": "",
                "correccion": r.get("more_info", "Ver documentación de Bandit."),
                "motor": "Bandit",
            })
    except FileNotFoundError:
        print("  (Bandit no está instalado, omitiendo análisis Python avanzado)")
    except Exception as e:
        print(f"  (Error al ejecutar Bandit: {e})")
    return hallazgos


def detectar_con_semgrep(ruta):
    hallazgos = []
    exclusiones = [arg for c in CARPETAS_IGNORADAS for arg in ["--exclude", c]]
    try:
        resultado = subprocess.run(
            [sys.executable, "-m", "semgrep", "scan",
             "--config", "p/owasp-top-ten",
             "--json", "--quiet",
             *exclusiones,
             ruta],
            capture_output=True,
            text=True,
            timeout=180,
        )
        datos = json.loads(resultado.stdout)
        for r in datos.get("results", []):
            meta = r["extra"].get("metadata", {})
            hallazgos.append({
                "archivo":    r["path"],
                "linea":      r["start"]["line"],
                "codigo":     r["extra"].get("lines", "").strip(),
                "regla":      r["check_id"].split(".")[-1].upper(),
                "nombre":     r["extra"]["message"],
                "severidad":  SEVERIDAD_SEMGREP.get(r["extra"]["severity"], "Media"),
                "owasp":      ", ".join(meta.get("owasp", ["—"])),
                "cwe":        ", ".join(meta.get("cwe", ["—"])),
                "cvss":       str(meta.get("cvss-score", "—")),
                "correccion": "Ver https://semgrep.dev/r para detalles de esta regla.",
                "motor":      "Semgrep",
            })
    except FileNotFoundError:
        print("  (Semgrep no está instalado, omitiendo análisis multi-lenguaje)")
    except Exception as e:
        print(f"  (Error al ejecutar Semgrep: {e})")
    return hallazgos


def main():
    parser = argparse.ArgumentParser(
        description="Herramienta de auditoría de seguridad para código generado por IA"
    )
    parser.add_argument("--proyecto", required=True,
                        help="Ruta a la carpeta del proyecto a analizar")
    args = parser.parse_args()

    ruta = args.proyecto

    if not os.path.isdir(ruta):
        print(f"Error: no se encontró la carpeta '{ruta}'")
        return

    print(f"Proyecto encontrado en: {ruta}")
    archivos = buscar_archivos_codigo(ruta)
    print(f"Se encontraron {len(archivos)} archivos de código.\n")

    hay_python = any(a.endswith(".py") for a in archivos)
    hay_otros  = any(a.endswith((".php", ".js", ".java", ".ts", ".c", ".cpp", ".h")) for a in archivos)

    print("Motores activos:")
    print(f"  {'✓' if hay_python else '✗'} Bandit   (Python / Django / Flask)")
    print(f"  {'✓' if hay_otros  else '✗'} Semgrep  (PHP, JavaScript, Java, TypeScript, C/C++)")
    print(f"  ✓ Regex    (todos los lenguajes)\n")

    todos_los_hallazgos = []

    if hay_python:
        print("Ejecutando Bandit...")
        todos_los_hallazgos.extend(detectar_con_bandit(ruta))

    if hay_otros:
        print("Ejecutando Semgrep...")
        todos_los_hallazgos.extend(detectar_con_semgrep(ruta))

    print("Ejecutando análisis por Regex...")
    for archivo in archivos:
        for regla in REGLAS:
            todos_los_hallazgos.extend(detectar_por_regex(archivo, regla))

    if todos_los_hallazgos:
        print(f"Se encontraron {len(todos_los_hallazgos)} posibles vulnerabilidades:\n")
        for h in todos_los_hallazgos:
            print(f"[{h['severidad']}] {h['regla']} - {h['nombre']}")
            print(f"  OWASP: {h['owasp']}  |  {h['cwe']}  |  CVSS: {h['cvss']}")
            print(f"  Archivo: {h['archivo']} (línea {h['linea']})")
            print(f"  Código:  {h['codigo']}")
            print(f"  Corrección: {h['correccion']}\n")
    else:
        print("No se encontraron vulnerabilidades con las reglas actuales.")


if __name__ == "__main__":
    main()
