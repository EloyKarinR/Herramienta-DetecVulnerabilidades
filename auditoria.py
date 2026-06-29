import argparse
import json
import os
import re
import subprocess
import sys
from datetime import date

try:
    from fpdf import FPDF
except ImportError:
    print("Instalando dependencias por primera vez, espera un momento...")
    subprocess.run(
        [sys.executable, "-m", "pip", "install", "fpdf2", "bandit", "semgrep"],
        check=True
    )
    from fpdf import FPDF

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


COLORES_SEVERIDAD = {
    "Alta":       (220, 53,  69),
    "Media-Alta": (253, 126, 20),
    "Media":      (255, 193,  7),
    "Baja":       (40,  167, 69),
}

MESES = {
    1: "enero", 2: "febrero", 3: "marzo",    4: "abril",
    5: "mayo",  6: "junio",   7: "julio",    8: "agosto",
    9: "septiembre", 10: "octubre", 11: "noviembre", 12: "diciembre",
}

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


def generar_reporte_pdf(hallazgos, ruta_proyecto):
    hoy = date.today()
    fecha_str = f"{hoy.day} de {MESES[hoy.month]} de {hoy.year}"

    conteo = {"Alta": 0, "Media-Alta": 0, "Media": 0, "Baja": 0}
    for h in hallazgos:
        sev = h.get("severidad", "Baja")
        conteo[sev] = conteo.get(sev, 0) + 1
    total = len(hallazgos)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── PORTADA ──────────────────────────────────────────────
    pdf.add_page()
    pdf.ln(25)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(30, 30, 30)
    pdf.multi_cell(0, 12, "REPORTE DE AUDITORÍA DE SEGURIDAD", align="C")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(100, 100, 100)
    pdf.multi_cell(0, 8, "Herramienta Auditor-IA v0.1", align="C")
    pdf.ln(12)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(60, 60, 60)
    pdf.multi_cell(0, 7, f"Proyecto auditado: {ruta_proyecto}", align="C")
    pdf.multi_cell(0, 7, f"Fecha: {fecha_str}", align="C")
    pdf.ln(12)
    r, g, b = (220, 53, 69) if total > 0 else (40, 167, 69)
    pdf.set_font("Helvetica", "B", 52)
    pdf.set_text_color(r, g, b)
    pdf.multi_cell(0, 22, str(total), align="C")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(80, 80, 80)
    pdf.multi_cell(0, 8, "vulnerabilidades detectadas", align="C")

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 9, "  RESUMEN EJECUTIVO", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(0, 7,
        "Este reporte presenta los resultados del análisis de seguridad automatizado "
        "realizado sobre el proyecto indicado. Las vulnerabilidades fueron detectadas "
        "mediante tres motores: análisis por expresiones regulares (Regex), Bandit para "
        "Python y Semgrep para múltiples lenguajes. Se recomienda corregir las "
        "vulnerabilidades de severidad Alta antes de llevar el sistema a producción."
    )
    pdf.ln(8)

    pdf.set_font("Helvetica", "B", 10)
    pdf.set_fill_color(230, 230, 230)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(120, 8, "  Severidad", border=1, fill=True)
    pdf.cell(50,  8, "Total", border=1, fill=True, align="C")
    pdf.ln()

    for severidad, cantidad in conteo.items():
        r, g, b = COLORES_SEVERIDAD.get(severidad, (150, 150, 150))
        pdf.set_fill_color(r, g, b)
        pdf.set_text_color(255, 255, 255)
        pdf.set_font("Helvetica", "B", 10)
        pdf.cell(120, 8, f"  {severidad}", border=1, fill=True)
        pdf.cell(50,  8, str(cantidad), border=1, fill=True, align="C")
        pdf.ln()

    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(120, 8, "  TOTAL", border=1, fill=True)
    pdf.cell(50,  8, str(total), border=1, fill=True, align="C")
    pdf.ln(12)

    if total == 0:
        pdf.set_font("Helvetica", "", 11)
        pdf.set_text_color(40, 167, 69)
        pdf.multi_cell(0, 7, "No se encontraron vulnerabilidades en el proyecto analizado.")

    # ── HALLAZGOS DETALLADOS ──────────────────────────────────
    if hallazgos:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(0, 9, "  HALLAZGOS DETALLADOS", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        for h in hallazgos:
            if pdf.get_y() > 240:
                pdf.add_page()

            r, g, b = COLORES_SEVERIDAD.get(h["severidad"], (150, 150, 150))

            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
            etiqueta = f"  [{h['severidad']}]  {h['regla']} — {h['nombre']}"
            pdf.multi_cell(0, 8, etiqueta, fill=True)

            pdf.set_fill_color(248, 248, 248)
            pdf.set_text_color(50, 50, 50)
            pdf.set_font("Helvetica", "", 9)

            owasp = h.get("owasp", "")
            cwe   = h.get("cwe", "")
            cvss  = h.get("cvss", "")
            if owasp or cwe or cvss:
                pdf.multi_cell(0, 6,
                    f"  OWASP: {owasp}   |   CWE: {cwe}   |   CVSS: {cvss}",
                    fill=True)

            motor   = h.get("motor", "Regex")
            archivo = h["archivo"]
            linea   = h["linea"]
            pdf.multi_cell(0, 6,
                f"  Motor: {motor}   |   Archivo: {archivo} (línea {linea})",
                fill=True)

            pdf.set_font("Courier", "", 8)
            pdf.set_fill_color(235, 235, 235)
            pdf.multi_cell(0, 6, f"  {h['codigo']}", fill=True)

            pdf.set_font("Helvetica", "", 9)
            pdf.set_fill_color(232, 245, 233)
            pdf.set_text_color(27, 94, 32)
            pdf.multi_cell(0, 6, f"  Corrección: {h['correccion']}", fill=True)

            pdf.set_text_color(0, 0, 0)
            pdf.ln(4)

    nombre_pdf = f"reporte_auditoria_{hoy.strftime('%Y-%m-%d')}.pdf"
    ruta_pdf   = os.path.join(ruta_proyecto, nombre_pdf)
    pdf.output(ruta_pdf)
    return ruta_pdf


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

    print("\nGenerando reporte PDF...")
    ruta_pdf = generar_reporte_pdf(todos_los_hallazgos, ruta)
    print(f"Reporte guardado en: {ruta_pdf}")


if __name__ == "__main__":
    main()
