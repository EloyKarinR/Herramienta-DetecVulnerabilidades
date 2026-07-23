import argparse
import json
import os
import re
import shutil
import subprocess
import sys
from datetime import date
import importlib.util

# La consola de Windows suele usar cp1252, que no sabe imprimir simbolos como
# los checks ni las tildes, y la herramienta reventaba con UnicodeEncodeError.
# Forzamos UTF-8; errors="replace" garantiza que nunca truene por un caracter.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass



def verificar_dependencias():
    paquetes = {
        "fpdf":     "fpdf2",
        "bandit":   "bandit",
        "semgrep":  "semgrep",
        "requests": "requests",
    }
    faltantes = [
        pip_name
        for modulo, pip_name in paquetes.items()
        if importlib.util.find_spec(modulo) is None
    ]
    if faltantes:
        print(f"Instalando dependencias faltantes: {', '.join(faltantes)}...")
        subprocess.run(
            [sys.executable, "-m", "pip", "install"] + faltantes,
            check=True
        )
        print()

verificar_dependencias()
from fpdf import FPDF
import requests

EXTENSIONES_CODIGO = (".py", ".php", ".js", ".java", ".ts", ".c", ".cpp", ".h")
# Carpetas que NO se auditan: entornos, control de versiones y librerías de
# terceros (el estudiante no escribió ese código, así que no es su responsabilidad).
# Se comparan en minúsculas para que "PHPMailer" o "Libs" también se ignoren.
CARPETAS_IGNORADAS = {
    "node_modules", "vendor", "vendors", "venv", ".venv", ".git",
    "__pycache__", "libs", "phpmailer", "third_party", "packages",
}
# Librerías de terceros que suelen venir SUELTAS (fuera de vendor/): no las escribió
# el autor, así que sus "vulnerabilidades" son ruido. Se comparan como subcadena del
# nombre en minúsculas (ej: "bootstrap.bundle.js" contiene "bootstrap").
LIBRERIAS_DE_TERCEROS = (
    "bootstrap", "jquery", "popper", "fpdf", "tcpdf", "dompdf", "quagga",
    "select2", "datatables", "moment", "chart", "sweetalert", "fullcalendar",
    "axios", "lodash", "underscore", "highcharts", "leaflet", "tinymce",
    "ckeditor", "swiper", "modernizr", "slick",
)
CARPETA_HERRAMIENTA = os.path.dirname(os.path.abspath(__file__))

# Palabras clave en nombres de archivo que sugieren funciones críticas del
# sistema (autenticación, base de datos, configuración, administración). Los
# hallazgos en estos archivos se priorizan en el reporte.
ARCHIVOS_SENSIBLES = {
    "login", "auth", "session", "password", "credencial", "secret",
    "db", "database", "conexion", "config", "settings",
    "admin", "usuario", "user",
}

REGLAS = [
    {
        "id": "SEC-01",
        "nombre": "Inyección SQL",
        "owasp": "A03:2021",
        "cwe": "CWE-89",
        "cvss": 9.8,
        "severidad": "Alta",
        # Exige una consulta SQL REAL (una palabra clave con su estructura:
        # SELECT..FROM, INSERT INTO, UPDATE..SET, DELETE..FROM) Y ADEMÁS una señal
        # de concatenación de variable: comilla seguida de + o . (Python/PHP),
        # un f-string, o un marcador de formato (%s, .format). Así se evita
        # confundir "querySelector" de JS o un <select> de HTML con SQL.
        "patron": r"(SELECT.+FROM|INSERT\s+INTO|UPDATE.+SET|DELETE.+FROM).*([\"']\s*[.+]|f[\"']|%[sd]|\.format\()",
        # Descarta consultas preparadas (seguras), código JavaScript del DOM y los
        # import/export de módulos (JS/TS): "import {...DELETE...} from './ruta'" no
        # es SQL, aunque contenga las palabras DELETE/SELECT y una ruta './...'.
        "anti_patron": r"(prepare\s*\(|->prepare|querySelector|getElementById|addEventListener|\bimport\s|\bexport\s|\brequire\s*\(|\bfrom\s+[\"'])",
        "correccion": "Usar consultas parametrizadas (prepared statements).",
        "impacto": "Un atacante podria leer, modificar o borrar toda la base de datos "
                   "(por ejemplo, los datos de todos los estudiantes) sin conocer ninguna contrasena.",
    },
    {
        "id": "SEC-02",
        "nombre": "Cross-Site Scripting (XSS)",
        "owasp": "A03:2021",
        "cwe": "CWE-79",
        "cvss": 8.8,
        "severidad": "Alta",
        # Exige una salida (echo/print/innerHTML/document.write) que realmente
        # incluya una VARIABLE: una comilla seguida de concatenación (. o +) y una
        # variable, o una superglobal de PHP ($_GET/$_POST...), o un f-string.
        # Antes el patrón marcaba cualquier punto, incluido el punto final de un
        # texto fijo ("Usuario no encontrado."), lo que causaba muchos falsos positivos.
        "patron": r"(echo|print|innerHTML|outerHTML|document\.write).*([\"']\s*[.+]\s*\$?\w|\$_(GET|POST|REQUEST|COOKIE|SESSION)|f[\"']|\$\{)|(innerHTML|outerHTML)\s*\+?=\s*[A-Za-z_$]",
        # Descarta salidas ya escapadas, datos del sistema, y salida a CONSOLA
        # (PHP_EOL, STDOUT, fwrite): un echo con PHP_EOL es un script de terminal
        # (CLI), no una página web, así que no puede ser XSS.
        "anti_patron": r"(htmlspecialchars|htmlentities|urlencode|real_escape|toLocaleTimeString|toLocaleDateString|include\s*\(|PHP_EOL|\bSTDOUT\b|\bSTDERR\b|fwrite\s*\()",
        # XSS es una vulnerabilidad web; no aplica a scripts Python de consola
        # (un print() va a la terminal, no al HTML de un navegador).
        "no_extensiones": (".py",),
        "correccion": "Escapar y sanitizar toda salida que incluya datos del usuario. Usar plantillas seguras del framework.",
        "impacto": "Un atacante podria inyectar codigo malicioso que se ejecuta en el navegador "
                   "de otros usuarios, robando sus sesiones o redirigiendolos a sitios falsos.",
    },
    {
        "id": "SEC-03",
        "nombre": "Credencial quemada en el código",
        "owasp": "A07:2021",
        "cwe": "CWE-798",
        "cvss": 7.5,
        "severidad": "Media-Alta",
        "patron": r"(password|passwd|api_key|apikey|secret|token)\s*[=:]\s*[\"'][^\"']+[\"']",
        # No es una credencial quemada si el valor se GENERA (randomUUID, crypto) o
        # viene de una variable de entorno (process.env, getenv) — eso es lo correcto.
        "anti_patron": r"(randomUUID|crypto\.|uuid|faker|process\.env|import\.meta\.env|getenv)",
        "correccion": "Mover secretos a variables de entorno o a un gestor de secretos. Nunca escribir credenciales en el código fuente.",
        "impacto": "Cualquiera con acceso al codigo (o a tu repositorio de GitHub) obtiene estas "
                   "claves y puede suplantar tu sistema o acceder a servicios pagos a tu nombre.",
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
        "impacto": "Un atacante podria ejecutar comandos arbitrarios en el servidor, tomando "
                   "control total de la maquina donde corre el sistema.",
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
        "impacto": "Un atacante podria leer archivos sensibles del servidor (contrasenas, "
                   "configuraciones) manipulando la ruta que envia al sistema.",
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
        "impacto": "Con el modo debug activo, ante cualquier error el sistema muestra al publico "
                   "detalles internos (rutas, codigo, variables) que facilitan un ataque.",
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
        "impacto": "Un atacante podria enviar datos manipulados que, al ser procesados, ejecuten "
                   "codigo malicioso en el servidor.",
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
        "impacto": "Un atacante podria hacer que el sistema ejecute cualquier codigo que el "
                   "escriba, comprometiendo por completo la aplicacion.",
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
        "impacto": "MD5 y SHA-1 estan rotos: un atacante puede descifrar las contrasenas "
                   "guardadas con ellos y acceder a las cuentas de los usuarios.",
    },
]

# Formatos reales de claves y tokens de servicios conocidos. A diferencia de
# SEC-03 (que busca la palabra "password"), aquí buscamos el patrón exacto de
# cada tipo de secreto, lo que da alta precisión y casi cero falsos positivos.
SECRETOS_CONOCIDOS = [
    {"nombre": "AWS Access Key ID",   "patron": r"AKIA[0-9A-Z]{16}"},
    {"nombre": "GitHub Token",        "patron": r"gh[pousr]_[0-9A-Za-z]{30,}"},
    {"nombre": "Stripe Secret Key",   "patron": r"sk_live_[0-9A-Za-z]{20,}"},
    {"nombre": "Google API Key",      "patron": r"AIza[0-9A-Za-z\-_]{30,}"},
    {"nombre": "Slack Token",         "patron": r"xox[baprs]-[0-9A-Za-z-]{10,}"},
    {"nombre": "Clave privada (PEM)", "patron": r"-----BEGIN [A-Z ]*PRIVATE KEY-----"},
]


def es_comentario(linea):
    limpia = linea.strip()
    return limpia.startswith(("#", "//", "*", "/*", "<!--"))


def es_archivo_sensible(ruta_archivo):
    """Indica si el nombre del archivo sugiere que maneja funciones críticas
    (login, base de datos, configuración, admin...). Un fallo en estos archivos
    suele tener mayor impacto, por eso se priorizan en el reporte.
    """
    nombre = os.path.basename(ruta_archivo).lower()
    return any(clave in nombre for clave in ARCHIVOS_SENSIBLES)


def es_archivo_de_prueba(ruta_archivo):
    """Indica si el archivo es de pruebas (test/spec/mock). Estos archivos
    contienen datos FALSOS por diseño (contraseñas y tokens de mentira como
    'password123'), así que auditarlos genera falsos positivos. Además no son
    código que llegue a producción.
    """
    n = os.path.basename(ruta_archivo).lower()
    return (".test." in n or ".spec." in n or ".mock." in n
            or n.startswith("test_") or n.endswith("_test.py"))


def es_libreria_de_terceros(ruta_archivo):
    """Indica si el archivo es una librería de terceros suelta (Bootstrap, jQuery,
    FPDF...) o un archivo minificado (.min.js/.min.css). El autor no escribió ese
    código, así que auditarlo genera falsos positivos (ej: la constante interna
    'DATA_API_KEY' de Bootstrap marcada como credencial quemada).
    """
    n = os.path.basename(ruta_archivo).lower()
    if n.endswith((".min.js", ".min.css")):
        return True
    return any(lib in n for lib in LIBRERIAS_DE_TERCEROS)


def buscar_archivos_codigo(ruta):
    archivos_encontrados = []
    for carpeta_actual, subcarpetas, archivos in os.walk(ruta):
        if os.path.abspath(carpeta_actual) == CARPETA_HERRAMIENTA:
            subcarpetas[:] = []
            continue
        subcarpetas[:] = [
            s for s in subcarpetas
            if s.lower() not in CARPETAS_IGNORADAS
            and os.path.abspath(os.path.join(carpeta_actual, s)) != CARPETA_HERRAMIENTA
        ]
        for archivo in archivos:
            if (archivo.endswith(EXTENSIONES_CODIGO)
                    and not es_archivo_de_prueba(archivo)
                    and not es_libreria_de_terceros(archivo)):
                ruta_completa = os.path.join(carpeta_actual, archivo)
                archivos_encontrados.append(ruta_completa)
    return archivos_encontrados


def detectar_por_regex(ruta_archivo, regla):
    hallazgos = []
    # Algunas reglas no aplican a ciertos lenguajes. Ej: el XSS (SEC-02) es una
    # vulnerabilidad WEB; un print() de Python escribe en la terminal, no en una
    # página, así que la regla de XSS NO debe evaluarse en archivos .py.
    no_ext = regla.get("no_extensiones")
    if no_ext and ruta_archivo.lower().endswith(no_ext):
        return hallazgos
    patron = re.compile(regla["patron"], re.IGNORECASE)
    # Un "anti-patrón" (opcional) marca líneas que parecen coincidir pero que en
    # realidad son seguras o no son lo que buscamos (p. ej. consultas preparadas,
    # o código JavaScript que contiene la palabra "select"). Si aparece, se
    # descarta el hallazgo: así se reducen los falsos positivos.
    anti = re.compile(regla["anti_patron"], re.IGNORECASE) if regla.get("anti_patron") else None
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for numero_linea, linea in enumerate(f, start=1):
                if es_comentario(linea):
                    continue
                if not patron.search(linea):
                    continue
                if anti and anti.search(linea):
                    continue
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
                        "impacto": regla["impacto"],
                    })
    except Exception as e:
        print(f"  (No se pudo leer {ruta_archivo}: {e})")
    return hallazgos


def detectar_secretos(ruta_archivo):
    """Busca claves y tokens reales de servicios conocidos (AWS, GitHub, Stripe,
    Google, Slack, claves privadas) dentro de un archivo.

    Nota: aquí NO saltamos los comentarios. Un secreto real es un secreto
    filtrado aunque esté comentado, y estos patrones son de alta confianza
    (coinciden con el formato exacto de la clave, no con palabras genéricas).
    """
    hallazgos = []
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for numero_linea, linea in enumerate(f, start=1):
                for secreto in SECRETOS_CONOCIDOS:
                    if re.search(secreto["patron"], linea):
                        hallazgos.append({
                            "archivo": ruta_archivo,
                            "linea": numero_linea,
                            "codigo": linea.strip()[:120],
                            "regla": "SEC-10",
                            "nombre": f"Secreto expuesto: {secreto['nombre']}",
                            "severidad": "Alta",
                            "owasp": "A07:2021",
                            "cwe": "CWE-798",
                            "cvss": 8.6,
                            "correccion": (
                                "Revocar de inmediato el secreto (ya se considera "
                                "comprometido) y moverlo a variables de entorno o a un "
                                "gestor de secretos. Nunca subirlo al repositorio."
                            ),
                            "impacto": (
                                "Cualquiera que vea el codigo o el repositorio puede usar "
                                "esta clave para suplantar tu sistema, acceder a servicios "
                                "pagos a tu nombre o entrar a tus datos."
                            ),
                            "motor": "Secretos",
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


def ruta_semgrep():
    """Localiza el ejecutable de Semgrep.

    Desde Semgrep 1.38 ya NO se puede invocar con "python -m semgrep": responde
    con un aviso de deprecación en vez de resultados. Hay que ejecutar el
    binario directamente, así que primero lo buscamos en el PATH y, si no está
    (caso típico en Windows), lo buscamos junto al intérprete de Python.
    """
    ruta = shutil.which("semgrep")
    if ruta:
        return ruta

    carpeta = os.path.dirname(sys.executable)
    for sub in ("Scripts", "bin", ""):
        for nombre in ("semgrep.exe", "semgrep"):
            posible = os.path.join(carpeta, sub, nombre)
            if os.path.isfile(posible):
                return posible
    return None


def leer_linea_de_archivo(ruta_archivo, numero_linea):
    """Devuelve el contenido de una línea concreta de un archivo.

    Se usa para mostrar el código REAL de un hallazgo de Semgrep cuando este no lo
    entrega: para algunas de sus reglas "Pro", Semgrep devuelve el texto
    'requires login' en vez del código si no se ha hecho `semgrep login`. Como
    Semgrep sí nos da el número de línea, leemos la línea directamente del archivo.
    """
    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as f:
            for i, linea in enumerate(f, start=1):
                if i == numero_linea:
                    return linea.strip()
    except OSError:
        pass
    return ""


def detectar_con_semgrep(ruta):
    hallazgos = []

    ejecutable = ruta_semgrep()
    if not ejecutable:
        print("  [AVISO] No se encontró el ejecutable de Semgrep.")
        print("          El análisis de PHP/JS/Java/C NO se realizó.")
        return hallazgos

    exclusiones = [arg for c in CARPETAS_IGNORADAS for arg in ["--exclude", c]]
    try:
        resultado = subprocess.run(
            [ejecutable, "scan",
             "--config", "p/owasp-top-ten",
             "--json", "--quiet",
             *exclusiones,
             ruta],
            capture_output=True,
            text=True,
            timeout=300,
        )

        # Si no devolvió nada, algo falló: hay que avisarlo, NO callarlo.
        # Un reporte de "0 vulnerabilidades" con un motor caído es un falso
        # "todo está bien", lo más peligroso en una herramienta de auditoría.
        if not resultado.stdout.strip():
            print("  [AVISO] Semgrep no devolvió resultados. El análisis de")
            print("          PHP/JS/Java/C NO se realizó. Detalle:")
            print(f"          {resultado.stderr.strip()[:300]}")
            return hallazgos

        datos = json.loads(resultado.stdout)
        for r in datos.get("results", []):
            meta = r["extra"].get("metadata", {})
            # Semgrep a veces devuelve 'requires login' en vez del código real.
            # En ese caso (o si viene vacío), leemos la línea del archivo nosotros.
            codigo = r["extra"].get("lines", "").strip()
            if not codigo or codigo.lower() == "requires login":
                codigo = leer_linea_de_archivo(r["path"], r["start"]["line"])
            hallazgos.append({
                "archivo":    r["path"],
                "linea":      r["start"]["line"],
                "codigo":     codigo,
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
        print("  [AVISO] Semgrep no está instalado. El análisis de PHP/JS/Java/C NO se realizó.")
    except Exception as e:
        print(f"  [AVISO] Error al ejecutar Semgrep: {e}")
        print("          El análisis de PHP/JS/Java/C NO se realizó.")
    return hallazgos


def leer_dependencias(ruta_proyecto):
    """Lee requirements.txt del proyecto y extrae nombre + versión de cada librería.

    Devuelve una lista de diccionarios como:
        [{"nombre": "Django", "version": "2.0.0", "ecosistema": "PyPI"}, ...]

    Esto es el primer paso del análisis SCA (Software Composition Analysis):
    saber QUÉ librerías usa el proyecto antes de preguntarle a la API OSV
    si esas versiones tienen vulnerabilidades conocidas.
    """
    dependencias = []
    ruta_req = os.path.join(ruta_proyecto, "requirements.txt")

    # Si el proyecto no tiene requirements.txt, no hay nada que analizar
    if not os.path.isfile(ruta_req):
        return dependencias

    with open(ruta_req, "r", encoding="utf-8", errors="ignore") as f:
        for linea in f:
            linea = linea.strip()

            # Saltar líneas vacías y comentarios
            if not linea or linea.startswith("#"):
                continue

            # En requirements.txt la versión se separa con operadores como
            # ==, >=, <=, ~=, !=, >, <   (ej: "Django==2.0.0", "flask>=1.0")
            # re.split parte la línea en esos operadores y nos deja
            # el nombre en la primera posición y la versión en la segunda.
            partes = re.split(r"[=<>!~]+", linea)
            nombre = partes[0].strip()
            version = partes[1].strip() if len(partes) > 1 else ""

            if nombre:
                dependencias.append({
                    "nombre": nombre,
                    "version": version,
                    "ecosistema": "PyPI",
                })

    return dependencias


# Dirección de la API OSV de Google (Open Source Vulnerabilities).
# Es gratuita y no requiere registro ni API key.
OSV_URL = "https://api.osv.dev/v1/query"


def consultar_osv(dependencia):
    """Le pregunta a la API OSV si una librería (nombre + versión) tiene
    vulnerabilidades conocidas.

    Devuelve la lista de vulnerabilidades que reporta OSV. Si la librería
    está limpia o no se pudo consultar, devuelve una lista vacía.
    """
    # Sin versión exacta no podemos consultar con precisión: la saltamos.
    if not dependencia["version"]:
        return []

    # Este es el "formulario" que espera OSV: qué librería y qué versión.
    consulta = {
        "package": {
            "name": dependencia["nombre"],
            "ecosystem": dependencia["ecosistema"],
        },
        "version": dependencia["version"],
    }

    try:
        # POST envía nuestra consulta; timeout evita que se quede colgado.
        respuesta = requests.post(OSV_URL, json=consulta, timeout=15)
        datos = respuesta.json()
        # OSV responde {"vulns": [...]} si hay fallas, o {} si está limpia.
        return datos.get("vulns", [])
    except Exception as e:
        print(f"  (No se pudo consultar OSV para {dependencia['nombre']}: {e})")
        return []


def detectar_dependencias_vulnerables(ruta_proyecto):
    """Análisis SCA completo: lee las dependencias del proyecto, consulta cada
    una en OSV y convierte las vulnerabilidades encontradas al formato de
    hallazgo que usa el resto de la herramienta (para que salgan en el PDF).
    """
    hallazgos = []
    dependencias = leer_dependencias(ruta_proyecto)

    if not dependencias:
        return hallazgos

    print(f"  Analizando {len(dependencias)} dependencias en OSV...")

    for dep in dependencias:
        vulns = consultar_osv(dep)

        # Si la librería está limpia, no generamos hallazgo.
        if not vulns:
            continue

        # Recolectamos el identificador de cada vulnerabilidad. Preferimos el
        # CVE (nombre oficial); si no hay, usamos el id de OSV (GHSA-...).
        identificadores = []
        for v in vulns:
            aliases = v.get("aliases", [])
            cve = next((a for a in aliases if a.startswith("CVE")), v.get("id", "SIN-ID"))
            identificadores.append(cve)

        n = len(vulns)

        # Mostramos los primeros 6 CVE y, si hay más, un "(+N más)".
        muestra = ", ".join(identificadores[:6])
        if n > 6:
            muestra += f"  (+{n - 6} más)"

        # La severidad depende de cuántas fallas acumula la librería:
        # muchas vulnerabilidades = riesgo mayor.
        severidad = "Alta" if n > 10 else "Media-Alta"

        # UN solo hallazgo por librería, con el conteo total de fallas.
        hallazgos.append({
            "archivo": os.path.join(ruta_proyecto, "requirements.txt"),
            "linea": "-",
            "codigo": muestra,
            "regla": "A06 - Dependencia vulnerable",
            "nombre": f"{dep['nombre']} {dep['version']} tiene {n} vulnerabilidad(es) conocida(s)",
            "severidad": severidad,
            "owasp": "A06:2021",
            "cwe": "CWE-1035",
            "cvss": "N/D",
            "correccion": (
                f"Actualizar {dep['nombre']} a una versión más reciente "
                f"que corrija estas vulnerabilidades."
            ),
            "motor": "OSV (dependencias)",
        })

    return hallazgos


def limpiar_pdf(texto):
    return "".join(c if ord(c) < 256 else "?" for c in str(texto))


# Peso de cada severidad para el puntaje de riesgo. Inspirado en la escala
# CVSS (0-10): las fallas graves pesan mucho más que las leves.
PESOS_SEVERIDAD = {
    "Alta":       10,
    "Media-Alta":  5,
    "Media":       2,
    "Baja":        1,
}


def calcular_riesgo(hallazgos):
    """Calcula el nivel de riesgo global del proyecto a partir de los hallazgos.

    Suma el peso de cada hallazgo según su severidad, acota el total a 100 y
    lo traduce a un nivel (Bajo, Medio, Alto, Crítico). Devuelve un diccionario
    con el puntaje, el nivel y el conteo por severidad.
    """
    conteo = {"Alta": 0, "Media-Alta": 0, "Media": 0, "Baja": 0}
    for h in hallazgos:
        sev = h.get("severidad", "Baja")
        conteo[sev] = conteo.get(sev, 0) + 1

    # Suma ponderada y techo de 100.
    puntaje = sum(PESOS_SEVERIDAD.get(sev, 1) * cant for sev, cant in conteo.items())
    puntaje = min(100, puntaje)

    if puntaje == 0:
        nivel = "Sin riesgo detectado"
    elif puntaje <= 25:
        nivel = "Bajo"
    elif puntaje <= 50:
        nivel = "Medio"
    elif puntaje <= 75:
        nivel = "Alto"
    else:
        nivel = "Critico"

    return {
        "puntaje": puntaje,
        "nivel": nivel,
        "conteo": conteo,
        "total": len(hallazgos),
    }


# Impacto genérico según severidad, para los hallazgos de Bandit, Semgrep y
# OSV, que no traen una explicación propia como sí la tienen las reglas Regex.
IMPACTO_POR_SEVERIDAD = {
    "Alta":       "Riesgo grave: podria permitir acceso no autorizado, robo o perdida de datos del sistema.",
    "Media-Alta": "Riesgo considerable: bajo ciertas condiciones un atacante podria comprometer datos o funciones del sistema.",
    "Media":      "Riesgo moderado: es una mala practica que facilita otros ataques si se combina con mas fallas.",
    "Baja":       "Riesgo bajo: conviene corregirlo como buena practica de seguridad.",
}


def obtener_impacto(h):
    """Devuelve la explicación de impacto de un hallazgo: la propia de la regla
    si la tiene (motor Regex), o una genérica según su severidad (otros motores).
    """
    return h.get("impacto") or IMPACTO_POR_SEVERIDAD.get(h.get("severidad", "Baja"), "")


def generar_reporte_pdf(hallazgos, ruta_proyecto):
    hoy = date.today()
    fecha_str = f"{hoy.day} de {MESES[hoy.month]} de {hoy.year}"

    conteo = {"Alta": 0, "Media-Alta": 0, "Media": 0, "Baja": 0}
    for h in hallazgos:
        sev = h.get("severidad", "Baja")
        conteo[sev] = conteo.get(sev, 0) + 1
    total = len(hallazgos)

    # Nivel de riesgo global y color según el nivel
    riesgo = calcular_riesgo(hallazgos)
    COLOR_NIVEL = {
        "Sin riesgo detectado": (40, 167, 69),
        "Bajo":    (40, 167, 69),
        "Medio":   (255, 193, 7),
        "Alto":    (253, 126, 20),
        "Critico": (220, 53, 69),
    }

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)

    # ── PORTADA ──────────────────────────────────────────────
    pdf.add_page()
    w = pdf.epw
    pdf.ln(25)
    pdf.set_font("Helvetica", "B", 22)
    pdf.set_text_color(30, 30, 30)
    pdf.cell(w, 12, "REPORTE DE AUDITORIA DE SEGURIDAD", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)
    pdf.set_font("Helvetica", "", 13)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(w, 8, "Herramienta Auditor-IA v0.1", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(12)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(60, 60, 60)
    ruta_mostrar = os.path.abspath(ruta_proyecto)
    pdf.cell(w, 7, "Proyecto auditado:", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "B", 10)
    pdf.multi_cell(w, 7, ruta_mostrar, align="C")
    pdf.set_font("Helvetica", "", 11)
    pdf.cell(w, 7, f"Fecha: {fecha_str}", align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(12)
    r, g, b = (220, 53, 69) if total > 0 else (40, 167, 69)
    pdf.set_font("Helvetica", "B", 52)
    pdf.set_text_color(r, g, b)
    pdf.cell(w, 22, str(total), align="C", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("Helvetica", "", 14)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(w, 8, "vulnerabilidades detectadas", align="C", new_x="LMARGIN", new_y="NEXT")

    # Recuadro con el nivel de riesgo global, coloreado según el nivel
    pdf.ln(14)
    rn, gn, bn = COLOR_NIVEL.get(riesgo["nivel"], (150, 150, 150))
    pdf.set_fill_color(rn, gn, bn)
    pdf.set_text_color(255, 255, 255)
    pdf.set_font("Helvetica", "B", 16)
    texto_riesgo = limpiar_pdf(f"NIVEL DE RIESGO: {riesgo['nivel'].upper()}  ({riesgo['puntaje']}/100)")
    pdf.cell(w, 14, texto_riesgo, align="C", fill=True, new_x="LMARGIN", new_y="NEXT")

    # ── RESUMEN EJECUTIVO ─────────────────────────────────────
    pdf.add_page()
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_fill_color(30, 30, 30)
    pdf.set_text_color(255, 255, 255)
    pdf.cell(0, 9, "  RESUMEN EJECUTIVO", fill=True, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)

    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(50, 50, 50)
    pdf.multi_cell(w, 7,
        "Este reporte presenta los resultados del analisis de seguridad automatizado "
        "realizado sobre el proyecto indicado. Las vulnerabilidades fueron detectadas "
        "mediante cuatro motores: Regex, Bandit para Python, Semgrep para multiples "
        "lenguajes y OSV para dependencias vulnerables. Se recomienda corregir las "
        "vulnerabilidades de severidad Alta antes de llevar el sistema a produccion."
    )
    pdf.ln(6)

    # Frase de nivel de riesgo dentro del resumen
    pdf.set_font("Helvetica", "B", 11)
    pdf.set_text_color(rn, gn, bn)
    pdf.multi_cell(w, 7,
        limpiar_pdf(f"Nivel de riesgo del proyecto: {riesgo['nivel'].upper()} "
                    f"({riesgo['puntaje']}/100), calculado sobre {riesgo['total']} hallazgos.")
    )
    pdf.set_text_color(50, 50, 50)
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
        pdf.multi_cell(w, 7, "No se encontraron vulnerabilidades en el proyecto analizado.")

    # ── HALLAZGOS DETALLADOS ──────────────────────────────────
    if hallazgos:
        pdf.add_page()
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_fill_color(30, 30, 30)
        pdf.set_text_color(255, 255, 255)
        pdf.cell(w, 9, "  HALLAZGOS DETALLADOS", fill=True, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)

        for h in hallazgos:
            if pdf.get_y() > 240:
                pdf.add_page()

            r, g, b = COLORES_SEVERIDAD.get(h["severidad"], (150, 150, 150))

            pdf.set_fill_color(r, g, b)
            pdf.set_text_color(255, 255, 255)
            pdf.set_font("Helvetica", "B", 10)
            marca = "[ARCHIVO SENSIBLE]  " if h.get("sensible") else ""
            etiqueta = limpiar_pdf(f"  [{h['severidad']}]  {marca}{h['regla']} - {h['nombre']}")
            pdf.multi_cell(w, 8, etiqueta, fill=True, new_x="LMARGIN", new_y="NEXT")

            pdf.set_fill_color(248, 248, 248)
            pdf.set_text_color(50, 50, 50)
            pdf.set_font("Helvetica", "", 9)

            owasp = limpiar_pdf(h.get("owasp", ""))
            cwe   = limpiar_pdf(h.get("cwe", ""))
            cvss  = limpiar_pdf(h.get("cvss", ""))
            if owasp or cwe or cvss:
                pdf.multi_cell(w, 6,
                    f"  OWASP: {owasp}   |   CWE: {cwe}   |   CVSS: {cvss}",
                    fill=True, new_x="LMARGIN", new_y="NEXT")

            motor   = limpiar_pdf(h.get("motor", "Regex"))
            archivo = limpiar_pdf(os.path.basename(h["archivo"]))
            linea   = h["linea"]
            pdf.multi_cell(w, 6,
                f"  Motor: {motor}   |   Archivo: {archivo} (linea {linea})",
                fill=True, new_x="LMARGIN", new_y="NEXT")

            codigo = limpiar_pdf(h["codigo"])
            codigo = codigo[:120] + "..." if len(codigo) > 120 else codigo
            pdf.set_font("Courier", "", 8)
            pdf.set_fill_color(235, 235, 235)
            pdf.multi_cell(w, 6, f"  {codigo}", fill=True, new_x="LMARGIN", new_y="NEXT")

            impacto = limpiar_pdf(obtener_impacto(h))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_fill_color(253, 237, 237)
            pdf.set_text_color(150, 40, 40)
            pdf.multi_cell(w, 6, f"  Impacto: {impacto}", fill=True, new_x="LMARGIN", new_y="NEXT")

            correccion = limpiar_pdf(h.get("correccion", ""))
            pdf.set_font("Helvetica", "", 9)
            pdf.set_fill_color(232, 245, 233)
            pdf.set_text_color(27, 94, 32)
            pdf.multi_cell(w, 6, f"  Correccion: {correccion}", fill=True, new_x="LMARGIN", new_y="NEXT")

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
    hay_deps   = os.path.isfile(os.path.join(ruta, "requirements.txt"))

    print("Motores activos:")
    print(f"  {'✓' if hay_python else '✗'} Bandit   (Python / Django / Flask)")
    print(f"  {'✓' if hay_otros  else '✗'} Semgrep  (PHP, JavaScript, Java, TypeScript, C/C++)")
    print(f"  {'✓' if hay_deps   else '✗'} OSV      (dependencias vulnerables - requirements.txt)")
    print(f"  ✓ Regex    (todos los lenguajes)")
    print(f"  ✓ Secretos (claves y tokens expuestos)\n")

    todos_los_hallazgos = []

    if hay_python:
        print("Ejecutando Bandit...")
        todos_los_hallazgos.extend(detectar_con_bandit(ruta))

    if hay_otros:
        print("Ejecutando Semgrep...")
        todos_los_hallazgos.extend(detectar_con_semgrep(ruta))

    if hay_deps:
        print("Ejecutando análisis de dependencias (OSV)...")
        todos_los_hallazgos.extend(detectar_dependencias_vulnerables(ruta))

    print("Ejecutando análisis por Regex...")
    for archivo in archivos:
        for regla in REGLAS:
            todos_los_hallazgos.extend(detectar_por_regex(archivo, regla))

    print("Ejecutando escaneo de secretos...")
    for archivo in archivos:
        todos_los_hallazgos.extend(detectar_secretos(archivo))

    # Marcar hallazgos de archivos sensibles (login, db, config, admin...)
    for h in todos_los_hallazgos:
        h["sensible"] = es_archivo_sensible(h["archivo"])

    # Ordenar: primero los archivos sensibles, luego por severidad
    ORDEN_SEVERIDAD = {"Alta": 0, "Media-Alta": 1, "Media": 2, "Baja": 3}
    todos_los_hallazgos.sort(
        key=lambda h: (not h["sensible"], ORDEN_SEVERIDAD.get(h["severidad"], 9))
    )

    if todos_los_hallazgos:
        print(f"Se encontraron {len(todos_los_hallazgos)} posibles vulnerabilidades:\n")
        for h in todos_los_hallazgos:
            marca = "[ARCHIVO SENSIBLE] " if h.get("sensible") else ""
            print(f"[{h['severidad']}] {marca}{h['regla']} - {h['nombre']}")
            print(f"  OWASP: {h['owasp']}  |  {h['cwe']}  |  CVSS: {h['cvss']}")
            print(f"  Archivo: {h['archivo']} (línea {h['linea']})")
            print(f"  Código:  {h['codigo']}")
            print(f"  Impacto: {obtener_impacto(h)}")
            print(f"  Corrección: {h['correccion']}\n")
    else:
        print("No se encontraron vulnerabilidades con las reglas actuales.")

    # Nivel de riesgo global del proyecto
    riesgo = calcular_riesgo(todos_los_hallazgos)
    c = riesgo["conteo"]
    print("\n" + "=" * 60)
    print(f"  NIVEL DE RIESGO DEL PROYECTO: {riesgo['nivel'].upper()}  ({riesgo['puntaje']}/100)")
    print(f"  {riesgo['total']} hallazgos  ->  Altas: {c['Alta']}  |  "
          f"Media-Altas: {c['Media-Alta']}  |  Medias: {c['Media']}  |  Bajas: {c['Baja']}")
    print("=" * 60)

    print("\nGenerando reporte PDF...")
    ruta_pdf = generar_reporte_pdf(todos_los_hallazgos, ruta)
    print(f"Reporte guardado en: {ruta_pdf}")


if __name__ == "__main__":
    main()
