# Protocolo de Auditoría — Reglas de Seguridad

Cada regla tiene: ID, nombre, estándar OWASP, CWE, puntuación CVSS, patrón de detección y corrección recomendada.

---

## SEC-01 — Inyección SQL

| Campo | Valor |
|---|---|
| OWASP | A03:2021 |
| CWE | CWE-89 |
| CVSS | 9.8 (Crítico) |
| Severidad | Alta |
| Motor | Regex |

**¿Qué detecta?** Variables del usuario concatenadas directamente en una consulta SQL.

**Ejemplo vulnerable:**
```python
consulta = "SELECT * FROM usuarios WHERE nombre = '" + nombre + "'"
```

**Corrección:** Usar consultas parametrizadas (prepared statements).

---

## SEC-02 — Cross-Site Scripting (XSS)

| Campo | Valor |
|---|---|
| OWASP | A03:2021 |
| CWE | CWE-79 |
| CVSS | 8.8 (Alto) |
| Severidad | Alta |
| Motor | Regex |

**¿Qué detecta?** Datos del usuario insertados en HTML sin escapar ni sanitizar.

**Ejemplo vulnerable:**
```php
echo $_GET['nombre'];
```

**Corrección:** Escapar y sanitizar toda salida. Usar plantillas seguras del framework.

---

## SEC-03 — Credencial quemada en el código

| Campo | Valor |
|---|---|
| OWASP | A07:2021 |
| CWE | CWE-798 |
| CVSS | 7.5 (Alto) |
| Severidad | Media-Alta |
| Motor | Regex |

**¿Qué detecta?** Contraseñas, API keys o tokens escritos directamente en el código fuente.

**Ejemplo vulnerable:**
```python
api_key = "sk_live_1234567890abcdef"
password = "miClaveSuperSecreta123"
```

**Corrección:** Mover secretos a variables de entorno o gestor de secretos.

---

## SEC-04 — Inyección de comandos del sistema

| Campo | Valor |
|---|---|
| OWASP | A03:2021 |
| CWE | CWE-78 |
| CVSS | 9.8 (Crítico) |
| Severidad | Alta |
| Motor | Regex |

**¿Qué detecta?** Datos del usuario pasados directamente a comandos del sistema operativo.

**Ejemplo vulnerable:**
```python
os.system("ping " + ip_usuario)
```

**Corrección:** No pasar datos del usuario a comandos del sistema. Usar listas de argumentos sin shell=True.

---

## SEC-05 — Path Traversal

| Campo | Valor |
|---|---|
| OWASP | A01:2021 |
| CWE | CWE-22 |
| CVSS | 7.5 (Alto) |
| Severidad | Alta |
| Motor | Regex |

**¿Qué detecta?** Rutas de archivo construidas con datos del usuario, que podrían acceder a archivos arbitrarios del sistema.

**Ejemplo vulnerable:**
```python
open("archivos/" + request.args.get("nombre"))
```

**Corrección:** Validar y normalizar rutas con os.path.abspath(). Verificar que estén dentro del directorio permitido.

---

## SEC-06 — Modo debug activo en producción

| Campo | Valor |
|---|---|
| OWASP | A05:2021 |
| CWE | CWE-489 |
| CVSS | 5.3 (Medio) |
| Severidad | Media |
| Motor | Regex |

**¿Qué detecta?** `DEBUG = True` en configuraciones de Flask o Django.

**Ejemplo vulnerable:**
```python
app.run(debug=True)
```

**Corrección:** Deshabilitar debug en producción. Controlar con variables de entorno.

---

## SEC-07 — Deserialización insegura

| Campo | Valor |
|---|---|
| OWASP | A08:2021 |
| CWE | CWE-502 |
| CVSS | 9.8 (Crítico) |
| Severidad | Alta |
| Motor | Regex |

**¿Qué detecta?** Uso de pickle.loads() o yaml.load() con datos no confiables.

**Ejemplo vulnerable:**
```python
datos = pickle.loads(request.data)
```

**Corrección:** No deserializar datos de fuentes no confiables. Usar yaml.safe_load().

---

## SEC-08 — Uso de eval() con datos externos

| Campo | Valor |
|---|---|
| OWASP | A03:2021 |
| CWE | CWE-95 |
| CVSS | 9.8 (Crítico) |
| Severidad | Alta |
| Motor | Regex |

**¿Qué detecta?** eval() aplicado sobre datos del usuario o entradas externas.

**Ejemplo vulnerable:**
```python
resultado = eval(input("Ingresa expresión: "))
```

**Corrección:** Evitar eval() con datos externos. Usar ast.literal_eval() para datos simples.

---

## SEC-09 — Algoritmo criptográfico débil

| Campo | Valor |
|---|---|
| OWASP | A02:2021 |
| CWE | CWE-327 |
| CVSS | 7.5 (Alto) |
| Severidad | Media-Alta |
| Motor | Regex |

**¿Qué detecta?** Uso de MD5 o SHA-1 para operaciones de seguridad (ej: hasheo de contraseñas).

**Ejemplo vulnerable:**
```python
hash = hashlib.md5(password.encode()).hexdigest()
```

**Corrección:** Usar SHA-256 o superior. Para contraseñas usar bcrypt, argon2 o PBKDF2.

---

## A06 — Dependencias vulnerables (motor OSV / SCA)

| Campo | Valor |
|---|---|
| OWASP | A06:2021 |
| CWE | CWE-1035 |
| Severidad | Alta si la librería tiene >10 CVE, Media-Alta si tiene 1-10 |
| Motor | OSV (Google) |

**¿Qué detecta?** Librerías declaradas en `requirements.txt` cuya versión tiene
vulnerabilidades conocidas (CVE) según la base de datos OSV.

**Ejemplo vulnerable:**
```
Django==2.0.0   # 25 CVE conocidos
```

**Corrección:** Actualizar la librería a una versión sin esas vulnerabilidades.

---

## Nota: campo "impacto" (reporte que educa)

Además de los 5 campos originales del protocolo, cada regla ahora tiene un sexto
campo: **impacto** — una explicación en lenguaje claro del daño real que causaría la
vulnerabilidad. Su objetivo es concientizar al estudiante, no solo señalar la falla.
Los hallazgos de Bandit/Semgrep/OSV usan un impacto genérico según su severidad.

---

## Vínculos

- [[proyecto]] — Visión general
- [[arquitectura]] — Cómo se aplican estas reglas
- [[limitaciones]] — Falsos positivos y alcance
