"""
Pruebas unitarias de la herramienta Auditor-IA.

Una prueba unitaria es código que verifica automáticamente que otra pieza de
código hace lo correcto. Comparamos el resultado REAL de una función contra el
resultado ESPERADO usando "assert" (afirmar). Si coinciden, la prueba pasa.

Para ejecutarlas:
    python -m unittest test_auditoria -v
"""

import os
import unittest
import auditoria


class TestFuncionesBasicas(unittest.TestCase):
    """Pruebas de funciones auxiliares simples de la herramienta."""

    def test_archivo_sensible_reconoce_login(self):
        # "login.py" SÍ debe considerarse un archivo sensible.
        self.assertTrue(auditoria.es_archivo_sensible("login.py"))

    def test_archivo_normal_no_es_sensible(self):
        # "utilidades.py" NO debe considerarse sensible.
        self.assertFalse(auditoria.es_archivo_sensible("utilidades.py"))

    def test_reconoce_comentario(self):
        # Una línea que empieza con # es un comentario.
        self.assertTrue(auditoria.es_comentario("# esto es un comentario"))

    def test_codigo_real_no_es_comentario(self):
        # Una línea de código real NO es comentario.
        self.assertFalse(auditoria.es_comentario("x = 1 + 2"))


class TestDeteccionEnArchivos(unittest.TestCase):
    """Pruebas sobre archivos con vulnerabilidades CONOCIDAS.

    Como sabemos de antemano qué falla tiene cada archivo, verificamos que la
    herramienta las detecte. Es la validación de que el motor funciona.
    """

    CARPETA = os.path.join("pruebas", "proyecto_vulnerable")

    def reglas_detectadas(self, nombre_archivo):
        """Corre las reglas Regex + el escaneo de secretos sobre un archivo y
        devuelve el conjunto de IDs de regla detectados (ej: {"SEC-01", "SEC-03"})."""
        ruta = os.path.join(self.CARPETA, nombre_archivo)
        hallazgos = []
        for regla in auditoria.REGLAS:
            hallazgos.extend(auditoria.detectar_por_regex(ruta, regla))
        hallazgos.extend(auditoria.detectar_secretos(ruta))
        return {h["regla"] for h in hallazgos}

    def test_login_detecta_sql_injection(self):
        # login.py concatena datos del usuario en una consulta SQL -> SEC-01.
        self.assertIn("SEC-01", self.reglas_detectadas("login.py"))

    def test_login_detecta_credencial(self):
        # login.py tiene una api_key quemada -> SEC-03.
        self.assertIn("SEC-03", self.reglas_detectadas("login.py"))

    def test_ejemplo_vulne_detecta_sql_injection(self):
        # ejemplo_vulne.py también tiene inyección SQL -> SEC-01.
        self.assertIn("SEC-01", self.reglas_detectadas("ejemplo_vulne.py"))

    def test_ejemplo_vulne_detecta_credencial(self):
        # ejemplo_vulne.py tiene credenciales quemadas -> SEC-03.
        self.assertIn("SEC-03", self.reglas_detectadas("ejemplo_vulne.py"))


class TestPuntuacionRiesgo(unittest.TestCase):
    """Prueba que el cálculo del puntaje de riesgo sea correcto."""

    def test_suma_ponderada(self):
        # 2 Altas (10 c/u) + 1 Media (2) = 22 puntos, nivel Bajo (1-25).
        hallazgos = [
            {"severidad": "Alta"},
            {"severidad": "Alta"},
            {"severidad": "Media"},
        ]
        resultado = auditoria.calcular_riesgo(hallazgos)
        self.assertEqual(resultado["puntaje"], 22)
        self.assertEqual(resultado["nivel"], "Bajo")

    def test_proyecto_limpio_sin_riesgo(self):
        # Sin hallazgos, el puntaje es 0.
        resultado = auditoria.calcular_riesgo([])
        self.assertEqual(resultado["puntaje"], 0)


if __name__ == "__main__":
    unittest.main()
