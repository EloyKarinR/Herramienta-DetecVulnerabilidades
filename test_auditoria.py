"""
Pruebas unitarias de la herramienta Auditor-IA.

Una prueba unitaria es código que verifica automáticamente que otra pieza de
código hace lo correcto. Comparamos el resultado REAL de una función contra el
resultado ESPERADO usando "assert" (afirmar). Si coinciden, la prueba pasa.

Las pruebas son autocontenidas: crean sus propios archivos temporales con
vulnerabilidades conocidas y los borran al terminar. No dependen de ninguna
carpeta externa.

Para ejecutarlas:
    python -m unittest test_auditoria -v
"""

import os
import tempfile
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


class TestDeteccion(unittest.TestCase):
    """Pruebas sobre código con vulnerabilidades CONOCIDAS.

    Cada prueba escribe un archivo temporal, lo audita y comprueba que la
    herramienta detecte (o no) lo que corresponde.
    """

    def setUp(self):
        # Carpeta temporal nueva para cada prueba.
        self._temporal = tempfile.TemporaryDirectory()
        self.carpeta = self._temporal.name

    def tearDown(self):
        # Se borra sola al terminar la prueba.
        self._temporal.cleanup()

    def crear_archivo(self, nombre, contenido):
        """Escribe un archivo temporal y devuelve su ruta."""
        ruta = os.path.join(self.carpeta, nombre)
        with open(ruta, "w", encoding="utf-8") as f:
            f.write(contenido)
        return ruta

    def reglas_detectadas(self, ruta):
        """Corre las reglas Regex + el escaneo de secretos sobre un archivo y
        devuelve el conjunto de IDs detectados (ej: {"SEC-01", "SEC-03"})."""
        hallazgos = []
        for regla in auditoria.REGLAS:
            hallazgos.extend(auditoria.detectar_por_regex(ruta, regla))
        hallazgos.extend(auditoria.detectar_secretos(ruta))
        return {h["regla"] for h in hallazgos}

    def test_detecta_inyeccion_sql(self):
        # Consulta que concatena datos del usuario -> SEC-01.
        ruta = self.crear_archivo(
            "login.py",
            'consulta = "SELECT * FROM usuarios WHERE nombre = \'" + usuario + "\'"\n'
        )
        self.assertIn("SEC-01", self.reglas_detectadas(ruta))

    def test_detecta_credencial_quemada(self):
        # Una clave escrita en el código -> SEC-03.
        ruta = self.crear_archivo("config.py", 'password = "miClaveSecreta123"\n')
        self.assertIn("SEC-03", self.reglas_detectadas(ruta))

    def test_detecta_secreto_de_aws(self):
        # Una clave con formato real de AWS -> SEC-10.
        ruta = self.crear_archivo("ajustes.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
        self.assertIn("SEC-10", self.reglas_detectadas(ruta))

    def test_ignora_vulnerabilidad_comentada(self):
        # La misma consulta insegura, pero comentada: NO debe marcarse.
        ruta = self.crear_archivo(
            "notas.py",
            '# consulta = "SELECT * FROM usuarios WHERE id = " + id\n'
        )
        self.assertNotIn("SEC-01", self.reglas_detectadas(ruta))

    def test_codigo_seguro_no_genera_hallazgos(self):
        # Consulta parametrizada: es segura, no debe marcarse.
        ruta = self.crear_archivo(
            "seguro.py",
            'cursor.execute("SELECT * FROM usuarios WHERE nombre = ?", (usuario,))\n'
        )
        self.assertEqual(self.reglas_detectadas(ruta), set())


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

    def test_puntaje_no_pasa_de_100(self):
        # 20 Altas = 200 puntos, pero el techo es 100 -> nivel Critico.
        hallazgos = [{"severidad": "Alta"} for _ in range(20)]
        resultado = auditoria.calcular_riesgo(hallazgos)
        self.assertEqual(resultado["puntaje"], 100)
        self.assertEqual(resultado["nivel"], "Critico")

    def test_proyecto_limpio_sin_riesgo(self):
        # Sin hallazgos, el puntaje es 0.
        resultado = auditoria.calcular_riesgo([])
        self.assertEqual(resultado["puntaje"], 0)


if __name__ == "__main__":
    unittest.main()
