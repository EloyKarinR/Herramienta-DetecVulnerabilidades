import sqlite3

def autenticar(usuario, clave):
    conn = sqlite3.connect("sistema.db")
    cursor = conn.cursor()
    # Vulnerable a inyeccion SQL: concatena datos del usuario en la consulta
    consulta = "SELECT * FROM usuarios WHERE nombre = '" + usuario + "'"
    cursor.execute(consulta)
    return cursor.fetchone()

# Credencial quemada en el codigo
api_key = "sk_live_1234567890abcdef"
