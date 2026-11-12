
import sqlite3
from getpass import getpass
from werkzeug.security import generate_password_hash
from database import conectar_bd

DOCTORES = [
    {
        "nombre": "Victor Manuel",
        "apellido": "Gomez Almansa",
        "foto": "victor-manuel-gomez-almansa.png"
    },
    {
        "nombre": "Ana Maria",
        "apellido": "Garcia Velasquez",
        "foto": "ana-maria-garcia-velasquez.png"
    },
    {
        "nombre": "Jose Antonio",
        "apellido": "Ramos Zuñiga",
        "foto": "jose-antonio-ramos-zuniga.png"
    }
]


def crear_doctores():
    conexion = conectar_bd()

    try:
        for doctor in DOCTORES:
            print(f"\nDoctor: {doctor['nombre']} {doctor['apellido']}")

            correo = input("Correo de acceso: ").strip().lower()
            especialidad = input("Especialidad: ").strip()

            if not correo or not especialidad:
                print("Correo y especialidad son obligatorios.")
                continue

            usuario = conexion.execute(
                "SELECT id_usuario, rol FROM usuarios WHERE correo = ?",
                (correo,)
            ).fetchone()

            if usuario:
                if usuario["rol"] != "DOCTOR":
                    print(
                        "Ese correo ya pertenece a un usuario "
                        "que no es doctor. No se modificó."
                    )
                    continue

                id_usuario = usuario["id_usuario"]

            else:
                password = getpass("Contraseña inicial: ")
                confirmar = getpass("Confirma la contraseña: ")

                if len(password) < 8 or password != confirmar:
                    print(
                        "Las contraseñas deben coincidir "
                        "y tener al menos 8 caracteres."
                    )
                    continue

                cursor = conexion.execute("""
                    INSERT INTO usuarios
                        (nombre, apellido, correo, password_hash, rol)
                    VALUES (?, ?, ?, ?, 'DOCTOR')
                """, (
                    doctor["nombre"],
                    doctor["apellido"],
                    correo,
                    generate_password_hash(password)
                ))

                id_usuario = cursor.lastrowid

            conexion.execute("""
                INSERT INTO doctores
                    (id_usuario, especialidad, universidad, foto)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(id_usuario) DO UPDATE SET
                    especialidad = excluded.especialidad,
                    universidad = excluded.universidad,
                    foto = excluded.foto
            """, (
                id_usuario,
                especialidad,
                "Universidad de Cartagena",
                doctor["foto"]
            ))

            conexion.commit()
            print("Doctor registrado y vinculado correctamente.")

    except sqlite3.IntegrityError as error:
        conexion.rollback()
        print("No se pudo guardar el registro:", error)

    finally:
        conexion.close()


if __name__ == "__main__":
    crear_doctores()
