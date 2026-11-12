
import sqlite3
from pathlib import Path


CARPETA_BASE = Path(__file__).resolve().parent
CARPETA_INSTANCE = CARPETA_BASE / "instance"
RUTA_BD = CARPETA_INSTANCE / "odontologia.db"


def conectar_bd():
    """Abre una conexión con la base de datos."""
    CARPETA_INSTANCE.mkdir(parents=True, exist_ok=True)

    conexion = sqlite3.connect(RUTA_BD)
    conexion.row_factory = sqlite3.Row
    conexion.execute("PRAGMA foreign_keys = ON")

    return conexion


def actualizar_estructura(conexion):
    """Agrega las columnas que falten en las tablas existentes."""

    columnas_citas = {
        columna["name"]
        for columna in conexion.execute(
            "PRAGMA table_info(citas)"
        ).fetchall()
    }

    columnas_nuevas = {
        "fecha_propuesta": "TEXT",
        "hora_inicio_propuesta": "TEXT",
        "hora_fin_propuesta": "TEXT",
        "archivada": "INTEGER NOT NULL DEFAULT 0"
    }

    for nombre, tipo in columnas_nuevas.items():
        if nombre not in columnas_citas:
            conexion.execute(
                f"ALTER TABLE citas ADD COLUMN {nombre} {tipo}"
            )
            print(f"Columna agregada: citas.{nombre}")


def inicializar_bd():
    """Crea las tablas y actualiza la estructura si es necesario."""

    conexion = conectar_bd()

    try:
        conexion.executescript("""
            CREATE TABLE IF NOT EXISTS intentos_login (
                correo TEXT NOT NULL,
                ip TEXT NOT NULL,
                intentos INTEGER NOT NULL DEFAULT 0,
                bloqueo_hasta TEXT,
                PRIMARY KEY (correo, ip)
            );
            CREATE TABLE IF NOT EXISTS usuarios (
                id_usuario INTEGER PRIMARY KEY AUTOINCREMENT,
                nombre TEXT NOT NULL,
                apellido TEXT NOT NULL,
                correo TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                telefono TEXT,
                rol TEXT NOT NULL CHECK (
                    rol IN ('PACIENTE', 'DOCTOR', 'ADMINISTRADOR')
                ),
                fecha_registro TEXT DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS doctores (
                id_doctor INTEGER PRIMARY KEY AUTOINCREMENT,
                id_usuario INTEGER NOT NULL UNIQUE,
                especialidad TEXT NOT NULL,
                universidad TEXT DEFAULT 'Universidad de Cartagena',
                foto TEXT,
                FOREIGN KEY (id_usuario)
                    REFERENCES usuarios(id_usuario)
            );

            CREATE TABLE IF NOT EXISTS horarios (
                id_horario INTEGER PRIMARY KEY AUTOINCREMENT,
                id_doctor INTEGER NOT NULL,
                dia_semana INTEGER NOT NULL CHECK (
                    dia_semana BETWEEN 0 AND 5
                ),
                hora_inicio TEXT NOT NULL,
                hora_fin TEXT NOT NULL,

                FOREIGN KEY (id_doctor)
                    REFERENCES doctores(id_doctor),

                CHECK (hora_inicio < hora_fin)
            );

            CREATE TABLE IF NOT EXISTS citas (
                id_cita INTEGER PRIMARY KEY AUTOINCREMENT,
                id_paciente INTEGER NOT NULL,
                id_doctor INTEGER NOT NULL,
                fecha TEXT NOT NULL,
                hora_inicio TEXT NOT NULL,
                hora_fin TEXT NOT NULL,
                motivo TEXT NOT NULL,

                estado TEXT NOT NULL DEFAULT 'PENDIENTE'
                    CHECK (
                        estado IN (
                            'PENDIENTE',
                            'CONFIRMADA',
                            'RECHAZADA',
                            'REPROGRAMACION_PROPUESTA',
                            'CANCELADA',
                            'COMPLETADA'
                        )
                    ),

                fecha_creacion TEXT DEFAULT CURRENT_TIMESTAMP,

                fecha_propuesta TEXT,
                hora_inicio_propuesta TEXT,
                hora_fin_propuesta TEXT,

                archivada INTEGER NOT NULL DEFAULT 0,

                FOREIGN KEY (id_paciente)
                    REFERENCES usuarios(id_usuario),

                FOREIGN KEY (id_doctor)
                    REFERENCES doctores(id_doctor),

                CHECK (hora_inicio < hora_fin)
            );

            CREATE TABLE IF NOT EXISTS notificaciones (
                id_notificacion INTEGER PRIMARY KEY AUTOINCREMENT,
                id_usuario INTEGER NOT NULL,
                id_cita INTEGER,
                mensaje TEXT NOT NULL,
                tipo TEXT NOT NULL,
                leida INTEGER NOT NULL DEFAULT 0 CHECK (
                    leida IN (0, 1)
                ),
                fecha TEXT DEFAULT CURRENT_TIMESTAMP,

                FOREIGN KEY (id_usuario)
                    REFERENCES usuarios(id_usuario),

                FOREIGN KEY (id_cita)
                    REFERENCES citas(id_cita)
            );

            CREATE INDEX IF NOT EXISTS idx_citas_doctor_fecha
            ON citas(id_doctor, fecha);

            CREATE INDEX IF NOT EXISTS idx_citas_paciente_fecha
            ON citas(id_paciente, fecha);

            CREATE INDEX IF NOT EXISTS idx_notificaciones_usuario_fecha
            ON notificaciones(id_usuario, fecha);
        """)
        
        actualizar_estructura(conexion)

        conexion.commit()

        print("Base de datos inicializada correctamente.")

    except Exception as error:
        conexion.rollback()
        print(f"Error al inicializar la base de datos: {error}")
        raise

    finally:
        conexion.close()


if __name__ == "__main__":
    inicializar_bd()
