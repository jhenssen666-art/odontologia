
from decoradores import requiere_login, requiere_rol
from datetime import date, datetime, timedelta, timezone
import os
import sqlite3
from flask import (
    Flask, render_template, request,
    redirect, url_for, session, flash, jsonify
)
from werkzeug.security import generate_password_hash, check_password_hash
from database import conectar_bd, inicializar_bd
from math import ceil

app = Flask(__name__)


app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY", "clave-temporal-solo-desarrollo"
)

inicializar_bd()


@app.route("/")
def inicio():
    print("APLICACIÓN:", app)
    print("MIS_CITAS REGISTRADA:", "mis_citas" in app.view_functions)
    print("ENDPOINTS:", list(app.view_functions.keys()))

    return render_template("index.html")


@app.route("/probar-bd")
def probar_bd():
    conexion = conectar_bd()
    try:
        tablas = conexion.execute("""
            SELECT name FROM sqlite_master
            WHERE type = 'table'
            AND name NOT LIKE 'sqlite_%'
            ORDER BY name
        """).fetchall()

        return jsonify({
            "mensaje": "Conexión con SQLite exitosa",
            "tablas": [fila["name"] for fila in tablas]
        })
    finally:
        conexion.close()


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        apellido = request.form.get("apellido", "").strip()
        correo = request.form.get("correo", "").strip().lower()
        telefono = request.form.get("telefono", "").strip()
        password = request.form.get("password", "")

        if not nombre or not apellido or not correo or not password:
            flash("Completa todos los campos obligatorios.", "error")
            return render_template("registro.html")

        if len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.", "error")
            return render_template("registro.html")

        conexion = conectar_bd()
        try:
            conexion.execute("""
                INSERT INTO usuarios
                    (nombre, apellido, correo, password_hash, telefono, rol)
                VALUES (?, ?, ?, ?, ?, 'PACIENTE')
            """, (
                nombre,
                apellido,
                correo,
                generate_password_hash(password),
                telefono or None
            ))
            conexion.commit()

            flash("Cuenta creada correctamente. Ya puedes iniciar sesión.", "exito")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Ese correo ya está registrado.", "error")
        finally:
            conexion.close()

    return render_template("registro.html")



@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")
        ip = request.remote_addr or "desconocida"

        ahora = datetime.now(timezone.utc)

        conexion = conectar_bd()

        try:
            intento = conexion.execute("""
                SELECT intentos, bloqueo_hasta
                FROM intentos_login
                WHERE correo = ? AND ip = ?
            """, (correo, ip)).fetchone()

            if intento and intento["bloqueo_hasta"]:
                bloqueo_hasta = datetime.fromisoformat(
                    intento["bloqueo_hasta"]
                )

                if ahora < bloqueo_hasta:
                    minutos = ceil(
                        (bloqueo_hasta - ahora).total_seconds() / 60
                    )

                    flash(
                        f"Demasiados intentos fallidos. "
                        f"Inténtalo nuevamente en aproximadamente "
                        f"{minutos} minutos.",
                        "error"
                    )

                    return render_template("login.html")

                else:
                    conexion.execute("""
                        DELETE FROM intentos_login
                        WHERE correo = ? AND ip = ?
                    """, (correo, ip))

                    conexion.commit()
                    intento = None

            usuario = conexion.execute("""
                SELECT id_usuario, nombre, apellido, correo,
                       password_hash, rol
                FROM usuarios
                WHERE correo = ?
            """, (correo,)).fetchone()

            if usuario and check_password_hash(
                usuario["password_hash"], password
            ):
                conexion.execute("""
                    DELETE FROM intentos_login
                    WHERE correo = ? AND ip = ?
                """, (correo, ip))

                conexion.commit()

                session.clear()
                session["id_usuario"] = usuario["id_usuario"]
                session["nombre"] = usuario["nombre"]
                session["rol"] = usuario["rol"]

                flash("Has iniciado sesión correctamente.", "exito")
                return redirect(url_for("inicio"))

            intentos = intento["intentos"] if intento else 0
            intentos += 1

            if intentos >= 5:
                bloqueo_hasta = (
                    ahora + timedelta(minutes=15)
                ).isoformat(timespec="seconds")

                conexion.execute("""
                    INSERT INTO intentos_login (
                        correo, ip, intentos, bloqueo_hasta
                    )
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(correo, ip)
                    DO UPDATE SET
                        intentos = excluded.intentos,
                        bloqueo_hasta = excluded.bloqueo_hasta
                """, (correo, ip, intentos, bloqueo_hasta))

                conexion.commit()

                flash(
                    "Has superado los 5 intentos permitidos. "
                    "Tu acceso ha sido bloqueado durante 15 minutos.",
                    "error"
                )

            else:
                conexion.execute("""
                    INSERT INTO intentos_login (
                        correo, ip, intentos, bloqueo_hasta
                    )
                    VALUES (?, ?, ?, NULL)
                    ON CONFLICT(correo, ip)
                    DO UPDATE SET
                        intentos = excluded.intentos,
                        bloqueo_hasta = NULL
                """, (correo, ip, intentos))

                conexion.commit()

                flash(
                    f"Correo o contraseña incorrectos. "
                    f"Intentos restantes: {5 - intentos}.",
                    "error"
                )

        finally:
            conexion.close()

    return render_template("login.html")

    if request.method == "POST":
        correo = request.form.get("correo", "").strip().lower()
        password = request.form.get("password", "")

        conexion = conectar_bd()
        try:
            usuario = conexion.execute("""
                SELECT id_usuario, nombre, apellido, correo,
                       password_hash, rol
                FROM usuarios
                WHERE correo = ?
            """, (correo,)).fetchone()
        finally:
            conexion.close()

        if usuario and check_password_hash(
            usuario["password_hash"], password
        ):
            session.clear()
            session["id_usuario"] = usuario["id_usuario"]
            session["nombre"] = usuario["nombre"]
            session["rol"] = usuario["rol"]

            flash("Has iniciado sesión correctamente.", "exito")
            return redirect(url_for("inicio"))

        flash("Correo o contraseña incorrectos.", "error")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Has cerrado sesión.", "exito")
    return redirect(url_for("inicio"))

@app.route("/mi-cuenta")
@requiere_login
def mi_cuenta():
    return f"Bienvenido, {session['nombre']}"




@app.route("/panel-doctor")
@requiere_rol("DOCTOR")
def panel_doctor():
    conexion = conectar_bd()

    try:
        # información del doctor
        doctor = conexion.execute("""
            SELECT
                u.nombre,
                u.apellido,
                u.correo,
                d.id_doctor,
                d.especialidad,
                d.universidad,
                d.foto
            FROM usuarios AS u
            INNER JOIN doctores AS d
                ON u.id_usuario = d.id_usuario
            WHERE u.id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        citas = conexion.execute("""
            SELECT
                c.id_cita,
                c.fecha,
                c.hora_inicio,
                c.hora_fin,
                c.motivo,
                c.estado,
                c.archivada,
                u.nombre AS nombre_paciente,
                u.apellido AS apellido_paciente,
                u.correo AS correo_paciente
            FROM citas AS c
            INNER JOIN usuarios AS u
                ON u.id_usuario = c.id_paciente
            WHERE c.id_doctor = ?
              AND c.archivada = 0
              AND c.estado IN (
                  'PENDIENTE',
                  'CONFIRMADA',
                  'RECHAZADA',
                  'COMPLETADA',
                  'CANCELADA'
              )
            ORDER BY c.fecha, c.hora_inicio
        """, (doctor["id_doctor"],)).fetchall()

        respuestas_reprogramacion = conexion.execute("""
            SELECT
                n.id_notificacion,
                n.id_cita,
                n.mensaje,
                n.leida,
                n.fecha,
                u.nombre AS nombre_paciente,
                u.apellido AS apellido_paciente
            FROM notificaciones AS n
            INNER JOIN usuarios AS u
                ON u.id_usuario = n.id_usuario
            WHERE n.id_usuario = ?
              AND n.tipo = 'RESPUESTA_REPROGRAMACION'
            ORDER BY n.fecha DESC, n.id_notificacion DESC
        """, (session["id_usuario"],)).fetchall()

    finally:
        conexion.close()

    return render_template(
        "panel_doctor.html",
        doctor=doctor,
        citas=citas,
        respuestas_reprogramacion=respuestas_reprogramacion,
        hoy=date.today().isoformat()
    )


@app.route("/citas/<int:id_cita>/archivar", methods=["POST"])
@requiere_rol("DOCTOR")
def archivar_cita(id_cita):
    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cita = conexion.execute("""
            SELECT estado
            FROM citas
            WHERE id_cita = ?
              AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"])).fetchone()

        if cita is None:
            return "No se encontró la cita.", 404

        estados_permitidos = (
            "CONFIRMADA",
            "RECHAZADA",
            "COMPLETADA",
            "CANCELADA"
        )

        if cita["estado"] not in estados_permitidos:
            return "Esta cita todavía no se puede archivar.", 400

        conexion.execute("""
            UPDATE citas
            SET archivada = 1
            WHERE id_cita = ?
              AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"]))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("panel_doctor"))

@app.route("/citas/<int:id_cita>/desarchivar", methods=["POST"])
@requiere_rol("DOCTOR")
def desarchivar_cita(id_cita):
    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cita = conexion.execute("""
            SELECT id_cita
            FROM citas
            WHERE id_cita = ?
              AND id_doctor = ?
              AND archivada = 1
        """, (id_cita, doctor["id_doctor"])).fetchone()

        if cita is None:
            flash("No se encontró la cita archivada.", "error")
            return redirect(url_for("historial_citas"))

        conexion.execute("""
            UPDATE citas
            SET archivada = 0
            WHERE id_cita = ?
              AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"]))

        conexion.commit()
        flash("La cita fue devuelta a tu agenda.", "exito")

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("historial_citas"))

@app.route("/citas/<int:id_cita>/eliminar-definitivamente", methods=["POST"])
@requiere_rol("DOCTOR")
def eliminar_cita_definitivamente(id_cita):
    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cita = conexion.execute("""
            SELECT id_cita, fecha, estado
            FROM citas
            WHERE id_cita = ?
              AND id_doctor = ?
              AND archivada = 1
        """, (id_cita, doctor["id_doctor"])).fetchone()

        if cita is None:
            flash("No se encontró la cita archivada.", "error")
            return redirect(url_for("historial_citas"))

        if cita["fecha"] >= date.today().isoformat():
            flash(
                "Solo puedes eliminar citas cuya fecha ya haya pasado.",
                "error"
            )
            return redirect(url_for("historial_citas"))

        # Eliminar primero las notificaciones relacionadas
        conexion.execute("""
            DELETE FROM notificaciones
            WHERE id_cita = ?
        """, (id_cita,))

        # Eliminar definitivamente la cita
        conexion.execute("""
            DELETE FROM citas
            WHERE id_cita = ?
              AND id_doctor = ?
              AND archivada = 1
        """, (id_cita, doctor["id_doctor"]))

        conexion.commit()
        flash("La cita fue eliminada definitivamente.", "exito")

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("historial_citas"))

@app.route("/historial-citas")
@requiere_rol("DOCTOR")
def historial_citas():
    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        citas_archivadas = conexion.execute("""
            SELECT
                c.id_cita,
                c.fecha,
                c.hora_inicio,
                c.hora_fin,
                c.motivo,
                c.estado,
                u.nombre AS nombre_paciente,
                u.apellido AS apellido_paciente,
                u.correo AS correo_paciente
            FROM citas AS c
            INNER JOIN usuarios AS u
                ON u.id_usuario = c.id_paciente
            WHERE c.id_doctor = ?
              AND c.archivada = 1
            ORDER BY c.fecha DESC, c.hora_inicio DESC
        """, (doctor["id_doctor"],)).fetchall()

    finally:
        conexion.close()

    return render_template(
        "historial_citas.html",
        citas_archivadas=citas_archivadas,
        hoy=date.today().isoformat()
    )


@app.route("/citas/<int:id_cita>/estado", methods=["POST"])
@requiere_rol("DOCTOR")
def actualizar_estado_cita(id_cita):
    nuevo_estado = request.form.get("estado")

    if nuevo_estado not in ("CONFIRMADA", "RECHAZADA"):
        return "Estado no válido.", 400

    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cita = conexion.execute("""
            SELECT
            id_cita,
            id_paciente,
            fecha,
            hora_inicio,
            hora_fin,
            estado
            FROM citas
            WHERE id_cita = ? AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"])).fetchone()

        if cita is None:
            return "No se encontró esa cita para este doctor.", 404

        if cita["estado"] != "PENDIENTE":
            flash("Esta solicitud ya fue procesada.", "error")
            return redirect(url_for("panel_doctor"))

        if nuevo_estado == "CONFIRMADA":
            conflicto = conexion.execute("""
                SELECT id_cita
                FROM citas
                WHERE id_doctor = ?
                  AND fecha = ?
                  AND id_cita != ?
                  AND estado IN (
                      'PENDIENTE',
                      'CONFIRMADA',
                      'REPROGRAMACION_PROPUESTA'
                  )
                  AND hora_inicio < ?
                  AND hora_fin > ?
                LIMIT 1
            """, (
                doctor["id_doctor"],
                cita["fecha"],
                id_cita,
                cita["hora_fin"],
                cita["hora_inicio"]
            )).fetchone()

            if conflicto:
                flash(
                    "No se puede confirmar: existe otra solicitud "
                    "que se cruza con ese horario.",
                    "error"
                )
                return redirect(url_for("panel_doctor"))

        conexion.execute("""
            UPDATE citas
            SET estado = ?
            WHERE id_cita = ?
              AND id_doctor = ?
              AND estado = 'PENDIENTE'
        """, (
            nuevo_estado,
            id_cita,
            doctor["id_doctor"]
        ))
        
        if nuevo_estado == "CONFIRMADA":
            mensaje = (
                f"Tu cita del {cita['fecha']} "
                f"a las {cita['hora_inicio']} "
                "ha sido confirmada."
            )
            tipo = "CITA_CONFIRMADA"
        else:
            mensaje = (
                f"Tu solicitud de cita del {cita['fecha']} "
                f"a las {cita['hora_inicio']} "
                "ha sido rechazada."
            )
            tipo = "CITA_RECHAZADA"

        conexion.execute("""
            INSERT INTO notificaciones (
                id_usuario,
                id_cita,
                mensaje,
                tipo
            )
            VALUES (?, ?, ?, ?)
        """, (
            cita["id_paciente"],
            cita["id_cita"],
            mensaje,
            tipo
        ))
        conexion.commit()

        if nuevo_estado == "CONFIRMADA":
            flash("La cita ha sido confirmada.", "exito")
        else:
            flash("La solicitud de cita ha sido rechazada.", "exito")

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("panel_doctor"))


@app.route("/citas/<int:id_cita>/cancelar", methods=["POST"])
@requiere_rol("DOCTOR")
def cancelar_cita_doctor(id_cita):
    motivo_cancelacion = request.form.get("motivo_cancelacion", "").strip()

    if not motivo_cancelacion:
        flash("Debes indicar el motivo de la cancelación.", "error")
        return redirect(url_for("panel_doctor"))

    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cita = conexion.execute("""
            SELECT id_cita, id_paciente, fecha, hora_inicio, estado, archivada
            FROM citas
            WHERE id_cita = ? AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"])).fetchone()

        if cita is None:
            return "No se encontró esa cita para este doctor.", 404

        estados_cancelables = (
            "PENDIENTE",
            "CONFIRMADA",
            "REPROGRAMACION_PROPUESTA"
        )

        if cita["estado"] not in estados_cancelables or cita["archivada"]:
            flash("Esta cita no se puede cancelar.", "error")
            return redirect(url_for("panel_doctor"))

        conexion.execute("""
            UPDATE citas
            SET estado = 'CANCELADA',
                fecha_propuesta = NULL,
                hora_inicio_propuesta = NULL,
                hora_fin_propuesta = NULL
            WHERE id_cita = ?
              AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"]))

        mensaje = (
            f"El doctor ha cancelado tu cita del {cita['fecha']} "
            f"a las {cita['hora_inicio']}. "
            f"Motivo: {motivo_cancelacion}"
        )

        conexion.execute("""
            INSERT INTO notificaciones (
                id_usuario,
                id_cita,
                mensaje,
                tipo
            )
            VALUES (?, ?, ?, ?)
        """, (
            cita["id_paciente"],
            cita["id_cita"],
            mensaje,
            "CITA_CANCELADA"
        ))

        conexion.commit()
        flash("La cita fue cancelada y el paciente ha sido notificado.", "exito")

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("panel_doctor"))


@app.route("/citas/<int:id_cita>/proponer-reprogramacion", methods=["POST"])
@requiere_rol("DOCTOR")
def proponer_reprogramacion(id_cita):
    fecha_texto = request.form.get("fecha_propuesta", "")
    inicio = request.form.get("hora_inicio_propuesta", "")
    fin = request.form.get("hora_fin_propuesta", "")

    try:
        fecha_nueva = date.fromisoformat(fecha_texto)
        hora_inicio = datetime.strptime(inicio, "%H:%M")
        hora_fin = datetime.strptime(fin, "%H:%M")
    except ValueError:
        flash("La fecha o las horas no son válidas.", "error")
        return redirect(url_for("panel_doctor"))

    if fecha_nueva < date.today():
        flash("No puedes proponer una fecha pasada.", "error")
        return redirect(url_for("panel_doctor"))

    if fecha_nueva.weekday() == 6:
        flash("No se pueden proponer citas los domingos.", "error")
        return redirect(url_for("panel_doctor"))

    if hora_fin <= hora_inicio:
        flash("La hora de finalización debe ser posterior al inicio.", "error")
        return redirect(url_for("panel_doctor"))

    if (hora_fin - hora_inicio).total_seconds() != 3600:
        flash("La cita debe durar exactamente una hora.", "error")
        return redirect(url_for("panel_doctor"))

    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cita = conexion.execute("""
            SELECT id_cita, id_paciente, estado
            FROM citas
            WHERE id_cita = ? AND id_doctor = ?
        """, (id_cita, doctor["id_doctor"])).fetchone()

        if cita is None:
            return "No se encontró esa cita para este doctor.", 404

        if cita["estado"] != "PENDIENTE":
            flash("Esta solicitud ya fue procesada.", "error")
            return redirect(url_for("panel_doctor"))

        horario = conexion.execute("""
            SELECT id_horario
            FROM horarios
            WHERE id_doctor = ?
              AND dia_semana = ?
              AND hora_inicio <= ?
              AND hora_fin >= ?
            LIMIT 1
        """, (
            doctor["id_doctor"],
            fecha_nueva.weekday(),
            inicio,
            fin
        )).fetchone()

        if horario is None:
            flash(
                "El horario propuesto está fuera del horario "
                "de atención del doctor.",
                "error"
            )
            return redirect(url_for("panel_doctor"))

        conflicto = conexion.execute("""
            SELECT id_cita
            FROM citas
            WHERE id_doctor = ?
              AND id_cita != ?
              AND estado IN (
                  'PENDIENTE',
                  'CONFIRMADA',
                  'REPROGRAMACION_PROPUESTA'
              )
              AND (
                  (
                      fecha = ?
                      AND hora_inicio < ?
                      AND hora_fin > ?
                  )
                  OR
                  (
                      estado = 'REPROGRAMACION_PROPUESTA'
                      AND fecha_propuesta = ?
                      AND hora_inicio_propuesta < ?
                      AND hora_fin_propuesta > ?
                  )
              )
            LIMIT 1
        """, (
            doctor["id_doctor"],
            id_cita,
            fecha_texto,
            fin,
            inicio,
            fecha_texto,
            fin,
            inicio
        )).fetchone()

        if conflicto:
            flash(
                "Ese horario se cruza con otra cita o propuesta.",
                "error"
            )
            return redirect(url_for("panel_doctor"))

        conexion.execute("""
            UPDATE citas
            SET fecha_propuesta = ?,
                hora_inicio_propuesta = ?,
                hora_fin_propuesta = ?,
                estado = 'REPROGRAMACION_PROPUESTA'
            WHERE id_cita = ? AND id_doctor = ?
        """, (
            fecha_texto,
            inicio,
            fin,
            id_cita,
            doctor["id_doctor"]
        ))

        mensaje = (
            f"Tu odontólogo propone cambiar tu cita para el "
            f"{fecha_texto}, de {inicio} a {fin}. "
            "Entra a tus notificaciones para aceptar o rechazar "
            "la propuesta."
        )

        conexion.execute("""
            INSERT INTO notificaciones (
                id_usuario,
                id_cita,
                mensaje,
                tipo
            )
            VALUES (?, ?, ?, ?)
        """, (
            cita["id_paciente"],
            id_cita,
            mensaje,
            "REPROGRAMACION_PROPUESTA"
        ))

        conexion.commit()
        flash("La propuesta se envió al paciente.", "exito")

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("panel_doctor"))


@app.route("/solicitar-cita")
@requiere_rol("PACIENTE")
def solicitar_cita():
    conexion = conectar_bd()
    try:
        doctores = conexion.execute("""
            SELECT
                d.id_doctor,
                u.nombre,
                u.apellido,
                d.especialidad,
                d.foto
            FROM doctores AS d
            INNER JOIN usuarios AS u
                ON u.id_usuario = d.id_usuario
            ORDER BY u.apellido, u.nombre
        """).fetchall()

        return render_template(
            "solicitar_cita.html",
            doctores=doctores
        )
    finally:
        conexion.close()


@app.route("/mis-citas")
@requiere_rol("PACIENTE")
def mis_citas():
    conexion = conectar_bd()

    try:
        citas = conexion.execute("""
            SELECT
                c.id_cita,
                c.fecha,
                c.hora_inicio,
                c.hora_fin,
                c.motivo,
                c.estado,
                c.fecha_propuesta,
                c.hora_inicio_propuesta,
                c.hora_fin_propuesta,
                d.especialidad,
                u.nombre AS nombre_doctor,
                u.apellido AS apellido_doctor
            FROM citas AS c
            INNER JOIN doctores AS d
                ON c.id_doctor = d.id_doctor
            INNER JOIN usuarios AS u
                ON d.id_usuario = u.id_usuario
            WHERE c.id_paciente = ?
            ORDER BY c.fecha DESC, c.hora_inicio DESC
        """, (session["id_usuario"],)).fetchall()

        citas_lista = []

        for fila in citas:
            cita = dict(fila)

            fecha = cita["fecha"]
            hora = cita["hora_inicio"]
            
            if cita["estado"] == "REPROGRAMACION_PROPUESTA":
                fecha = cita["fecha_propuesta"] or fecha
                hora = cita["hora_inicio_propuesta"] or hora

            try:
                inicio = datetime.strptime(
                    f"{fecha} {str(hora)[:5]}",
                    "%Y-%m-%d %H:%M"
                )

                cita["puede_cancelar"] = (
                    inicio > datetime.now()
                    and cita["estado"] in (
                        "PENDIENTE",
                        "CONFIRMADA",
                        "REPROGRAMACION_PROPUESTA"
                    )
                )
            except (ValueError, TypeError):
                cita["puede_cancelar"] = False

            citas_lista.append(cita)

    finally:
        conexion.close()

    return render_template(
        "mis_citas.html",
        citas=citas_lista
    )


@app.route("/mis-citas/<int:id_cita>/cancelar", methods=["POST"])
@requiere_rol("PACIENTE")
def cancelar_cita_paciente(id_cita):
    motivo_cancelacion = request.form.get("motivo_cancelacion", "").strip()

    if not motivo_cancelacion:
        flash("Debes indicar el motivo de la cancelación.", "error")
        return redirect(url_for("mis_citas"))

    conexion = conectar_bd()

    try:
        cita = conexion.execute("""
            SELECT
                c.id_cita,
                c.id_paciente,
                c.id_doctor,
                c.fecha,
                c.hora_inicio,
                c.estado,
                c.archivada,
                c.fecha_propuesta,
                c.hora_inicio_propuesta,
                d.id_usuario AS id_usuario_doctor
            FROM citas AS c
            INNER JOIN doctores AS d
                ON c.id_doctor = d.id_doctor
            WHERE c.id_cita = ?
              AND c.id_paciente = ?
        """, (id_cita, session["id_usuario"])).fetchone()

        if cita is None:
            return "No se encontró esa cita.", 404

        estados_cancelables = (
            "PENDIENTE",
            "CONFIRMADA",
            "REPROGRAMACION_PROPUESTA"
        )

        if cita["estado"] not in estados_cancelables or cita["archivada"]:
            flash("Esta cita no se puede cancelar.", "error")
            return redirect(url_for("mis_citas"))

        fecha_cita = cita["fecha"]
        hora_cita = cita["hora_inicio"]

        if cita["estado"] == "REPROGRAMACION_PROPUESTA":
            fecha_cita = cita["fecha_propuesta"] or fecha_cita
            hora_cita = cita["hora_inicio_propuesta"] or hora_cita

        try:
            inicio = datetime.strptime(
                f"{fecha_cita} {str(hora_cita)[:5]}",
                "%Y-%m-%d %H:%M"
            )
        except (ValueError, TypeError):
            flash("No se pudo comprobar la fecha de la cita.", "error")
            return redirect(url_for("mis_citas"))

        if inicio <= datetime.now():
            flash("No puedes cancelar una cita que ya comenzó o pasó.", "error")
            return redirect(url_for("mis_citas"))

        conexion.execute("""
            UPDATE citas
            SET estado = 'CANCELADA',
                fecha_propuesta = NULL,
                hora_inicio_propuesta = NULL,
                hora_fin_propuesta = NULL
            WHERE id_cita = ?
              AND id_paciente = ?
        """, (id_cita, session["id_usuario"]))

        mensaje = (
            f"El paciente ha cancelado su cita del {fecha_cita} "
            f"a las {hora_cita}. "
            f"Motivo: {motivo_cancelacion}"
        )

        conexion.execute("""
            INSERT INTO notificaciones (
                id_usuario,
                id_cita,
                mensaje,
                tipo
            )
            VALUES (?, ?, ?, ?)
        """, (
            cita["id_usuario_doctor"],
            cita["id_cita"],
            mensaje,
            "CITA_CANCELADA_PACIENTE"
        ))

        conexion.commit()

        flash("Tu cita fue cancelada correctamente.", "exito")

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("mis_citas"))

@app.route("/mis-notificaciones")
@requiere_rol("PACIENTE")
def mis_notificaciones():
    conexion = conectar_bd()

    try:
        notificaciones = conexion.execute("""
            SELECT
                id_notificacion,
                id_cita,
                mensaje,
                tipo,
                leida,
                fecha
            FROM notificaciones
            WHERE id_usuario = ?
            ORDER BY fecha DESC, id_notificacion DESC
        """, (session["id_usuario"],)).fetchall()

        return render_template(
            "mis_notificaciones.html",
            notificaciones=notificaciones
        )
    finally:
        conexion.close()

@app.route("/citas/<int:id_cita>/responder-reprogramacion", methods=["POST"])
@requiere_rol("PACIENTE")
def responder_reprogramacion(id_cita):
    decision = request.form.get("decision")

    if decision not in ("ACEPTAR", "RECHAZAR"):
        return "Decisión no válida.", 400

    conexion = conectar_bd()

    try:
        cita = conexion.execute("""
            SELECT
                c.id_cita,
                c.id_paciente,
                c.id_doctor,
                c.fecha,
                c.hora_inicio,
                c.hora_fin,
                c.fecha_propuesta,
                c.hora_inicio_propuesta,
                c.hora_fin_propuesta,
                c.estado,
                d.id_usuario AS id_usuario_doctor
            FROM citas AS c
            INNER JOIN doctores AS d
                ON d.id_doctor = c.id_doctor
            WHERE c.id_cita = ?
              AND c.id_paciente = ?
        """, (
            id_cita,
            session["id_usuario"]
        )).fetchone()

        if cita is None:
            return "No se encontró esa cita.", 404

        if cita["estado"] != "REPROGRAMACION_PROPUESTA":
            flash("Esta propuesta ya fue respondida o no está disponible.", "error")
            return redirect(url_for("mis_notificaciones"))

        if not cita["fecha_propuesta"] or not cita["hora_inicio_propuesta"] or not cita["hora_fin_propuesta"]:
            flash("La propuesta no contiene un horario válido.", "error")
            return redirect(url_for("mis_notificaciones"))

        if decision == "ACEPTAR":

            # comprobar que el nuevo horario no tenga conflictos.
            conflicto = conexion.execute("""
                SELECT id_cita
                FROM citas
                WHERE id_doctor = ?
                  AND id_cita != ?
                  AND estado IN (
                      'PENDIENTE',
                      'CONFIRMADA',
                      'REPROGRAMACION_PROPUESTA'
                  )
                  AND (
                      (
                          fecha = ?
                          AND hora_inicio < ?
                          AND hora_fin > ?
                      )
                      OR
                      (
                          estado = 'REPROGRAMACION_PROPUESTA'
                          AND fecha_propuesta = ?
                          AND hora_inicio_propuesta < ?
                          AND hora_fin_propuesta > ?
                      )
                  )
                LIMIT 1
            """, (
                cita["id_doctor"],
                id_cita,
                cita["fecha_propuesta"],
                cita["hora_fin_propuesta"],
                cita["hora_inicio_propuesta"],
                cita["fecha_propuesta"],
                cita["hora_fin_propuesta"],
                cita["hora_inicio_propuesta"]
            )).fetchone()

            if conflicto:
                flash(
                    "No se puede aceptar la propuesta porque "
                    "ese horario ya no está disponible.",
                    "error"
                )
                return redirect(url_for("mis_notificaciones"))

            # Actualizar la cita con el horario propuesto.
            conexion.execute("""
                UPDATE citas
                SET fecha = fecha_propuesta,
                    hora_inicio = hora_inicio_propuesta,
                    hora_fin = hora_fin_propuesta,
                    fecha_propuesta = NULL,
                    hora_inicio_propuesta = NULL,
                    hora_fin_propuesta = NULL,
                    estado = 'CONFIRMADA'
                WHERE id_cita = ?
            """, (id_cita,))

            mensaje = (
                f"El paciente ha aceptado la reprogramación "
                f"de la cita #{id_cita}. "
                f"La nueva fecha es {cita['fecha_propuesta']}, "
                f"de {cita['hora_inicio_propuesta']} "
                f"a {cita['hora_fin_propuesta']}."
            )

            flash("Has aceptado el nuevo horario. Tu cita está confirmada.", "exito")

        else:
            # conservara la fecha original y devolver la solicitud al odontólogo para que pueda revisarla nuevamente.
            conexion.execute("""
                UPDATE citas
                SET fecha_propuesta = NULL,
                    hora_inicio_propuesta = NULL,
                    hora_fin_propuesta = NULL,
                    estado = 'PENDIENTE'
                WHERE id_cita = ?
            """, (id_cita,))

            mensaje = (
                f"El paciente ha rechazado la propuesta "
                f"de reprogramación de la cita #{id_cita}. "
                "La solicitud original vuelve a estar pendiente."
            )

            flash("Has rechazado la propuesta. Se conserva tu solicitud original.", "exito")

        # notificar al odontólogo.
        conexion.execute("""
            INSERT INTO notificaciones (
                id_usuario,
                id_cita,
                mensaje,
                tipo
            )
            VALUES (?, ?, ?, ?)
        """, (
            cita["id_usuario_doctor"],
            id_cita,
            mensaje,
            "RESPUESTA_REPROGRAMACION"
        ))

        conexion.commit()

    except Exception:
        conexion.rollback()
        raise

    finally:
        conexion.close()

    return redirect(url_for("mis_notificaciones"))

@app.route("/notificaciones/<int:id_notificacion>/leida",
    methods=["POST"])
@requiere_rol("PACIENTE")
def marcar_notificacion_leida(id_notificacion):
    conexion = conectar_bd()

    try:
        conexion.execute("""
            UPDATE notificaciones
            SET leida = 1
            WHERE id_notificacion = ?
              AND id_usuario = ?
        """, (id_notificacion, session["id_usuario"]))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("mis_notificaciones"))

# eliminara una de las notificación leída
@app.route("/notificaciones/<int:id_notificacion>/eliminar", methods=["POST"])
@requiere_rol("PACIENTE")
def eliminar_notificacion(id_notificacion):
    conexion = conectar_bd()

    try:
        conexion.execute("""
            DELETE FROM notificaciones
            WHERE id_notificacion = ?
              AND id_usuario = ?
              AND leida = 1
        """, (id_notificacion, session["id_usuario"]))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("mis_notificaciones"))


# esto eliminara las notificaciones leídas
@app.route("/notificaciones/eliminar-leidas", methods=["POST"])
@requiere_rol("PACIENTE")
def eliminar_notificaciones_leidas():
    conexion = conectar_bd()

    try:
        conexion.execute("""
            DELETE FROM notificaciones
            WHERE id_usuario = ?
              AND leida = 1
        """, (session["id_usuario"],))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("mis_notificaciones"))

# Mostrar notificaciones del doctor
@app.route("/notificaciones-doctor")
@requiere_rol("DOCTOR")
def notificaciones_doctor():
    conexion = conectar_bd()

    try:
        notificaciones = conexion.execute("""
            SELECT
                id_notificacion,
                id_cita,
                mensaje,
                tipo,
                leida,
                fecha
            FROM notificaciones
            WHERE id_usuario = ?
            ORDER BY fecha DESC, id_notificacion DESC
        """, (session["id_usuario"],)).fetchall()

    finally:
        conexion.close()

    return render_template(
        "notificaciones_doctor.html",
        notificaciones=notificaciones
    )


# marcara la notificación del doctor como leída
@app.route("/notificaciones-doctor/<int:id_notificacion>/leida", methods=["POST"])
@requiere_rol("DOCTOR")
def marcar_notificacion_doctor_leida(id_notificacion):
    conexion = conectar_bd()

    try:
        conexion.execute("""
            UPDATE notificaciones
            SET leida = 1
            WHERE id_notificacion = ?
              AND id_usuario = ?
        """, (id_notificacion, session["id_usuario"]))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("notificaciones_doctor"))


# Eliminar una notificación leída del doctor
@app.route("/notificaciones-doctor/<int:id_notificacion>/eliminar", methods=["POST"])
@requiere_rol("DOCTOR")
def eliminar_notificacion_doctor(id_notificacion):
    conexion = conectar_bd()

    try:
        conexion.execute("""
            DELETE FROM notificaciones
            WHERE id_notificacion = ?
              AND id_usuario = ?
              AND leida = 1
        """, (id_notificacion, session["id_usuario"]))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("notificaciones_doctor"))


# con esto se eliminaran todas las notificaciones leídas del doctor
@app.route("/notificaciones-doctor/eliminar-leidas", methods=["POST"])
@requiere_rol("DOCTOR")
def eliminar_notificaciones_doctor_leidas():
    conexion = conectar_bd()

    try:
        conexion.execute("""
            DELETE FROM notificaciones
            WHERE id_usuario = ?
              AND leida = 1
        """, (session["id_usuario"],))

        conexion.commit()

    finally:
        conexion.close()

    return redirect(url_for("notificaciones_doctor"))


@app.route("/doctor/<int:id_doctor>/horarios-cita")
@requiere_rol("PACIENTE")
def ver_horarios_cita(id_doctor):
    fecha_texto = request.args.get("fecha", "")
    fecha_seleccionada = None
    horarios_disponibles = []
    horarios_ocupados = []

    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT
                d.id_doctor,
                u.nombre,
                u.apellido,
                d.especialidad,
                d.foto
            FROM doctores AS d
            INNER JOIN usuarios AS u
                ON u.id_usuario = d.id_usuario
            WHERE d.id_doctor = ?
        """, (id_doctor,)).fetchone()

        if doctor is None:
            return "No se encontró el doctor.", 404

        if fecha_texto:
            try:
                fecha_seleccionada = date.fromisoformat(fecha_texto)
            except ValueError:
                flash("La fecha seleccionada no es válida.", "error")
                fecha_texto = ""

        if fecha_seleccionada:
            if fecha_seleccionada < date.today():
                flash("No puedes consultar fechas anteriores.", "error")
                fecha_seleccionada = None
                fecha_texto = ""

            elif fecha_seleccionada.weekday() == 6:
                flash("La clínica no atiende los domingos.", "error")

            else:
                horarios = conexion.execute("""
                    SELECT hora_inicio, hora_fin
                    FROM horarios
                    WHERE id_doctor = ?
                      AND dia_semana = ?
                    ORDER BY hora_inicio
                """, (
                    id_doctor,
                    fecha_seleccionada.weekday()
                )).fetchall()

                # Consultar citas originales y propuestas
                citas = conexion.execute("""
                    SELECT
                        fecha,
                        hora_inicio,
                        hora_fin,
                        fecha_propuesta,
                        hora_inicio_propuesta,
                        hora_fin_propuesta,
                        estado
                    FROM citas
                    WHERE id_doctor = ?
                      AND estado IN (
                          'PENDIENTE',
                          'CONFIRMADA',
                          'REPROGRAMACION_PROPUESTA'
                      )
                      AND (
                          fecha = ?
                          OR (
                              estado = 'REPROGRAMACION_PROPUESTA'
                              AND fecha_propuesta = ?
                          )
                      )
                """, (
                    id_doctor,
                    fecha_texto,
                    fecha_texto
                )).fetchall()

                for horario in horarios:
                    actual = datetime.strptime(
                        horario["hora_inicio"], "%H:%M"
                    )

                    fin = datetime.strptime(
                        horario["hora_fin"], "%H:%M"
                    )

                    while actual + timedelta(hours=1) <= fin:
                        siguiente = actual + timedelta(hours=1)

                        inicio_texto = actual.strftime("%H:%M")
                        fin_texto = siguiente.strftime("%H:%M")

                        ocupada = False

                        for cita in citas:

                            # comprobar el horario original
                            if cita["fecha"] == fecha_texto:
                                if (
                                    inicio_texto < cita["hora_fin"]
                                    and fin_texto > cita["hora_inicio"]
                                ):
                                    ocupada = True

                            # comprobar el horario propuesto
                            if (
                                cita["estado"] == "REPROGRAMACION_PROPUESTA"
                                and cita["fecha_propuesta"] == fecha_texto
                                and cita["hora_inicio_propuesta"]
                                and cita["hora_fin_propuesta"]
                            ):
                                if (
                                    inicio_texto < cita["hora_fin_propuesta"]
                                    and fin_texto > cita["hora_inicio_propuesta"]
                                ):
                                    ocupada = True

                            if ocupada:
                                break

                        franja = {
                            "inicio": inicio_texto,
                            "fin": fin_texto
                        }

                        if ocupada:
                            horarios_ocupados.append(franja)
                        else:
                            horarios_disponibles.append(franja)

                        actual = siguiente

        return render_template(
            "horarios_cita.html",
            doctor=doctor,
            fecha_seleccionada=fecha_texto,
            horarios_disponibles=horarios_disponibles,
            horarios_ocupados=horarios_ocupados
        )

    finally:
        conexion.close()



@app.route("/doctor/<int:id_doctor>/solicitar-cita", methods=["GET", "POST"])
@requiere_rol("PACIENTE")
def formulario_cita(id_doctor):
    fecha_texto = request.args.get("fecha", "")
    hora_inicio = request.args.get("hora_inicio", "")
    hora_fin = request.args.get("hora_fin", "")

    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT d.id_doctor, u.nombre, u.apellido, d.especialidad
            FROM doctores d
            JOIN usuarios u ON u.id_usuario = d.id_usuario
            WHERE d.id_doctor = ?
        """, (id_doctor,)).fetchone()

        if doctor is None:
            return "Doctor no encontrado.", 404

        if request.method == "POST":
            fecha_texto = request.form.get("fecha", "")
            hora_inicio = request.form.get("hora_inicio", "")
            hora_fin = request.form.get("hora_fin", "")
            motivo = request.form.get("motivo", "").strip()

            if not motivo:
                flash("Escribe el motivo de la cita.", "error")
            else:
                try:
                    fecha = date.fromisoformat(fecha_texto)
                    inicio = datetime.strptime(hora_inicio, "%H:%M")
                    fin = datetime.strptime(hora_fin, "%H:%M")
                except ValueError:
                    return "Los datos de la cita no son válidos.", 400

                if (
                    fecha < date.today()
                    or fecha.weekday() == 6
                    or fin - inicio != timedelta(hours=1)
                ):
                    return "La fecha o el horario no son válidos.", 400

                horario = conexion.execute("""
                    SELECT id_horario
                    FROM horarios
                    WHERE id_doctor = ?
                      AND dia_semana = ?
                      AND hora_inicio <= ?
                      AND hora_fin >= ?
                """, (
                    id_doctor, fecha.weekday(),
                    hora_inicio, hora_fin
                )).fetchone()

                if horario is None:
                    return "El doctor no atiende en ese horario.", 400

                ocupada = conexion.execute("""
                    SELECT id_cita
                    FROM citas
                    WHERE id_doctor = ?
                      AND fecha = ?
                      AND estado IN (
                          'PENDIENTE', 'CONFIRMADA',
                          'REPROGRAMACION_PROPUESTA'
                      )
                      AND hora_inicio < ?
                      AND hora_fin > ?
                """, (
                    id_doctor, fecha_texto,
                    hora_fin, hora_inicio
                )).fetchone()

                if ocupada:
                    flash("Esa hora acaba de ocuparse. Elige otra.", "error")
                    return redirect(url_for(
                        "ver_horarios_cita",
                        id_doctor=id_doctor,
                        fecha=fecha_texto
                    ))

                conexion.execute("""
                    INSERT INTO citas (
                        id_paciente, id_doctor, fecha,
                        hora_inicio, hora_fin, motivo, estado
                    )
                    VALUES (?, ?, ?, ?, ?, ?, 'PENDIENTE')
                """, (
                    session["id_usuario"], id_doctor, fecha_texto,
                    hora_inicio, hora_fin, motivo
                ))

                conexion.commit()
                flash("Tu solicitud de cita fue enviada al doctor.", "exito")
                return redirect(url_for("solicitar_cita"))

        return render_template(
            "formulario_cita.html",
            doctor=doctor,
            fecha=fecha_texto,
            hora_inicio=hora_inicio,
            hora_fin=hora_fin
        )

    finally:
        conexion.close()


@app.route("/horarios-doctor", methods=["GET", "POST"])
@requiere_rol("DOCTOR")
def horarios_doctor():
    conexion = conectar_bd()

    dias = {
        0: "Lunes",
        1: "Martes",
        2: "Miércoles",
        3: "Jueves",
        4: "Viernes",
        5: "Sábado",
    }

    try:
        doctor = conexion.execute("""
            SELECT d.id_doctor, u.nombre, u.apellido
            FROM doctores AS d
            INNER JOIN usuarios AS u
                ON u.id_usuario = d.id_usuario
            WHERE u.id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        if request.method == "POST":
            dia_texto = request.form.get("dia_semana", "")
            hora_inicio = request.form.get("hora_inicio", "")
            hora_fin = request.form.get("hora_fin", "")

            try:
                dia = int(dia_texto)
            except ValueError:
                dia = -1

            if (
                dia not in dias
                or len(hora_inicio) != 5
                or len(hora_fin) != 5
                or hora_inicio[2] != ":"
                or hora_fin[2] != ":"
                or not hora_inicio.replace(":", "").isdigit()
                or not hora_fin.replace(":", "").isdigit()
                or not (
                    "00:00" <= hora_inicio <= "23:59"
                    and "00:00" <= hora_fin <= "23:59"
                )
                or hora_inicio >= hora_fin
            ):
                flash("Revisa el día y las horas ingresadas.", "error")

            else:
                cruce = conexion.execute("""
                    SELECT id_horario
                    FROM horarios
                    WHERE id_doctor = ?
                      AND dia_semana = ?
                      AND hora_inicio < ?
                      AND hora_fin > ?
                """, (
                    doctor["id_doctor"],
                    dia,
                    hora_fin,
                    hora_inicio,
                )).fetchone()

                if cruce:
                    flash(
                        "Ese horario se cruza con otro que ya registraste.",
                        "error"
                    )
                else:
                    conexion.execute("""
                        INSERT INTO horarios
                            (id_doctor, dia_semana, hora_inicio, hora_fin)
                        VALUES (?, ?, ?, ?)
                    """, (
                        doctor["id_doctor"],
                        dia,
                        hora_inicio,
                        hora_fin,
                    ))

                    conexion.commit()
                    flash("Horario guardado correctamente.", "exito")

            return redirect(url_for("horarios_doctor"))

        # Consultar  horarios  registrados
        horarios = conexion.execute("""
            SELECT id_horario, dia_semana, hora_inicio, hora_fin
            FROM horarios
            WHERE id_doctor = ?
            ORDER BY dia_semana, hora_inicio
        """, (doctor["id_doctor"],)).fetchall()

        # fecha que el doctor quiere ver
        fecha_texto = request.args.get(
            "fecha",
            date.today().isoformat()
        )

        try:
            fecha_consulta = date.fromisoformat(fecha_texto)
        except ValueError:
            fecha_consulta = date.today()
            fecha_texto = fecha_consulta.isoformat()

        numero_dia = fecha_consulta.weekday()
        nombre_dia = dias.get(numero_dia, "Domingo")

        # horarios correspondientes a ese día
        horarios_dia = []

        if numero_dia in dias:
            horarios_dia = conexion.execute("""
                SELECT hora_inicio, hora_fin
                FROM horarios
                WHERE id_doctor = ?
                  AND dia_semana = ?
                ORDER BY hora_inicio
            """, (
                doctor["id_doctor"],
                numero_dia,
            )).fetchall()

        # mirar citas originales y propuestas para esa fecha
        citas_dia = conexion.execute("""
            SELECT
                c.id_cita,
                c.fecha,
                c.hora_inicio,
                c.hora_fin,
                c.motivo,
                c.estado,
                c.fecha_propuesta,
                c.hora_inicio_propuesta,
                c.hora_fin_propuesta,
                u.nombre AS nombre_paciente,
                u.apellido AS apellido_paciente
            FROM citas AS c
            INNER JOIN usuarios AS u
                ON u.id_usuario = c.id_paciente
            WHERE c.id_doctor = ?
              AND c.estado IN (
                  'PENDIENTE',
                  'CONFIRMADA',
                  'REPROGRAMACION_PROPUESTA'
              )
              AND (
                  c.fecha = ?
                  OR (
                      c.estado = 'REPROGRAMACION_PROPUESTA'
                      AND c.fecha_propuesta = ?
                  )
              )
            ORDER BY c.hora_inicio
        """, (
            doctor["id_doctor"],
            fecha_texto,
            fecha_texto,
        )).fetchall()

        agenda_dia = []

        for horario in horarios_dia:
            inicio = datetime.strptime(
                str(horario["hora_inicio"])[:5],
                "%H:%M"
            )

            fin = datetime.strptime(
                str(horario["hora_fin"])[:5],
                "%H:%M"
            )

            while inicio + timedelta(hours=1) <= fin:
                fin_espacio = inicio + timedelta(hours=1)

                hora_inicio_espacio = inicio.strftime("%H:%M")
                hora_fin_espacio = fin_espacio.strftime("%H:%M")

                ocupaciones = []

                for cita in citas_dia:

                    # revisar el horario original de la cita
                    if cita["fecha"] == fecha_texto:
                        cita_inicio = str(cita["hora_inicio"])[:5]
                        cita_fin = str(cita["hora_fin"])[:5]

                        if (
                            cita_inicio < hora_fin_espacio
                            and cita_fin > hora_inicio_espacio
                        ):
                            ocupaciones.append({
                                "id_cita": cita["id_cita"],
                                "nombre_paciente": cita["nombre_paciente"],
                                "apellido_paciente": cita["apellido_paciente"],
                                "motivo": cita["motivo"],
                                "estado": cita["estado"],
                                "hora_inicio": cita_inicio,
                                "hora_fin": cita_fin,
                                "tipo": "Cita registrada"
                            })

                    # revisar el horario propuesto
                    if (
                        cita["estado"] == "REPROGRAMACION_PROPUESTA"
                        and cita["fecha_propuesta"] == fecha_texto
                        and cita["hora_inicio_propuesta"]
                        and cita["hora_fin_propuesta"]
                    ):
                        propuesta_inicio = str(
                            cita["hora_inicio_propuesta"]
                        )[:5]

                        propuesta_fin = str(
                            cita["hora_fin_propuesta"]
                        )[:5]

                        if (
                            propuesta_inicio < hora_fin_espacio
                            and propuesta_fin > hora_inicio_espacio
                        ):
                            ocupaciones.append({
                                "id_cita": cita["id_cita"],
                                "nombre_paciente": cita["nombre_paciente"],
                                "apellido_paciente": cita["apellido_paciente"],
                                "motivo": cita["motivo"],
                                "estado": cita["estado"],
                                "hora_inicio": propuesta_inicio,
                                "hora_fin": propuesta_fin,
                                "tipo": "Horario propuesto"
                            })

                agenda_dia.append({
                    "hora_inicio": hora_inicio_espacio,
                    "hora_fin": hora_fin_espacio,
                    "ocupado": len(ocupaciones) > 0,
                    "ocupaciones": ocupaciones
                })

                inicio = fin_espacio

        return render_template(
            "horarios_doctor.html",
            doctor=doctor,
            horarios=horarios,
            dias=dias,
            fecha_consulta=fecha_texto,
            nombre_dia=nombre_dia,
            agenda_dia=agenda_dia
        )

    finally:
        conexion.close()


@app.route("/horarios-doctor/editar/<int:id_horario>", methods=["POST"])
@requiere_rol("DOCTOR")
def editar_horario(id_horario):
    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        horario = conexion.execute("""
            SELECT id_horario
            FROM horarios
            WHERE id_horario = ? AND id_doctor = ?
        """, (id_horario, doctor["id_doctor"])).fetchone()

        if horario is None:
            return "Horario no encontrado.", 404

        dia_texto = request.form.get("dia_semana", "")
        hora_inicio = request.form.get("hora_inicio", "")
        hora_fin = request.form.get("hora_fin", "")

        dias_validos = range(6)

        try:
            dia = int(dia_texto)
        except ValueError:
            dia = -1

        formato_valido = all(
            len(hora) == 5
            and hora[2] == ":"
            and hora.replace(":", "").isdigit()
            and "00:00" <= hora <= "23:59"
            for hora in (hora_inicio, hora_fin)
        )

        if (
            dia not in dias_validos
            or not formato_valido
            or hora_inicio >= hora_fin
        ):
            flash("Revisa el día y las horas ingresadas.", "error")
            return redirect(url_for("horarios_doctor"))

        cruce = conexion.execute("""
            SELECT id_horario
            FROM horarios
            WHERE id_doctor = ?
              AND dia_semana = ?
              AND hora_inicio < ?
              AND hora_fin > ?
              AND id_horario != ?
        """, (
            doctor["id_doctor"],
            dia,
            hora_fin,
            hora_inicio,
            id_horario
        )).fetchone()

        if cruce:
            flash("El nuevo horario se cruza con otro horario.", "error")
            return redirect(url_for("horarios_doctor"))

        conexion.execute("""
            UPDATE horarios
            SET dia_semana = ?, hora_inicio = ?, hora_fin = ?
            WHERE id_horario = ? AND id_doctor = ?
        """, (
            dia,
            hora_inicio,
            hora_fin,
            id_horario,
            doctor["id_doctor"]
        ))

        conexion.commit()
        flash("Horario actualizado correctamente.", "exito")
        return redirect(url_for("horarios_doctor"))

    finally:
        conexion.close()


@app.route("/horarios-doctor/eliminar/<int:id_horario>", methods=["POST"])
@requiere_rol("DOCTOR")
def eliminar_horario(id_horario):
    conexion = conectar_bd()

    try:
        doctor = conexion.execute("""
            SELECT id_doctor
            FROM doctores
            WHERE id_usuario = ?
        """, (session["id_usuario"],)).fetchone()

        if doctor is None:
            return "No se encontró el perfil del doctor.", 404

        cursor = conexion.execute("""
            DELETE FROM horarios
            WHERE id_horario = ? AND id_doctor = ?
        """, (id_horario, doctor["id_doctor"]))

        conexion.commit()

        if cursor.rowcount == 0:
            flash("No se encontró ese horario.", "error")
        else:
            flash("Horario eliminado correctamente.", "exito")

        return redirect(url_for("horarios_doctor"))

    finally:
        conexion.close()


if __name__ == "__main__":
    app.run(debug=True)
