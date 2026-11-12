
from functools import wraps
from flask import session, redirect, url_for, flash, abort


def requiere_login(funcion):
    @wraps(funcion)
    def envoltura(*args, **kwargs):
        if "id_usuario" not in session:
            flash("Debes iniciar sesión para acceder.", "error")
            return redirect(url_for("login"))

        return funcion(*args, **kwargs)

    return envoltura


def requiere_rol(*roles_permitidos):
    def decorador(funcion):
        @wraps(funcion)
        def envoltura(*args, **kwargs):
            if "id_usuario" not in session:
                flash("Debes iniciar sesión para acceder.", "error")
                return redirect(url_for("login"))

            if session.get("rol") not in roles_permitidos:
                abort(403)

            return funcion(*args, **kwargs)

        return envoltura
    return decorador
