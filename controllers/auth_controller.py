from flask import session, request, redirect, url_for
from utils.decorators import templated
from typing import Optional
from models.ldap_connection import LDAPConnection
from app import app


def authenticate_user(domain: str, username: str, password: str) -> bool:
    """
    Выполняет аутентификацию пользователя по переданной комбинации логина и пароля

    Аргументы:
        username: логин пользователя
        password: пароль пользователя
    Возвращаемое значение:
        булево: истина, если пользователь успешно аутентифицирован
    """
    try:
        LDAPConnection(domain, username, password)
        app.logger.info(
            f"Аутентификация пользователя {username} и домена {domain} выполнена успешно"
        )
        return True
    except Exception as e:
        app.logger.error(
            f"Не удалось выполнить аутентификацию для пользователя {username} и домена {domain} по причине: {e}"
        )
        return False


@templated()
def login_page():
    """
    Обработчик бизнес-логики страницы входа пользователя в приложение
    """
    next = request.args.get("next", "/")

    error: Optional[str] = None
    username: Optional[str] = None
    domain: Optional[str] = None

    if request.method == "POST":
        domain, username, password = (
            request.form["domain"],
            request.form["username"],
            request.form["password"],
        )
        if authenticate_user(domain, username, password):
            session["username"] = request.form["username"]
            session["domain"] = request.form["domain"]
            return redirect(next)
        error = "Введены некорректные данные!"
    return {"next": next, "error": error, "username": username, "domain": domain}


def logout():
    """
    Обработчик бизес логики выхода пользователя из приложения
    """
    session.clear()
    return redirect(url_for("login_page"))
