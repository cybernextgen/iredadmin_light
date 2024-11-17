from flask import session, request, redirect, url_for, g
from utils.decorators import templated
from typing import Optional
from models.ldap_connection import get_connection
from app import app


def authenticate_user(email: str, password: str) -> bool:
    """
    Выполняет аутентификацию пользователя по переданной комбинации логина и пароля

    Аргументы:
        username: логин пользователя
        password: пароль пользователя
    Возвращаемое значение:
        булево: истина, если пользователь успешно аутентифицирован
    """
    try:
        get_connection(email, password)
        app.logger.info(f"Аутентификация пользователя {email} выполнена успешно")
        return True
    except Exception as e:
        app.logger.error(
            f"Не удалось выполнить аутентификацию для пользователя {email} по причине: {e}"
        )
        return False


@templated()
def login_page():
    """
    Обработчик бизнес-логики страницы входа пользователя в приложение
    """
    next = request.args.get("next", "/")

    error: Optional[str] = None
    email: Optional[str] = None

    if request.method == "POST":
        email, password = (
            request.form["email"],
            request.form["password"],
        )
        if authenticate_user(email, password):
            session["email"] = request.form["email"]
            return redirect(next)
        error = "Введены некорректные данные!"
    return {"next": next, "error": error, "email": email}


def logout():
    """
    Обработчик бизес логики выхода пользователя из приложения
    """
    session.clear()
    return redirect(url_for("login_page"))
