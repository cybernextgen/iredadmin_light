from flask import Flask, redirect, url_for
from controllers import user_list_controller, auth_controller


def default_route_handler():
    return redirect(url_for("users_list"))


def register(app: Flask):
    """
    Регистрирует обработчики для URL адресов

    Аргументы:
      app: экземпляр Flask для которого выполняется регистрация обработчиков
    """
    app.add_url_rule("/", "index", default_route_handler)
    app.add_url_rule("/users", "users_list", user_list_controller.users_list)
    app.add_url_rule(
        "/login",
        "login_page",
        auth_controller.login_page,
        methods=["GET", "POST"],
    )
    app.add_url_rule("/logout", "logout", auth_controller.logout)
