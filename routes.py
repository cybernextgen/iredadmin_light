from flask import Flask, redirect, url_for
from controllers import (
    domain_controller,
    user_controller,
    auth_controller,
    base_controller,
)
from models.ldap_connection import LDAPConnectionError


def default_route_handler():
    return redirect(url_for("domain_list"))


def register(app: Flask):
    """
    Регистрирует обработчики для URL адресов

    Аргументы:
      app: экземпляр Flask для которого выполняется регистрация обработчиков
    """
    app.add_url_rule("/", "index", default_route_handler)
    app.add_url_rule("/<domain>/users", "user_list", user_controller.user_list)
    app.add_url_rule(
        "/<domain>/users/create",
        "user_create",
        user_controller.user_create_view,
        methods=["GET", "POST"],
    )
    app.add_url_rule(
        "/<domain>/users/<user_uid>/<edit_mode>",
        "user_view",
        user_controller.user_view,
        methods=["GET", "POST"],
    )

    app.add_url_rule(
        "/login",
        "login_page",
        auth_controller.login_page,
        methods=["GET", "POST"],
    )
    app.add_url_rule("/domains", "domain_list", domain_controller.domain_list)
    app.add_url_rule("/logout", "logout", auth_controller.logout)

    app.register_error_handler(404, base_controller.page_404)
    app.register_error_handler(
        LDAPConnectionError, base_controller.ldap_connection_error_handler
    )
