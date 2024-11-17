from utils.decorators import templated
from flask import redirect, url_for


@templated()
def page_404(e):
    return {}


@templated()
def page_500(e): ...


def ldap_connection_error_handler(e):
    """
    Обработчик ошибки LDAP-соединения
    """
    return redirect(url_for("logout"))
