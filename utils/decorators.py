from flask import session, request, redirect, url_for, render_template
from functools import wraps
from typing import Optional


def login_required(f):
    """
    Декоратор обработчиков для адресов URL. Выполняет проверку аутентификации текущего пользователя.
    В случае, если аутентификация не была выполнена ранее, перенаправляет пользователя на форму входа
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("username") is None:
            return redirect(url_for("login_page", next=request.url))
        return f(*args, **kwargs)

    return decorated_function


def templated(template: Optional[str] = None):
    """
    Декоратор для рендеринга шаблона, соответвующего endpoint'у текущего запроса. Вызывает
    обработчик endpoint'a и рендерит шаблон с возвращенным из обработчика словарем

    Аргументы:
      template: путь к файлу шаблона
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            template_name = template
            if template_name is None:
                if not request.endpoint:
                    return f(*args, **kwargs)
                template_name = f"{request.endpoint.replace('.', '/')}.html"

            ctx = f(*args, **kwargs)
            if ctx is None:
                ctx = {}
            elif not isinstance(ctx, dict):
                return ctx
            return render_template(template_name, **ctx)

        return decorated_function

    return decorator
