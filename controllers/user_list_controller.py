from utils.decorators import login_required
from utils.decorators import templated
from flask import session


@login_required
@templated()
def users_list():
    """
    Отображение страницы со списком пользователей
    """

    return {"username": session.get("username")}
