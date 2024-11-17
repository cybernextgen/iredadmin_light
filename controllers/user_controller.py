from typing import Optional, List, Dict

import ldapurl
from flask import abort, request
from pydantic import ValidationError

from models.ldap_connection import get_connection
from models.user import User
from models.user_password import UserPassword
from utils.decorators import login_required, templated
from utils.ldap import bytes2str, get_domain_dn, get_email_dn, mod_replace
from utils.password import generate_password_hash


def __ldap_query_to_user(query) -> User:
    """
    Преобразует данные атрибутов из каталога в модель пользователя
    """
    user_data = {k: bytes2str(v[0]) for k, v in query[1].items()}
    user_data["accountStatus"] = user_data["accountStatus"] == "active"  # type: ignore
    user_data["domainGlobalAdmin"] = user_data.get("domainGlobalAdmin") == "yes"  # type: ignore
    return User(
        **user_data,  # type: ignore
    )


def __validation_errors_to_dict(e: ValidationError) -> Dict[str, str]:
    result = {}
    for error_dict in e.errors():
        for field_name in error_dict["loc"]:
            msg = error_dict["msg"].replace("Value error,", "").strip()
            result[field_name] = msg
    return result


def get_user_from_ldap(domain: str, user_id: str) -> Optional[User]:
    """
    Получение модели пользователя по идентификатору и доменному имени
    """
    connection = get_connection()

    query_result = connection.conn.search_s(
        f"ou=Users,{get_domain_dn(domain)}",
        ldapurl.LDAP_SCOPE_ONELEVEL,
        f"(&(objectClass=mailUser)(uid={user_id}))",
        [
            "mail",
            "accountStatus",
            "domainGlobalAdmin",
            "mailQuota",
            "uid",
            "cn",
            "givenName",
            "sn",
            "title",
            "telephoneNumber",
            "mobile",
            "employeeNumber",
        ],
    )

    if not query_result:
        return None

    return __ldap_query_to_user(query_result[0])


def get_users_from_ldap(domain: str) -> List[User]:
    """
    Получение списка моделей пользователей для указанного домена
    """
    connection = get_connection()

    query_result = connection.conn.search_s(
        f"ou=Users,{get_domain_dn(domain)}",
        ldapurl.LDAP_SCOPE_ONELEVEL,
        f"(&(objectClass=mailUser)(!(mail=@{domain})))",
        ["mail", "accountStatus", "domainGlobalAdmin", "mailQuota", "uid"],
    )

    users: List[User] = []
    if query_result:
        for result in query_result:
            users.append(__ldap_query_to_user(result))
    return users


def update_user(domain: str, user: User):
    connection = get_connection()

    mod_attrs = mod_replace(
        "domainGlobalAdmin", "yes" if user.domainGlobalAdmin else None
    )
    mod_attrs += mod_replace("mailQuota", user.mailQuota * 1024 * 1024)
    mod_attrs += mod_replace("cn", user.cn)
    mod_attrs += mod_replace("givenName", user.givenName)
    mod_attrs += mod_replace("sn", user.sn)
    mod_attrs += mod_replace("employeeNumber", user.employeeNumber)
    mod_attrs += mod_replace("title", user.title)
    mod_attrs += mod_replace("telephoneNumber", user.telephoneNumber)
    mod_attrs += mod_replace("mobile", user.mobile)
    mod_attrs += mod_replace(
        "accountStatus", "active" if user.accountStatus else "disabled"
    )

    dn_user = get_email_dn(f"{user.uid}@{domain}")
    connection.conn.modify_s(dn_user, mod_attrs)


def update_user_password(domain: str, user_uid: str, password_hash: str):
    connection = get_connection()
    mod_attrs = mod_replace("userPassword", password_hash)
    dn_user = get_email_dn(f"{user_uid}@{domain}")
    connection.conn.modify_s(dn_user, mod_attrs)


def create_user(domain: str, user_uid: str, password_hash): ...


@login_required
@templated()
def user_list(domain: str):
    """
    Отображение страницы со списком пользователей
    """
    users = get_users_from_ldap(domain)
    users.sort(key=lambda x: x.uid)

    return {"domain": domain, "users": users}


@login_required
@templated()
def user_view(domain: str, user_uid: str, edit_mode: str):
    """
    Отображение карточки пользователя
    """
    error: Optional[str] = None
    validation_errors: Dict[str, str] = {}
    success: Optional[str] = None

    if request.method == "POST":
        try:
            if edit_mode == "general":
                user = User(**request.form)  # type: ignore
                update_user(domain, user)
                success = "Информация обновлена успешно!"

            elif edit_mode == "password":
                user_password = UserPassword(**request.form)  # type: ignore
                password_hash = generate_password_hash(
                    user_password.password.get_secret_value()
                )
                update_user_password(domain, user_uid, password_hash)
                success = "Пароль обновлен успешно!"
        except ValidationError as e:
            validation_errors = __validation_errors_to_dict(e)

    user = get_user_from_ldap(domain, user_uid)
    if not user:
        return abort(404)

    return {
        "domain": domain,
        "user": user,
        "error": error,
        "validation_errors": validation_errors,
        "success": success,
        "edit_mode": edit_mode,
    }


@login_required
@templated()
def user_create_view(domain: str):
    validation_errors: Dict[str, str] = {}
    user: Optional[User] = None

    if request.method == "POST":

        user_uid = request.form["uid"]
        user = get_user_from_ldap(domain, user_uid)
        if user:
            validation_errors["uid"] = (
                f"Пользователь с идентификатором {user_uid} уже существует"
            )

        else:
            try:
                user = User(**request.form)  # type: ignore
                password = UserPassword(**request.form)  # type: ignore
            except ValidationError as e:
                validation_errors = __validation_errors_to_dict(e)
    return {"domain": domain, "validation_errors": validation_errors, "user": user}
