import ldapurl
from utils.decorators import login_required
from utils.decorators import templated
from models.ldap_connection import get_connection
from ldap.ldapobject import LDAPObject
from models.settings import get_settings
from flask import session, redirect
from utils.ldap import bytes2str


@login_required
@templated()
def domain_list():
    """
    Отображение страницы со списком пользователей
    """

    connection = get_connection()
    settings = get_settings()

    query_result = connection.conn.search_s(
        settings.LDAP_ROOT_DN,
        ldapurl.LDAP_SCOPE_SUBTREE,
        "(objectClass=mailDomain)",
        ["domainName", "accountStatus", "domainCurrentUserNumber"],
    )

    domain_info = []
    if query_result:
        for result in query_result:
            domain_info.append({k: bytes2str(v[0]) for k, v in result[1].items()})

    return {"domain_info": domain_info}
