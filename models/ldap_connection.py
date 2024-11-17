import ldap
from .settings import get_settings
from ldap.dn import escape_dn_chars
from ldap.ldapobject import LDAPObject
from utils.ldap import get_email_dn
from typing import Optional
import ldapurl


class LDAPConnection:

    def __init__(self, email: str, password: str):
        settings = get_settings()
        # self.conn = None
        uri = str(settings.LDAP_URI)

        starttls = False
        if uri.startswith("ldaps://"):
            starttls = True
            uri = uri.replace("ldaps://", "ldap://")
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # type: ignore

        self.conn = ldap.initialize(uri=uri, bytes_mode=False)
        self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)  # type: ignore

        if starttls:
            self.conn.start_tls_s()

        safe_email = escape_dn_chars(email)
        if email.find("@") >= 0:
            email_dn = get_email_dn(email)
            self.conn.bind_s(email_dn, password)

            qr = self.conn.search_s(
                email_dn,
                ldapurl.LDAP_SCOPE_BASE,
                f"(&(domainGlobalAdmin=yes)(mail={safe_email}))",
                ["domainGlobalAdmin"],
            )
            if not qr:
                raise Exception(f"Пользователь {email} не является администратором!")
        else:
            self.conn.bind_s(f"cn={safe_email},{settings.LDAP_ROOT_DN}", password)

    def __del__(self):
        try:
            if self.conn:
                self.conn.unbind()
        except:
            pass


__connection_instance: Optional[LDAPConnection] = None


class LDAPConnectionError(Exception): ...


def get_connection(
    email: Optional[str] = None, password: Optional[str] = None
) -> LDAPConnection:
    """
    Возвращает экземпляр настроек приложения. Настройки будут прочитаны из файла .env
    или .env.prod (если данный файл представлен в рабочем каталоге приложения)
    """

    global __connection_instance
    if email and password:
        __connection_instance = LDAPConnection(email, password)

    elif not __connection_instance:
        raise LDAPConnectionError("Аутентификация пользователя не выполнена")

    return __connection_instance
