import ldap
from .settings import get_settings
from ldap.dn import escape_dn_chars


class LDAPConnection:

    def __init__(self, domain: str, username: str, password: str):
        settings = get_settings()
        self.conn = None
        uri = str(settings.LDAP_URI)

        starttls = False
        if uri.startswith("ldaps://"):
            starttls = True
            uri = uri.replace("ldaps://", "ldap://")
            ldap.set_option(ldap.OPT_X_TLS_REQUIRE_CERT, ldap.OPT_X_TLS_NEVER)  # type: ignore

        self.conn = ldap.initialize(uri=uri)
        self.conn.set_option(ldap.OPT_PROTOCOL_VERSION, ldap.VERSION3)  # type: ignore

        if starttls:
            self.conn.start_tls_s()

        safe_username = escape_dn_chars(username)
        safe_domain = escape_dn_chars(domain)

        admin_mail = f"{safe_username}@{safe_domain}"
        bind_dn = f"mail={admin_mail},ou=Users,domainName={safe_domain},o=domains,{settings.LDAP_ROOT_DN}"

        self.conn.bind_s(bind_dn, password)

        qr = self.conn.search_s(
            bind_dn,
            ldap.SCOPE_BASE,  # type: ignore
            f"(&(domainGlobalAdmin=yes)(mail={admin_mail}))",
            ["domainGlobalAdmin"],
        )
        if not qr:
            raise Exception(
                f"Пользователь {username} не является администратором домена {domain}"
            )

    def __del__(self):
        try:
            if self.conn:
                self.conn.unbind()
        except:
            pass
