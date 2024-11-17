from ldap.dn import escape_dn_chars
import ldap
import ldap.modlist
import ldapurl
from models.settings import get_settings
from typing import Union, List, Tuple, Any, Set, Dict, Container


def get_domains_for_admin(): ...


def get_email_dn(email: str) -> str:
    settings = get_settings()

    domain = email.split("@")[1]
    safe_domain = escape_dn_chars(domain)
    safe_email = escape_dn_chars(email)

    return f"mail={safe_email},ou=Users,domainName={safe_domain},o=domains,{settings.LDAP_ROOT_DN}"


def get_user_dn(user_id: str, domain: str) -> str:
    return get_email_dn(f"{user_id}@{domain}")


def get_domain_dn(domain: str):
    settings = get_settings()
    safe_domain = escape_dn_chars(domain)
    return f"domainName={safe_domain},o=domains,{settings.LDAP_ROOT_DN}"


def settings_list_to_dict(settings_list: List[str]) -> Dict:
    """Return a dict of 'accountSetting' values."""
    setting_dict = {}

    for item in settings_list:
        item = bytes2str(item)

        if type(item) == str:
            if ":" in item:
                (k, v) = item.split(":", 1)

                if k in [
                    "defaultQuota",
                    "maxUserQuota",
                    "minPasswordLength",
                    "maxPasswordLength",
                    "numberOfUsers",
                    "numberOfAliases",
                    "numberOfLists",
                    # Per-admin domain creation settings
                    "create_max_domains",
                    "create_max_quota",
                    "create_max_users",
                    "create_max_aliases",
                    "create_max_lists",
                ]:
                    # Value of these settings must be integer or '-1' (except 'maxUserQuota').
                    # '-1' means not allowed to add this kind of account.
                    if v.isdigit() or v == "-1":
                        setting_dict[k] = int(v)
                elif k in [
                    "disabledDomainProfile",
                    "disabledUserProfile",
                    "disabledUserPreference",
                    "disabledMailService",
                ]:
                    # These settings contains multiple values
                    # ldap value format: key:v1,v2,v3
                    v = v.lower()

                    if k in setting_dict:
                        setting_dict[k].append(v)
                    else:
                        setting_dict[k] = [v]
                elif k in ["defaultList"]:
                    setting_dict[k] = v.split(",")
                else:
                    setting_dict[k] = v

    return setting_dict


def __bytes2str(b) -> str:
    """Convert object `b` to string.

    >>> __bytes2str("a")
    'a'
    >>> __bytes2str(b"a")
    'a'
    >>> __bytes2str(["a"])  # list: return `repr()`
    "['a']"
    >>> __bytes2str(("a",)) # tuple: return `repr()`
    "('a',)"
    >>> __bytes2str({"a"})  # set: return `repr()`
    "{'a'}"
    """
    if isinstance(b, str):
        return b

    if isinstance(b, (bytes, bytearray)):
        return b.decode()
    elif isinstance(b, memoryview):
        return b.tobytes().decode()
    else:
        return repr(b)


def bytes2str(b: Union[bytes, str, List, Tuple, Set, Dict]):
    """Convert `b` from bytes-like type to string.

    - If `b` is a string object, returns original `b`.
    - If `b` is a bytes, returns `b.decode()`.

    bytes-like object, return `repr(b)` directly.

    >>> bytes2str("a")
    'a'
    >>> bytes2str(b"a")
    'a'
    >>> bytes2str(["a"])
    ['a']
    >>> bytes2str((b"a",))
    ('a',)
    >>> bytes2str({b"a"})
    {'a'}
    >>> bytes2str({"a": b"a"})      # used to convert LDAP query result.
    {'a': 'a'}
    """
    # if isinstance(b, (list, web.db.ResultSet)):
    #     s = [bytes2str(i) for i in b]
    if isinstance(b, tuple):
        s = tuple([bytes2str(i) for i in b])
    elif isinstance(b, set):
        s = {bytes2str(i) for i in b}  # type: ignore
    # elif isinstance(b, (dict, web.utils.Storage)):
    #     new_dict = {}
    #     for k, v in list(b.items()):
    #         new_dict[k] = bytes2str(v)  # v could be list/tuple/dict
    #     s = new_dict
    else:
        s = __bytes2str(b)

    return s


def __str2bytes(s) -> bytes:
    """Convert `s` from string to bytes."""
    if isinstance(s, bytes):
        return s
    elif isinstance(s, str):
        return s.encode()
    elif isinstance(s, (int, float)):
        return str(s).encode()
    else:
        return bytes(s)


def str2bytes(s):
    # if isinstance(s, (list, web.db.ResultSet)):
    #     s = [str2bytes(i) for i in s]
    if isinstance(s, tuple):
        s = tuple([str2bytes(i) for i in s])
    elif isinstance(s, set):
        s = {str2bytes(i) for i in s}
    # elif isinstance(s, (dict, web.utils.Storage)):
    #     new_dict = {}
    #     for k, v in list(s.items()):
    #         new_dict[k] = str2bytes(v)  # v could be list/tuple/dict
    #     s = new_dict
    else:
        s = __str2bytes(s)

    return s


def attr_ldif(attr, value, default=None, mode=None) -> List:
    """Generate a list of LDIF data with given attribute name and value.
    Returns empty list if no valid value.

    Value is properly handled with str/bytes/list/tuple/set types, and
    converted to list of bytes at the end.

    To generate ldif list with ldap modification like `ldap.MOD_REPLACE`,
    please use function `mod_replace()` instead.
    """
    v = value or default
    _ldif = []

    if v:
        if isinstance(value, (list, tuple, set)):
            lst = []
            for i in v:
                # Avoid duplicate element.
                if i in lst:
                    continue

                if isinstance(i, bytes):
                    lst.append(i)
                else:
                    lst.append(str2bytes(i))

            v = lst
        elif isinstance(value, (int, float)):
            v = [str(v).encode()]
        else:
            v = [str2bytes(v)]

    if mode == "replace":
        if v:
            _ldif = [(ldap.MOD_REPLACE, attr, v)]  # type: ignore
        else:
            _ldif = [(ldap.MOD_REPLACE, attr, None)]  # type: ignore
    elif mode == "add":
        if v:
            _ldif = [(ldap.MOD_ADD, attr, v)]  # type: ignore
    elif mode == "delete":
        if v or v is None:
            # Remove specified attr/value pair(s) if v is valid, or remove
            # completely if v is None.
            _ldif = [(ldap.MOD_DELETE, attr, v)]  # type: ignore
    else:
        if v:
            # Used for adding ldap object.
            _ldif = [(attr, v)]

    return _ldif


def attrs_ldif(kvs: Dict) -> List:
    lst = []
    for k, v in kvs.items():
        lst += attr_ldif(k, v)

    return lst


# Return list of `ldap.MOD_REPLACE` operation.
def mod_replace(attr, value, default=None) -> List[Tuple]:
    """Return list of (only one) `ldap.MOD_REPLACE` used to remove of update
    LDAP value.

    When final value is `None` or empty list/tuple/set, LDAP
    attribute `attr` will be removed.

    >>> mod_replace(attr='name', value=None)
    [(2, 'name', None)]
    >>> mod_replace(attr='name', value='')
    [(2, 'name', None)]
    >>> mod_replace(attr='name', value=[])
    [(2, 'name', None)]
    >>> mod_replace(attr='name', value='', default=None)
    [(2, 'name', None)]
    >>> mod_replace(attr='name', value='my name')
    [(2, 'name', [b'my name'])]
    >>> mod_replace(attr='aint', value=5)
    [(2, 'aint', ['5'])]
    >>> mod_replace(attr='alist', value=['elm1', 'elm2'])
    [(2, 'alist', [b'elm1', b'elm2'])]
    >>> mod_replace(attr='atuple', value=('elm1', 'elm2'))
    [(2, 'atuple', [b'elm1', b'elm2'])]
    >>> mod_replace(attr='aset', value={'elm1', 'elm2'})
    [(2, 'aset', [b'elm1', b'elm2'])]
    """
    return attr_ldif(attr=attr, value=value, default=default, mode="replace")
