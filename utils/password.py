# Author: Zhang Huangbin <zhb@iredmail.org>

import crypt
import hashlib

import subprocess
from base64 import b64encode

from os import urandom
from typing import List, Optional, Union

from models.settings import get_settings


def generate_bcrypt_password(p) -> str:
    if isinstance(p, str):
        p = p.encode()

    try:
        import bcrypt
    except:
        return generate_ssha_password(p)

    return "{CRYPT}" + bcrypt.hashpw(p, bcrypt.gensalt()).decode()


def generate_md5_password(p: str) -> str:
    return crypt.crypt(p, salt=crypt.METHOD_MD5)


def generate_plain_md5_password(p: Union[str, bytes]) -> str:
    if isinstance(p, str):
        p_as_str = p.encode()

    p_as_str = p_as_str.strip()
    return hashlib.md5(p_as_str).hexdigest()


def generate_ssha_password(p: Union[str, bytes]) -> str:
    if isinstance(p, str):
        p_as_str = p.encode()

    p_as_str = p_as_str.strip()
    salt = urandom(8)
    pw = hashlib.sha1(p_as_str)
    pw.update(salt)

    return "{SSHA}" + b64encode(pw.digest() + salt).decode()


def generate_sha512_password(p: Union[str, bytes]) -> str:
    """Generate SHA512 password with prefix '{SHA512}'."""
    if isinstance(p, str):
        p_as_str = p.encode()

    p_as_str = p_as_str.strip()
    pw = hashlib.sha512(p_as_str)
    return "{SHA512}" + b64encode(pw.digest()).decode()


def generate_ssha512_password(p: Union[str, bytes]) -> str:
    """Generate salted SHA512 password with prefix '{SSHA512}'."""
    if isinstance(p, str):
        p_as_str = p.encode()

    p_as_str = p_as_str.strip()
    salt = urandom(8)
    pw = hashlib.sha512(p_as_str)
    pw.update(salt)
    return "{SSHA512}" + b64encode(pw.digest() + salt).decode()


def generate_password_with_doveadmpw(scheme: str, plain_password: str) -> str:
    """Generate password hash with `doveadm pw` command.
    Return SSHA instead if no 'doveadm' command found or other error raised."""
    # scheme: CRAM-MD5, NTLM
    scheme = scheme.upper()
    settings = get_settings()

    p = str(plain_password).strip()

    try:
        pp = subprocess.Popen(
            args=["doveadm", "pw", "-s", scheme, "-p", p], stdout=subprocess.PIPE
        )
        pw = pp.communicate()[0].decode()

        if settings.PASSWORD_HASHES_USE_PREFIXED_SCHEME:
            pw = pw.lstrip("{" + scheme + "}")

        # remove '\n'
        pw = pw.strip()

        return pw
    except:
        return generate_ssha_password(p)


def generate_cram_md5_password(p):
    return generate_password_with_doveadmpw("CRAM-MD5", p)


def generate_ntlm_password(p):
    return generate_password_with_doveadmpw("NTLM", p)


def generate_password_hash(p: Union[str, bytes], scheme: Optional[str] = None) -> str:
    """Generate password for LDAP mail user and admin."""
    settings = get_settings()

    if isinstance(p, bytes):
        p_as_str = p.decode()
    else:
        p_as_str = str(p)

    p_as_str = p_as_str.strip()
    scheme = scheme or settings.PASSWORD_DEFAULT_SCHEME

    # # Supports returning multiple passwords.
    # pw_schemes = pwscheme.split("+")
    # pws = []

    if scheme == "BCRYPT":
        pw_hash = generate_bcrypt_password(p_as_str)
    elif scheme == "SSHA512":
        pw_hash = generate_ssha512_password(p_as_str)
    elif scheme == "SHA512":
        pw_hash = generate_sha512_password(p_as_str)
    elif scheme == "SSHA":
        pw_hash = generate_ssha_password(p_as_str)
    elif scheme == "MD5":
        pw_hash = "{CRYPT}" + generate_md5_password(p_as_str)
    elif scheme == "CRAM-MD5":
        pw_hash = generate_cram_md5_password(p_as_str)
    elif scheme == "PLAIN-MD5":
        pw_hash = generate_plain_md5_password(p_as_str)
    elif scheme == "NTLM":
        pw_hash = generate_ntlm_password(p_as_str)
    elif scheme == "PLAIN":
        if settings.PASSWORD_HASHES_USE_PREFIXED_SCHEME:
            pw_hash = "{PLAIN}" + p_as_str
        else:
            pw_hash = p_as_str

    else:
        pw_hash = p_as_str
    return pw_hash


def is_supported_password_scheme(pw_hash):
    if not (pw_hash.startswith("{") and "}" in pw_hash):
        return False

    # Extract scheme name from password hash: "{SSHA}xxxx" -> "SSHA"
    try:
        scheme = pw_hash.split("}", 1)[0].split("{", 1)[-1]
        scheme = scheme.upper()

        if scheme in [
            "PLAIN",
            "CRYPT",
            "MD5",
            "PLAIN-MD5",
            "SHA",
            "SSHA",
            "SHA512",
            "SSHA512",
            "SHA512-CRYPT",
            "BCRYPT",
            "CRAM-MD5",
            "NTLM",
        ]:
            return True
    except:
        pass

    return False
