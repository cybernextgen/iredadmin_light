from typing_extensions import Annotated, Literal
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyUrl, UrlConstraints, Field
from typing import Optional, Union


LDAPUrl = Annotated[AnyUrl, UrlConstraints(allowed_schemes=["ldap", "ldaps"])]


class Settings(BaseSettings):
    """
    Класс с настройками приложения
    """

    model_config = SettingsConfigDict(
        env_prefix="IREDADMIN_LIGHT_",
        env_file=(".env", ".env.prod"),
        env_file_encoding="utf-8",
        extra="forbid",
    )

    NAME: str = "local"
    SECRET_KEY: str
    LDAP_URI: LDAPUrl
    LDAP_ROOT_DN: str

    TEMPLATES_AUTO_RELOAD: bool = True

    LDAP_USER: str
    LDAP_PASSWORD: str

    PASSWORD_MIN_LENGTH: int = 8
    PASSWORD_INCLUDES_SPECIAL_CHARS: bool = True
    PASSWORD_INCLUDES_NUMBERS: bool = True
    PASSWORD_INCLUDES_LOWERCASE: bool = True
    PASSWORD_INCLUDES_UPPERCASE: bool = True
    PASSWORD_HASHES_USE_PREFIXED_SCHEME: bool = True
    PASSWORD_DEFAULT_SCHEME: Literal[
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
    ] = "SSHA512"


settings_instance: Optional[Settings] = None


def get_settings() -> Settings:
    """
    Возвращает экземпляр настроек приложения. Настройки будут прочитаны из файла .env
    или .env.prod (если данный файл представлен в рабочем каталоге приложения)
    """
    global settings_instance
    if not settings_instance:
        settings_instance = Settings()  # type: ignore
    return settings_instance
