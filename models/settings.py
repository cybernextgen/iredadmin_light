from typing_extensions import Annotated
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import AnyUrl, UrlConstraints, Field
from typing import Optional


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

    DEBUG: bool = False
    NAME: str = "local"
    SECRET_KEY: str
    LDAP_URI: LDAPUrl
    LDAP_ROOT_DN: str


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
