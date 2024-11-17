from typing import Any
from typing import Dict
from typing import Set
from typing import Type

from pydantic import SecretStr, BaseModel, field_validator, ValidationInfo
from pydantic.utils import update_not_none
from .settings import get_settings


SPECIAL_CHARS = {
    "$",
    "@",
    "#",
    "%",
    "!",
    "^",
    "&",
    "*",
    "(",
    ")",
    "-",
    "_",
    "+",
    "=",
    "{",
    "}",
    "[",
    "]",
}


def __has_non_ascii_character(s: str):
    for i in s:
        try:
            if not (32 <= ord(i) <= 126):
                return True
        except TypeError:
            return True
    return False


class UserPassword(BaseModel):
    password: SecretStr
    password_repeat: SecretStr

    @field_validator("password", "password_repeat")
    def check_password_constraints(
        cls, v: SecretStr, info: ValidationInfo
    ) -> SecretStr:
        settings = get_settings()
        secret_value = v.get_secret_value()

        for i in secret_value:
            try:
                if not (32 <= ord(i) <= 126):
                    raise ValueError(f"Пароль должен содержать только символы ASCII")
            except TypeError:
                raise ValueError(f"Пароль должен содержать только символы ASCII")

        if len(secret_value) < settings.PASSWORD_MIN_LENGTH:
            raise ValueError(
                f"Пароль должен содержать не менее {settings.PASSWORD_MIN_LENGTH} символов"
            )

        if settings.PASSWORD_INCLUDES_NUMBERS and not any(
            char.isdigit() for char in secret_value
        ):
            raise ValueError("Пароль должен содержать хотя бы одну цифру")

        if settings.PASSWORD_INCLUDES_UPPERCASE and not any(
            char.isupper() for char in secret_value
        ):
            raise ValueError("Пароль должен содержать хотя бы одну заглавную букву")

        if settings.PASSWORD_INCLUDES_LOWERCASE and not any(
            char.islower() for char in secret_value
        ):
            raise ValueError(
                "Пароль должен содержать хотя бы ону букву в нижнем регистре"
            )

        if settings.PASSWORD_INCLUDES_SPECIAL_CHARS and not any(
            char in SPECIAL_CHARS for char in secret_value
        ):
            raise ValueError(
                f"Пароль должен содержать хотя бы один спецсимвол {SPECIAL_CHARS}"
            )
        return v

    @field_validator("password_repeat")
    def passwords_match(cls, v: SecretStr, info: ValidationInfo) -> SecretStr:
        if "password" in info.data and v != info.data["password"]:
            raise ValueError("Пароль и подтверждение пароля не совпадают")
        return v
