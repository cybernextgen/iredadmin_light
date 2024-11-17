from typing import Any, Optional
from typing_extensions import Self
from pydantic import BaseModel, ValidationError, model_validator, ConfigDict


class User(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, arbitrary_types_allowed=True)

    accountStatus: bool = False
    uid: str
    mailQuota: int = 100
    cn: str = ""
    givenName: str = ""
    sn: str = ""
    employeeNumber: str = ""
    title: str = ""
    mobile: str = ""
    telephoneNumber: str = ""
    domainGlobalAdmin: bool = False
