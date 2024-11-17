from flask import Flask
from models.settings import get_settings
from pydantic import ValidationError
import sys

from models.ldap_connection import get_connection

app = Flask(__name__)

import routes
import template_filters

try:
    settings = get_settings()
except ValidationError as e:
    app.logger.error(e)
    sys.exit(1)


# get_connection(settings.LDAP_USER, settings.LDAP_PASSWORD)

routes.register(app)
template_filters.register(app)

app.config.update(get_settings())
