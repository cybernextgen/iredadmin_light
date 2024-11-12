from flask import Flask
from models.settings import get_settings
from pydantic import ValidationError
import sys
import routes

app = Flask(__name__)

try:
    get_settings()
except ValidationError as e:
    app.logger.error(e)
    sys.exit(1)


if __name__ == "__main__":
    routes.register(app)
    app.config.update(get_settings())
    app.run()
