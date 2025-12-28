from flask import Blueprint

cert_bp = Blueprint("cert", __name__, url_prefix="/certificate")

from app.blueprints.cert import routes  # noqa: E402,F401
