import os

from flask import abort
from flask import current_app
from flask import redirect
from flask import request
from flask import session
from flask import url_for


_LOCAL_IPS = {"127.0.0.1", "::1"}


def is_local_request():
    return request.remote_addr in _LOCAL_IPS


def _credentials_configured():
    return bool(os.environ.get("IB_ADMIN_USER")) and bool(
        os.environ.get("IB_ADMIN_PASSWORD")
    )


def _check_session_login():
    return session.get("ib_authenticated") is True


def dashboard_access_allowed():
    # Localhost bypass alleen als er geen credentials geconfigureerd zijn
    if is_local_request() and not _credentials_configured():
        return True

    if _check_session_login():
        return True

    token = current_app.config.get("DASHBOARD_ACCESS_TOKEN") or current_app.config.get("TASK_RUNNER_TOKEN")
    if not token:
        return False

    supplied = request.headers.get("X-Dashboard-Token") or request.headers.get("X-Task-Token")
    return supplied == token


def require_dashboard_access():
    if dashboard_access_allowed():
        return
    if request.is_json or request.headers.get("X-Dashboard-Token") or request.headers.get("X-Task-Token"):
        abort(403)
    abort(redirect(url_for("login_bp.login", next=request.path)))
