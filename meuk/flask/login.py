"""Login/logout blueprint voor dashboard toegang."""

import hmac
import os

from flask import Blueprint, redirect, render_template, request, session, url_for


login_bp = Blueprint(
    "login_bp",
    __name__,
    template_folder="html",
)


def _credentials_configured():
    return bool(os.environ.get("IB_ADMIN_USER")) and bool(
        os.environ.get("IB_ADMIN_PASSWORD")
    )


def _verify_credentials(username, password):
    expected_user = os.environ.get("IB_ADMIN_USER", "")
    expected_pass = os.environ.get("IB_ADMIN_PASSWORD", "")
    if not expected_user or not expected_pass:
        return False
    return hmac.compare_digest(username, expected_user) and hmac.compare_digest(
        password, expected_pass
    )


def _safe_next(target):
    """Alleen relatieve paden toestaan (open-redirect preventie)."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return "/"


@login_bp.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if not _credentials_configured():
        error = "Login niet beschikbaar: IB_ADMIN_USER / IB_ADMIN_PASSWORD niet geconfigureerd."
        return render_template("login.html", error=error), 500

    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _verify_credentials(username, password):
            session["ib_authenticated"] = True
            return redirect(_safe_next(request.args.get("next") or request.form.get("next")))
        error = "Ongeldige gebruikersnaam of wachtwoord."

    return render_template("login.html", error=error)


@login_bp.route("/logout")
def logout():
    session.pop("ib_authenticated", None)
    return redirect(url_for("login_bp.login"))
