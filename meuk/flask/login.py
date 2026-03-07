"""Login/logout blueprint voor dashboard toegang."""

import hmac
import os
import threading
import time

from flask import Blueprint, redirect, render_template, request, session, url_for


login_bp = Blueprint(
    "login_bp",
    __name__,
    template_folder="html",
)

# ── Simpele in-memory brute-force bescherming ──────────────────────────────────
# Maximaal 10 pogingen per IP per 15 minuten. Na blokkade: 15 minuten wachten.
_RATE_LIMIT_MAX     = 10
_RATE_LIMIT_WINDOW  = 900   # seconden
_RATE_LIMIT_BLOCK   = 900   # blokkeerduur in seconden

_rate_data = {}   # ip -> {'count': int, 'window_start': float, 'blocked_until': float}
_rate_lock = threading.Lock()


def _check_rate_limit(ip):
    """Return (allowed: bool, retry_after: int). Registreert ook de poging."""
    now = time.time()
    with _rate_lock:
        entry = _rate_data.get(ip, {'count': 0, 'window_start': now, 'blocked_until': 0.0})

        # Nog geblokkeerd?
        if entry['blocked_until'] > now:
            return False, int(entry['blocked_until'] - now)

        # Reset venster als het verlopen is
        if now - entry['window_start'] > _RATE_LIMIT_WINDOW:
            entry = {'count': 0, 'window_start': now, 'blocked_until': 0.0}

        entry['count'] += 1

        if entry['count'] > _RATE_LIMIT_MAX:
            entry['blocked_until'] = now + _RATE_LIMIT_BLOCK
            _rate_data[ip] = entry
            return False, _RATE_LIMIT_BLOCK

        _rate_data[ip] = entry
        return True, 0


def _reset_rate_limit(ip):
    """Reset teller na succesvolle login."""
    with _rate_lock:
        _rate_data.pop(ip, None)


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
        ip = request.remote_addr or "unknown"
        allowed, retry_after = _check_rate_limit(ip)
        if not allowed:
            error = f"Te veel pogingen. Probeer over {retry_after // 60} minuten opnieuw."
            return render_template("login.html", error=error), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if _verify_credentials(username, password):
            _reset_rate_limit(ip)
            session["ib_authenticated"] = True
            return redirect(_safe_next(request.args.get("next") or request.form.get("next")))
        error = "Ongeldige gebruikersnaam of wachtwoord."

    return render_template("login.html", error=error)


@login_bp.route("/logout")
def logout():
    session.pop("ib_authenticated", None)
    return redirect(url_for("login_bp.login"))
