#!/bin/env python3
# -*- coding: utf-8 -*-

"""
admin.py
Beheer functionaliteit
"""

import hmac
import os

from flask import Response
from flask import current_app as app
from flask import request, session
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView

from .models import *


def _is_local_request():
    return request.remote_addr in {"127.0.0.1", "::1"}


def _admin_credentials_set():
    return bool(os.environ.get("IB_ADMIN_USER")) and bool(os.environ.get("IB_ADMIN_PASSWORD"))


def _check_basic_auth():
    expected_user = os.environ.get("IB_ADMIN_USER")
    expected_password = os.environ.get("IB_ADMIN_PASSWORD")
    auth = request.authorization
    if not auth or not auth.username or not auth.password:
        return False
    return hmac.compare_digest(auth.username, expected_user) and hmac.compare_digest(
        auth.password, expected_password
    )


class ProtectedModelView(ModelView):
    def is_accessible(self):
        # Localhost bypass alleen als er geen credentials geconfigureerd zijn
        if _is_local_request() and not _admin_credentials_set():
            return True
        if session.get("ib_authenticated"):
            return True
        if _admin_credentials_set():
            return _check_basic_auth()
        return False

    def inaccessible_callback(self, name, **kwargs):
        return Response(
            "Authentication required",
            401,
            {"WWW-Authenticate": 'Basic realm="Incompetent Bastard Admin"'},
        )


class Bevindingen_templatesview(ProtectedModelView):
    form_choices = {
        "owasp": [
            ("1", "A1 - Broken Access Control"),
            ("2", "A2 - Crypthographic Failures"),
            ("3", "A3 - Injection"),
            ("4", "A4 - Insecure Design"),
            ("5", "A5 - Security Misconfiguration"),
            ("6", "A6 - Vulnerable and Outdated Components"),
            ("7", "A7 - Identification and Authentication Failures"),
            ("8", "A8 - Software and Data Integrity Failures"),
            ("9", "A9 - Security Logging and Monitoring Failures"),
            ("10", "A10 - Server Side Request Forgery"),
        ]
    }
    column_exclude_list = [
        "kans",
        "impact",
        "cve",
        "nlbeschrijving",
        "enbeschrijving",
        "nlimpact",
        "enimpact",
        "nlimpactkort",
        "enimpactkort",
        "nlaanbevelingkort",
        "nlaanbeveling",
        "enaanbeveling",
        "enaanbevelingkort",
        "referenties",
    ]


class Bevindingen_view(ProtectedModelView):
    pass


class Instellingen(ProtectedModelView):
    pass


class Tijdelijk(ProtectedModelView):
    pass


admin = Admin(app, name="incompetent bastard", url="/dashboard/admin")
admin.add_view(Bevindingen_templatesview(db_bevindingen_templates, db.session, name="Templates"))
admin.add_view(Bevindingen_view(db_bevindingen, db.session, name="Bevindingen"))
admin.add_view(Tijdelijk(db_xxs_cookies, db.session, name="db_xxs_cookies", category="XSS"))
admin.add_view(Tijdelijk(db_xxs_hooked, db.session, name="db_xxs_hooked", category="XSS"))
admin.add_view(Tijdelijk(db_xxs_login, db.session, name="db_xxs_login", category="XSS"))
admin.add_view(Tijdelijk(db_xxs_localstorage, db.session, name="db_xxs_localstorage", category="XSS"))
admin.add_view(Tijdelijk(db_xxs_keylogger, db.session, name="db_xxs_keylogger", category="XSS"))
admin.add_view(Tijdelijk(db_xxs_form, db.session, name="db_xxs_form", category="XSS"))
admin.add_view(Instellingen(db_instellingen, db.session, name="Instellingen"))
