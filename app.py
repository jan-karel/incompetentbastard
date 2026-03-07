"""Initialize app."""

import os
import secrets
from secrets import token_urlsafe

from flask import Flask, g, request
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.csrf import generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix


db = SQLAlchemy()


def _as_bool(value, default=False):
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


class _ConditionalProxyFix:
    """WSGI middleware that applies ProxyFix only when BEHIND_PROXY is enabled."""

    def __init__(self, wsgi_app, flask_app):
        self._wsgi_app = wsgi_app
        self._flask_app = flask_app
        self._proxy_fix = ProxyFix(wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    def __call__(self, environ, start_response):
        if self._flask_app.config.get("BEHIND_PROXY"):
            return self._proxy_fix(environ, start_response)
        return self._wsgi_app(environ, start_response)


def create_app():
    """Construct the core app object."""
    app = Flask(__name__, instance_relative_config=False)

    app.wsgi_app = _ConditionalProxyFix(app.wsgi_app, app)

    default_db = "sqlite:///{0}/meuk/flask/db/db.sqlite".format(os.path.dirname(__file__))
    app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", token_urlsafe(32))
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", default_db)
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("MAX_CONTENT_LENGTH", 10 * 1024 * 1024))
    app.config["PUBLIC_UPLOAD"] = _as_bool(os.environ.get("PUBLIC_UPLOAD"), default=False)
    app.config["PUBLIC_DOWNLOADS"] = _as_bool(os.environ.get("PUBLIC_DOWNLOADS"), default=False)
    app.config["BEHIND_PROXY"] = _as_bool(os.environ.get("BEHIND_PROXY"), default=False)
    app.config["DASHBOARD_ACCESS_TOKEN"] = os.environ.get("DASHBOARD_ACCESS_TOKEN", "")
    app.config["TASK_RUNNER_TOKEN"] = os.environ.get("TASK_RUNNER_TOKEN", "")
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["SESSION_COOKIE_SECURE"] = _as_bool(os.environ.get("SESSION_COOKIE_SECURE"), default=False)

    db.init_app(app)
    Migrate(app, db, render_as_batch=True)

    with app.app_context():
        from meuk.flask import models  # noqa: F401 — import models first
        db.create_all()

        # Auto-migrate existing databases for new settings columns
        with db.engine.connect() as conn:
            for col in ("public_upload", "public_downloads", "public_payloads", "behind_proxy"):
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_instellingen ADD COLUMN {col} BOOLEAN DEFAULT 0"))
                    conn.commit()
                except Exception:
                    pass

            for col, coltype in [("status", "VARCHAR(16) DEFAULT 'queued'"),
                                 ("result", "TEXT"),
                                 ("created", "DATETIME")]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_xxs_commands ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

            # Auto-migrate: finding status
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_bevinding ADD COLUMN status VARCHAR(16) DEFAULT 'draft'"))
                conn.commit()
                conn.execute(db.text(
                    "UPDATE db_bevinding SET status='final' WHERE status IS NULL"))
                conn.commit()
            except Exception:
                pass

            # Auto-migrate: rapport metadata op instellingen
            for col in ("rapport_titel", "rapport_auteur", "rapport_subtitel",
                         "rapport_project", "rapport_omgeving"):
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_instellingen ADD COLUMN {col} VARCHAR(200) DEFAULT ''"))
                    conn.commit()
                except Exception:
                    pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_classificatie VARCHAR(200) DEFAULT 'TLP:RED'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_taal VARCHAR(5) DEFAULT 'nl'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_isdraft BOOLEAN DEFAULT 1"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_testtype VARCHAR(20) DEFAULT 'pentest'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_testscope VARCHAR(20) DEFAULT 'blackbox'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_management_samenvatting TEXT DEFAULT ''"))
                conn.commit()
            except Exception:
                pass
            for col in ("rapport_legsup_startpunt", "rapport_legsup_privileges",
                        "rapport_legsup_informatie"):
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_instellingen ADD COLUMN {col} TEXT DEFAULT ''"))
                    conn.commit()
                except Exception:
                    pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_scenarios TEXT DEFAULT '[]'"))
                conn.commit()
            except Exception:
                pass
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_instellingen ADD COLUMN rapport_scope_targets TEXT DEFAULT '[]'"))
                conn.commit()
            except Exception:
                pass

            # Auto-migrate: rapport versienummer
            for col, coltype in [
                ("rapport_versie", "VARCHAR(20) DEFAULT ''"),
                ("rapport_versie_status", "VARCHAR(20) DEFAULT 'concept'"),
            ]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_instellingen ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

            # Auto-migrate: rapport extended settings
            for col, coltype in [
                ("rapport_logo_path", "VARCHAR(300) DEFAULT ''"),
                ("rapport_template_variant", "VARCHAR(20) DEFAULT 'detailed'"),
                ("rapport_roe", "TEXT DEFAULT ''"),
                ("rapport_test_start_date", "DATE"),
                ("rapport_test_end_date", "DATE"),
            ]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_instellingen ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

            # Auto-migrate: obfuscatie instellingen
            for col, coltype in [
                ("obfuscate_downloads", "BOOLEAN DEFAULT 0"),
                ("obfuscate_technique", "VARCHAR(20) DEFAULT 'mixed'"),
            ]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_instellingen ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

            # Auto-migrate: finding remediation & tracking columns
            for col, coltype in [
                ("created_at", "DATETIME"),
                ("updated_at", "DATETIME"),
                ("discovered_at", "DATETIME"),
                ("remediation_status", "VARCHAR(20) DEFAULT 'open'"),
                ("remediation_target_date", "DATE"),
                ("remediation_owner", "VARCHAR(200)"),
                ("affected_assets", "TEXT DEFAULT ''"),
                ("data_classification", "VARCHAR(50) DEFAULT ''"),
                ("business_impact", "TEXT DEFAULT ''"),
                ("remediation_effort", "VARCHAR(20) DEFAULT ''"),
            ]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_bevinding ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

            # Auto-migrate: retest workflow, faalmodus, detecteerbaarheid, risicomatrix
            for col, coltype in [
                ("retest_status",    "VARCHAR(20) DEFAULT 'not_applicable'"),
                ("retest_date",      "DATE"),
                ("retest_notes",     "TEXT DEFAULT ''"),
                ("faalmodus",        "VARCHAR(20) DEFAULT ''"),
                ("control_ref",      "VARCHAR(200) DEFAULT ''"),
                ("detecteerbaarheid","VARCHAR(10) DEFAULT ''"),
                ("detectie_notitie", "TEXT DEFAULT ''"),
                ("kans",             "VARCHAR(5) DEFAULT ''"),
                ("impact_niveau",    "VARCHAR(5) DEFAULT ''"),
            ]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_bevinding ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

            # Auto-migrate: evidence extended columns
            for col, coltype in [
                ("tool_name", "VARCHAR(100)"),
                ("timestamp_captured", "DATETIME"),
                ("evidence_category", "VARCHAR(50)"),
                ("description", "TEXT"),
            ]:
                try:
                    conn.execute(db.text(
                        f"ALTER TABLE db_evidence ADD COLUMN {col} {coltype}"))
                    conn.commit()
                except Exception:
                    pass

        # Auto-migrate: OWASP 2025 kolom op templates
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_bevindingen_templates ADD COLUMN owasp_2025 VARCHAR(16)"))
                conn.commit()
            except Exception:
                pass

        # Auto-migrate: NCSC/DigiD richtlijn kolom op templates
            try:
                conn.execute(db.text(
                    "ALTER TABLE db_bevindingen_templates ADD COLUMN ncsc VARCHAR(16)"))
                conn.commit()
            except Exception:
                pass

        # Ensure a settings row exists (required by blueprints that read it at import)
        s = models.db_instellingen.query.first()
        if not s:
            s = models.db_instellingen(localhost='http://127.0.0.1:5000')
            db.session.add(s)
            db.session.commit()

        # Load behind_proxy from DB (DB setting overrides env var when True)
        if s and getattr(s, 'behind_proxy', False):
            app.config["BEHIND_PROXY"] = True

        # Now safe to import blueprints (some query db at module level)
        from meuk.flask import admin
        from meuk.flask import agent
        from meuk.flask import checklists
        from meuk.flask import csrf
        from meuk.flask import download
        from meuk.flask import findings
        from meuk.flask import index
        from meuk.flask import login
        from meuk.flask import macro
        from meuk.flask import notes
        from meuk.flask import output_view
        from meuk.flask import rapport
        from meuk.flask import search
        from meuk.flask import msfrpc
        from meuk.flask import stix_taxii
        from meuk.flask import sqli2
        from meuk.flask import ssrf
        from meuk.flask import tasks
        from meuk.flask import upload
        from meuk.flask import xxe
        from meuk.flask import xxs

        app.register_blueprint(agent.agent_bp)
        app.register_blueprint(checklists.checklists_bp)
        app.register_blueprint(index.index_bp)
        app.register_blueprint(login.login_bp)
        app.register_blueprint(xxe.xxe_bp)
        app.register_blueprint(download.download_bp)
        app.register_blueprint(upload.upload_bp)
        app.register_blueprint(xxs.xxs_bp)
        app.register_blueprint(csrf.csrf_bp)
        app.register_blueprint(sqli2.sqli2_bp)
        app.register_blueprint(ssrf.ssrf_bp)
        app.register_blueprint(tasks.tasks_bp)
        app.register_blueprint(output_view.output_bp)
        app.register_blueprint(findings.findings_bp)
        app.register_blueprint(macro.macro_bp)
        app.register_blueprint(notes.notes_bp)
        app.register_blueprint(rapport.rapport_bp)
        app.register_blueprint(msfrpc.msf_bp)
        app.register_blueprint(stix_taxii.stix_taxii_bp)
        app.register_blueprint(search.search_bp)

    _LAB_PREFIXES = ('/x.js', '/xxs/', '/xxe/', '/csrf.', '/csrf/', '/sqli2/', '/ssrf/')
    _AGENT_PREFIXES = ('/agent/checkin', '/agent/cmd/', '/agent/res/', '/agent/heartbeat/')

    @app.before_request
    def _generate_nonce():
        g.csp_nonce = secrets.token_urlsafe(32)

    @app.context_processor
    def _inject_globals():
        return {"csp_nonce": getattr(g, "csp_nonce", ""), "csrf_token": generate_csrf}

    @app.after_request
    def set_csp(response):
        if request.path.startswith(_LAB_PREFIXES) or request.path.startswith(_AGENT_PREFIXES):
            return response

        nonce = getattr(g, "csp_nonce", "")

        if getattr(g, "is_public_page", False):
            csp = (
                "default-src 'self'; "
                f"script-src 'unsafe-eval' 'nonce-{nonce}'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src *; "
                "connect-src *; "
                "frame-src 'none'; "
                "object-src 'none'"
            )
        elif request.path.startswith('/dashboard/recordings'):
            csp = (
                "default-src 'self'; "
                f"script-src 'self' 'unsafe-eval' 'nonce-{nonce}'; "
                "style-src 'self' 'unsafe-inline'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-src 'none'; "
                "object-src 'none'"
            )
        else:
            csp = (
                "default-src 'self'; "
                f"script-src 'self' 'nonce-{nonce}'; "
                f"style-src 'self' 'nonce-{nonce}'; "
                "img-src 'self' data:; "
                "connect-src 'self'; "
                "frame-src 'none'; "
                "object-src 'none'"
            )

        response.headers['Content-Security-Policy'] = csp
        return response

    @app.template_filter("filesizeformat")
    def _filesizeformat(value):
        for unit in ("B", "KB", "MB", "GB"):
            if abs(value) < 1024.0:
                return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
            value /= 1024.0
        return f"{value:.1f} TB"

    return app


if __name__ == "__main__":
    create_app()
