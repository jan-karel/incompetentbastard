"""Read-only audit module catalog; no agent execution or binary loading."""

from dataclasses import asdict, dataclass

from flask import Blueprint, abort, jsonify, render_template, request

from meuk.flask.security import require_dashboard_access


audit_modules_bp = Blueprint("audit_modules_bp", __name__, template_folder="html")


@dataclass(frozen=True)
class AuditModule:
    id: str
    name: str
    description: str
    platforms: tuple[str, ...]
    architectures: tuple[str, ...]
    runtime: str
    required_privilege: str
    version: str = "1.0.0"
    implementation: str = "planned"


MODULES = (
    AuditModule(
        "demo-result", "Voorbeeldresultaat",
        "Fictief auditresultaat voor het testen van weergave en rapportage.",
        ("windows", "linux", "macos"), ("x86", "x64", "arm64"),
        "simulation", "none", implementation="fixture",
    ),
    AuditModule(
        "windows-autologon-policy", "Autologon-configuratie",
        "Ontwerp voor controle of autologon actief is, zonder wachtwoorden uit te lezen.",
        ("windows",), ("x86", "x64", "arm64"), "powershell", "user",
    ),
    AuditModule(
        "windows-credential-protection", "Credentialbescherming",
        "Ontwerp voor controle van Credential Guard- en LSA-beschermingsinstellingen.",
        ("windows",), ("x64", "arm64"), "powershell", "administrator",
    ),
)


def compatibility(module, platform, architecture, runtime):
    """Compare explicitly supplied metadata, never infer agent capabilities."""
    reasons = []
    for value, label, supported in (
        (platform, "platform", module.platforms),
        (architecture, "architectuur", module.architectures),
        (runtime, "runtime", (module.runtime,)),
    ):
        if not value:
            reasons.append(f"{label} ontbreekt")
        elif value not in supported:
            reasons.append(f"{label} wordt niet ondersteund")
    return {
        "metadata_matches": not reasons,
        "reasons": reasons,
        "execution_available": False,
        "privileges_verified": False,
    }


def module_record(module):
    record = asdict(module)
    record["execution_available"] = False
    return record


def example_result():
    """Return a fresh, explicitly fictional result without inspecting a host."""
    return {
        "schema_version": 1,
        "module_id": "demo-result",
        "module_version": "1.0.0",
        "simulated": True,
        "target": "example.invalid",
        "status": "info",
        "summary": "Fictief resultaat; er is geen systeem gecontroleerd.",
        "evidence": {"source": "fixture", "message": "Voorbeeld van audituitvoer"},
        "recommendation": "Gebruik dit resultaat uitsluitend om de verwerking te testen.",
    }


@audit_modules_bp.before_request
def guard():
    require_dashboard_access()


@audit_modules_bp.get("/dashboard/audit-modules")
def catalog_page():
    return render_template("audit_modules.html", modules=MODULES)


@audit_modules_bp.get("/api/audit-modules")
def catalog_api():
    return jsonify({"schema_version": 1, "modules": [module_record(m) for m in MODULES]})


@audit_modules_bp.get("/api/audit-modules/<module_id>/compatibility")
def compatibility_api(module_id):
    module = next((m for m in MODULES if m.id == module_id), None)
    if module is None:
        abort(404)
    return jsonify(compatibility(
        module, request.args.get("platform"), request.args.get("architecture"),
        request.args.get("runtime"),
    ))


@audit_modules_bp.get("/api/audit-modules/demo-result/example")
def example_api():
    return jsonify(example_result())
