"""AgentWarden application spec and ASGI entry point."""

from __future__ import annotations

from pathlib import Path

from . import views
from .catalog import DEFAULT_AI_KEYWORDS
from .collector import GRAPH_PERMISSIONS, collect_live
from .core import AppSpec, Config, NavItem, SettingDef, create_app
from .core.context import Context
from .demo import collect_demo, seed_registry
from .rules import RULES, analyse

SCHEMA = """
CREATE TABLE IF NOT EXISTS agent_registry (
    identity_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    classification TEXT NOT NULL DEFAULT 'ai_agent',
    business_owner TEXT,
    technical_owner TEXT,
    purpose TEXT,
    data_classification TEXT,
    model_provider TEXT,
    human_in_loop INTEGER NOT NULL DEFAULT 0,
    approved_permissions TEXT,
    review_interval_days INTEGER NOT NULL DEFAULT 90,
    last_reviewed TEXT,
    notes TEXT,
    updated_at TEXT,
    updated_by TEXT
);
"""

SETTINGS = [
    SettingDef("dormant_days", "Dormant after (days)", "int", 90,
               "Identities with permissions and no sign-in for longer than this are flagged.", "Hygiene", 14, 730),
    SettingDef("max_secret_lifetime_days", "Maximum client secret lifetime (days)", "int", 180,
               "Secrets valid for longer than this are flagged.", "Hygiene", 7, 3650),
    SettingDef("credential_expiry_warning_days", "Warn before credential expiry (days)", "int", 30,
               "", "Hygiene", 1, 180),
    SettingDef("ai_keywords", "AI agent keywords", "textarea", "\n".join(DEFAULT_AI_KEYWORDS),
               "One per line. Matched against the name, publisher and tags to classify AI agents. Classify an "
               "identity in the register to override.", "AI agents"),
    SettingDef("require_registry_for_agents", "Require a register entry for every AI agent", "bool", True,
               "", "AI agents"),
    SettingDef("default_review_interval_days", "Default review interval (days)", "int", 90, "", "AI agents", 7, 730),
    SettingDef("anomaly_enabled", "Enable ML anomaly detection", "bool", True,
               "Isolation Forest over each identity's privilege and hygiene features.", "Anomaly detection"),
    SettingDef("anomaly_contamination", "Expected share of outliers", "float", 0.08,
               "Between 0.01 and 0.3. Higher flags more identities.", "Anomaly detection", 0.01, 0.3),
    SettingDef("extra_tier0", "Extra tier-0 permissions", "textarea", "",
               "Permissions to treat as tenant-takeover risk, one per line.", "Permission tiers"),
    SettingDef("extra_tier1", "Extra tier-1 permissions", "textarea", "",
               "Permissions to treat as broad data access, one per line.", "Permission tiers"),
    SettingDef("include_microsoft_apps", "Include Microsoft first-party apps (live mode)", "bool", False,
               "Usually left off: first-party apps are managed by Microsoft and add noise.", "Scope"),
]


def _with_registry(data: dict, ctx: Context) -> dict:
    data["registry"] = ctx.db.query("SELECT * FROM agent_registry")
    return data


def collect_demo_wrapped(ctx: Context) -> dict:
    return _with_registry(collect_demo(ctx), ctx)


def collect_live_wrapped(ctx: Context) -> dict:
    return _with_registry(collect_live(ctx), ctx)


def live_requirements(ctx: Context) -> list[str]:
    c = ctx.config
    return [n for n, v in (("AZURE_TENANT_ID", c.tenant_id), ("AZURE_CLIENT_ID", c.client_id),
                           ("AZURE_CLIENT_SECRET", c.client_secret)) if not v]


def on_startup(ctx: Context) -> None:
    if ctx.config.demo_mode:
        seed_registry(ctx)


SPEC = AppSpec(
    slug="agentwarden",
    name="AgentWarden",
    tagline="AI agent and non-human identity governance for Microsoft Entra ID",
    description="Inventories AI agents, service principals and managed identities, flags over-privilege and "
                "detects outliers with machine learning.",
    package_dir=Path(__file__).parent,
    nav=[NavItem("Identities", "/identities"), NavItem("Register", "/registry"), NavItem("Anomalies", "/anomalies")],
    rules=RULES,
    setting_defs=SETTINGS,
    collect_demo=collect_demo_wrapped,
    collect_live=collect_live_wrapped,
    analyse=analyse,
    dashboard=views.dashboard,
    register_routes=views.register_routes,
    live_requirements=live_requirements,
    schema_sql=SCHEMA,
    entity_link=views.entity_link,
    report_context=views.report_context,
    on_startup=on_startup,
    graph_permissions=GRAPH_PERMISSIONS,
)


def build(config: Config | None = None, run_initial_scan: bool = True):
    return create_app(SPEC, config or Config.from_env(SPEC.slug), run_initial_scan=run_initial_scan)


def __getattr__(name: str):
    if name == "app":
        global app
        app = build()
        return app
    raise AttributeError(name)
