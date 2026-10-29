"""Synthetic non-human identity estate with a realistic baseline and planted risks."""

from __future__ import annotations

import random
import uuid
from datetime import timedelta

from .core.context import Context
from .core.db import iso, utcnow

TENANT = "8f2d6b1e-1c3a-4d55-9b7e-2a1f0c9d4e10"
GRAPH = "Microsoft Graph"
EXO = "Office 365 Exchange Online"
SPO = "Office 365 SharePoint Online"

BASELINE_APPS = [
    ("ServiceNow Integration", ["User.Read.All", "Group.Read.All"]),
    ("Payroll Connector", ["User.Read.All"]),
    ("Expense Sync", ["User.Read.All", "Directory.Read.All"]),
    ("Intranet Search", ["Sites.Selected"]),
    ("Asset Inventory", ["DeviceManagementManagedDevices.Read.All"]),
    ("Room Booking Display", ["Calendars.Read"]),
    ("Rota Planner", ["User.Read.All", "Group.Read.All"]),
    ("Patient Feedback Portal", ["Sites.Selected"]),
    ("Power BI Gateway Reporter", ["Reports.Read.All"]),
    ("SIEM Log Shipper", ["AuditLog.Read.All", "SecurityEvents.Read.All"]),
    ("Backup Reporter", ["Reports.Read.All"]),
    ("Ticketing Webhook", ["User.Read.All"]),
    ("Contract Archive", ["Sites.Selected"]),
    ("Staff Survey Tool", ["User.Read.All"]),
    ("Print Management", ["Group.Read.All"]),
    ("Guest Wi-Fi Portal", ["User.Read.All"]),
    ("Learning Management Sync", ["User.Read.All", "Group.Read.All"]),
    ("Visitor Sign-in", ["User.Read.All"]),
    ("Org Chart Publisher", ["User.Read.All", "Directory.Read.All"]),
    ("Fleet Tracker", []),
    ("Clinical Rota Export", ["Group.Read.All"]),
    ("Finance Data Warehouse", ["User.Read.All"]),
    ("Email Signature Manager", ["User.Read.All", "MailboxSettings.Read"]),
    ("Telephony Directory Sync", ["User.Read.All", "Directory.Read.All"]),
    ("Purchase Order Approvals", ["User.Read.All"]),
    ("Records Retention Reporter", ["Reports.Read.All"]),
    ("Desk Booking", ["Calendars.Read", "User.Read.All"]),
    ("Compliance Training Tracker", ["User.Read.All"]),
    ("Accounts Payable OCR", ["Sites.Selected"]),
    ("github-actions-deploy", ["Directory.Read.All"]),
    ("terraform-landing-zone", ["Directory.Read.All", "Application.Read.All"]),
    ("Intune Compliance Reporter", ["DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All"]),
]
BASELINE_MI = [
    ("mi-func-claims-prod", ["User.Read.All"]),
    ("mi-logicapp-onboarding", ["User.Read.All", "Group.Read.All"]),
    ("mi-automation-reporting", ["Reports.Read.All"]),
    ("mi-webapp-portal", []),
]
OWNERS = [("Priya Shah", "priya.shah"), ("Daniel Okafor", "daniel.okafor"), ("Grace Hall", "grace.hall"),
          ("Samuel Mensah", "samuel.mensah"), ("Erin Ward", "erin.ward"), ("Leo Patel", "leo.patel")]


def _id(name: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"sp/{name}"))


def build(seed: int = 7) -> dict:
    rng = random.Random(seed)
    now = utcnow()
    identities: list[dict] = []

    def owner(n=1):
        picks = rng.sample(OWNERS, n)
        return [{"name": p[0], "upn": f"{p[1]}@northwindcare.example"} for p in picks]

    def cred(kind, start_days_ago, valid_days, name=None):
        start = now - timedelta(days=start_days_ago)
        return {"type": kind, "name": name or ("client secret" if kind == "password" else "certificate"),
                "source": "application", "start": iso(start),
                "end": iso(start + timedelta(days=valid_days)) if kind != "federated" else None}

    def resource_of(p: str) -> str:
        if p in ("full_access_as_app", "Exchange.ManageAsApp"):
            return EXO
        if p.startswith("Sites.FullControl") and rng.random() < 0.5:
            return SPO
        return GRAPH

    def add(name, perms, *, kind="Application", owners=None, creds=None, roles=None, last=1, created=None,
            publisher="Northwind Care Group", external_org=None, delegated=None, tags=None, audience="AzureADMyOrg"):
        identities.append({
            "id": _id(name),
            "appId": str(uuid.uuid5(uuid.NAMESPACE_DNS, f"app.{name}")),
            "displayName": name,
            "type": kind,
            "publisher": publisher if kind == "Application" else "",
            "appOwnerOrganizationId": external_org or (TENANT if kind == "Application" else None),
            "external": bool(external_org),
            "microsoft": False,
            "created": iso(now - timedelta(days=created if created is not None else rng.randint(200, 1500))),
            "enabled": True,
            "tags": tags or [],
            "signInAudience": audience,
            "owners": owners if owners is not None else ([] if kind == "ManagedIdentity" else owner(rng.choice([1, 1, 2]))),
            "appPermissions": [{"resource": resource_of(p), "permission": p,
                                "granted": iso(now - timedelta(days=rng.randint(20, 600)))} for p in perms],
            "delegated": delegated or [],
            "roles": roles or [],
            "credentials": creds if creds is not None else (
                [] if kind == "ManagedIdentity" else [cred("certificate", rng.randint(10, 300), 365)]),
            "lastSignIn": iso(now - timedelta(days=last, hours=rng.randint(0, 20))) if last is not None else None,
            "signinKnown": True,
        })

    for name, perms in BASELINE_APPS:
        creds = None
        if name == "github-actions-deploy":
            creds = [cred("federated", 300, 0, "repo:northwind/landing-zone:ref:refs/heads/main")]
        elif rng.random() < 0.35:
            creds = [cred("password", rng.randint(20, 150), 180)]
        add(name, perms, creds=creds, last=rng.choice([0, 0, 1, 1, 2, 4, 7, 12]))
    for name, perms in BASELINE_MI:
        add(name, perms, kind="ManagedIdentity", last=rng.choice([0, 1, 2]))

    # Housekeeping issues on otherwise normal apps
    identities[2]["credentials"] = [cred("password", 160, 180)]  # expires within ~20 days
    identities[9]["credentials"] = [cred("password", 400, 365), cred("certificate", 30, 365)]  # expired secret left behind
    identities[14]["owners"] = []

    # ---------------------------------------------------------------- AI agents
    add("HR Helpdesk Agent (Copilot Studio)", ["User.Read.All", "Sites.Read.All", "Mail.Send"], owners=[],
        creds=[cred("password", 40, 730)], last=0, created=45, tags=["CopilotStudio"])
    add("Claims Summariser GPT", ["Mail.ReadWrite", "Files.ReadWrite.All", "User.Read.All"],
        owners=owner(1), creds=[cred("password", 120, 730)], last=0, created=130)
    add("invoice-agent-prod", ["Application.ReadWrite.All", "Files.Read.All", "Mail.Send"], owners=owner(1),
        creds=[cred("password", 300, 365)], last=0, created=310)
    add("ai-triage-orchestrator", ["RoleManagement.ReadWrite.Directory", "Mail.ReadWrite", "Directory.ReadWrite.All",
                                   "Sites.FullControl.All"],
        owners=[], creds=[cred("password", 18, 730), cred("password", 15, 730, "temp-secret")],
        roles=["Global Administrator"], last=0, created=20)
    add("Knowledge Base RAG Indexer", ["Sites.Read.All", "Files.Read.All"], owners=owner(2),
        creds=[cred("certificate", 60, 365)], last=0, created=200)
    add("mi-aks-agents-prod", ["Directory.ReadWrite.All", "Mail.Send", "User.Read.All"], kind="ManagedIdentity",
        last=0, created=90)
    add("Sales Copilot Connector", ["Sites.Read.All"], publisher="Contoso AI Ltd",
        external_org="5d1c3a2b-0f4e-4b7a-9c61-7e2d8a9b3c11", audience="AzureADMultipleOrgs",
        owners=[], creds=[], last=1, created=75,
        delegated=[{"resource": GRAPH, "scope": s, "consentType": "AllPrincipals"}
                   for s in ("Mail.Read", "Files.Read.All", "User.Read", "offline_access")])
    add("Meeting Notes Bot", ["Chat.Read.All", "Calendars.Read", "User.Read.All"], publisher="Fabrikam Notes Inc",
        external_org="9a7b6c5d-4e3f-4a2b-8c1d-0e9f8a7b6c5d", audience="AzureADMultipleOrgs", owners=[],
        creds=[], last=2, created=160)

    # ------------------------------------------------------------- legacy & ops
    add("Legacy SharePoint Migration Tool", ["Sites.FullControl.All", "full_access_as_app", "User.Read.All"],
        owners=owner(1), creds=[cred("password", 900, 3650)], last=410, created=1100)
    add("Veeam Backup for Microsoft 365", ["full_access_as_app", "Sites.FullControl.All", "Directory.Read.All"],
        publisher="Veeam Software", owners=owner(2), creds=[cred("certificate", 100, 730)], last=0)
    add("Old Intranet (2019)", ["User.Read.All", "Group.ReadWrite.All"], owners=owner(1),
        creds=[cred("password", 700, 730)], last=240, created=2200)
    add("HR Onboarding Automation", ["User.ReadWrite.All", "Group.ReadWrite.All"], owners=owner(1),
        creds=[cred("password", 50, 180)], roles=["User Administrator"], last=0)
    add("Identity Lifecycle Sync", ["User.Read.All", "Group.Read.All"], owners=owner(1),
        creds=[cred("certificate", 30, 365)], roles=["Privileged Authentication Administrator"], last=1)

    return {
        "tenant": {"id": TENANT, "name": "Northwind Care Group (demo)"},
        "identities": identities,
        "warnings": [],
        "counts": {"service_principals": len(identities) + 412, "analysed": len(identities), "graph_calls": 0},
    }


def collect_demo(ctx: Context) -> dict:
    return build()


DEMO_REGISTRY = [
    # name, classification, business owner, technical owner, purpose, data class, provider, hitl, approved, interval, reviewed days ago
    ("Claims Summariser GPT", "ai_agent", "Claims Operations", "Daniel Okafor",
     "Summarises inbound claim emails and attachments for case handlers", "Confidential", "Azure OpenAI (GPT-4o)",
     False, ["Mail.Read", "Files.Read.All", "User.Read.All"], 90, 40),
    ("invoice-agent-prod", "ai_agent", "Finance", "Leo Patel",
     "Extracts invoice data from the AP mailbox and posts to the finance system", "Confidential",
     "Azure OpenAI (GPT-4o mini)", True, ["Application.ReadWrite.All", "Files.Read.All", "Mail.Send"], 90, 160),
    ("Knowledge Base RAG Indexer", "ai_agent", "Clinical Governance", "Priya Shah",
     "Indexes policy documents for the staff knowledge assistant", "Internal", "Azure AI Search + Azure OpenAI",
     True, ["Sites.Read.All", "Files.Read.All"], 180, 30),
    ("mi-aks-agents-prod", "ai_agent", "Digital Services", "Samuel Mensah",
     "Runs the patient-communication agent workloads on AKS", "Restricted", "Self-hosted (Mistral 7B)",
     False, ["User.Read.All", "Mail.Send"], 90, 20),
    ("Veeam Backup for Microsoft 365", "integration", "IT Operations", "Grace Hall",
     "Backs up Exchange, SharePoint and OneDrive", "Restricted", "", True,
     ["full_access_as_app", "Sites.FullControl.All", "Directory.Read.All"], 365, 100),
]


def seed_registry(ctx: Context) -> None:
    if ctx.db.scalar("SELECT COUNT(*) FROM agent_registry", (), 0):
        return
    now = utcnow()
    with ctx.db.conn() as con:
        for (name, cls, bo, to, purpose, dc, provider, hitl, approved, interval, reviewed) in DEMO_REGISTRY:
            con.execute(
                """INSERT INTO agent_registry (identity_id, display_name, classification, business_owner,
                technical_owner, purpose, data_classification, model_provider, human_in_loop,
                approved_permissions, review_interval_days, last_reviewed, notes, updated_at, updated_by)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (_id(name), name, cls, bo, to, purpose, dc, provider, 1 if hitl else 0, "\n".join(approved),
                 interval, (now - timedelta(days=reviewed)).date().isoformat(), "Demo record", iso(now), "demo"),
            )
