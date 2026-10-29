"""Governance rules for AI agents and other non-human identities.

`analyse` also annotates each identity in the dataset with its classification, permission tiers,
risk score and anomaly result; the annotated dataset is what the inventory pages display.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from .catalog import (
    DEFAULT_AI_KEYWORDS,
    HIGH_RISK_DELEGATED,
    is_write,
    keyword_matches,
    role_severity,
    tier_of,
)
from .core.db import parse_dt, utcnow
from .core.findings import Finding, RuleInfo
from .ml import detect, features_for

CLASS_LABELS = {
    "ai_agent": "AI agent",
    "managed_identity": "Managed identity",
    "third_party": "Third-party app",
    "workload": "Workload app",
    "integration": "Integration",
    "automation": "Automation",
}

RULES = {r.rule_id: r for r in [
    RuleInfo("AGW-001", "Tier-0 permission (tenant takeover path)", "critical", "Privilege",
             "The identity holds an application permission that can be used to grant itself or others more "
             "privilege, change authentication policy or act as any mailbox. A stolen secret or a "
             "prompt-injected agent with this permission can compromise the whole tenant.",
             "Microsoft guidance: grant least-privileged permissions; prefer Sites.Selected / RBAC for Applications."),
    RuleInfo("AGW-002", "Privileged directory role on a non-human identity", "critical", "Privilege",
             "A service principal or managed identity holds a privileged Entra ID role. Workload identities "
             "cannot use MFA and are not covered by most Conditional Access policies."),
    RuleInfo("AGW-003", "Broad data permissions", "high", "Privilege",
             "The identity can read or change data across the organisation (all mailboxes, all files, all chats). "
             "For AI agents this is the main data-exfiltration path if the agent is manipulated."),
    RuleInfo("AGW-004", "No accountable owner", "medium", "Governance",
             "Nobody is recorded as the owner, so nobody is accountable for its permissions, secrets or retirement."),
    RuleInfo("AGW-005", "Dormant identity still holds permissions", "high", "Hygiene",
             "The identity has not signed in for longer than the dormancy threshold but still holds permissions. "
             "Unused, privileged identities are attractive to attackers and easy to remove."),
    RuleInfo("AGW-006", "Long-lived client secret", "medium", "Credentials",
             "A client secret is valid for longer than policy allows. Long-lived secrets leak into code, "
             "config and laptops and are rarely rotated."),
    RuleInfo("AGW-007", "Credential expiring soon or expired credential left behind", "low", "Credentials",
             "A secret or certificate expires soon (risk of outage) or an expired one is still attached (clutter "
             "that hides real credentials)."),
    RuleInfo("AGW-008", "Privileged identity authenticates with a secret", "medium", "Credentials",
             "A highly privileged identity uses a client secret. Certificates, managed identities or workload "
             "identity federation remove the shared secret entirely."),
    RuleInfo("AGW-009", "External multi-tenant app with high-risk access", "high", "Third party",
             "An application owned by another organisation has tier-0 or tier-1 access to your data. Its "
             "security is outside your control."),
    RuleInfo("AGW-010", "Tenant-wide consent to high-risk delegated scopes", "high", "Consent",
             "An admin consented on behalf of all users to scopes such as Mail.Read or Files.Read.All. Any "
             "user's data can be accessed through this app while they are signed in to it."),
    RuleInfo("AGW-011", "AI agent missing from the governance register", "medium", "Governance",
             "An identity that looks like an AI agent has no register entry recording its purpose, owner, data "
             "classification, model provider and approved permissions."),
    RuleInfo("AGW-012", "Agent access review overdue", "medium", "Governance",
             "The last recorded review of this identity is older than its review interval."),
    RuleInfo("AGW-013", "Permission drift beyond what was approved", "high", "Governance",
             "The identity holds permissions that are not on its approved list in the register."),
    RuleInfo("AGW-014", "Statistical outlier: over-privileged compared with peers", "medium", "Anomaly",
             "Machine-learning (Isolation Forest) comparison of every identity's privilege and hygiene profile "
             "flags this one as unusual. The evidence lists the features that drive the score."),
    RuleInfo("AGW-015", "Autonomous agent with write access", "medium", "Governance",
             "The register says this agent acts without a human approving its actions, yet it holds write "
             "permissions. Add an approval step or reduce it to read-only."),
]}


def _lines(text: str) -> set[str]:
    return {x.strip() for x in (text or "").replace(",", "\n").splitlines() if x.strip()}


def classify(identity: dict, registry: dict | None, keywords: list[str]) -> tuple[str, list[str]]:
    if registry and registry.get("classification"):
        return registry["classification"], ["register"]
    hay = " ".join([identity.get("displayName", ""), identity.get("publisher", ""), " ".join(identity.get("tags", []))])
    hits = keyword_matches(hay, keywords)
    if hits:
        return "ai_agent", hits
    if identity.get("type") == "ManagedIdentity":
        return "managed_identity", []
    if identity.get("external"):
        return "third_party", []
    return "workload", []


def risk_score(a: dict) -> int:
    score = 0
    score += min(2, a["tier0"]) * 35
    score += min(3, a["tier1"]) * 12
    score += 40 if "critical" in a["role_severities"] else (25 if "high" in a["role_severities"] else 0)
    score += 10 if a["tenant_wide_high"] else 0
    score += 10 if a["no_owner"] else 0
    score += 15 if a["dormant"] else 0
    score += 8 if a["long_secret"] else 0
    score += 15 if a["external"] and (a["tier0"] or a["tier1"]) else 0
    score += 10 if a["unregistered_agent"] else 0
    score += 15 if a["anomaly"] else 0
    score += 10 if a["drift"] else 0
    return min(100, score)


def band(score: int) -> str:
    return "critical" if score >= 70 else "high" if score >= 45 else "medium" if score >= 20 else "low"


def analyse(data: dict, settings: dict[str, Any], ctx=None) -> list[Finding]:
    now = utcnow()
    keywords = [k for k in (settings["ai_keywords"] or "").splitlines() if k.strip()] or DEFAULT_AI_KEYWORDS
    extra0, extra1 = _lines(settings["extra_tier0"]), _lines(settings["extra_tier1"])
    dormant_days = int(settings["dormant_days"])
    max_secret = int(settings["max_secret_lifetime_days"])
    expiry_warn = int(settings["credential_expiry_warning_days"])
    registry = {r["identity_id"]: r for r in data.get("registry", [])}
    out: list[Finding] = []
    features: list[tuple[str, dict]] = []

    for ident in data.get("identities", []):
        iid = ident["id"]
        name = ident["displayName"]
        reg = registry.get(iid)
        cls, hits = classify(ident, reg, keywords)
        is_agent = cls == "ai_agent"
        etype = CLASS_LABELS.get(cls, cls)
        for p in ident.get("appPermissions", []):
            p["tier"] = tier_of(p["permission"], extra0, extra1)
            p["write"] = is_write(p["permission"])
        perms = ident.get("appPermissions", [])
        tier0 = sorted({p["permission"] for p in perms if p["tier"] == 0})
        tier1 = sorted({p["permission"] for p in perms if p["tier"] == 1})
        writes = sorted({p["permission"] for p in perms if p["write"]})
        role_sev = {r: role_severity(r.split(" (scope")[0]) for r in ident.get("roles", [])}
        priv_roles = {r: s for r, s in role_sev.items() if s}
        wide = sorted({d["scope"] for d in ident.get("delegated", [])
                       if d.get("consentType") == "AllPrincipals" and d["scope"] in HIGH_RISK_DELEGATED})
        is_mi = ident.get("type") == "ManagedIdentity"
        owners = ident.get("owners") or []
        no_owner = not owners and not is_mi and not (reg and (reg.get("business_owner") or reg.get("technical_owner")))
        privileged = bool(tier0 or tier1 or priv_roles)
        base = {"type": ident.get("type"), "classification": etype, "app_id": ident.get("appId"),
                "publisher": ident.get("publisher") or "—"}
        owner_hint = (reg or {}).get("technical_owner") or (owners[0]["name"] if owners else None)

        def add(rule, sev, title, details, rec, key="", due=None):
            out.append(Finding(rule, sev, title, "identity", iid, name, {**base, **details}, rec,
                               owner_hint=owner_hint, key=key, due_date=due))

        if tier0:
            add("AGW-001", "critical", f"Holds {len(tier0)} tier-0 permission(s): {', '.join(tier0)}",
                {"tier0_permissions": tier0},
                "Remove the permission or replace it with a scoped alternative (for example Sites.Selected, "
                "Application.ReadWrite.OwnedBy with care, RBAC for Applications in Exchange). If it is genuinely "
                "required, move the identity to certificate or federated credentials, restrict it with "
                "Conditional Access for workload identities and accept the risk with an expiry date.")
        for role, sev in priv_roles.items():
            add("AGW-002", sev, f"Holds the {role} role", {"role": role},
                "Remove the role assignment. Grant the narrowest role that covers the task, scope it to an "
                "administrative unit where possible, or use PIM so the role is only active when needed.", key=role)
        if tier1:
            add("AGW-003", "high" if is_agent or ident.get("external") else "medium",
                f"Broad data access: {', '.join(tier1)}", {"tier1_permissions": tier1, "is_ai_agent": is_agent},
                ("Agents should only reach the data they need: use Sites.Selected / resource-specific consent, "
                 "Exchange RBAC for Applications to limit mailboxes, and read-only scopes where the agent does "
                 "not need to write." if is_agent else
                 "Confirm the business need. Replace tenant-wide permissions with scoped ones where the API "
                 "supports it."))
        if no_owner:
            add("AGW-004", "high" if privileged else "medium", "No owner recorded", {"privileged": privileged},
                "Add at least two owners on the app registration (a technical and a business owner) or record "
                "them in the governance register.")

        last = parse_dt(ident.get("lastSignIn"))
        dormant = False
        if ident.get("signinKnown") and (perms or priv_roles):
            days = (now - last).days if last else None
            if days is None or days > dormant_days:
                dormant = True
                add("AGW-005", "high" if privileged else "low",
                    "Never signed in" if days is None else f"No sign-in for {days} days",
                    {"last_sign_in": ident.get("lastSignIn") or "never", "permissions": len(perms)},
                    "Disable the service principal for 30 days to confirm nothing breaks, then remove its "
                    "permissions and delete it.")

        long_secret = False
        secrets = []
        for c in ident.get("credentials", []):
            start, end = parse_dt(c.get("start")), parse_dt(c.get("end"))
            if c["type"] == "password":
                secrets.append(c)
            if c["type"] == "password" and start and end and (end - start).days > max_secret and end > now:
                long_secret = True
                add("AGW-006", "high" if privileged else "medium",
                    f"Client secret “{c.get('name')}” valid for {(end - start).days} days", {"credential": c.get("name"),
                                                                            "expires": c.get("end")},
                    f"Rotate to a secret valid for at most {max_secret} days, or better, switch to a certificate, "
                    "managed identity or workload identity federation.", key=f"{c.get('name')}:{c.get('end')}")
            if end and now < end <= now + timedelta(days=expiry_warn):
                add("AGW-007", "medium" if perms else "low", f"{c['type'].capitalize()} expires in {(end - now).days} days",
                    {"credential": c.get("name"), "expires": c.get("end")},
                    "Rotate the credential before it expires and update every system that uses it.",
                    key=f"expiring:{c.get('name')}:{c.get('end')}", due=end.date().isoformat())
            elif end and end < now:
                add("AGW-007", "low", f"Expired {c['type']} still attached", {"credential": c.get("name"),
                                                                            "expired": c.get("end")},
                    "Remove expired credentials so the remaining ones are easy to audit.",
                    key=f"expired:{c.get('name')}:{c.get('end')}")
        if secrets and (tier0 or priv_roles) and not is_mi:
            add("AGW-008", "medium", "Highly privileged identity uses a client secret", {"secrets": len(secrets)},
                "Replace the client secret with a certificate (stored in Key Vault/HSM) or workload identity "
                "federation, then delete the secret.")
        if ident.get("external") and (tier0 or tier1):
            add("AGW-009", "critical" if tier0 else "high", "External app has high-risk access",
                {"publisher": ident.get("publisher"), "owner_tenant": ident.get("appOwnerOrganizationId"),
                 "permissions": tier0 + tier1},
                "Review the vendor's security posture and contract, reduce the permissions consented to, and "
                "remove the app if it is no longer used.")
        if wide:
            add("AGW-010", "high", f"Tenant-wide consent to {', '.join(wide)}", {"scopes": wide},
                "Revoke the tenant-wide grant and re-consent per user or per group, or replace with an app that "
                "needs fewer scopes. Enable the admin consent workflow to stop users granting this in future.")

        unregistered = is_agent and not reg and settings["require_registry_for_agents"]
        if unregistered:
            add("AGW-011", "high" if privileged else "medium", "AI agent is not in the governance register",
                {"matched_keywords": hits},
                "Add a register entry: business and technical owner, purpose, data classification, model provider, "
                "human-in-the-loop and the permissions you approve. If it is not an agent, classify it in the "
                "register so it stops matching.")
        drift = []
        if reg:
            interval = int(reg.get("review_interval_days") or settings["default_review_interval_days"])
            reviewed = parse_dt(reg.get("last_reviewed"))
            due = (reviewed + timedelta(days=interval)) if reviewed else None
            if due is None or due < now:
                add("AGW-012", "medium" if privileged else "low",
                    "Never reviewed" if not reviewed else f"Review overdue by {(now - due).days} days",
                    {"last_reviewed": reg.get("last_reviewed") or "never", "interval_days": interval},
                    "Review the identity with its owner: confirm the purpose, permissions and credentials, then "
                    "record the review date in the register.", due=due.date().isoformat() if due else None)
            approved = _lines(reg.get("approved_permissions") or "")
            if approved:
                drift = sorted({p["permission"] for p in perms} - approved)
                if drift:
                    add("AGW-013", "high", f"{len(drift)} permission(s) beyond what was approved",
                        {"unapproved": drift, "approved": sorted(approved)},
                        "Remove the unapproved permissions, or record an approval decision and add them to the "
                        "register.", key=",".join(drift))
            if is_agent and not reg.get("human_in_loop") and writes:
                add("AGW-015", "medium", "Acts without human approval but can write data", {"write_permissions": writes},
                    "Add a human approval step for actions that send, change or delete data, or reduce the agent to "
                    "read-only permissions.")

        f = features_for(ident, len(priv_roles), len(wide))
        features.append((iid, f))
        ident["analysis"] = {
            "classification": cls, "classification_label": etype, "keyword_hits": hits,
            "tier0": len(tier0), "tier1": len(tier1), "writes": len(writes), "role_severities": list(priv_roles.values()),
            "tenant_wide_high": wide, "no_owner": no_owner, "dormant": dormant, "long_secret": long_secret,
            "external": bool(ident.get("external")), "unregistered_agent": bool(unregistered), "drift": drift,
            "registered": bool(reg), "features": f, "anomaly": False, "anomaly_score": 0.0, "anomaly_reasons": [],
        }

    if settings["anomaly_enabled"] and features:
        results = detect(features, contamination=float(settings["anomaly_contamination"]))
        by_id = {i["id"]: i for i in data.get("identities", [])}
        for iid, res in results.items():
            ident = by_id[iid]
            a = ident["analysis"]
            a.update(anomaly=res.is_anomaly, anomaly_score=res.score, anomaly_reasons=res.reasons,
                     anomaly_method=res.method)
            if res.is_anomaly:
                top = "; ".join(f"{r['label']}: {r['value']} (peer median {r['peer_median']})" for r in res.reasons[:3])
                out.append(Finding(
                    "AGW-014", "high" if (a["tier0"] or a["role_severities"]) else "medium",
                    f"Unusual privilege profile (anomaly score {res.score:.2f})", "identity", iid,
                    ident["displayName"],
                    {"classification": a["classification_label"], "anomaly_score": res.score, "method": res.method,
                     "drivers": top},
                    "Compare this identity with others doing similar work. The drivers show which permissions or "
                    "hygiene factors make it stand out; remove what is not needed.",
                ))
    for ident in data.get("identities", []):
        a = ident.get("analysis")
        if a:
            a["risk_score"] = risk_score(a)
            a["risk_band"] = band(a["risk_score"])
    return out
