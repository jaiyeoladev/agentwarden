from datetime import timedelta

import httpx

from agentwarden.catalog import keyword_matches, tier_of
from agentwarden.collector import collect_live
from agentwarden.core.db import iso, utcnow
from agentwarden.core.graph import GraphClient
from agentwarden.demo import _id, build
from agentwarden.ml import detect
from agentwarden.rules import analyse

from .conftest import csrf


def _analyse(ctx):
    data = build()
    data["registry"] = ctx.db.query("SELECT * FROM agent_registry")
    return data, analyse(data, ctx.settings.all(), ctx)


def test_demo_triggers_every_rule(ctx):
    _, findings = _analyse(ctx)
    rules = {f.rule_id for f in findings}
    expected = {f"AGW-{n:03d}" for n in range(1, 16)}
    assert expected <= rules, expected - rules


def test_planted_outlier_is_top_risk_and_flagged(ctx):
    data, findings = _analyse(ctx)
    idents = {i["displayName"]: i for i in data["identities"]}
    triage = idents["ai-triage-orchestrator"]["analysis"]
    assert triage["risk_score"] == 100 and triage["anomaly"]
    assert triage["anomaly_method"] == "isolation-forest"
    assert any(r["feature"] == "tier0_permissions" for r in triage["anomaly_reasons"])
    # a benign baseline app is neither flagged nor high risk
    payroll = idents["Payroll Connector"]["analysis"]
    assert not payroll["anomaly"] and payroll["risk_band"] == "low"


def test_permission_drift_and_autonomy(ctx):
    _, findings = _analyse(ctx)
    drift = [f for f in findings if f.rule_id == "AGW-013"]
    claims = next(f for f in drift if f.entity_name == "Claims Summariser GPT")
    assert set(claims.details["unapproved"]) == {"Files.ReadWrite.All", "Mail.ReadWrite"}
    assert any(f.rule_id == "AGW-015" and f.entity_name == "Claims Summariser GPT" for f in findings)


def test_keyword_matching_avoids_substrings():
    kws = ["agent", "ai", "bot", "gpt"]
    assert keyword_matches("Claims GPT4o", kws) == ["gpt"]
    assert keyword_matches("Robotics Sync", kws) == []
    assert keyword_matches("Maintenance portal", kws) == []
    assert keyword_matches("ai-triage", kws) == ["ai"]


def test_tiers():
    assert tier_of("RoleManagement.ReadWrite.Directory") == 0
    assert tier_of("Mail.Send") == 1
    assert tier_of("User.Read.All") == 2
    assert tier_of("Sites.Selected") == 3
    assert tier_of("Custom.Perm", extra_tier0={"Custom.Perm"}) == 0


def test_ml_falls_back_with_few_samples():
    base = {k: 0 for k in ["tier0_permissions", "tier1_permissions", "tier2_permissions", "write_permissions",
                           "privileged_roles", "tenant_wide_delegated", "client_secrets", "max_secret_lifetime_days",
                           "days_since_sign_in", "no_owner", "external_publisher", "age_days"]}
    rows = [(f"id{i}", {**base, "tier2_permissions": 1, "age_days": 300}) for i in range(6)]
    rows.append(("bad", {**base, "tier0_permissions": 3, "privileged_roles": 1, "write_permissions": 4, "age_days": 5}))
    res = detect(rows, contamination=0.15)
    assert res["bad"].method == "robust-z"
    assert res["bad"].is_anomaly
    assert max(res, key=lambda k: res[k].score) == "bad"


def test_live_collector_resolves_permissions(ctx):
    now = utcnow()
    graph_sp = {"id": "graph-sp", "displayName": "Microsoft Graph",
                "appRoles": [{"id": "r-mail", "value": "Mail.Send"}, {"id": "r-role", "value": "RoleManagement.ReadWrite.Directory"}]}

    def handler(req: httpx.Request):
        p = req.url.path
        if p.endswith("/token"):
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        if p.endswith("/organization"):
            return httpx.Response(200, json={"value": [{"id": "tenant-1", "displayName": "Contoso"}]})
        if p.endswith("/v1.0/servicePrincipals"):
            return httpx.Response(200, json={"value": [
                {"id": "sp1", "appId": "app1", "displayName": "Support Copilot Agent", "servicePrincipalType": "Application",
                 "appOwnerOrganizationId": "tenant-1", "tags": [], "passwordCredentials": []},
                {"id": "sp-ms", "appId": "ms", "displayName": "Office 365", "servicePrincipalType": "Application",
                 "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"},
            ]})
        if p.endswith("/applications"):
            return httpx.Response(200, json={"value": [
                {"id": "appobj1", "appId": "app1", "createdDateTime": iso(now - timedelta(days=10)),
                 "passwordCredentials": [{"displayName": "prod", "startDateTime": iso(now - timedelta(days=5)),
                                          "endDateTime": iso(now + timedelta(days=720))}], "keyCredentials": []}]})
        if p.endswith("/roleManagement/directory/roleAssignments"):
            return httpx.Response(200, json={"value": [{"principalId": "sp1", "directoryScopeId": "/",
                                                        "roleDefinition": {"displayName": "Global Administrator"}}]})
        if p.endswith("/oauth2PermissionGrants"):
            return httpx.Response(200, json={"value": [{"clientId": "sp1", "resourceId": "graph-sp",
                                                        "consentType": "AllPrincipals", "scope": "Mail.Read User.Read"}]})
        if p.endswith("/beta/reports/servicePrincipalSignInActivities"):
            return httpx.Response(200, json={"value": [{"appId": "app1", "lastSignInActivity": {"lastSignInDateTime": iso(now)}}]})
        if p.endswith("/servicePrincipals/sp1/owners") or p.endswith("/applications/appobj1/owners"):
            return httpx.Response(200, json={"value": []})
        if p.endswith("/servicePrincipals/sp1/appRoleAssignments"):
            return httpx.Response(200, json={"value": [
                {"resourceId": "graph-sp", "resourceDisplayName": "Microsoft Graph", "appRoleId": "r-mail"},
                {"resourceId": "graph-sp", "resourceDisplayName": "Microsoft Graph", "appRoleId": "r-role"}]})
        if p.endswith("/applications/appobj1/federatedIdentityCredentials"):
            return httpx.Response(200, json={"value": []})
        if p.endswith("/servicePrincipals/graph-sp"):
            return httpx.Response(200, json=graph_sp)
        return httpx.Response(404, json={"error": {"code": "NotFound", "message": p}})

    client = GraphClient("t", "c", "s", transport=httpx.MockTransport(handler), sleep=lambda s: None)
    data = collect_live(ctx, client=client)
    assert [i["displayName"] for i in data["identities"]] == ["Support Copilot Agent"]
    ident = data["identities"][0]
    assert {p["permission"] for p in ident["appPermissions"]} == {"Mail.Send", "RoleManagement.ReadWrite.Directory"}
    assert ident["roles"] == ["Global Administrator"]
    assert ident["lastSignIn"] and ident["signinKnown"]
    data["registry"] = []
    rules = {f.rule_id for f in analyse(data, ctx.settings.all(), ctx)}
    assert {"AGW-001", "AGW-002", "AGW-003", "AGW-004", "AGW-006", "AGW-008", "AGW-010", "AGW-011"} <= rules


def test_register_identity_via_ui(admin, ctx):
    iid = _id("HR Helpdesk Agent (Copilot Studio)")
    token = csrf(admin, f"/identities/{iid}")
    r = admin.post(f"/identities/{iid}/register", data={
        "csrf_token": token, "classification": "ai_agent", "business_owner": "HR", "technical_owner": "Grace",
        "purpose": "Answers HR policy questions", "data_classification": "Internal", "model_provider": "Copilot Studio",
        "approved_permissions": "User.Read.All\nSites.Read.All", "review_interval_days": "90", "mark_reviewed": "on",
    }, follow_redirects=False)
    assert r.status_code == 303
    reg = ctx.db.one("SELECT * FROM agent_registry WHERE identity_id = ?", (iid,))
    assert reg["business_owner"] == "HR" and reg["last_reviewed"] == utcnow().date().isoformat()
    ctx.scanner.run("test", "test")
    drift = ctx.findings.search(rule_id="AGW-013", entity_id=iid)[0]
    assert drift and drift[0]["details"]["unapproved"] == ["Mail.Send"]
    assert not ctx.findings.search(rule_id="AGW-011", entity_id=iid)[0]
