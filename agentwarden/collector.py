"""Builds an inventory of non-human identities from Microsoft Graph (read-only)."""

from __future__ import annotations

import logging
from typing import Any

from .catalog import MICROSOFT_TENANTS
from .core.context import Context
from .core.db import iso, parse_dt
from .core.graph import GraphClient, GraphError, graph_client_from_config

log = logging.getLogger(__name__)

GRAPH_PERMISSIONS = [
    "Application.Read.All",
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "AuditLog.Read.All (service principal sign-in activity)",
]

SP_FIELDS = (
    "id,appId,displayName,appDisplayName,servicePrincipalType,appOwnerOrganizationId,publisherName,"
    "tags,accountEnabled,passwordCredentials,keyCredentials,signInAudience"
)
APP_FIELDS = "id,appId,displayName,createdDateTime,passwordCredentials,keyCredentials,signInAudience"


def _creds(obj: dict, source: str) -> list[dict]:
    out = []
    for c in obj.get("passwordCredentials") or []:
        out.append({"type": "password", "name": c.get("displayName") or "client secret", "source": source,
                    "start": iso(parse_dt(c.get("startDateTime"))), "end": iso(parse_dt(c.get("endDateTime")))})
    for c in obj.get("keyCredentials") or []:
        out.append({"type": "certificate", "name": c.get("displayName") or "certificate", "source": source,
                    "start": iso(parse_dt(c.get("startDateTime"))), "end": iso(parse_dt(c.get("endDateTime")))})
    return out


def _latest_signin(activity: dict) -> str | None:
    dates = []
    for value in activity.values():
        if isinstance(value, dict):
            for k in ("lastSignInDateTime", "lastSuccessfulSignInDateTime"):
                d = parse_dt(value.get(k))
                if d:
                    dates.append(d)
    d = parse_dt(activity.get("lastSignInDateTime"))
    if d:
        dates.append(d)
    return iso(max(dates)) if dates else None


class Resources:
    """Caches resource service principals so appRoleId GUIDs can be resolved to permission names."""

    def __init__(self, client: GraphClient):
        self.client = client
        self._cache: dict[str, dict] = {}

    def get(self, resource_id: str) -> dict:
        if resource_id not in self._cache:
            try:
                self._cache[resource_id] = self.client.get(
                    f"servicePrincipals/{resource_id}", params={"$select": "id,appId,displayName,appRoles"}
                )
            except GraphError as exc:
                log.warning("Could not resolve resource %s: %s", resource_id, exc)
                self._cache[resource_id] = {"id": resource_id, "displayName": resource_id, "appRoles": []}
        return self._cache[resource_id]

    def role_name(self, resource_id: str, app_role_id: str) -> str:
        if app_role_id == "00000000-0000-0000-0000-000000000000":
            return "Default access"
        for role in self.get(resource_id).get("appRoles") or []:
            if role.get("id") == app_role_id:
                return role.get("value") or role.get("displayName") or app_role_id
        return app_role_id


def collect_live(ctx: Context, client: GraphClient | None = None) -> dict[str, Any]:
    warnings: list[str] = []
    settings = ctx.settings.all()
    include_ms = bool(settings.get("include_microsoft_apps"))
    own = client is None
    client = client or graph_client_from_config(ctx.config)
    try:
        org = (client.get_all("organization", params={"$select": "id,displayName"}) or [{}])[0]
        tenant_id = org.get("id") or ctx.config.tenant_id
        sps = client.get_all("servicePrincipals", params={"$select": SP_FIELDS, "$top": "999"})
        apps = {a["appId"]: a for a in client.get_all("applications", params={"$select": APP_FIELDS, "$top": "999"})}
        res = Resources(client)

        def keep(sp: dict) -> bool:
            if sp.get("servicePrincipalType") not in ("Application", "ManagedIdentity"):
                return False
            if not include_ms and sp.get("appOwnerOrganizationId") in MICROSOFT_TENANTS:
                return False
            return True

        kept = [sp for sp in sps if keep(sp)]

        # Directory roles held by service principals
        roles_by_principal: dict[str, list[str]] = {}
        try:
            assignments = client.get_all("roleManagement/directory/roleAssignments",
                                         params={"$expand": "roleDefinition($select=displayName)"})
            for a in assignments:
                name = (a.get("roleDefinition") or {}).get("displayName") or a.get("roleDefinitionId")
                scope = a.get("directoryScopeId", "/")
                roles_by_principal.setdefault(a.get("principalId"), []).append(
                    name if scope in ("/", None) else f"{name} (scope {scope})"
                )
        except GraphError as exc:
            warnings.append(f"Directory role assignments unavailable ({exc.status}); role rules were skipped.")

        # Tenant-wide and per-user delegated consents
        delegated: dict[str, list[dict]] = {}
        try:
            for g in client.get_all("oauth2PermissionGrants", params={"$top": "999"}):
                resource = res.get(g.get("resourceId", "")).get("displayName", "")
                for scope in (g.get("scope") or "").split():
                    delegated.setdefault(g.get("clientId"), []).append(
                        {"resource": resource, "scope": scope, "consentType": g.get("consentType")}
                    )
        except GraphError as exc:
            warnings.append(f"Delegated permission grants unavailable ({exc.status}).")

        # Sign-in activity (beta report)
        signins: dict[str, str | None] = {}
        signin_known = True
        try:
            for s in client.get_all("reports/servicePrincipalSignInActivities", beta=True):
                signins[s.get("appId")] = _latest_signin(s)
        except GraphError as exc:
            signin_known = False
            warnings.append(
                f"Service principal sign-in activity unavailable ({exc.status}); dormancy rules were skipped. "
                "Grant AuditLog.Read.All (requires Entra ID P1/P2)."
            )

        identities = []
        for sp in kept:
            sid = sp["id"]
            app = apps.get(sp["appId"])
            owners: list[dict] = []
            perms: list[dict] = []
            creds = _creds(sp, "service principal")
            try:
                for o in client.get_all(f"servicePrincipals/{sid}/owners",
                                        params={"$select": "id,displayName,userPrincipalName"}):
                    owners.append({"name": o.get("displayName"), "upn": o.get("userPrincipalName") or ""})
                for a in client.get_all(f"servicePrincipals/{sid}/appRoleAssignments"):
                    resource_id = a.get("resourceId", "")
                    perms.append({
                        "resource": a.get("resourceDisplayName") or res.get(resource_id).get("displayName"),
                        "permission": res.role_name(resource_id, a.get("appRoleId", "")),
                        "granted": iso(parse_dt(a.get("createdDateTime"))),
                    })
                if app:
                    creds += _creds(app, "application")
                    for o in client.get_all(f"applications/{app['id']}/owners",
                                            params={"$select": "id,displayName,userPrincipalName"}):
                        entry = {"name": o.get("displayName"), "upn": o.get("userPrincipalName") or ""}
                        if entry not in owners:
                            owners.append(entry)
                    for f in client.get_all(f"applications/{app['id']}/federatedIdentityCredentials"):
                        creds.append({"type": "federated", "name": f.get("name") or "federated credential",
                                      "source": "application", "issuer": f.get("issuer"),
                                      "subject": f.get("subject"), "start": None, "end": None})
            except GraphError as exc:
                warnings.append(f"Partial data for {sp.get('displayName')}: {exc.status} {exc.code}")
            owner_org = sp.get("appOwnerOrganizationId")
            identities.append({
                "id": sid,
                "appId": sp.get("appId"),
                "displayName": sp.get("displayName") or sp.get("appDisplayName") or sid,
                "type": sp.get("servicePrincipalType"),
                "publisher": sp.get("publisherName") or "",
                "appOwnerOrganizationId": owner_org,
                "external": bool(owner_org) and owner_org != tenant_id and owner_org not in MICROSOFT_TENANTS,
                "microsoft": owner_org in MICROSOFT_TENANTS,
                "created": iso(parse_dt((app or {}).get("createdDateTime"))),
                "enabled": sp.get("accountEnabled", True),
                "tags": sp.get("tags") or [],
                "signInAudience": sp.get("signInAudience") or (app or {}).get("signInAudience"),
                "owners": owners,
                "appPermissions": perms,
                "delegated": delegated.get(sid, []),
                "roles": roles_by_principal.get(sid, []),
                "credentials": creds,
                "lastSignIn": signins.get(sp.get("appId")),
                "signinKnown": signin_known,
            })
        return {
            "tenant": {"id": tenant_id, "name": org.get("displayName", "")},
            "identities": identities,
            "warnings": warnings,
            "counts": {"service_principals": len(sps), "analysed": len(identities), "graph_calls": client.calls},
        }
    finally:
        if own:
            client.close()
