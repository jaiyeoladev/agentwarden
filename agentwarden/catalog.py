"""Permission risk tiers, privileged roles and AI-agent classification hints.

Tier 0  — can be used to take over the tenant (grant itself or others more privilege).
Tier 1  — broad read or write access to business data (mail, files, chats, users, devices).
Tier 2  — broad read of directory or configuration data.
Tier 3  — everything else (scoped or low impact).

The lists below cover the most commonly abused Microsoft Graph and Exchange application
permissions. Extend them in the Settings page ("Extra tier 0/1 permissions") for your estate.
"""

from __future__ import annotations

import re

TIER0 = {
    "RoleManagement.ReadWrite.Directory",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Application.ReadWrite.OwnedBy",
    "Domain.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess",
    "Policy.ReadWrite.AuthenticationMethod",
    "Policy.ReadWrite.PermissionGrant",
    "UserAuthenticationMethod.ReadWrite.All",
    "Organization.ReadWrite.All",
    "PrivilegedAccess.ReadWrite.AzureAD",
    "PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup",
    "RoleManagementPolicy.ReadWrite.Directory",
    "EntitlementManagement.ReadWrite.All",
    "Directory.ReadWrite.All",
    "full_access_as_app",
    "Exchange.ManageAsApp",
}

TIER1 = {
    "Mail.Read", "Mail.ReadWrite", "Mail.Send", "MailboxSettings.ReadWrite",
    "Files.Read.All", "Files.ReadWrite.All",
    "Sites.Read.All", "Sites.ReadWrite.All", "Sites.Manage.All", "Sites.FullControl.All",
    "Calendars.ReadWrite", "Contacts.ReadWrite", "Notes.ReadWrite.All",
    "Chat.Read.All", "Chat.ReadWrite.All", "ChannelMessage.Read.All", "ChatMessage.Read.All",
    "User.ReadWrite.All", "Group.ReadWrite.All", "GroupMember.ReadWrite.All",
    "DeviceManagementConfiguration.ReadWrite.All", "DeviceManagementApps.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All", "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementRBAC.ReadWrite.All", "TeamMember.ReadWrite.All", "Team.Create",
    "InformationProtectionPolicy.Read.All", "eDiscovery.ReadWrite.All", "SecurityEvents.ReadWrite.All",
}

TIER2 = {
    "Directory.Read.All", "User.Read.All", "Group.Read.All", "GroupMember.Read.All",
    "Application.Read.All", "AuditLog.Read.All", "Reports.Read.All", "Policy.Read.All",
    "Calendars.Read", "Contacts.Read", "People.Read.All", "Team.ReadBasic.All",
    "DeviceManagementManagedDevices.Read.All", "DeviceManagementConfiguration.Read.All",
    "RoleManagement.Read.Directory", "IdentityRiskyUser.Read.All", "SecurityEvents.Read.All",
    "Mail.ReadBasic.All", "Organization.Read.All",
}

# Delegated (consented) scopes that are dangerous when granted tenant-wide (AllPrincipals).
HIGH_RISK_DELEGATED = {
    "Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All", "Sites.FullControl.All",
    "Directory.ReadWrite.All", "Directory.AccessAsUser.All", "User.ReadWrite.All",
    "Mail.Read", "Files.Read.All", "Chat.ReadWrite", "RoleManagement.ReadWrite.Directory",
    "Application.ReadWrite.All", "full_access_as_user", "EWS.AccessAsUser.All",
}

CRITICAL_ROLES = {
    "Global Administrator", "Privileged Role Administrator", "Privileged Authentication Administrator",
    "Partner Tier2 Support", "Hybrid Identity Administrator",
}
HIGH_ROLES = {
    "Application Administrator", "Cloud Application Administrator", "Security Administrator",
    "Exchange Administrator", "SharePoint Administrator", "User Administrator", "Intune Administrator",
    "Conditional Access Administrator", "Authentication Administrator", "Groups Administrator",
    "Directory Writers", "Authentication Policy Administrator", "Domain Name Administrator",
    "External Identity Provider Administrator", "Teams Administrator", "Compliance Administrator",
}

# Tenants that own Microsoft first-party applications (Microsoft Services, Microsoft Corp).
MICROSOFT_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
}

# Matched against name, publisher and tags. Short keywords (3 letters or fewer) must be whole
# tokens; longer ones match the start of a token ("agent" matches "agentic").
DEFAULT_AI_KEYWORDS = [
    "agent", "copilot", "gpt", "openai", "llm", "chatbot", "bot", "assistant", "genai",
    "langchain", "autogen", "semantic kernel", "anthropic", "claude", "gemini", "mistral", "ai",
    "rag", "foundry", "mcp",
]

WRITE_MARKERS = ("ReadWrite", ".Send", "FullControl", "Manage", "full_access", "Create", "PrivilegedOperations")


def tier_of(permission: str, extra_tier0: set[str] | None = None, extra_tier1: set[str] | None = None) -> int:
    if permission in TIER0 or (extra_tier0 and permission in extra_tier0):
        return 0
    if permission in TIER1 or (extra_tier1 and permission in extra_tier1):
        return 1
    if permission in TIER2:
        return 2
    return 3


def is_write(permission: str) -> bool:
    return any(m in permission for m in WRITE_MARKERS)


def role_severity(role: str) -> str | None:
    if role in CRITICAL_ROLES:
        return "critical"
    if role in HIGH_ROLES:
        return "high"
    return None


def keyword_matches(text: str, keywords: list[str]) -> list[str]:
    text = (text or "").lower()
    hits = []
    for kw in keywords:
        kw = kw.strip().lower()
        if not kw:
            continue
        if " " in kw:
            found = kw in text
        elif len(kw) <= 3:
            found = re.search(rf"(?<![a-z0-9]){re.escape(kw)}(?![a-z])", text) is not None
        else:
            found = re.search(rf"(?<![a-z0-9]){re.escape(kw)}", text) is not None
        if found:
            hits.append(kw)
    return hits
