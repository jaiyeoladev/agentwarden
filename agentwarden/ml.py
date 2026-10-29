"""Peer-based anomaly detection for over-privileged non-human identities.

Each identity becomes a feature vector describing its privilege and hygiene. An Isolation Forest
(scikit-learn) scores how isolated each identity is from the rest of the estate; robust z-scores
against the peer median explain *which* features make it unusual, so every flag is explainable.

If scikit-learn is not installed, or there are too few identities to train on, a robust z-score
model is used instead.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

import numpy as np

from .core.db import parse_dt, utcnow

FEATURES = [
    ("tier0_permissions", "Tier-0 (tenant takeover) permissions"),
    ("tier1_permissions", "Tier-1 (broad data) permissions"),
    ("tier2_permissions", "Tier-2 (broad read) permissions"),
    ("write_permissions", "Write permissions"),
    ("privileged_roles", "Privileged directory roles"),
    ("tenant_wide_delegated", "Tenant-wide delegated high-risk scopes"),
    ("client_secrets", "Client secrets"),
    ("max_secret_lifetime_days", "Longest secret lifetime (days)"),
    ("days_since_sign_in", "Days since last sign-in"),
    ("no_owner", "Has no owner"),
    ("external_publisher", "External multi-tenant publisher"),
    ("age_days", "Age (days)"),
]
FEATURE_LABELS = dict(FEATURES)
# Features where a *low* value is the unusual direction are not flagged as reasons.
UPWARD_ONLY = {k for k, _ in FEATURES} - {"age_days"}


@dataclass
class AnomalyResult:
    identity_id: str
    score: float  # 0..1, higher = more anomalous
    is_anomaly: bool
    reasons: list[dict]
    method: str


def features_for(identity: dict, roles_privileged: int, tenant_wide_high: int) -> dict:
    """Identity permissions must already be annotated with 'tier' and 'write'."""
    now = utcnow()
    perms = identity.get("appPermissions", [])
    counts = {0: 0, 1: 0, 2: 0}
    for p in perms:
        t = p.get("tier", 3)
        if t in counts:
            counts[t] += 1
    secrets = [c for c in identity.get("credentials", []) if c["type"] == "password"]
    lifetimes = []
    for c in secrets:
        s, e = parse_dt(c.get("start")), parse_dt(c.get("end"))
        if s and e:
            lifetimes.append((e - s).days)
    last = parse_dt(identity.get("lastSignIn"))
    if identity.get("signinKnown"):
        since = min((now - last).days, 730) if last else 730
    else:
        since = -1  # unknown, imputed later
    created = parse_dt(identity.get("created"))
    return {
        "tier0_permissions": counts[0],
        "tier1_permissions": counts[1],
        "tier2_permissions": counts[2],
        "write_permissions": sum(1 for p in perms if p.get("write")),
        "privileged_roles": roles_privileged,
        "tenant_wide_delegated": tenant_wide_high,
        "client_secrets": len(secrets),
        "max_secret_lifetime_days": max(lifetimes) if lifetimes else 0,
        "days_since_sign_in": since,
        "no_owner": 1 if (not identity.get("owners") and identity.get("type") != "ManagedIdentity") else 0,
        "external_publisher": 1 if identity.get("external") else 0,
        "age_days": min((now - created).days, 3650) if created else -1,
    }


def _robust_z(matrix: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    med = np.median(matrix, axis=0)
    mad = np.median(np.abs(matrix - med), axis=0) * 1.4826
    std = matrix.std(axis=0)
    scale = np.where(mad > 1e-9, mad, np.where(std > 1e-9, std, 1.0))
    return (matrix - med) / scale, med


def detect(rows: list[tuple[str, dict]], contamination: float = 0.08, min_samples: int = 12,
           z_threshold: float = 2.5) -> dict[str, AnomalyResult]:
    if not rows:
        return {}
    keys = [k for k, _ in FEATURES]
    raw = np.array([[float(f[k]) for k in keys] for _, f in rows], dtype=float)
    # impute unknowns (-1) with the column median of known values
    for j in range(raw.shape[1]):
        col = raw[:, j]
        known = col[col >= 0]
        fill = float(np.median(known)) if known.size else 0.0
        col[col < 0] = fill
    # log-scale heavy-tailed features so one large value does not dominate
    transformed = np.log1p(raw)
    z, med = _robust_z(transformed)

    method = "robust-z"
    scores: np.ndarray
    flags: np.ndarray
    try:
        if len(rows) < min_samples:
            raise RuntimeError("too few samples")
        from sklearn.ensemble import IsolationForest

        model = IsolationForest(n_estimators=300, contamination=contamination, random_state=0)
        model.fit(transformed)
        raw_scores = -model.score_samples(transformed)
        lo, hi = float(raw_scores.min()), float(raw_scores.max())
        scores = (raw_scores - lo) / (hi - lo) if hi > lo else np.zeros_like(raw_scores)
        flags = model.predict(transformed) == -1
        method = "isolation-forest"
    except Exception:  # noqa: BLE001 - fall back to a dependency-free model
        upward = np.clip(z, 0, None)
        combined = np.sqrt((upward**2).sum(axis=1))
        hi = float(combined.max()) or 1.0
        scores = combined / hi
        flags = (upward.max(axis=1) >= z_threshold) & (combined >= np.percentile(combined, 100 * (1 - contamination)))

    raw_med = np.median(raw, axis=0)
    results: dict[str, AnomalyResult] = {}
    for i, (identity_id, _) in enumerate(rows):
        reasons = []
        for j, k in enumerate(keys):
            if k not in UPWARD_ONLY or z[i, j] < 2.0 or raw[i, j] <= raw_med[j]:
                continue
            reasons.append({
                "feature": k,
                "label": FEATURE_LABELS[k],
                "value": _fmt(raw[i, j]),
                "peer_median": _fmt(raw_med[j]),
                "z": round(float(z[i, j]), 1),
            })
        reasons.sort(key=lambda r: -r["z"])
        # An outlier with no privilege-related reason is not useful to report.
        flagged = bool(flags[i]) and any(
            r["feature"] in ("tier0_permissions", "tier1_permissions", "privileged_roles", "write_permissions",
                             "tenant_wide_delegated") for r in reasons
        )
        results[identity_id] = AnomalyResult(identity_id, round(float(scores[i]), 3), flagged, reasons[:4], method)
    return results


def _fmt(v: float) -> str:
    return str(int(v)) if math.isclose(v, round(v)) else f"{v:.1f}"
