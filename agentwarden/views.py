"""AgentWarden pages: dashboard, identity inventory, identity detail, register and anomalies."""

from __future__ import annotations

import csv
import io
from collections import Counter
from datetime import date, timedelta

from fastapi import Depends, FastAPI, Request
from fastapi.responses import HTMLResponse, Response

from .core.auth import current_user, require_admin_form, require_user
from .core.context import Context
from .core.db import iso, utcnow
from .core.web import _csv_safe, page_render, parse_date_field, redirect
from .ml import FEATURES
from .rules import CLASS_LABELS

DATA_CLASSES = ["Public", "Internal", "Confidential", "Restricted"]
REG_FIELDS = ["classification", "business_owner", "technical_owner", "purpose", "data_classification",
              "model_provider", "human_in_loop", "approved_permissions", "review_interval_days", "last_reviewed",
              "notes"]


def _identities(ctx: Context) -> tuple[list[dict], dict]:
    _, data = ctx.latest()
    return [i for i in data.get("identities", []) if i.get("analysis")], data


def dashboard(ctx: Context) -> dict:
    idents, data = _identities(ctx)
    agents = [i for i in idents if i["analysis"]["classification"] == "ai_agent"]
    bands = Counter(i["analysis"]["risk_band"] for i in idents)
    by_class = Counter(i["analysis"]["classification_label"] for i in idents)
    tier0 = sum(1 for i in idents if i["analysis"]["tier0"] or i["analysis"]["role_severities"])
    anomalies = sorted((i for i in idents if i["analysis"]["anomaly"]),
                       key=lambda i: -i["analysis"]["anomaly_score"])
    top = sorted(idents, key=lambda i: -i["analysis"]["risk_score"])[:10]
    summary = ctx.findings.summary()
    rule_counts = [(f"{r['rule_id']} · {ctx.spec.rules[r['rule_id']].title}", r["n"])
                   for r in summary["by_rule"] if r["rule_id"] in ctx.spec.rules][:8]
    agents_registered = sum(1 for a in agents if a["analysis"]["registered"])
    perm_counter = Counter()
    for i in idents:
        for p in i.get("appPermissions", []):
            if p.get("tier", 3) <= 1:
                perm_counter[p["permission"]] += 1
    return {
        "tenant": data.get("tenant", {}),
        "total": len(idents),
        "agents": len(agents),
        "agents_registered": agents_registered,
        "privileged": tier0,
        "anomalies": anomalies[:6],
        "anomaly_count": len(anomalies),
        "top": top,
        "band_segments": [(b.capitalize(), bands.get(b, 0), "bar-info" if b == "low" else f"bar-{b}") for b in ("critical", "high", "medium", "low")],
        "bands": bands,
        "by_class": sorted(by_class.items(), key=lambda x: -x[1]),
        "rule_counts": rule_counts,
        "top_perms": perm_counter.most_common(8),
        "unowned": sum(1 for i in idents if i["analysis"]["no_owner"]),
    }


def entity_link(f: dict) -> str | None:
    return f"/identities/{f['entity_id']}" if f["entity_type"] == "identity" else None


def report_context(ctx: Context) -> dict:
    d = dashboard(ctx)
    return {"agw": d}


def register_routes(app: FastAPI, ctx: Context) -> None:
    render = page_render(ctx)
    db = ctx.db

    @app.get("/identities", response_class=HTMLResponse)
    async def identities(request: Request, cls: str = "", band: str = "", q: str = "", sort: str = "risk",
                         user=Depends(require_user)):
        idents, _ = _identities(ctx)
        q_l = q.strip().lower()
        rows = []
        for i in idents:
            a = i["analysis"]
            if cls and a["classification"] != cls:
                continue
            if band and a["risk_band"] != band:
                continue
            if q_l and q_l not in i["displayName"].lower() and q_l not in (i.get("appId") or "").lower() \
                    and q_l not in (i.get("publisher") or "").lower():
                continue
            rows.append(i)
        key = {
            "risk": lambda i: -i["analysis"]["risk_score"],
            "anomaly": lambda i: -i["analysis"]["anomaly_score"],
            "name": lambda i: i["displayName"].lower(),
        }.get(sort, lambda i: -i["analysis"]["risk_score"])
        rows.sort(key=key)
        counts = Counter(i["analysis"]["classification"] for i in idents)
        return render(request, "identities.html", rows=rows, cls=cls, band=band, q=q, sort=sort,
                      class_labels=CLASS_LABELS, counts=counts, title="Identities")

    @app.get("/identities/{identity_id}", response_class=HTMLResponse)
    async def identity_detail(request: Request, identity_id: str, user=Depends(require_user)):
        idents, _ = _identities(ctx)
        ident = next((i for i in idents if i["id"] == identity_id), None)
        reg = db.one("SELECT * FROM agent_registry WHERE identity_id = ?", (identity_id,))
        if not ident:
            return render(request, "error.html", status_code=404, title="Not found",
                          message="That identity was not found in the latest scan.")
        findings, _ = ctx.findings.search(status="active", entity_type="identity", entity_id=identity_id, limit=100)
        feats = [(label, ident["analysis"]["features"].get(k)) for k, label in FEATURES]
        perms = sorted(ident.get("appPermissions", []), key=lambda p: (p.get("tier", 3), p["permission"]))
        approved = set((reg or {}).get("approved_permissions", "").split()) if reg else set()
        return render(request, "identity.html", i=ident, a=ident["analysis"], reg=reg, findings=findings,
                      feats=feats, perms=perms, approved=approved, class_labels=CLASS_LABELS,
                      data_classes=DATA_CLASSES, title=ident["displayName"])

    @app.post("/identities/{identity_id}/register")
    async def identity_register(request: Request, identity_id: str, form=Depends(require_admin_form)):
        actor = current_user(request)["name"]
        idents, _ = _identities(ctx)
        ident = next((i for i in idents if i["id"] == identity_id), None)
        existing = db.one("SELECT * FROM agent_registry WHERE identity_id = ?", (identity_id,))
        if not ident and not existing:
            return redirect("/identities")
        rec = {k: str(form.get(k, "")).strip() for k in REG_FIELDS}
        if rec["classification"] not in CLASS_LABELS:
            rec["classification"] = "ai_agent"
        if rec["data_classification"] not in DATA_CLASSES:
            rec["data_classification"] = "Internal"
        rec["human_in_loop"] = 1 if form.get("human_in_loop") == "on" else 0
        try:
            rec["review_interval_days"] = max(7, min(730, int(rec["review_interval_days"] or 90)))
        except ValueError:
            rec["review_interval_days"] = 90
        rec["last_reviewed"] = parse_date_field(rec["last_reviewed"])
        if form.get("mark_reviewed") == "on":
            rec["last_reviewed"] = utcnow().date().isoformat()
        perms = sorted({p.strip() for p in rec["approved_permissions"].replace(",", "\n").splitlines() if p.strip()})
        rec["approved_permissions"] = "\n".join(perms)[:4000]
        for k in ("business_owner", "technical_owner", "model_provider"):
            rec[k] = rec[k][:120]
        rec["purpose"], rec["notes"] = rec["purpose"][:1000], rec["notes"][:2000]
        name = ident["displayName"] if ident else existing["display_name"]
        with db.conn() as con:
            con.execute(
                "INSERT INTO agent_registry (identity_id, display_name, " + ", ".join(REG_FIELDS)
                + ", updated_at, updated_by) VALUES (" + ", ".join("?" * (len(REG_FIELDS) + 4)) + ") "
                "ON CONFLICT(identity_id) DO UPDATE SET display_name=excluded.display_name, "
                + ", ".join(f"{k}=excluded.{k}" for k in REG_FIELDS)
                + ", updated_at=excluded.updated_at, updated_by=excluded.updated_by",
                [identity_id, name, *[rec[k] for k in REG_FIELDS], iso(utcnow()), actor],
            )
        db.audit(actor, "registry.save", f"identity:{identity_id}", name)
        request.session.setdefault("flash", []).append(["success", "Register entry saved. Run a scan to re-evaluate."])
        return redirect(f"/identities/{identity_id}")

    @app.post("/identities/{identity_id}/unregister")
    async def identity_unregister(request: Request, identity_id: str, form=Depends(require_admin_form)):
        actor = current_user(request)["name"]
        db.execute("DELETE FROM agent_registry WHERE identity_id = ?", (identity_id,))
        db.audit(actor, "registry.delete", f"identity:{identity_id}")
        request.session.setdefault("flash", []).append(["success", "Register entry removed."])
        return redirect(f"/identities/{identity_id}")

    @app.get("/registry", response_class=HTMLResponse)
    async def registry(request: Request, user=Depends(require_user)):
        regs = db.query("SELECT * FROM agent_registry ORDER BY display_name COLLATE NOCASE")
        idents, _ = _identities(ctx)
        by_id = {i["id"]: i for i in idents}
        now = utcnow().date()
        for r in regs:
            r["identity"] = by_id.get(r["identity_id"])
            last = r.get("last_reviewed")
            r["next_review"] = None
            if last:
                r["next_review"] = (date.fromisoformat(last) + timedelta(days=r["review_interval_days"] or 90)).isoformat()
            r["overdue"] = bool(r["next_review"] and r["next_review"] < now.isoformat()) or not last
        unregistered = [i for i in idents if i["analysis"]["unregistered_agent"]]
        return render(request, "registry.html", regs=regs, unregistered=unregistered, class_labels=CLASS_LABELS,
                      title="Governance register")

    @app.get("/registry.csv")
    async def registry_csv(request: Request, user=Depends(require_user)):
        buf = io.StringIO()
        w = csv.writer(buf)
        cols = ["identity_id", "display_name", *REG_FIELDS, "updated_at", "updated_by"]
        w.writerow(cols)
        for r in db.query("SELECT * FROM agent_registry ORDER BY display_name"):
            w.writerow([_csv_safe(r.get(c)) if r.get(c) is not None else "" for c in cols])
        return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                        headers={"Content-Disposition": 'attachment; filename="agent-register.csv"'})

    @app.get("/anomalies", response_class=HTMLResponse)
    async def anomalies(request: Request, user=Depends(require_user)):
        idents, _ = _identities(ctx)
        rows = sorted(idents, key=lambda i: -i["analysis"]["anomaly_score"])
        method = next((i["analysis"].get("anomaly_method") for i in idents if i["analysis"].get("anomaly_method")), None)
        scatter = [(i["displayName"], i["analysis"]["anomaly_score"],
                    "bar-critical" if i["analysis"]["anomaly"] else "bar-muted") for i in rows[:20]]
        return render(request, "anomalies.html", rows=rows, method=method, chart=scatter,
                      enabled=ctx.settings.get("anomaly_enabled"), features=FEATURES, title="Anomalies")
