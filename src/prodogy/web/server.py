"""FastAPI backend for the Prodogy dashboard.

The backend is deliberately thin: it runs the same deterministic ``Scanner``
the CLI uses and serves the resulting ``Report`` as JSON. The frontend is a
single static page that renders that JSON. This keeps the web UI a pure
*renderer* of the single source of truth — no separate logic that could drift
from CLI results.

Endpoints:
  GET  /                      -> the dashboard page
  GET  /api/health            -> liveness
  GET  /api/rules             -> list of registered rules
  POST /api/scan              -> scan a path on the server, return the report
                                  body: {"path": "...", "maintainability": bool}
  POST /api/enrich            -> enrich findings with LLM context
                                  body: {"path": "...", "force": bool}
  GET  /api/enrich-cache      -> enrichment cache statistics

Security note: this server executes scans against server-side filesystem paths
and is intended for LOCAL developer use only. It binds to 127.0.0.1 by default
and has no authentication. Do not expose it to a network without adding
auth + path allow-listing.
"""

from __future__ import annotations

import secrets
from pathlib import Path

from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from prodogy import __version__
from prodogy.engine import load_default_rules
from prodogy.scanner import Scanner

_STATIC_DIR = Path(__file__).parent / "static"


class ScanRequest(BaseModel):
    path: str = "."
    maintainability: bool = True


class EnrichRequest(BaseModel):
    path: str = "."
    force: bool = False


def _is_within(child: Path, parent: Path) -> bool:
    """True if resolved ``child`` is ``parent`` or a descendant of it."""
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def create_app(
    allowed_roots: list[Path] | None = None,
    auth_token: str | None = None,
) -> FastAPI:
    """Build the dashboard app.

    Security controls (added per security review):
      * ``allowed_roots`` — scans are restricted to these directories. A request
        for any path outside them is rejected. Defaults to the current working
        directory. This prevents the dashboard from reading arbitrary files
        (e.g. ~/.ssh, /etc) via the scan API.
      * ``auth_token`` — when set, every /api call must present it as a Bearer
        token. The CLI generates a random token per run and prints it.
    """
    app = FastAPI(title="Prodogy Dashboard", version=__version__)
    scanner = Scanner()
    roots = [p.resolve() for p in (allowed_roots or [Path.cwd()])]

    def require_auth(authorization: str | None = Header(default=None)) -> None:
        if auth_token is None:
            return  # auth disabled (no token configured)
        expected = f"Bearer {auth_token}"
        if authorization is None or not secrets.compare_digest(authorization, expected):
            raise HTTPException(status_code=401, detail="Missing or invalid auth token")

    def _validate_path(raw: str) -> Path:
        # No tilde expansion: keep scans scoped to the allowed roots only.
        target = Path(raw)
        if not target.is_absolute():
            target = (roots[0] / target)
        target = target.resolve()
        if not target.exists():
            # Do not echo the resolved absolute path (avoids a path oracle).
            raise HTTPException(status_code=404, detail="Path not found within allowed roots")
        if not any(_is_within(target, r) for r in roots):
            raise HTTPException(status_code=403, detail="Path is outside the allowed scan roots")
        return target

    @app.get("/api/health")
    def health() -> dict:
        return {"status": "ok", "version": __version__, "auth_required": auth_token is not None}

    @app.get("/api/rules")
    def rules(_: None = Depends(require_auth)) -> JSONResponse:
        registry = load_default_rules()
        data = [
            {
                "id": r.id,
                "title": r.title,
                "severity": r.severity.value,
                "category": r.category.value,
                "rationale": r.rationale,
                "remediation": r.remediation,
                "compliance_refs": list(r.compliance_refs),
            }
            for r in sorted(registry.all(), key=lambda r: r.id)
        ]
        return JSONResponse(data)

    @app.post("/api/scan")
    def scan(req: ScanRequest, _: None = Depends(require_auth)) -> JSONResponse:
        target = _validate_path(req.path)
        report = scanner.scan(target, with_maintainability=req.maintainability)
        return JSONResponse(report.model_dump(mode="json"))

    @app.post("/api/enrich")
    def enrich(req: EnrichRequest, _: None = Depends(require_auth)) -> JSONResponse:
        """Enrich findings with LLM-generated contextual explanations."""
        from prodogy.config import resolve_config as _resolve_config
        from prodogy.enricher import Enricher, EnrichmentError

        target = _validate_path(req.path)
        cfg = _resolve_config(target)
        enricher = Enricher(config=cfg.model_dump(), root=str(target))

        if not enricher.is_configured():
            raise HTTPException(
                status_code=400,
                detail="LLM not configured. Set api_key in .prodogy.yml or PRODOGY_LLM_API_KEY env var.",
            )

        try:
            report = scanner.scan(target)
            report = enricher.enrich_report(report, only_unenriched=not req.force)
            enriched_count = sum(
                1 for f in report.active_findings() if f.llm_explanation
            )
        except EnrichmentError as exc:
            raise HTTPException(status_code=502, detail=f"Enrichment failed: {exc}") from exc

        result = report.model_dump(mode="json")
        result["_enriched_count"] = enriched_count
        return JSONResponse(result)

    @app.get("/api/enrich-cache")
    def enrich_cache_stats(_: None = Depends(require_auth)) -> JSONResponse:
        """Return enrichment cache statistics."""
        from prodogy.enricher import _cache_path, _load_cache

        cache_path = _cache_path(Path("."))
        cache = _load_cache(cache_path)
        import time

        valid = sum(
            1
            for e in cache.values()
            if isinstance(e, dict) and e.get("_ts", 0) and (time.time() - e["_ts"]) < 86400 * 7
        )
        return JSONResponse({
            "total_entries": len(cache),
            "valid_entries": valid,
            "expired_entries": len(cache) - valid,
            "cache_file": str(cache_path),
        })

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(_STATIC_DIR / "index.html")

    if _STATIC_DIR.exists():
        app.mount("/static", StaticFiles(directory=str(_STATIC_DIR)), name="static")

    return app


def _app_from_env() -> FastAPI:
    """Build the app using PRODOGY_* env vars.

    uvicorn imports this module by string ("prodogy.web.server:app"), so the CLI
    passes configuration through the environment rather than function args.
    """
    import os

    roots_env = os.environ.get("PRODOGY_ALLOWED_ROOTS", "")
    roots = [Path(p) for p in roots_env.split(os.pathsep) if p] or None
    token = os.environ.get("PRODOGY_AUTH_TOKEN") or None
    return create_app(allowed_roots=roots, auth_token=token)


app = _app_from_env()
