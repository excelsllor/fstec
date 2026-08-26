from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from contextlib import asynccontextmanager
import logging
import os
from pathlib import Path
from app.database import init_db, SessionLocal
from app.api import auth, users, letters, generate, templates
from app.api.auth import ensure_bootstrap

logger = logging.getLogger(__name__)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    with SessionLocal() as db:
        bootstrap_pw = ensure_bootstrap(db)
        if bootstrap_pw:
            logger.warning(
                "Bootstrap password for user '%s': %s — "
                "check systemd journal (journalctl -u fstec-backend) "
                "or save it now. This password is shown ONLY ONCE.",
                "admin", bootstrap_pw,
            )
    yield


_docs_enabled = not os.environ.get("FSTEC_DISABLE_DOCS", "1")

app = FastAPI(
    title="FSTEC Service API",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if _docs_enabled else None,
    redoc_url="/redoc" if _docs_enabled else None,
    openapi_url="/openapi.json" if _docs_enabled else None,
)

app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "tauri://localhost",
        "http://tauri.localhost",
    ],
    allow_origin_regex=r"^(https?://(tauri\.localhost|localhost|127\.0\.0\.1)(:8765)?|tauri://localhost)$",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(letters.router)
app.include_router(generate.router)
app.include_router(templates.router)


@app.get("/api/health")
def health():
    return {"status": "ok"}


_FRONTEND_DIR = os.environ.get("FSTEC_FRONTEND_DIR")
if _FRONTEND_DIR:
    _dist = Path(_FRONTEND_DIR)
    _assets_dir = _dist / "assets"
    if _assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=_assets_dir), name="assets")
    _index_html = _dist / "index.html"
    if _index_html.exists():

        @app.get("/{full_path:path}", include_in_schema=False)
        def _spa(full_path: str):
            return FileResponse(_index_html)
