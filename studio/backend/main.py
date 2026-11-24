import os
import sys
from pathlib import Path
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Ensure root is on Python path
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from studio.backend.routes.recon import router as recon_router
from studio.backend.routes.crafter import router as crafter_router
from studio.backend.routes.testbed import router as testbed_router

app = FastAPI(
    title="PolyMorph Studio",
    description="Unified Cyber Range Web Interface: Reconnaissance, Polyglot Crafter & Live Simulation Range",
    version="1.0.0",
)

# Enable CORS for local development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def disable_browser_cache_middleware(request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Register API Routers
app.include_router(recon_router)
app.include_router(crafter_router)
app.include_router(testbed_router)


@app.get("/api/health")
def health():
    return {
        "status": "online",
        "app": "PolyMorph Studio",
        "version": "1.0.0",
        "tabs": ["recon", "crafter", "testbed", "defense_placeholder"],
    }


# Mount Static Frontend
FRONTEND_DIR = Path(__file__).resolve().parent.parent / "frontend"
if FRONTEND_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND_DIR)), name="static")

    @app.get("/")
    def serve_index():
        return FileResponse(FRONTEND_DIR / "index.html")


if __name__ == "__main__":
    import uvicorn
    print("[*] Starting PolyMorph Studio on http://localhost:8888 ...")
    uvicorn.run("studio.backend.main:app", host="0.0.0.0", port=8888, reload=True)
