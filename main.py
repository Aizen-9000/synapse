"""
synapse-auth/main.py

Auth server entry point.
Runs on port 9000 (separate from agent runtime on 8000).

Start with:
  python main.py
  or
  uvicorn main:app --host 0.0.0.0 --port 9000
"""

import os
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel

load_dotenv()

from database import init_db
from routes.auth_routes    import router as auth_router
from routes.license_routes import router as license_router
from routes.webhook_routes import router as webhook_router

console = Console()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    init_db()
    console.print(Panel(
        "[bold violet]Synapse Auth Server[/bold violet]\n"
        f"Port: [cyan]{os.getenv('PORT', '9000')}[/cyan]\n"
        f"DB:   [cyan]{os.getenv('DATABASE_URL', 'sqlite:///./synapse_auth.db')}[/cyan]\n"
        f"Razorpay: [cyan]{'configured' if os.getenv('RAZORPAY_KEY_ID') else 'NOT SET — add to .env'}[/cyan]",
        border_style="violet",
    ))
    yield
    # Shutdown (nothing to clean up)


app = FastAPI(
    title="Synapse Auth Server",
    description="License management and billing for Synapse.",
    version="0.1.0",
    lifespan=lifespan,
)

# CORS — allow the desktop client and signup page
origins = os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(auth_router)
app.include_router(license_router)
app.include_router(webhook_router)

# Serve the signup web page
if os.path.exists("web"):
    app.mount("/web", StaticFiles(directory="web"), name="web")

@app.get("/")
def root():
    """Redirect root to the signup page."""
    if os.path.exists("web/index.html"):
        return FileResponse("web/index.html")
    return {"service": "Synapse Auth Server", "version": "0.1.0", "docs": "/docs"}

@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host=os.getenv("HOST", "0.0.0.0"),
        port=int(os.getenv("PORT", "9000")),
        reload=False,
    )
