"""RAKSHA AI backend application."""

from __future__ import annotations

from pathlib import Path

from dotenv import load_dotenv

for _env_path in (
    Path("/app/.env"),
    Path(__file__).resolve().parents[2] / ".env",
    Path(__file__).resolve().parents[1] / ".env",
):
    if _env_path.is_file():
        load_dotenv(_env_path)
        break

from fastapi import FastAPI

from app.api.events import router as events_router

app = FastAPI(title="RAKSHA AI Backend", version="0.1.0")
app.include_router(events_router)


@app.get("/health")
def health_check() -> dict[str, str]:
    return {"status": "ok"}
