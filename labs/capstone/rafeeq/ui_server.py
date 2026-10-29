# /// script
# requires-python = ">=3.11"
# dependencies = ["fastapi>=0.150", "uvicorn>=0.40", "openai>=3.30", "pydantic>=2.12", "python-dotenv>=1.1",
#                 "opentelemetry-sdk>=1.45"]
# ///
"""Rafeeq's HTTP service (the course reference service, unchanged) plus a one-page HTML client on the same origin.

    RAFEEQ_API_KEYS=<your-key> uv run capstone/rafeeq/ui_server.py --port 8793      # then open http://localhost:8793/

The key is typed into the page (password field); it is never written into the page or the repository.
"""
import argparse
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
LABS = HERE.parents[1]
sys.path[:0] = [str(LABS), str(LABS / "servers")]

import uvicorn  # noqa: E402
from fastapi.responses import HTMLResponse  # noqa: E402
from rafeeq_api import create_app  # noqa: E402

PAGE = (HERE / "ui.html").read_text(encoding="utf-8")


def build():
    app = create_app(LABS / "artifacts" / "rafeeq_ui")

    @app.get("/", response_class=HTMLResponse)
    def index() -> str:
        return PAGE

    return app


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8793)
    uvicorn.run(build(), host="127.0.0.1", port=ap.parse_args().port, log_level="warning")
