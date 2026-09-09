# backend/main.py  ─  Cyber Data Engine v1.0.0
# =============================================================================
# FastAPI Backend — Full Production Server
#
# API Endpoints:
#   GET  /                                  → Health check
#   GET  /api/v1/stats                      → Pipeline statistics
#   GET  /api/v1/providers                  → List all providers
#   POST /api/v1/providers                  → Add a new provider
#   PUT  /api/v1/providers/{name}           → Edit a provider
#   DELETE /api/v1/providers/{name}         → Remove a provider
#   POST /api/v1/providers/ping             → Health check all providers
#   POST /api/v1/pipeline/run               → Launch pipeline job
#   GET  /api/v1/pipeline/stream/{job_id}   → SSE real-time progress
#   GET  /api/v1/records                    → Paginated records viewer
#   GET  /api/v1/export/alpaca              → Download Alpaca JSONL
#   GET  /api/v1/export/rich                → Download Rich JSONL
#   GET  /api/v1/export/llama3              → Download LLaMA-3 formatted
#   POST /api/v1/cache/clear                → Clear file dedup cache
# =============================================================================
"""
main.py  —  FastAPI Server & Pipeline Controller

Coordinates the HTTP API, Server-Sent Events (SSE) streaming, and the
background pipeline execution.

Concurrency Architecture:
  1. FastAPI handles HTTP requests asynchronously.
  2. /api/v1/pipeline/run creates a new background job and returns a job_id.
  3. The job runs in asyncio.create_task(_run_pipeline_worker).
  4. File parsing and regex classification (CPU-bound) are offloaded to a
     ThreadPoolExecutor via loop.run_in_executor to avoid blocking the event loop.
  5. LLM generation runs concurrently via MultiSchemaGenerator's Semaphore.
  6. Progress is pushed to a job-specific Queue and streamed via SSE.
"""

from __future__ import annotations

import io
import json
import logging
import os
import signal
import sys
import threading
import time
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Optional
from queue import Queue, Empty

from fastapi import FastAPI, File, HTTPException, Request, UploadFile, Body, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import sys, os
sys.path.insert(0, str(Path(__file__).parent.parent))

from shared_lib.rag_processor import RAGProcessor
from shared_lib.schemas import DataSchema
from shared_lib.formatter import (
    format_dataset, NegativeExampleGenerator,
    MitreValidator, apply_curriculum_to_jsonl,
)
from backend.core.providers import (
    ModelGateway, ProviderConfig, ProviderType, RoutingStrategy,
    make_ollama_provider, make_lmstudio_provider,
    make_vllm_provider, make_openai_provider,
)
from backend.core.classifier import ContentClassifier
from backend.core.multi_schema_generator import make_multi_schema_generator
from backend.core.state_manager import (
    load_providers, save_providers, is_cached, add_to_cache, append_to_output,
)
from shared_lib.parser import FileParser

# ─────────────────────────────────────────────────────────────────────────────
# App setup & Logging
# ─────────────────────────────────────────────────────────────────────
# Logging — Terminal: COLORED, CDE only  |  File: plain text, everything
# ─────────────────────────────────────────────────────────────────────

# ANSI color codes
class _Colors:
    RESET  = "\033[0m"
    GREEN  = "\033[92m"   # bright green  → success ✓
    RED    = "\033[91m"   # bright red    → error ✗
    YELLOW = "\033[93m"   # bright yellow → warning
    CYAN   = "\033[96m"   # cyan          → info/progress
    DIM    = "\033[2m"    # dim           → debug/misc
    BOLD   = "\033[1m"


class _ColoredFormatter(logging.Formatter):
    """Colorize terminal output based on log level and message content."""

    _BASE_FMT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"

    def format(self, record: logging.LogRecord) -> str:
        msg = super().format(record)
        txt = record.getMessage()

        if record.levelno >= logging.ERROR:
            return f"{_Colors.RED}{_Colors.BOLD}{msg}{_Colors.RESET}"
        if record.levelno >= logging.WARNING:
            return f"{_Colors.YELLOW}{msg}{_Colors.RESET}"
        # INFO from CDE loggers — color by content
        if record.name.startswith("CDE."):
            if "✓" in txt or "done" in txt.lower() or "complete" in txt.lower():
                return f"{_Colors.GREEN}{msg}{_Colors.RESET}"
            if "✗" in txt or "fail" in txt.lower() or "error" in txt.lower():
                return f"{_Colors.RED}{msg}{_Colors.RESET}"
            if "progress" in txt.lower() or "%" in txt or "→" in txt:
                return f"{_Colors.CYAN}{msg}{_Colors.RESET}"
        return f"{_Colors.DIM}{msg}{_Colors.RESET}"


_plain_fmt   = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
_colored_fmt = _ColoredFormatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")

ROOT_DIR    = Path(__file__).parent.parent
OUTPUT_DIR  = ROOT_DIR / "output"
FRONTEND_DIR = ROOT_DIR / "frontend"
LOGS_DIR    = ROOT_DIR / "logs"

OUTPUT_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# File handler → everything, plain text
_file_handler = logging.FileHandler(LOGS_DIR / "engine.log", encoding="utf-8")
_file_handler.setLevel(logging.DEBUG)
_file_handler.setFormatter(_plain_fmt)

# Terminal handler → CDE.* + warnings/errors only, WITH colors
class _CDEFilter(logging.Filter):
    """Allow only CDE.* loggers OR WARNING+ from any logger."""
    def filter(self, record: logging.LogRecord) -> bool:
        return record.name.startswith("CDE.") or record.levelno >= logging.WARNING

_stream_handler = logging.StreamHandler()
_stream_handler.setLevel(logging.DEBUG)
_stream_handler.setFormatter(_colored_fmt)
_stream_handler.addFilter(_CDEFilter())

# SSE Log Handler → pushing logs to web UI
class _SSELogHandler(logging.Handler):
    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            level = record.levelname
            # Clean ANSI escape sequences for web
            import re
            msg_clean = re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', msg)
            
            # _jobs is defined below, but global lookup works in emit
            global _jobs
            if '_jobs' in globals():
                for j_id, job in _jobs.items():
                    if job.get("status") in ("parsing", "running", "queued"):
                        job["queue"].put({"type": "log", "level": level, "message": msg_clean})
        except Exception:
            pass

_sse_handler = _SSELogHandler()
_sse_handler.setLevel(logging.INFO)
_sse_handler.setFormatter(_plain_fmt)
_sse_handler.addFilter(_CDEFilter())

# Root logger — attach handlers
logging.basicConfig(level=logging.INFO, handlers=[_file_handler, _stream_handler, _sse_handler])

# Silence noisy third-party loggers from terminal (they still go to file)
logging.getLogger("watchfiles").setLevel(logging.WARNING)
logging.getLogger("uvicorn.access").setLevel(logging.WARNING)   # HTTP requests → file only
logging.getLogger("uvicorn.error").setLevel(logging.INFO)       # server errors still show
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logging.getLogger("asyncio").setLevel(logging.ERROR)            # socket.send exceptions → file only

logger = logging.getLogger("CDE.API")

app = FastAPI(
    title="Cyber Data Engine API",
    description="Full production API for Cyber Data Engine v1.0.0",
    version="4.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

app.add_middleware(
    CORSMiddleware,
    # TASK-3.3 FIX: Wildcard + credentials is a CORS spec violation and security risk.
    # Restricting to localhost origins only — this is a local dev tool, not a public API.
    allow_origins=[
        "http://localhost:59919",
        "http://127.0.0.1:59919",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Requested-With"],
)

# ─────────────────────────────────────────────────────────────────────────────
# Instant Ctrl+C shutdown  — kills process regardless of background threads
# ─────────────────────────────────────────────────────────────────────────────

# INSTANT SHUTDOWN — Force-kill the process on SIGINT (Ctrl+C).
# Bypasses Python's normal thread cleanup which can hang if ThreadPoolExecutor
# threads are blocked on I/O.
def _instant_shutdown(sig, frame):  # noqa
    """Force-kill the process immediately on SIGINT (Ctrl+C)."""
    print("\n[CDE] ⚡ Ctrl+C detected — shutting down instantly...", flush=True)
    os._exit(0)  # bypasses atexit / threading cleanup — immediate

signal.signal(signal.SIGINT,  _instant_shutdown)
signal.signal(signal.SIGTERM, _instant_shutdown)

# ─────────────────────────────────────────────────────────────────────────────
# Global state
# ─────────────────────────────────────────────────────────────────────────────

# Pipeline worker pool
_executor = ThreadPoolExecutor(max_workers=4)

# job_id → {"status", "progress", "cancelled", "records_ok", "records_fail", "queue": Queue}
_jobs: dict[str, dict] = {}

# In-memory stats (lost on restart; disk files persist)
_stats = {
    "files": 0, "chunks": 0, "ok": 0, "fail": 0,
    "schema_counts": {s.value: 0 for s in DataSchema},
    "provider_counts": {},
}

_rag = RAGProcessor(chunk_size=1200, overlap=150)


# ─────────────────────────────────────────────────────────────────────────────
# Pydantic models
# ─────────────────────────────────────────────────────────────────────────────

class ProviderCreateRequest(BaseModel):
    name: str
    provider_type: str = "ollama"
    endpoint: str = "http://localhost:11434/api/generate"
    model: str = "llama3"
    api_key: str = ""
    temperature: float = 0.15
    max_tokens: int = 8000
    timeout: int = 180
    max_retries: int = 3
    enabled: bool = True
    preferred_schemas: list[str] = []

class PipelineRunRequest(BaseModel):
    training_goal: str = "general_cyber_assistant"
    routing_strategy: str = "primary_fallback"
    force_schema: str = "Auto-detect"
    chunk_size: int = 3500
    overlap: int = 400
    min_quality: float = 0.35
    multi_schema: bool = True
    max_schemas: int = 3


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _all_alpaca_lines() -> list[str]:
    """Stream lines from disk — O(1) memory regardless of file size."""
    master = OUTPUT_DIR / "all_records.jsonl"
    if not master.exists():
        return []
    lines = []
    with open(master, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
    return lines


def _stream_alpaca_lines():
    """Generator version — never loads full file. Use for streaming exports."""
    master = OUTPUT_DIR / "all_records.jsonl"
    if not master.exists():
        return
    with open(master, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                yield stripped


def _all_rich_lines() -> list[str]:
    """Stream rich lines from disk — O(1) memory regardless of file size."""
    master = OUTPUT_DIR / "all_rich_records.jsonl"
    if not master.exists():
        return []
    lines = []
    with open(master, "r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            stripped = line.strip()
            if stripped:
                lines.append(stripped)
    return lines

def _job_send(job_id: str, event_type: str, data: dict):
    """Push an SSE event into the job's queue."""
    job = _jobs.get(job_id)
    if job:
        job["queue"].put({"type": event_type, "data": data})


# ─────────────────────────────────────────────────────────────────────────────
# Pipeline worker (runs in ThreadPool)
# ─────────────────────────────────────────────────────────────────────────────

def _parse_and_classify_sync(job_id: str, file_bytes: bytes, filename: str, cfg: PipelineRunRequest):
    _job_send(job_id, "status", {"message": f"Parsing {filename}…", "progress": 0.05})

    parser    = FileParser(chunk_size=cfg.chunk_size, overlap=cfg.overlap)
    file_io   = io.BytesIO(file_bytes)
    text      = parser.read(file_io, filename)

    if is_cached(text):
        _job_send(job_id, "warning", {"message": f"⏭ {filename} already cached — skipped."})
        return None, None, None, True

    chunks = parser.chunk(text)
    _job_send(job_id, "status", {"message": f"Parsed into {len(chunks)} chunks", "progress": 0.15})
    
    classifier = ContentClassifier()
    preview    = text[:3000]
    cls        = classifier.classify(filename, preview)

    if cfg.force_schema != "Auto-detect":
        cls.schema = DataSchema(cfg.force_schema)

    _job_send(job_id, "classification", {
        "schema": cls.schema.value,
        "task_type": cls.task_type.value,
        "confidence": cls.confidence,
        "chunks": len(chunks),
    })
    
    return chunks, cls, text, False


async def _run_pipeline_worker(
    job_id: str,
    file_bytes: bytes,
    filename: str,
    cfg: PipelineRunRequest,
):
    """Background worker: parse → classify → generate → save."""
    global _stats
    job = _jobs[job_id]

    try:
        job["status"] = "parsing"

        # Offload parsing to ThreadPool to avoid blocking the event loop
        loop = asyncio.get_running_loop()
        chunks, cls, text, is_cached_file = await loop.run_in_executor(
            _executor, 
            _parse_and_classify_sync, 
            job_id, file_bytes, filename, cfg
        )

        if is_cached_file:
            job["status"] = "complete"
            _job_send(job_id, "complete", {"records_ok": 0, "records_fail": 0, "message": "File already processed."})
            return

        _stats["files"] += 1
        _stats["chunks"] += len(chunks)

        # Build items
        all_items = [(c, filename, cls) for c in chunks]

        # Providers
        providers = load_providers()
        active    = [p for p in providers if p.enabled]
        if not active:
            raise RuntimeError("No enabled LLM providers configured.")

        gateway   = ModelGateway(providers=active, strategy=RoutingStrategy(cfg.routing_strategy))
        generator = make_multi_schema_generator(
            gateway,
            enabled=cfg.multi_schema,
            max_schemas=cfg.max_schemas,
            training_goal=cfg.training_goal,
            min_quality=cfg.min_quality,
        )

        total = len(all_items)
        ok_count = 0
        fail_count = 0

        async for completed, total_chunks, mresult in generator.generate_stream(all_items):
            # ── Cancel check ──────────────────────────────────
            if job.get("cancelled"):
                _job_send(job_id, "cancelled", {"message": "⛔ Pipeline cancelled by user."})
                job["status"] = "cancelled"
                return
            # ─────────────────────────────────────────────────

            pct = 0.15 + (completed / max(total_chunks, 1)) * 0.80

            _job_send(job_id, "progress", {
                "progress": round(pct, 3),
                "chunk": completed + 1,
                "total": total_chunks,
                "file": mresult.source_file,
                "schema": mresult.primary_schema,
                "threat": mresult.threat_level,
                "records": mresult.total_records,
            })

            if mresult.results:
                for res in mresult.results:
                    if res.ok:
                        append_to_output(filename, res.alpaca_lines, is_rich=False)
                        if res.rich_line:
                            append_to_output(filename, [res.rich_line], is_rich=True)

                        _stats["ok"] += res.record_count
                        ok_count += res.record_count
                        sc = _stats["schema_counts"]
                        sc[res.schema_used] = sc.get(res.schema_used, 0) + res.record_count
                        pc = _stats["provider_counts"]
                        pc[res.provider] = pc.get(res.provider, 0) + res.record_count

                        _job_send(job_id, "record", {
                            "schema": res.schema_used,
                            "provider": res.provider,
                            "quality": res.quality,
                            "count": res.record_count,
                        })
            else:
                fail_count += 1
                _stats["fail"] += 1

        # Cache it ONLY if it reached the end without crashing AND produced data
        if ok_count > 0:
            add_to_cache(text)
        else:
            _job_send(job_id, "warning", {"message": "No valid records produced. File will NOT be cached."})

        job["status"] = "complete"
        job["records_ok"] = ok_count
        job["records_fail"] = fail_count
        _job_send(job_id, "complete", {
            "records_ok": ok_count,
            "records_fail": fail_count,
            "message": f"✅ Pipeline done — {ok_count} records generated.",
        })

    except Exception as exc:
        logger.exception(f"Pipeline job {job_id} failed: {exc}")
        job["status"] = "error"
        _job_send(job_id, "error", {"message": str(exc)})
    finally:
        job["queue"].put(None)  # Signal end of stream
        # Schedule cleanup to prevent memory leak
        async def _cleanup_job():
            await asyncio.sleep(300) # 5 mins TTL
            _jobs.pop(job_id, None)
        asyncio.create_task(_cleanup_job())


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Health
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/health", tags=["System"])
async def health():
    return {"status": "ok", "service": "Cyber Data Engine v1.0.0", "timestamp": time.time()}


@app.get("/api/v1/stats", tags=["System"])
async def get_stats():
    alpaca_count = len(_all_alpaca_lines())
    rich_count   = len(_all_rich_lines())
    return {**_stats, "alpaca_total": alpaca_count, "rich_total": rich_count}


@app.post("/api/v1/cache/clear", tags=["System"])
async def clear_cache():
    from backend.core.state_manager import CACHE_FILE
    if CACHE_FILE.exists():
        CACHE_FILE.write_text("{}")
    return {"message": "Cache cleared."}


@app.post("/api/v1/pipeline/cancel/{job_id}", tags=["Pipeline"])
async def cancel_pipeline(job_id: str):
    """Cancel a running pipeline job."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    if job["status"] not in ("parsing", "running", "queued"):
        return {"message": f"Job is already {job['status']} — nothing to cancel."}
    job["cancelled"] = True
    job["status"] = "cancelling"
    return {"message": f"Cancel signal sent to job {job_id[:8]}…"}


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Providers
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/providers", tags=["Providers"])
async def list_providers():
    providers = load_providers()
    return [
        {
            "name": p.name, "provider_type": p.provider_type.value,
            "endpoint": p.endpoint, "model": p.model,
            "temperature": p.temperature, "max_tokens": p.max_tokens,
            "timeout": p.timeout, "enabled": p.enabled,
            "preferred_schemas": p.preferred_schemas,
        }
        for p in providers
    ]


@app.post("/api/v1/providers", tags=["Providers"])
async def add_provider(req: ProviderCreateRequest):
    providers = load_providers()
    if any(p.name == req.name for p in providers):
        raise HTTPException(status_code=409, detail=f"Provider '{req.name}' already exists.")
    new_p = ProviderConfig(
        name=req.name, provider_type=ProviderType(req.provider_type),
        endpoint=req.endpoint, model=req.model, api_key=req.api_key,
        temperature=req.temperature, max_tokens=req.max_tokens,
        timeout=req.timeout, max_retries=req.max_retries,
        enabled=req.enabled, preferred_schemas=req.preferred_schemas,
    )
    providers.append(new_p)
    save_providers(providers)
    return {"message": f"Provider '{req.name}' added.", "name": req.name}


@app.put("/api/v1/providers/{name}", tags=["Providers"])
async def update_provider(name: str, req: ProviderCreateRequest):
    providers = load_providers()
    for i, p in enumerate(providers):
        if p.name == name:
            providers[i] = ProviderConfig(
                name=req.name, provider_type=ProviderType(req.provider_type),
                endpoint=req.endpoint, model=req.model, api_key=req.api_key,
                temperature=req.temperature, max_tokens=req.max_tokens,
                timeout=req.timeout, max_retries=req.max_retries,
                enabled=req.enabled, preferred_schemas=req.preferred_schemas,
            )
            save_providers(providers)
            return {"message": f"Provider '{name}' updated."}
    raise HTTPException(status_code=404, detail=f"Provider '{name}' not found.")


@app.delete("/api/v1/providers/{name}", tags=["Providers"])
async def delete_provider(name: str):
    providers = load_providers()
    before = len(providers)
    providers = [p for p in providers if p.name != name]
    if len(providers) == before:
        raise HTTPException(status_code=404, detail=f"Provider '{name}' not found.")
    save_providers(providers)
    return {"message": f"Provider '{name}' deleted."}


@app.post("/api/v1/providers/ping", tags=["Providers"])
async def ping_providers():
    providers = load_providers()
    if not providers:
        return {}
    gw = ModelGateway(providers)
    return await gw.health_check_all()


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Pipeline
# ─────────────────────────────────────────────────────────────────────────────

@app.post("/api/v1/pipeline/run", tags=["Pipeline"])
async def run_pipeline(
    file: UploadFile = File(...),
    training_goal: str = Form("general_cyber_assistant"),
    routing_strategy: str = Form("primary_fallback"),
    force_schema: str = Form("Auto-detect"),
    chunk_size: int = Form(3500),
    overlap: int = Form(400),
    min_quality: float = Form(0.35),
    multi_schema: bool = Form(True),
    max_schemas: int = Form(3),
):
    """Upload a file and launch the LLM data-generation pipeline."""
    if not file.filename:
        raise HTTPException(status_code=400, detail="No filename provided.")

    file_bytes = await file.read()
    job_id = str(uuid.uuid4())

    cfg = PipelineRunRequest(
        training_goal=training_goal,
        routing_strategy=routing_strategy,
        force_schema=force_schema,
        chunk_size=chunk_size,
        overlap=overlap,
        min_quality=min_quality,
        multi_schema=multi_schema,
        max_schemas=max_schemas,
    )

    _jobs[job_id] = {
        "status": "queued",
        "filename": file.filename,
        "progress": 0.0,
        "records_ok": 0,
        "records_fail": 0,
        "cancelled": False,
        "queue": Queue(),
    }

    asyncio.create_task(_run_pipeline_worker(job_id, file_bytes, file.filename, cfg))

    return {"job_id": job_id, "filename": file.filename, "status": "queued"}


@app.get("/api/v1/pipeline/stream/{job_id}", tags=["Pipeline"])
async def stream_pipeline(job_id: str):
    """SSE stream for real-time pipeline progress."""
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")

    async def event_generator():
        q: Queue = job["queue"]
        import asyncio
        loop = asyncio.get_running_loop()
        while True:
            try:
                # offload blocking get to a thread to avoid deadlocking the asyncio loop
                item = await loop.run_in_executor(None, q.get, True, 30)
                if item is None:  # end of stream
                    try:
                        yield "data: {\"type\": \"done\"}\n\n"
                    except (BrokenPipeError, ConnectionResetError, GeneratorExit):
                        pass
                    break
                payload = json.dumps(item, ensure_ascii=False)
                try:
                    yield f"data: {payload}\n\n"
                except (BrokenPipeError, ConnectionResetError, GeneratorExit):
                    # Client disconnected — stop streaming silently
                    logger.debug(f"SSE client disconnected for job {job_id[:8]}")
                    break
            except Empty:
                try:
                    yield ": keepalive\n\n"
                except (BrokenPipeError, ConnectionResetError, GeneratorExit):
                    break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@app.get("/api/v1/pipeline/status/{job_id}", tags=["Pipeline"])
async def get_job_status(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found.")
    return {k: v for k, v in job.items() if k != "queue"}


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Records Viewer
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/records", tags=["Records"])
async def get_records(
    page: int = 1,
    page_size: int = 10,
    search: str = "",
    task_type: str = "",
    schema: str = "",
):
    lines = _all_alpaca_lines()
    if search:
        lines = [l for l in lines if search.lower() in l.lower()]
    if task_type:
        def _match_task(ln):
            try: return json.loads(ln).get("task_type") == task_type
            except: return False
        lines = [l for l in lines if _match_task(l)]
    if schema:
        def _match_schema(ln):
            try: return json.loads(ln).get("schema_type") == schema
            except: return False
        lines = [l for l in lines if _match_schema(l)]

    total = len(lines)
    start = (page - 1) * page_size
    page_lines = lines[start:start + page_size]

    records = []
    for ln in page_lines:
        try: records.append(json.loads(ln))
        except: pass

    return {"total": total, "page": page, "page_size": page_size, "records": records}


# ─────────────────────────────────────────────────────────────────────────────
# Routes — Export
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/export/alpaca", tags=["Export"])
async def export_alpaca(
    add_negatives: bool = True,
    run_mitre_val: bool = True,
    apply_curriculum: bool = True,
):
    lines = _all_alpaca_lines()
    if not lines:
        raise HTTPException(status_code=404, detail="No records yet. Run the pipeline first.")

    final = list(lines)

    if add_negatives:
        neg = NegativeExampleGenerator()
        final = neg.get_as_jsonl() + final

    if run_mitre_val:
        mv = MitreValidator()
        validated = []
        for ln in final:
            try:
                rec = json.loads(ln)
                rec = mv.validate_record(rec)
                validated.append(json.dumps(rec, ensure_ascii=False))
            except:
                validated.append(ln)
        final = validated

    if apply_curriculum:
        final = apply_curriculum_to_jsonl(final)

    content = ("\n".join(final) + "\n").encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/jsonl",
        headers={"Content-Disposition": "attachment; filename=cyber_alpaca.jsonl"},
    )


@app.get("/api/v1/export/llama3", tags=["Export"])
async def export_llama3(
    add_negatives: bool = True,
    apply_curriculum: bool = True,
):
    lines = _all_alpaca_lines()
    if not lines:
        raise HTTPException(status_code=404, detail="No records yet.")

    final = list(lines)
    if add_negatives:
        neg = NegativeExampleGenerator()
        final = neg.get_as_jsonl() + final
    if apply_curriculum:
        final = apply_curriculum_to_jsonl(final)

    llama3 = format_dataset(final)
    content = ("\n".join(llama3) + "\n").encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/jsonl",
        headers={"Content-Disposition": "attachment; filename=cyber_llama3.jsonl"},
    )


@app.get("/api/v1/export/rich", tags=["Export"])
async def export_rich():
    lines = _all_rich_lines()
    if not lines:
        raise HTTPException(status_code=404, detail="No rich records yet.")
    content = ("\n".join(lines) + "\n").encode("utf-8")
    return StreamingResponse(
        io.BytesIO(content),
        media_type="application/jsonl",
        headers={"Content-Disposition": "attachment; filename=cyber_rich.jsonl"},
    )



# ─────────────────────────────────────────────────────────────────────────────
# v1.0.0 addition: Audit & Quality Endpoints
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/api/v1/audit")
async def get_audit_report():
    """
    Run a comprehensive quality audit on the latest generated dataset.
    Returns schema distribution, quality metrics, hallucination warnings.
    """
    from shared_lib.dataset_auditor import DatasetAuditor
    auditor = DatasetAuditor()
    reports = []

    # Audit all JSONL files in output directory
    if OUTPUT_DIR.exists():
        for f in sorted(OUTPUT_DIR.glob("*.jsonl")):
            report = auditor.audit_file(str(f))
            reports.append(report.to_dict())

    if not reports:
        return JSONResponse({"status": "no_data", "message": "No output files found to audit."})

    # Aggregate summary across all files
    total_records = sum(r["total_records"] for r in reports)
    total_warnings = sum(r["hallucination_warnings"] for r in reports)
    total_low_quality = sum(r["low_quality_records"] for r in reports)
    overall_fallback = (
        sum(r["total_records"] * r["fallback_rate"] for r in reports) / max(total_records, 1)
    )

    return JSONResponse({
        "status": "ok",
        "summary": {
            "total_records":          total_records,
            "hallucination_warnings": total_warnings,
            "low_quality_records":    total_low_quality,
            "overall_fallback_rate":  round(overall_fallback, 4),
            "files_audited":          len(reports),
        },
        "files": reports,
    })


@app.get("/api/v1/quality/report")
async def get_quality_report():
    """
    Return quality statistics for the current session.
    _stats is a plain dict (defined at module level) — no .get_summary() method exists.
    """
    stats = dict(_stats) if isinstance(_stats, dict) else {}
    return JSONResponse({"status": "ok", "quality_report": stats})


@app.get("/api/v1/records/sample")
async def get_sample_records(n: int = 5):
    """
    Return the last N records from the generated dataset as a sample.
    Useful for previewing output quality before downloading.
    """
    if not OUTPUT_DIR.exists():
        return JSONResponse({"status": "no_data", "records": []})

    # Stream files line-by-line — never loads full file into memory.
    # Collect last N lines using a deque of fixed size O(n) not O(file_size).
    from collections import deque
    tail: deque[str] = deque(maxlen=n)
    for f in sorted(OUTPUT_DIR.glob("*_alpaca.jsonl")):
        with open(f, encoding="utf-8", errors="replace") as fh:
            for raw_line in fh:
                stripped = raw_line.strip()
                if stripped:
                    tail.append(stripped)

    records = []
    for line in tail:
        try:
            records.append(json.loads(line))
        except Exception:
            pass

    return JSONResponse({"status": "ok", "count": len(records), "records": records})


# ─────────────────────────────────────────────────────────────────────────────
# Serve the frontend SPA
# ─────────────────────────────────────────────────────────────────────────────

if FRONTEND_DIR.exists():
    app.mount("/", StaticFiles(directory=str(FRONTEND_DIR), html=True), name="frontend")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.main:app", host="0.0.0.0", port=8000, reload=True)
