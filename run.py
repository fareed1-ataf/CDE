"""
run.py — Cyber Data Engine v1.0.0 launcher
Starts uvicorn with instant Ctrl+C shutdown support.
"""
import os
import sys
import signal

def main():
    # Enable ANSI colors on Windows terminal
    os.system("")  # activates VT100 on Windows CMD/PowerShell

    try:
        import uvicorn
    except ImportError:
        print("[CDE] ERROR: uvicorn not installed. Run: pip install uvicorn[standard]")
        sys.exit(1)

    print("\033[96m")
    print("  ================================================")
    print("       ⚡  CYBER DATA ENGINE  v1.0.0             ")
    print("       http://localhost:8080                   ")
    print("       Press Ctrl+C once to stop               ")
    print("  ================================================")
    print("\033[0m")

    config = uvicorn.Config(
        "backend.main:app",
        host="0.0.0.0",
        port=8080,
        reload=False,           # disable reload so we control the process fully
        log_level="warning",    # uvicorn logs go to WARNING only (CDE handles its own)
        timeout_graceful_shutdown=0,  # no waiting on shutdown
    )

    server = uvicorn.Server(config)

    # Override uvicorn's signal handler AFTER server is created
    def _shutdown(sig, frame):
        print("\n\033[91m[CDE] ⚡ Ctrl+C — shutting down instantly...\033[0m", flush=True)
        os._exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    server.run()


if __name__ == "__main__":
    main()
