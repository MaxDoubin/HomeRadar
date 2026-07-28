"""Launch the frozen Home Radar backend and verify its health endpoint.

This script is intentionally stdlib-only so GitHub Actions can run it on every
installer platform immediately after PyInstaller finishes.
"""
from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def wait_for_health(port: int, process: subprocess.Popen[str], timeout: float) -> None:
    deadline = time.monotonic() + timeout
    url = f"http://127.0.0.1:{port}/health"
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            stdout, stderr = process.communicate(timeout=5)
            raise RuntimeError(
                f"Packaged backend exited with code {process.returncode}.\n"
                f"--- stdout ---\n{stdout}\n--- stderr ---\n{stderr}"
            )
        try:
            with urllib.request.urlopen(url, timeout=1.5) as response:
                if 200 <= response.status < 500:
                    return
        except (urllib.error.URLError, TimeoutError) as error:
            last_error = error
        time.sleep(0.25)
    raise TimeoutError(f"Backend did not become healthy within {timeout}s: {last_error}")


def terminate(process: subprocess.Popen[str]) -> None:
    """Stop the complete frozen-process tree on every supported platform."""
    if process.poll() is not None:
        return

    if os.name == "nt":
        # A PyInstaller one-file executable uses a bootloader parent and an
        # application child. Terminating only the parent can leave the child
        # holding SQLite files open, so stop the complete Windows process tree.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=15,
        )
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        return

    process.terminate()
    try:
        process.wait(timeout=8)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def cleanup_data_dir(path: Path, attempts: int = 20, delay: float = 0.5) -> None:
    """Best-effort removal of temporary data after all child processes stop."""
    last_error: OSError | None = None
    for _attempt in range(attempts):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError as error:
            last_error = error
            time.sleep(delay)
    # A successful health check must not be converted into a product failure by
    # runner-specific antivirus/indexer file locks in the disposable temp tree.
    print(f"Warning: could not remove temporary smoke-test data: {last_error}", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("executable", type=Path)
    parser.add_argument("--timeout", type=float, default=45.0)
    args = parser.parse_args()

    executable = args.executable.resolve()
    if not executable.is_file():
        raise FileNotFoundError(f"Packaged backend not found: {executable}")

    port = free_port()
    temp_dir = tempfile.mkdtemp(prefix="homeradar-smoke-")
    try:
        data_dir = Path(temp_dir)
        environment = {
            **os.environ,
            "HOMERADAR_API_HOST": "127.0.0.1",
            "HOMERADAR_API_PORT": str(port),
            "HOMERADAR_DATA_DIR": str(data_dir),
            "HOMERADAR_DB_PATH": str(data_dir / "homeradar.db"),
            "HOMERADAR_BACKUP_DIR": str(data_dir / "backups"),
            "HOMERADAR_DNS_ENABLED": "false",
            "HOMERADAR_TRAFFIC_MONITOR_ENABLED": "false",
            "HOMERADAR_BLOCKLIST_AUTO_UPDATE": "false",
            "PYTHONUNBUFFERED": "1",
        }
        process = subprocess.Popen(
            [str(executable)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        try:
            wait_for_health(port, process, args.timeout)
            print(f"Packaged backend is healthy on 127.0.0.1:{port}")
        finally:
            terminate(process)
    finally:
        cleanup_data_dir(Path(temp_dir))

    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"Packaged backend smoke test failed: {error}", file=sys.stderr)
        raise
