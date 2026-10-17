
#!/usr/bin/env python3

import hashlib
import os
import queue
import time
from pathlib import Path

import requests
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# =========================
# CONFIGURATION
# =========================

ROOT = Path.home().resolve()

VT_KEY = os.environ.get("VT_KEY", "").strip()

SHUFFLE_WEBHOOK_URL = os.environ.get(
    "SHUFFLE_WEBHOOK_URL", ""
).strip()

VT_API = "https://www.virustotal.com/api/v3"

MAX_SIZE = 32 * 1024 * 1024
MIN_SECONDS_BETWEEN_VT_CALLS = 17

# Exclude potentially sensitive files
BLOCKED_EXT = {
    ".pem", ".key", ".p12", ".pfx",
    ".kdbx", ".db", ".sqlite",
    ".csv", ".pdf", ".docx",
    ".xlsx", ".env", ".json"
}

BLOCKED_WORDS = (
    "password", "secret", "token",
    "credential", "private", "backup"
)

work_queue = queue.Queue()
seen = set()
last_vt_request = 0.0


# =========================
# FILE FILTER
# =========================

def is_allowed(path):
    path = Path(path)

    try:
        rel = path.relative_to(ROOT)

        if any(part.startswith(".") for part in rel.parts):
            return False

        if any(
            word in path.name.lower()
            for word in BLOCKED_WORDS
        ):
            return False

        if path.suffix.lower() in BLOCKED_EXT:
            return False

        if path.is_symlink() or not path.is_file():
            return False

        path.resolve(strict=True).relative_to(ROOT)

        return True

    except (OSError, ValueError):
        return False


# =========================
# WAIT UNTIL FILE IS READY
# =========================

def wait_until_stable(path):
    path = Path(path)

    for _ in range(30):

        if not is_allowed(path):
            return False

        st = path.stat()

        if st.st_size > MAX_SIZE:
            print(
                f"SKIP (>32 MB): {path}",
                flush=True
            )
            return False

        if (
            st.st_size > 0
            and time.time() - st.st_mtime >= 6
        ):
            time.sleep(2)

            if not is_allowed(path):
                return False

            current = path.stat()

            if (
                current.st_size,
                current.st_mtime_ns
            ) == (
                st.st_size,
                st.st_mtime_ns
            ):
                return True

        time.sleep(2)

    print(
        f"SKIP (not stable): {path}",
        flush=True
    )

    return False


# =========================
# VIRUSTOTAL REQUEST
# =========================

def vt_request(method, endpoint, **kwargs):
    global last_vt_request

    delay = MIN_SECONDS_BETWEEN_VT_CALLS - (
        time.monotonic() - last_vt_request
    )

    if delay > 0:
        time.sleep(delay)

    last_vt_request = time.monotonic()

    return requests.request(
        method,
        VT_API + endpoint,
        headers={"x-apikey": VT_KEY},
        timeout=90,
        **kwargs
    )


# =========================
# CALCULATE SHA256
# =========================

def sha256_of_file(path):
    digest = hashlib.sha256()

    with Path(path).open("rb") as stream:
        for chunk in iter(
            lambda: stream.read(1024 * 1024),
            b""
        ):
            digest.update(chunk)

    return digest.hexdigest()


# =========================
# SEND ALERT TO SHUFFLE
# =========================

def send_to_shuffle(path, sha256, stats):

    # Avoid treating missing results as clean
    if not isinstance(stats, dict) or not all(
        key in stats
        for key in ("malicious", "suspicious")
    ):
        print(
            f"VT STATS MISSING - SKIP TELEGRAM: {path.name}",
            flush=True
        )
        return

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)

    # No detection -> no Telegram notification
    if malicious == 0 and suspicious == 0:
        print(
            f"VT NO DETECTION - SKIP TELEGRAM: {path.name}",
            flush=True
        )
        return

    # Detection ratio
    detected = malicious + suspicious

    scanned = sum(
        int(stats.get(key) or 0)
        for key in (
            "malicious",
            "suspicious",
            "harmless",
            "undetected"
        )
    )

    ratio = f"{detected}/{scanned}"

    # Risk classification
    if malicious >= 5:
        risk = "CRITICAL"

    elif malicious >= 3 or suspicious >= 3:
        risk = "HIGH"

    else:
        risk = "WARNING"

    if not SHUFFLE_WEBHOOK_URL:
        print(
            "SHUFFLE SKIP: SHUFFLE_WEBHOOK_URL not configured",
            flush=True
        )
        return

    description = (
        f"VirusTotal COMPLETED | "
        f"File: {path.name} | "
        f"Detection: {ratio} | "
        f"Risk: {risk} | "
        f"Malicious: {malicious} | "
        f"Suspicious: {suspicious} | "
        f"Undetected: {stats.get('undetected', 0)} | "
        f"SHA256: {sha256}"
    )

    payload = {
        "rule_id": "VT_FILE",
        "severity": 2,
        "pretext": "VirusTotal Result",
        "title": "VirusTotal file analysis completed",
        "text": description,

        "all_fields": {
            "rule": {
                "id": "VT_FILE",
                "level": 5,
                "description": description
            },

            "agent": {
                "name": "ubuntu-victim"
            },

            "data": {
                "srcip": "N/A"
            },

            "syscheck": {
                "path": str(path),
                "sha256_after": sha256
            },

            "virustotal": {
                "status": "completed",
                "stats": stats,
                "detection_ratio": ratio,
                "risk_level": risk
            }
        }
    }

    try:
        response = requests.post(
            SHUFFLE_WEBHOOK_URL,
            json=payload,
            timeout=20
        )

        if 200 <= response.status_code < 300:
            print(
                f"SHUFFLE SENT: HTTP {response.status_code} "
                f"| {risk} {ratio}",
                flush=True
            )

        else:
            print(
                f"SHUFFLE FAILED: HTTP {response.status_code}",
                flush=True
            )

    except requests.RequestException as exc:
        print(
            f"SHUFFLE ERROR: {type(exc).__name__}",
            flush=True
        )


# =========================
# UPLOAD FILE TO VIRUSTOTAL
# =========================

def scan_new_file(filename):
    path = Path(filename)

    if not wait_until_stable(path):
        return

    st = path.stat()

    signature = (
        str(path),
        st.st_size,
        st.st_mtime_ns
    )

    if signature in seen:
        return

    seen.add(signature)

    print(
        f"UPLOADING: {path}",
        flush=True
    )

    sha256 = sha256_of_file(path)

    with path.open("rb") as stream:

        response = vt_request(
            "POST",
            "/files",
            files={
                "file": (path.name, stream)
            }
        )

    if response.status_code not in (200, 201):
        print(
            f"UPLOAD FAILED: HTTP {response.status_code}",
            flush=True
        )
        return

    analysis_id = response.json()["data"]["id"]

    print(
        "UPLOAD OK; waiting for analysis...",
        flush=True
    )

    # Wait for analysis to complete
    for _ in range(10):

        time.sleep(20)

        result = vt_request(
            "GET",
            "/analyses/" + analysis_id
        )

        if result.status_code != 200:
            print(
                f"ANALYSIS FAILED: HTTP {result.status_code}",
                flush=True
            )
            return

        attrs = result.json().get(
            "data", {}
        ).get(
            "attributes", {}
        )

        if attrs.get("status") != "completed":
            continue

        stats = attrs.get("stats", {})

        print(
            f"COMPLETED {path.name}: "
            f"malicious={stats.get('malicious', 'N/A')}, "
            f"suspicious={stats.get('suspicious', 'N/A')}, "
            f"undetected={stats.get('undetected', 'N/A')}, "
            f"unsupported={stats.get('type-unsupported', 'N/A')}",
            flush=True
        )

        # Send only if VirusTotal reports detections
        send_to_shuffle(
            path,
            sha256,
            stats
        )

        return

    print(
        f"PENDING: {path.name} "
        f"(analysis not completed yet)",
        flush=True
    )


# =========================
# WATCH NEW FILES
# =========================

class NewFileHandler(FileSystemEventHandler):

    def on_created(self, event):
        if not event.is_directory:
            work_queue.put(event.src_path)

    def on_moved(self, event):
        if not event.is_directory:
            work_queue.put(event.dest_path)


# =========================
# MAIN
# =========================

if __name__ == "__main__":

    if not VT_KEY:
        raise SystemExit(
            "Missing VT_KEY environment variable"
        )

    observer = Observer()

    observer.schedule(
        NewFileHandler(),
        str(ROOT),
        recursive=True
    )

    observer.start()

    print(
        f"Watching newly created files in {ROOT} "
        f"(Ctrl+C to stop)",
        flush=True
    )

    try:
        while True:

            filename = work_queue.get()

            try:
                scan_new_file(filename)

            except Exception as exc:
                print(
                    f"ERROR processing {filename}: "
                    f"{type(exc).__name__}",
                    flush=True
                )

            finally:
                work_queue.task_done()

    except KeyboardInterrupt:
        print(
            "\nStopping watcher...",
            flush=True
        )

    finally:
        observer.stop()
        observer.join()
