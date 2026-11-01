"""Subprocess entry point used by analyze_safe(). Reads a JSON job on stdin, writes JSON on stdout.

Progress goes to stderr as 'PROGRESS <n>' lines. Packet contents are never logged.
"""
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[0] = ROOT  # import the package, never sibling modules by bare name


def main() -> None:
    from engine.analyze import analyze
    from engine.loader import CaptureError

    job = json.loads(sys.stdin.read() or "{}")

    def progress(n: int) -> None:
        sys.stderr.write(f"PROGRESS {n}\n")
        sys.stderr.flush()

    try:
        result = analyze(job["path"], job.get("options") or {}, progress)
        payload = {"result": result.to_dict()}
    except CaptureError as exc:
        payload = {"error": exc.code}
    except MemoryError:
        payload = {"error": "internal"}
    except Exception:  # never echo internals or packet data back
        payload = {"error": "internal"}
    sys.stdout.write(json.dumps(payload))
    sys.stdout.flush()


if __name__ == "__main__":
    main()
