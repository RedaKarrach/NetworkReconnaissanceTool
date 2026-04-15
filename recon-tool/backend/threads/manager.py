"""
threads/manager.py
------------------
Centralized manager for all background scan / attack threads.

Each operation gets:
  • A unique thread_id
  • A threading.Event() stop flag so it can be cleanly halted via the API
  • An entry in the global registry so we can look it up later
"""
import uuid
import threading
from typing import Callable, Optional


# Global registry: thread_id → { thread, stop_flag, meta }
_registry: dict = {}
_lock = threading.Lock()


def start_thread(target: Callable, args: tuple = (), name: str = "") -> str:
    """
    Start a background daemon thread and register it.

    Parameters
    ----------
    target : the function to run in the thread
    args   : positional args to pass (stop_flag will be prepended if needed)
    name   : human-readable label for the thread

    Returns
    -------
    thread_id : str UUID you can use to stop this thread later
    """
    thread_id = str(uuid.uuid4())
    stop_flag = threading.Event()

    # Convention: every threaded function's first positional arg is stop_flag.
    # We prepend it here so callers don't have to manage it.
    full_args = (stop_flag,) + args

    thread = threading.Thread(
        target=target,
        args=full_args,
        name=name or thread_id,
        daemon=True     # die automatically when the main process exits
    )

    with _lock:
        _registry[thread_id] = {
            "thread": thread,
            "stop_flag": stop_flag,
            "name": name,
            "status": "running"
        }

    thread.start()
    return thread_id


def stop_thread(thread_id: str) -> bool:
    """
    Signal a running thread to stop via its Event flag.

    Returns True if found and signalled, False if not found.
    """
    with _lock:
        entry = _registry.get(thread_id)
        if entry is None:
            return False
        entry["stop_flag"].set()
        entry["status"] = "stopping"
        return True


def get_status(thread_id: str) -> Optional[dict]:
    """Return metadata for a thread, or None if unknown."""
    with _lock:
        entry = _registry.get(thread_id)
        if entry is None:
            return None
        return {
            "thread_id": thread_id,
            "name": entry["name"],
            "alive": entry["thread"].is_alive(),
            "status": entry["status"]
        }


def list_threads() -> list:
    """Return status of all registered threads."""
    with _lock:
        return [
            {
                "thread_id": tid,
                "name": v["name"],
                "alive": v["thread"].is_alive(),
                "status": v["status"]
            }
            for tid, v in _registry.items()
        ]


def cleanup_dead_threads():
    """Remove finished threads from the registry."""
    with _lock:
        dead = [tid for tid, v in _registry.items()
                if not v["thread"].is_alive()]
        for tid in dead:
            del _registry[tid]
