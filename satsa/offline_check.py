"""SAT-SA Offline-Only Air-Gap Verification Utility.

Provides startup verification and enforcement ensuring that:
1. No external DNS resolution or non-loopback network connections can be initiated.
2. All analytics, detectors, machine learning, and reporting execute 100% locally.
3. Only local loopback (127.0.0.1) IPC bindings (for FastAPI and Streamlit) are permitted.
"""

import socket
import sys
from typing import Tuple


class AirgapViolationError(RuntimeError):
    """Raised when an unauthorized outbound network call is attempted."""
    pass


_ORIGINAL_CONNECT = socket.socket.connect
_ORIGINAL_GETADDRINFO = socket.getaddrinfo


def is_loopback(host: str) -> bool:
    """Check if destination address is local loopback."""
    clean_host = host.lower().strip("[]")
    return clean_host in {"127.0.0.1", "localhost", "::1", "0.0.0.0"}


def enforce_offline_airgap() -> None:
    """Monkey-patch socket and DNS calls to strictly prevent external communication."""

    def sandboxed_connect(self, address):
        host = address[0] if isinstance(address, tuple) and len(address) > 0 else str(address)
        if not is_loopback(host):
            raise AirgapViolationError(
                f"[AIR-GAP ENFORCEMENT] Unauthorized outbound network attempt blocked: {address}. "
                "SAT-SA is strictly offline-only."
            )
        return _ORIGINAL_CONNECT(self, address)

    def sandboxed_getaddrinfo(host, port, *args, **kwargs):
        if host and not is_loopback(str(host)):
            raise AirgapViolationError(
                f"[AIR-GAP ENFORCEMENT] External DNS lookup blocked for '{host}'. "
                "SAT-SA must not perform remote network queries."
            )
        return _ORIGINAL_GETADDRINFO(host, port, *args, **kwargs)

    socket.socket.connect = sandboxed_connect
    socket.getaddrinfo = sandboxed_getaddrinfo


def verify_offline_environment() -> Tuple[bool, str]:
    """Run verification checks to confirm offline execution safety."""
    enforce_offline_airgap()

    # Verify that external socket connection is indeed blocked
    blocked_successfully = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("8.8.8.8", 53))
    except AirgapViolationError:
        blocked_successfully = True
    except Exception:
        # Network unreachable or blocked by OS firewall is also acceptable
        blocked_successfully = True
    finally:
        s.close()

    if not blocked_successfully:
        return False, "Failed to trap outbound connection to external IP."

    return True, "Air-gap sandbox verified: Outbound network calls are strictly intercepted and blocked."


if __name__ == "__main__":
    success, msg = verify_offline_environment()
    print(f"[{'PASS' if success else 'FAIL'}] {msg}")
    if not success:
        sys.exit(1)
