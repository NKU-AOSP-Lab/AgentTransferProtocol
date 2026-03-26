import threading
import time
from dataclasses import dataclass, field


@dataclass
class SecurityMetrics:
    ats_pass: int = 0
    ats_fail: int = 0
    ats_neutral: int = 0
    atk_pass: int = 0
    atk_fail: int = 0
    replay_blocked: int = 0
    credential_pass: int = 0
    credential_fail: int = 0


@dataclass
class MessageMetrics:
    received: int = 0        # Total messages received by this server
    delivered_local: int = 0  # Delivered to local agents
    forwarded: int = 0       # Forwarded to remote servers
    delivery_success: int = 0 # Remote delivery succeeded
    delivery_failed: int = 0  # Remote delivery failed (temporary)
    bounced: int = 0         # Permanently failed


class ServerMetrics:
    """Thread-safe server metrics collector."""

    def __init__(self):
        self._lock = threading.Lock()
        self._start_time = time.time()
        self.security = SecurityMetrics()
        self.messages = MessageMetrics()

    @property
    def uptime_seconds(self) -> int:
        return int(time.time() - self._start_time)

    def record_ats(self, status: str) -> None:
        """Record ATS verification result. status: 'PASS', 'FAIL', 'NEUTRAL'"""
        with self._lock:
            if status == "PASS":
                self.security.ats_pass += 1
            elif status == "FAIL":
                self.security.ats_fail += 1
            else:
                self.security.ats_neutral += 1

    def record_atk(self, passed: bool) -> None:
        with self._lock:
            if passed:
                self.security.atk_pass += 1
            else:
                self.security.atk_fail += 1

    def record_replay_blocked(self) -> None:
        with self._lock:
            self.security.replay_blocked += 1

    def record_credential_passed(self) -> None:
        with self._lock:
            self.security.credential_pass += 1

    def record_credential_failed(self) -> None:
        with self._lock:
            self.security.credential_fail += 1

    def record_message_received(self) -> None:
        with self._lock:
            self.messages.received += 1

    def record_local_delivery(self) -> None:
        with self._lock:
            self.messages.delivered_local += 1

    def record_forwarded(self) -> None:
        with self._lock:
            self.messages.forwarded += 1

    def record_delivery_success(self) -> None:
        with self._lock:
            self.messages.delivery_success += 1

    def record_delivery_failed(self) -> None:
        with self._lock:
            self.messages.delivery_failed += 1

    def record_bounced(self) -> None:
        with self._lock:
            self.messages.bounced += 1

    def to_dict(self) -> dict:
        """Snapshot of all metrics."""
        with self._lock:
            return {
                "uptime": self.uptime_seconds,
                "messages": {
                    "received": self.messages.received,
                    "delivered_local": self.messages.delivered_local,
                    "forwarded": self.messages.forwarded,
                    "delivery_success": self.messages.delivery_success,
                    "delivery_failed": self.messages.delivery_failed,
                    "bounced": self.messages.bounced,
                },
                "security": {
                    "ats_pass": self.security.ats_pass,
                    "ats_fail": self.security.ats_fail,
                    "ats_neutral": self.security.ats_neutral,
                    "atk_pass": self.security.atk_pass,
                    "atk_fail": self.security.atk_fail,
                    "replay_blocked": self.security.replay_blocked,
                    "credential_pass": self.security.credential_pass,
                    "credential_fail": self.security.credential_fail,
                },
            }
