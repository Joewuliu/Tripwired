"""The live event stream: one small event per step of a scan, for the dashboard.

Events are public: anything the stream shows, anyone with the address sees. So an event carries only
what the report already shows publicly (defanged addresses, the verdict and its plain sentences) and
a masked sender (•••-4412). Never the number, never the sender's hash, never page text. Sender data
is held in memory for this stream only; stored reports have none.

The bus keeps the most recent events so a dashboard that connects mid-scan still has something to
draw, and so a browser that reconnects can ask for what it missed (Last-Event-ID).
"""
import asyncio
import json
import re
from collections import deque
from collections.abc import Awaitable, Callable
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import AsyncIterator

KINDS = ("scan_started", "check_done", "screenshot_ready", "verdict", "reply_sent", "guardian_alerted", "scan_failed")

BACKLOG = 300
REPLAY_ON_CONNECT = 60  # what a fresh connection is given, newest last
MAX_SUBSCRIBERS = 64
SUBSCRIBER_QUEUE = 200  # a reader this far behind is dropped; it reconnects with Last-Event-ID
HEARTBEAT_S = 15.0

_HASH = re.compile(r"[0-9a-f]{16}")
_LAST4 = re.compile(r"\d{4}")


@dataclass(frozen=True)
class Sender:
    """Who asked, in the only two pieces the gateway keeps. Only `mask` ever leaves this process."""

    hash: str
    last4: str | None

    @property
    def mask(self) -> str:
        return f"•••-{self.last4}" if self.last4 else "•••"


def sender_from(raw: dict | None) -> Sender | None:
    """A Sender from the gateway's {hash, last4}, or None if it is absent or not shaped like one."""
    if not isinstance(raw, dict):
        return None
    h, last4 = raw.get("hash"), raw.get("last4")
    if not isinstance(h, str) or not _HASH.fullmatch(h):
        return None
    if last4 is not None and not (isinstance(last4, str) and _LAST4.fullmatch(last4)):
        return None
    return Sender(hash=h, last4=last4)


@dataclass(frozen=True)
class Event:
    id: int  # increases by one per event; the SSE id
    at: str  # ISO 8601, UTC
    scan: str  # the 12-hex scan id every event of one scan shares
    kind: str  # one of KINDS
    sender: str | None  # the mask (•••-4412) or None for a scan started from the website
    data: dict


class EventBus:
    def __init__(self, backlog: int = BACKLOG, max_subscribers: int = MAX_SUBSCRIBERS):
        self._events: deque[Event] = deque(maxlen=backlog)
        self._next_id = 1
        self._subscribers: set[asyncio.Queue] = set()
        self._max_subscribers = max_subscribers

    def publish(self, scan: str, kind: str, data: dict, sender: Sender | None = None) -> Event:
        if kind not in KINDS:
            raise ValueError(f"unknown event kind {kind!r}")
        event = Event(
            id=self._next_id,
            at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z",
            scan=scan, kind=kind, sender=sender.mask if sender else None, data=data,
        )
        self._next_id += 1
        self._events.append(event)
        for queue in list(self._subscribers):
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                self._subscribers.discard(queue)  # too slow to keep up: it can reconnect and catch up
                queue.get_nowait()  # make room for the end marker, which ends its stream
                queue.put_nowait(None)
        return event

    def since(self, last_id: int) -> list[Event]:
        return [e for e in self._events if e.id > last_id]

    def recent(self, count: int = REPLAY_ON_CONNECT) -> list[Event]:
        return list(self._events)[-count:]

    def has_room(self) -> bool:
        return len(self._subscribers) < self._max_subscribers

    async def stream(
        self, last_id: int | None, disconnected: Callable[[], Awaitable[bool]], heartbeat_s: float = HEARTBEAT_S
    ) -> AsyncIterator[str]:
        """SSE frames: first what was missed (or the recent backlog), then live events and heartbeats."""
        queue: asyncio.Queue = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        # Subscribe before reading the backlog, so nothing published in between is lost.
        self._subscribers.add(queue)
        try:
            backlog = self.recent() if last_id is None else self.since(last_id)
            sent = max((e.id for e in backlog), default=last_id or 0)
            yield "retry: 3000\n\n"
            for event in backlog:
                yield frame(event)
            while not await disconnected():
                try:
                    event = await asyncio.wait_for(queue.get(), heartbeat_s)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                if event is None:
                    return
                if event.id > sent:
                    sent = event.id
                    yield frame(event)
        finally:
            self._subscribers.discard(queue)


def frame(event: Event) -> str:
    """One Server-Sent Event: id, a named event, and the event as one line of JSON."""
    return f"id: {event.id}\nevent: {event.kind}\ndata: {json.dumps(asdict(event), ensure_ascii=False)}\n\n"


bus = EventBus()
