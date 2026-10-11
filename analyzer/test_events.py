"""The live event stream: ordering, replay, what it may contain, and that it never carries sender data."""
import asyncio
import json

import pytest

import events
import main
from events import EventBus, Sender, frame, sender_from
from test_main import OLD, client, fake_world  # noqa: F401  (fixtures and the fake page world)

HASH = "3f9a1c2e7b4d5a60"
SENDER = {"hash": HASH, "last4": "4412"}


def parse(frames: list[str]) -> list[dict]:
    out = []
    for text in frames:
        for block in text.strip().split("\n\n"):
            data = [line[6:] for line in block.split("\n") if line.startswith("data: ")]
            if data:
                out.append(json.loads(data[0]))
    return out


async def collect(bus, last_id, count, disconnect_after=None):
    """Read `count` frames that carry data from a bus stream, then stop."""
    seen: list[str] = []
    state = {"closed": False}

    async def disconnected() -> bool:
        return state["closed"]

    async for text in bus.stream(last_id, disconnected, heartbeat_s=0.05):
        seen.append(text)
        if sum("data: " in t for t in seen) >= count:
            state["closed"] = True
    return seen


# --- the bus -----------------------------------------------------------------------------------


def test_events_get_increasing_ids_and_a_mask_for_the_sender():
    bus = EventBus()
    a = bus.publish("abc123abc123", "scan_started", {"url": "hxxps://a[.]example"}, Sender(HASH, "4412"))
    b = bus.publish("abc123abc123", "verdict", {"verdict": "dangerous"})
    assert (a.id, b.id) == (1, 2)
    assert a.sender == "•••-4412" and b.sender is None
    assert HASH not in frame(a) and "4412" in frame(a)


def test_an_email_sender_masks_to_dots_only():
    assert Sender(HASH, None).mask == "•••"


def test_the_backlog_is_bounded_and_since_returns_what_was_missed():
    bus = EventBus(backlog=3)
    for i in range(5):
        bus.publish("abc123abc123", "check_done", {"n": i})
    assert [e.id for e in bus.recent()] == [3, 4, 5]
    assert [e.id for e in bus.since(3)] == [4, 5]


def test_an_unknown_kind_is_a_programming_error():
    with pytest.raises(ValueError):
        EventBus().publish("abc123abc123", "page_text_dump", {})


@pytest.mark.parametrize(
    "raw",
    [None, {}, {"hash": "short", "last4": "4412"}, {"hash": HASH, "last4": "44a2"}, {"hash": HASH.upper(), "last4": None},
     {"hash": HASH, "last4": 4412}, "+19195554412"],
)
def test_a_malformed_sender_is_ignored_not_trusted(raw):
    assert sender_from(raw) is None


def test_a_well_formed_sender_is_accepted():
    assert sender_from(SENDER) == Sender(HASH, "4412")
    assert sender_from({"hash": HASH, "last4": None}) == Sender(HASH, None)


# --- the stream ------------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_a_new_viewer_gets_the_recent_events_then_live_ones():
    bus = EventBus()
    bus.publish("abc123abc123", "scan_started", {"n": 1})
    bus.publish("abc123abc123", "check_done", {"n": 2})

    async def later():
        await asyncio.sleep(0.02)
        bus.publish("abc123abc123", "verdict", {"n": 3})

    task = asyncio.create_task(later())
    got = parse(await collect(bus, None, 3))
    await task
    assert [e["id"] for e in got] == [1, 2, 3]
    assert [e["kind"] for e in got] == ["scan_started", "check_done", "verdict"]


@pytest.mark.asyncio
async def test_reconnecting_with_last_event_id_gets_only_what_was_missed():
    bus = EventBus()
    for n in range(4):
        bus.publish("abc123abc123", "check_done", {"n": n})
    got = parse(await collect(bus, 2, 2))
    assert [e["id"] for e in got] == [3, 4]


@pytest.mark.asyncio
async def test_an_idle_stream_sends_keepalives_and_a_retry_hint():
    bus = EventBus()
    state = {"n": 0}

    async def disconnected() -> bool:
        state["n"] += 1
        return state["n"] > 3

    frames = [text async for text in bus.stream(None, disconnected, heartbeat_s=0.01)]
    assert frames[0] == "retry: 3000\n\n"
    assert ": keepalive\n\n" in frames


@pytest.mark.asyncio
async def test_a_viewer_who_falls_behind_is_dropped_and_can_catch_up():
    bus = EventBus()
    stalled: asyncio.Queue = asyncio.Queue(maxsize=1)
    bus._subscribers.add(stalled)
    bus.publish("abc123abc123", "check_done", {"n": 1})
    bus.publish("abc123abc123", "check_done", {"n": 2})  # the queue was full
    assert stalled not in bus._subscribers
    assert stalled.get_nowait() is None  # its stream is told to end
    assert [e.id for e in bus.since(0)] == [1, 2]  # and the events are still there to ask for


def test_viewers_are_capped():
    bus = EventBus(max_subscribers=1)
    bus._subscribers.add(asyncio.Queue())
    assert not bus.has_room()


# --- a scan, end to end ------------------------------------------------------------------------


@pytest.fixture
def fresh_bus(monkeypatch):
    bus = EventBus()
    monkeypatch.setattr(main, "bus", bus)
    return bus


def test_a_scan_emits_one_event_per_step_in_order_and_defanged(client, fresh_bus, monkeypatch):  # noqa: F811
    fake_world(monkeypatch, age=OLD)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"], "sender": SENDER}).json()
    seen = fresh_bus.recent()

    kinds = [e.kind for e in seen]
    assert kinds[0] == "scan_started" and kinds[-1] == "verdict"
    assert kinds.count("screenshot_ready") == 1
    assert kinds.index("screenshot_ready") < kinds.index("verdict")
    checks = [e.data["check"] for e in seen if e.kind == "check_done"]
    assert set(checks) == {"page_opened", "threat_feeds", "domain_age", "brand_match", "sensitive_form", "platform_warning"}
    assert checks[0] == "page_opened"
    assert {e.scan for e in seen} == {body["id"]}
    assert {e.sender for e in seen} == {"•••-4412"}

    started = seen[0].data
    assert started == {"url": "hxxps://short[.]example/x", "source": "imessage"}
    shot = next(e for e in seen if e.kind == "screenshot_ready")
    assert shot.data == {"screenshot_url": f"/shots/{body['id']}.png"}
    verdict = seen[-1].data
    assert verdict["verdict"] == body["verdict"] and verdict["score"] == body["score"]
    assert verdict["report_path"] == f"/r/{body['id']}"
    for e in seen:
        assert e.data.get("outcome", "clear") in ("clear", "flagged", "unavailable")
    text = " ".join(frame(e) for e in seen)
    assert "https://" not in text and "http://" not in text  # every address is defanged


def test_no_sender_data_reaches_a_report_or_the_stream_beyond_the_mask(client, fresh_bus, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    body = client.post("/analyze", json={"urls": ["https://short.example/x"], "sender": SENDER}).json()
    stored = client.get(f"/api/report/{body['id']}").text
    streamed = " ".join(frame(e) for e in fresh_bus.recent())
    for place in (stored, json.dumps(body), streamed):
        assert HASH not in place
        assert '"last4"' not in place
    assert "4412" not in stored and "4412" not in json.dumps(body)  # only the live stream has the mask
    assert "•••-4412" in streamed


def test_a_website_scan_has_no_sender_and_says_so(client, fresh_bus, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    client.post("/api/check", json={"url": "short.example/x"})
    seen = fresh_bus.recent()
    assert seen[0].data["source"] == "web" and {e.sender for e in seen} == {None}


def test_a_scan_that_blows_up_says_so_without_the_error_text(client, fresh_bus, monkeypatch):  # noqa: F811
    async def boom(*args, **kwargs):
        raise RuntimeError("secret internal detail https://10.0.0.1/x")

    monkeypatch.setattr(main, "scan", boom)
    with pytest.raises(RuntimeError):
        client.post("/analyze", json={"urls": ["https://short.example/x"]})
    last = fresh_bus.recent()[-1]
    assert last.kind == "scan_failed" and "secret" not in json.dumps(last.data)


def test_the_gateway_reports_the_reply_and_it_shows_the_mask(client, fresh_bus):  # noqa: F811
    response = client.post("/internal/reply-sent", json={"scan": "abc123abc123", "sender": SENDER})
    assert response.status_code == 204
    event = fresh_bus.recent()[-1]
    assert (event.kind, event.scan, event.sender, event.data) == ("reply_sent", "abc123abc123", "•••-4412", {"delivered": True})
    assert client.post("/internal/reply-sent", json={"scan": "not-an-id"}).status_code == 422
    assert client.post("/internal/reply-sent", json={"scan": "abc123abc123", "sender": {"hash": "+19195554412"}}).status_code == 422


def test_a_bad_sender_on_analyze_is_refused_not_stored(client, fresh_bus, monkeypatch):  # noqa: F811
    fake_world(monkeypatch)
    response = client.post("/analyze", json={"urls": ["https://short.example/x"], "sender": {"hash": "+19195554412", "last4": "4412"}})
    assert response.status_code == 422


# --- the route -------------------------------------------------------------------------------


def test_the_events_route_serves_event_stream_and_reads_last_event_id(client, monkeypatch):  # noqa: F811
    asked = {}

    class StubBus:
        def has_room(self):
            return True

        async def stream(self, last_id, disconnected, heartbeat_s=15.0):
            asked["last_id"] = last_id
            yield "retry: 3000\n\n"
            yield 'id: 5\nevent: verdict\ndata: {"id":5}\n\n'

    monkeypatch.setattr(main, "bus", StubBus())
    response = client.get("/events", headers={"Last-Event-ID": "4"})
    assert response.headers["content-type"].startswith("text/event-stream")
    assert response.headers["cache-control"] == "no-store"
    assert "id: 5" in response.text and asked["last_id"] == 4
    client.get("/events?since=2")
    assert asked["last_id"] == 2
    client.get("/events", headers={"Last-Event-ID": "nonsense"})
    assert asked["last_id"] is None


def test_the_events_route_is_read_only_and_capped(client, monkeypatch):  # noqa: F811
    assert client.post("/events").status_code == 405

    class Full:
        def has_room(self):
            return False

    monkeypatch.setattr(main, "bus", Full())
    assert client.get("/events").status_code == 503


def test_every_kind_the_bus_can_emit_is_documented_in_the_replay_file():
    import pathlib

    sample = json.loads((pathlib.Path(__file__).resolve().parent.parent / "web" / "src" / "sample" / "events.sample.json").read_text(encoding="utf-8"))
    kinds = {item["event"]["kind"] for item in sample["events"]}
    assert kinds == set(events.KINDS)
