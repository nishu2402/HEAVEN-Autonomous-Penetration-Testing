"""Regression: WebSocket subscriber-set cleanup on abnormal disconnect.

The fleet / autonomous / watch job-progress streams are *push-only* (the browser
subscribes and only listens). An earlier implementation looped on
``msg = await queue.get()`` alone, so when a client vanished mid-stream the
handler stayed parked on the queue: the ASGI server reports a drop as a
``websocket.disconnect`` event delivered through ``receive`` (which that loop
never called) and uvicorn does not cancel the endpoint task. The orphaned
per-subscriber queue then lingered in its ``*_subscribers`` set and the broadcast
loop kept pushing into a queue nobody drained, until the job's *next* send
happened to fail. (Starlette's TestClient hid the bug because it cancels the task
on close, firing the ``finally``; real uvicorn does not.)

The shared helper now races a ``receive`` task against the queue so a disconnect
is reaped at once. These tests drive the real helper with a faithful WebSocket
stand-in (the disconnect arrives via ``receive``, the task is never cancelled),
so they fail against the old parked-on-``queue.get()`` loop.
"""
from __future__ import annotations

import asyncio
import inspect

import pytest

import heaven.api.server as server


class _FakeWS:
    """Starlette-WebSocket stand-in with a controllable inbound channel.

    ``receive`` returns raw ASGI message dicts and, after a disconnect, raises
    like the real socket, matching ``starlette.websockets.WebSocket``.
    """

    def __init__(self) -> None:
        self.sent: list[dict] = []
        self.closed = False
        self.close_code: int | None = None
        self.accepted = False
        self._inbound: asyncio.Queue = asyncio.Queue()
        self._disconnect_consumed = False

    async def accept(self) -> None:
        self.accepted = True

    async def send_json(self, msg: dict) -> None:
        if self.closed:
            raise RuntimeError("send after close")
        self.sent.append(msg)

    async def receive(self) -> dict:
        if self._disconnect_consumed:
            raise RuntimeError('Cannot call "receive" once a disconnect '
                               "message has been received.")
        msg = await self._inbound.get()
        if msg.get("type") == "websocket.disconnect":
            self._disconnect_consumed = True
        return msg

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = True
        self.close_code = code

    # ── test controls ──
    def client_disconnect(self, code: int = 1006) -> None:
        self._inbound.put_nowait({"type": "websocket.disconnect", "code": code})

    def client_frame(self, text: str = "hi") -> None:
        self._inbound.put_nowait({"type": "websocket.receive", "text": text})


# Each job family: (jobs dict, subscribers dict, label) on the live module.
_FAMILIES = [
    ("fleet", "fleet_jobs", "_fleet_subscribers"),
    ("autonomous", "autonomous_jobs", "_autonomous_subscribers"),
    ("watch", "watch_jobs", "_watch_subscribers"),
]


@pytest.fixture(autouse=True)
def _auth_off(monkeypatch):
    monkeypatch.setenv("HEAVEN_DISABLE_AUTH", "1")


async def _start(label, jobs, subs, ws, job_id="J"):
    task = asyncio.ensure_future(server._stream_job_updates(
        ws, job_id, jobs=jobs, subscribers=subs, token=None, label=label))
    # Let it authenticate, send the snapshot, and register its queue.
    for _ in range(50):
        await asyncio.sleep(0)
        if ws.sent or task.done():
            break
    return task


@pytest.mark.parametrize("label", [f[0] for f in _FAMILIES])
async def test_abnormal_disconnect_reaps_subscriber_without_broadcast(label):
    """The headline regression: a client that vanishes while the job is quiet is
    reaped immediately — no broadcast required — so the subscriber set empties."""
    jobs = {"J": {"job_id": "J", "status": "running", "progress": [{"i": 0}]}}
    subs: dict[str, set] = {}
    ws = _FakeWS()
    task = await _start(label, jobs, subs, ws)

    assert ws.sent and ws.sent[0]["type"] == "snapshot"
    assert len(subs["J"]) == 1, "subscriber queue must be registered while live"

    # Client drops. NOTHING is broadcast afterwards.
    ws.client_disconnect()
    await asyncio.wait_for(task, timeout=5)

    assert subs.get("J") is None, "subscriber must be reaped on abnormal disconnect"
    assert ws.closed, "handler must close the socket on exit"


@pytest.mark.parametrize("label", [f[0] for f in _FAMILIES])
async def test_delivers_iteration_then_done_and_unregisters(label):
    jobs = {"J": {"job_id": "J", "status": "running", "progress": []}}
    subs: dict[str, set] = {}
    ws = _FakeWS()
    task = await _start(label, jobs, subs, ws)

    queue = next(iter(subs["J"]))
    queue.put_nowait({"type": "iteration", "data": {"n": 1}})
    await asyncio.sleep(0)
    queue.put_nowait({"type": "done", "job": jobs["J"]})
    await asyncio.wait_for(task, timeout=5)

    assert [m["type"] for m in ws.sent] == ["snapshot", "iteration", "done"]
    assert subs.get("J") is None


@pytest.mark.parametrize("label", [f[0] for f in _FAMILIES])
async def test_stray_inbound_frame_does_not_end_push_only_stream(label):
    """A push-only stream must ignore an unexpected client frame, not treat it as
    end-of-stream (and not re-enter a broken receive state)."""
    jobs = {"J": {"job_id": "J", "status": "running", "progress": []}}
    subs: dict[str, set] = {}
    ws = _FakeWS()
    task = await _start(label, jobs, subs, ws)

    ws.client_frame("unexpected")
    await asyncio.sleep(0.05)
    assert not task.done(), "a stray inbound frame must not end the stream"

    queue = next(iter(subs["J"]))
    queue.put_nowait({"type": "done", "job": jobs["J"]})
    await asyncio.wait_for(task, timeout=5)
    assert subs.get("J") is None


@pytest.mark.parametrize("label", [f[0] for f in _FAMILIES])
async def test_nonrunning_job_sends_done_and_registers_nothing(label):
    jobs = {"J": {"job_id": "J", "status": "completed", "progress": [{"i": 1}]}}
    subs: dict[str, set] = {}
    ws = _FakeWS()
    task = await _start(label, jobs, subs, ws)
    await asyncio.wait_for(task, timeout=5)

    assert [m["type"] for m in ws.sent] == ["snapshot", "done"]
    assert ws.closed
    assert "J" not in subs, "a finished job must not register a subscriber"


@pytest.mark.parametrize("label", [f[0] for f in _FAMILIES])
async def test_unknown_job_closes_4404_without_accept(label):
    subs: dict[str, set] = {}
    ws = _FakeWS()
    task = asyncio.ensure_future(server._stream_job_updates(
        ws, "missing", jobs={}, subscribers=subs, token=None, label=label))
    await asyncio.wait_for(task, timeout=5)

    assert ws.closed and ws.close_code == 4404
    assert not ws.accepted
    assert subs == {}


def test_stream_handlers_delegate_to_shared_helper():
    """Lock the fix in: the three handlers must route through the shared helper
    (which owns the receive-race), not a hand-rolled ``await queue.get()`` loop."""
    src = inspect.getsource(server)
    for label, jobs_name, subs_name in _FAMILIES:
        assert f"subscribers={subs_name}" in src, (
            f"{label} stream must delegate to _stream_job_updates with {subs_name}")
    # No endpoint should re-introduce a bare queue.get() stream loop.
    assert "msg = await queue.get()" not in src, (
        "a push-only stream must not park on queue.get() alone (abnormal-disconnect leak)")
