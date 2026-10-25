"""Phase 3 — single-packet race + business-logic abuse.

The single-packet race detector must fire on a non-atomic check-then-act limit
(coupon reuse) and stay silent on an atomic one and on an endpoint with no limit
at all. The logic scanner must prove numeric tampering / workflow step-skip from
reflected values / observed status, and reject inputs the server validates. All
servers run in-process on asyncio, so the check-then-act window is deterministic.
"""

from __future__ import annotations

import asyncio

import pytest

pytest.importorskip("aiohttp")

from aiohttp import web  # noqa: E402

from heaven.vulnscan.advanced_attacks import RaceConditionDetector  # noqa: E402
from heaven.vulnscan.logic_scanner import scan_business_logic  # noqa: E402


async def _serve(app: web.Application):
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    return runner, f"http://127.0.0.1:{port}"


# ── single-packet race ────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_single_packet_race_proves_limit_overrun():
    state = {"used": False}

    async def redeem(request):
        if state["used"]:
            return web.Response(status=409, text="coupon already redeemed")
        await asyncio.sleep(0.08)             # the check-then-act window
        state["used"] = True
        return web.Response(text="SUCCESS: coupon applied")

    app = web.Application()
    app.router.add_post("/redeem", redeem)
    runner, base = await _serve(app)
    try:
        f = await RaceConditionDetector.test_single_packet_race(base + "/redeem", n=10)
    finally:
        await runner.cleanup()
    assert f is not None
    assert f.vuln_type == "race_condition_limit_overrun"
    assert f.severity == "high"
    assert f.evidence["single_packet_fresh_successes"] >= 2
    assert f.evidence["sequential_fresh_successes"] <= 1


@pytest.mark.asyncio
async def test_atomic_limit_is_not_flagged():
    state = {"used": False}

    async def redeem(request):
        # Atomic check-then-set with no await between → serialised by the loop.
        if state["used"]:
            return web.Response(status=409, text="already redeemed")
        state["used"] = True
        return web.Response(text="SUCCESS: coupon applied")

    app = web.Application()
    app.router.add_post("/redeem", redeem)
    runner, base = await _serve(app)
    try:
        f = await RaceConditionDetector.test_single_packet_race(base + "/redeem", n=10)
    finally:
        await runner.cleanup()
    assert f is None  # only one success under the race → no overrun


@pytest.mark.asyncio
async def test_unlimited_endpoint_is_not_flagged():
    async def act(request):
        return web.Response(text="SUCCESS: done")   # no limit, repeatable

    app = web.Application()
    app.router.add_post("/act", act)
    runner, base = await _serve(app)
    try:
        f = await RaceConditionDetector.test_single_packet_race(base + "/act", n=10)
    finally:
        await runner.cleanup()
    assert f is None  # sequential also succeeds repeatedly → not a race bug


# ── business logic ──────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_numeric_tampering_detected_and_rejected_case_silent():
    async def vuln_buy(request):
        qty = request.query.get("qty", "1")
        return web.Response(text=f"<p>Order quantity: {qty}</p>ok")

    async def safe_buy(request):
        qty = request.query.get("qty", "1")
        if not qty.isdigit() or int(qty) < 1:
            return web.Response(status=400, text="invalid quantity")
        return web.Response(text=f"<p>Order quantity: {qty}</p>ok")

    app = web.Application()
    app.router.add_get("/vuln", vuln_buy)
    app.router.add_get("/safe", safe_buy)
    runner, base = await _serve(app)
    try:
        res = await scan_business_logic([base + "/vuln?qty=2", base + "/safe?qty=2"])
    finally:
        await runner.cleanup()
    hits = {(f["vuln_type"], f["target"]) for f in res["findings"]}
    assert ("numeric_tampering", base + "/vuln?qty=2") in hits
    # The validating endpoint rejects -1 (400, not reflected) → never flagged.
    assert not any(f["target"] == base + "/safe?qty=2" for f in res["findings"])


@pytest.mark.asyncio
async def test_numeric_validation_redisplay_is_not_flagged():
    # The endpoint re-renders at HTTP 200 and echoes the invalid value, but with a
    # rejection message — it did NOT accept the value. Treating that echo as
    # "accepted" would be a false positive; the rejection-differential guard must
    # suppress it.
    async def redisplay(request):
        qty = request.query.get("qty", "1")
        if qty.lstrip("-").isdigit() and int(qty) < 1:
            return web.Response(text=f"<p>quantity: {qty}</p> invalid quantity, must be positive")
        return web.Response(text=f"<p>quantity: {qty}</p> ok")

    app = web.Application()
    app.router.add_get("/order", redisplay)
    runner, base = await _serve(app)
    try:
        res = await scan_business_logic([base + "/order?qty=2"])
    finally:
        await runner.cleanup()
    assert not any(f["vuln_type"] == "numeric_tampering" for f in res["findings"]), \
        [f["evidence"] for f in res["findings"]]


@pytest.mark.asyncio
async def test_step_skip_silent_on_benign_content_urls():
    # Ordinary public pages whose paths merely CONTAIN a step keyword as a
    # substring (reviews, success-stories, autocomplete) must not be read as
    # workflow steps, even with a login link present (which satisfies has_early).
    async def page(request):
        return web.Response(text="<h1>Welcome</h1> read our latest content here")

    app = web.Application()
    app.router.add_get("/login", page)
    app.router.add_get("/reviews", page)             # old substring: "review"
    app.router.add_get("/success-stories", page)     # old substring: "success"
    app.router.add_get("/autocomplete", page)        # old substring: "complete"
    runner, base = await _serve(app)
    try:
        res = await scan_business_logic([
            base + "/login", base + "/reviews",
            base + "/success-stories", base + "/autocomplete"])
    finally:
        await runner.cleanup()
    assert not any(f["vuln_type"] == "workflow_step_skip" for f in res["findings"]), \
        [f["target"] for f in res["findings"]]


@pytest.mark.asyncio
async def test_step_skip_silent_without_success_content():
    # A late-step URL that returns a bare 200 with no confirmation vocabulary is
    # not proof the workflow completed (could be a soft-404 or a shell page).
    async def cart(request):
        return web.Response(text="your cart (step 1)")

    async def bare(request):
        return web.Response(text="<h1>Page</h1><p>nothing to see here</p>")

    app = web.Application()
    app.router.add_get("/cart", cart)
    app.router.add_get("/checkout/confirm", bare)
    runner, base = await _serve(app)
    try:
        res = await scan_business_logic([base + "/cart", base + "/checkout/confirm"])
    finally:
        await runner.cleanup()
    assert not any(f["vuln_type"] == "workflow_step_skip" for f in res["findings"])


@pytest.mark.asyncio
async def test_workflow_step_skip_positive_and_guarded_negative():
    async def cart(request):
        return web.Response(text="your cart (step 1)")

    async def open_confirm(request):
        return web.Response(text="<h1>Order confirmed</h1> receipt thank you")

    async def guarded_confirm(request):
        # Enforces order: bounces an out-of-order request back to login.
        return web.Response(text="please log in to continue")

    app = web.Application()
    app.router.add_get("/cart", cart)
    app.router.add_get("/checkout/confirm", open_confirm)
    app.router.add_get("/secure/complete", guarded_confirm)
    runner, base = await _serve(app)
    try:
        res = await scan_business_logic(
            [base + "/cart", base + "/checkout/confirm", base + "/secure/complete"])
    finally:
        await runner.cleanup()
    skip = [f for f in res["findings"] if f["vuln_type"] == "workflow_step_skip"]
    targets = {f["target"] for f in skip}
    assert base + "/checkout/confirm" in targets
    assert base + "/secure/complete" not in targets  # guarded step stays silent
