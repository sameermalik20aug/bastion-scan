"""Tests for the AI enrichment layer.

The Anthropic client is always faked here — no test makes a network call or needs
a real key. We focus on the contract that matters: enrichment is optional, the
model's output is validated (not trusted), failures degrade gracefully, the key
never leaks into a result, and explanations are cached by vulnerability ID.
"""

import asyncio

import pytest

from app.models.schemas import PackageResult, ScanResult, Vulnerability
from app.services import ai_service

VALID_JSON = (
    '{"what_it_is": "A prototype pollution bug.", '
    '"real_world_risk": "An attacker can tamper with object prototypes.", '
    '"should_i_worry": "Fix now", '
    '"fix_note": "Upgrade to the patched release."}'
)


@pytest.fixture(autouse=True)
def _clear_cache():
    """Each test starts with an empty explanation cache."""
    ai_service._explanation_cache.clear()
    yield
    ai_service._explanation_cache.clear()


# --------------------------------------------------------------------------- #
# Fake Anthropic client
# --------------------------------------------------------------------------- #


class _FakeTextBlock:
    type = "text"

    def __init__(self, text: str) -> None:
        self.text = text


class _FakeMessage:
    def __init__(self, text: str) -> None:
        self.content = [_FakeTextBlock(text)]


class _FakeMessages:
    def __init__(self, handler) -> None:
        self._handler = handler

    async def create(self, **kwargs):
        return await self._handler(kwargs)


class _FakeClient:
    """Stand-in for anthropic.AsyncAnthropic with a scripted ``messages.create``."""

    def __init__(self, handler) -> None:
        self.messages = _FakeMessages(handler)
        self.closed = False

    async def close(self) -> None:
        self.closed = True


def _install(monkeypatch, handler) -> list[_FakeClient]:
    """Patch the client factory to return fakes; return the list of built clients."""
    built: list[_FakeClient] = []

    def factory(api_key: str) -> _FakeClient:
        client = _FakeClient(handler)
        built.append(client)
        return client

    monkeypatch.setattr(ai_service, "_build_client", factory)
    return built


def _const_handler(text: str):
    async def handler(kwargs):
        return _FakeMessage(text)

    return handler


def _branching_handler(explanation_text: str, summary_text: str):
    """Return explanation text for per-vuln calls, summary text for the summary."""

    async def handler(kwargs):
        user = kwargs["messages"][0]["content"]
        if "<scan_data>" in user:
            return _FakeMessage(summary_text)
        return _FakeMessage(explanation_text)

    return handler


# --------------------------------------------------------------------------- #
# Fixtures / builders
# --------------------------------------------------------------------------- #


def _vuln(vuln_id: str = "GHSA-aaaa", summary: str = "raw osv summary") -> Vulnerability:
    return Vulnerability(
        id=vuln_id,
        package="lodash",
        current_version="4.17.20",
        severity="high",
        summary=summary,
        is_direct=True,
        fixed_version="4.17.21",
    )


def _scan_with(*vulns: Vulnerability) -> ScanResult:
    return ScanResult(
        ecosystem="npm",
        packages=[
            PackageResult(
                name="lodash",
                version="4.17.20",
                is_direct=True,
                vulnerabilities=list(vulns),
            )
        ],
        total_packages=1,
        total_vulnerabilities=len(vulns),
    )


# --------------------------------------------------------------------------- #
# No key => no enrichment
# --------------------------------------------------------------------------- #


async def test_no_key_skips_enrichment(monkeypatch):
    built = _install(monkeypatch, _const_handler(VALID_JSON))
    scan = _scan_with(_vuln())

    result = await ai_service.enrich_scan(scan_result=scan, api_key=None)

    # The endpoint must work end to end with no key: results pass through, the
    # client is never even constructed.
    assert result is scan
    assert result.packages[0].vulnerabilities[0].ai_explanation is None
    assert result.executive_summary is None
    assert built == []


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #


async def test_valid_response_is_validated_and_attached(monkeypatch):
    _install(monkeypatch, _branching_handler(VALID_JSON, "Two packages scanned."))
    scan = _scan_with(_vuln())

    result = await ai_service.enrich_scan(scan_result=scan, api_key="sk-test")

    explanation = result.packages[0].vulnerabilities[0].ai_explanation
    assert explanation is not None
    parsed = ai_service.VulnExplanation.model_validate_json(explanation)
    assert parsed.should_i_worry == "Fix now"
    assert result.executive_summary == "Two packages scanned."


async def test_client_is_closed(monkeypatch):
    built = _install(monkeypatch, _const_handler(VALID_JSON))
    await ai_service.enrich_scan(scan_result=_scan_with(_vuln()), api_key="sk-test")
    assert built and all(c.closed for c in built)


# --------------------------------------------------------------------------- #
# Fallbacks: the model output is validated, never trusted
# --------------------------------------------------------------------------- #


async def test_malformed_json_falls_back_to_osv_summary(monkeypatch):
    _install(monkeypatch, _branching_handler("not json at all {", "summary"))
    scan = _scan_with(_vuln(summary="the real osv text"))

    result = await ai_service.enrich_scan(scan_result=scan, api_key="sk-test")

    assert result.packages[0].vulnerabilities[0].ai_explanation == "the real osv text"


async def test_invalid_verdict_falls_back(monkeypatch):
    # Valid JSON, all keys present, but should_i_worry is not one of the three.
    bad = (
        '{"what_it_is": "x", "real_world_risk": "y", '
        '"should_i_worry": "Maybe later", "fix_note": "z"}'
    )
    _install(monkeypatch, _branching_handler(bad, "summary"))
    scan = _scan_with(_vuln(summary="osv fallback text"))

    result = await ai_service.enrich_scan(scan_result=scan, api_key="sk-test")

    assert result.packages[0].vulnerabilities[0].ai_explanation == "osv fallback text"


async def test_valid_json_wrong_shape_falls_back(monkeypatch):
    # Valid JSON, but the top-level value is an array, not the expected object.
    # json.loads succeeds; model validation must reject it and fall back to OSV.
    _install(monkeypatch, _branching_handler('[{"what_it_is": "x"}]', "summary"))
    scan = _scan_with(_vuln(summary="osv fallback text"))

    result = await ai_service.enrich_scan(scan_result=scan, api_key="sk-test")

    assert result.packages[0].vulnerabilities[0].ai_explanation == "osv fallback text"


async def test_missing_key_falls_back(monkeypatch):
    incomplete = '{"what_it_is": "x", "real_world_risk": "y", "should_i_worry": "Fix now"}'
    _install(monkeypatch, _branching_handler(incomplete, "summary"))
    scan = _scan_with(_vuln(summary="osv fallback text"))

    result = await ai_service.enrich_scan(scan_result=scan, api_key="sk-test")

    assert result.packages[0].vulnerabilities[0].ai_explanation == "osv fallback text"


async def test_api_error_falls_back_without_leaking_key(monkeypatch):
    async def boom(kwargs):
        # Simulate an SDK error whose text embeds the key — exactly what must
        # never reach a response.
        raise RuntimeError("401 invalid x-api-key: sk-secret-leak")

    _install(monkeypatch, boom)
    scan = _scan_with(_vuln(summary="osv fallback text"))

    result = await ai_service.enrich_scan(scan_result=scan, api_key="sk-secret-leak")

    explanation = result.packages[0].vulnerabilities[0].ai_explanation
    assert explanation == "osv fallback text"
    assert "sk-secret-leak" not in (explanation or "")
    # A failed summary degrades to no summary, never to the error text.
    assert result.executive_summary is None


# --------------------------------------------------------------------------- #
# Caching by vulnerability ID, not by key
# --------------------------------------------------------------------------- #


async def test_explanation_cached_by_vuln_id(monkeypatch):
    calls = {"n": 0}

    async def counting(kwargs):
        if "<scan_data>" in kwargs["messages"][0]["content"]:
            return _FakeMessage("summary")
        calls["n"] += 1
        return _FakeMessage(VALID_JSON)

    _install(monkeypatch, counting)

    # First scan populates the cache for GHSA-dup.
    await ai_service.enrich_scan(scan_result=_scan_with(_vuln("GHSA-dup")), api_key="key-A")
    assert calls["n"] == 1

    # A second scan of the same CVE — even with a *different* key — serves from
    # the cache and makes no new per-vuln model call.
    scan2 = _scan_with(_vuln("GHSA-dup"))
    result2 = await ai_service.enrich_scan(scan_result=scan2, api_key="key-B")
    assert calls["n"] == 1
    assert result2.packages[0].vulnerabilities[0].ai_explanation is not None


async def test_failures_are_not_cached(monkeypatch):
    state = {"fail": True}

    async def flaky(kwargs):
        if "<scan_data>" in kwargs["messages"][0]["content"]:
            return _FakeMessage("summary")
        if state["fail"]:
            raise RuntimeError("transient")
        return _FakeMessage(VALID_JSON)

    _install(monkeypatch, flaky)

    # First attempt fails -> falls back, must NOT cache.
    await ai_service.enrich_scan(scan_result=_scan_with(_vuln("GHSA-x")), api_key="k")
    assert "GHSA-x" not in ai_service._explanation_cache

    # Recovery: the next scan of the same CVE succeeds and now caches.
    state["fail"] = False
    result = await ai_service.enrich_scan(scan_result=_scan_with(_vuln("GHSA-x")), api_key="k")
    assert result.packages[0].vulnerabilities[0].ai_explanation is not None
    assert "GHSA-x" in ai_service._explanation_cache


# --------------------------------------------------------------------------- #
# Concurrency is capped
# --------------------------------------------------------------------------- #


async def test_concurrency_is_capped_at_semaphore_limit(monkeypatch):
    state = {"current": 0, "peak": 0}

    async def tracked(kwargs):
        if "<scan_data>" in kwargs["messages"][0]["content"]:
            return _FakeMessage("summary")
        state["current"] += 1
        state["peak"] = max(state["peak"], state["current"])
        await asyncio.sleep(0.01)  # hold the slot so overlap is observable
        state["current"] -= 1
        return _FakeMessage(VALID_JSON)

    _install(monkeypatch, tracked)

    # 20 distinct vulns; without the cap all 20 would run at once.
    vulns = [_vuln(f"GHSA-{i}") for i in range(20)]
    scan = ScanResult(
        ecosystem="npm",
        packages=[
            PackageResult(name="lodash", version="4.17.20", is_direct=True, vulnerabilities=vulns)
        ],
        total_packages=1,
        total_vulnerabilities=len(vulns),
    )

    await ai_service.enrich_scan(scan_result=scan, api_key="k")

    assert state["peak"] <= ai_service.MAX_CONCURRENCY
    assert state["peak"] > 1  # confirm the calls really did overlap


# --------------------------------------------------------------------------- #
# Client construction: a stalled API must hit a bounded timeout, not hang
# --------------------------------------------------------------------------- #


def test_build_client_applies_the_request_timeout():
    # The audit added a tight per-request timeout so a stalled Anthropic API
    # degrades to the OSV fallback instead of tying up a worker for minutes.
    # Construct the real client (no network on construction) and assert the cap.
    client = ai_service._build_client("sk-not-used")
    assert client.timeout == ai_service.ANTHROPIC_TIMEOUT_SECONDS
