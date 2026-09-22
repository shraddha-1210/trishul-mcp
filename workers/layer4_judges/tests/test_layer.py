"""Layer 4 tests. Verdict tests call the REAL local Ollama (llama3.1:8b): slow by design.

Failure-mode tests point judge() at a real local HTTP server that misbehaves the
way a broken Ollama would (slow, garbage body, bad model output, HTTP 500).
"""
from __future__ import annotations

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from attacks.payloads import ATTACK1_PAYLOAD, ATTACK2_PAYLOAD
from workers.layer1_5_normalize.layer import normalize
from workers.layer4_judges import layer as l4
from workers.layer4_judges.layer import judge


@pytest.fixture(scope="module", autouse=True)
def warm_model():
    l4.warmup()  # real load; fails the module loudly if Ollama is down


def _assert_real_verdict(r, expected):
    print(f"\n  verdict={r.verdict} confidence={r.confidence} latency={r.latency_ms:.0f}ms"
          f"\n  reasoning: {r.reasoning}")
    assert r.error is None, r.reasoning
    assert r.verdict == expected
    assert r.reasoning and len(r.reasoning) > 10
    assert r.confidence is not None and 0.0 < r.confidence <= 1.0
    assert r.latency_ms < l4.TIMEOUT_S * 1000
    assert json.loads(r.raw_response)["verdict"].upper() == expected


# ---------------------------------------------------------------- real Ollama

def test_attack1_canonical_blocked():
    r = judge(normalize(ATTACK1_PAYLOAD).canonical_text,
              "sentry.get_error_logs", "Fetch recent error logs for a Sentry project.")
    _assert_real_verdict(r, "BLOCK")


def test_attack2_canonical_blocked():
    r = judge(normalize(ATTACK2_PAYLOAD).canonical_text,
              "github.get_issue", "Fetch a GitHub issue by number, including title and body.")
    _assert_real_verdict(r, "BLOCK")


def test_benign_weather_allowed():
    r = judge("Weather is sunny, 72F", "weather.get_forecast", "Get the current weather for a city.")
    _assert_real_verdict(r, "ALLOW")


# ---------------------------------------------------------------- fail-closed

class _Stub(BaseHTTPRequestHandler):
    mode = "ok"

    def do_POST(self):
        self.rfile.read(int(self.headers.get("content-length", 0)))
        m = type(self).mode
        if m == "slow":
            time.sleep(20)
            body = {"response": '{"verdict": "ALLOW", "reasoning": "too late"}'}
        elif m == "http500":
            self.send_response(500); self.end_headers(); self.wfile.write(b"boom"); return
        elif m == "garbage_body":
            self.send_response(200); self.end_headers(); self.wfile.write(b"<html>not json"); return
        elif m == "model_not_json":
            body = {"response": 'Sure! {"verdict": "ALLOW", reasoning: oops'}
        elif m == "bad_verdict":
            body = {"response": '{"verdict": "MAYBE", "reasoning": "unsure"}'}
        elif m == "no_reasoning":
            body = {"response": '{"verdict": "ALLOW"}'}
        else:
            body = {"response": '{"verdict": "allow", "reasoning": "benign content"}'}
        data = json.dumps(body).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


@pytest.fixture
def stub():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Stub)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def _call(url, **kw):
    return judge("Weather is sunny, 72F", "weather.get_forecast", "Get the weather.", base_url=url, **kw)


def test_default_timeout_is_15s():
    assert l4.TIMEOUT_S == 15.0


def test_slow_ollama_times_out_to_block(stub):
    _Stub.mode = "slow"
    t0 = time.perf_counter()
    r = _call(stub, timeout_s=2.0)
    elapsed = time.perf_counter() - t0
    assert r.verdict == "BLOCK" and r.error == "judge_timeout"
    assert 1.9 <= elapsed < 3.0  # hard cap honoured, not the stub's 20 s


@pytest.mark.parametrize("mode,error", [
    ("model_not_json", "judge_parse_error"),
    ("bad_verdict", "judge_parse_error"),
    ("no_reasoning", "judge_parse_error"),
    ("garbage_body", "judge_parse_error"),
    ("http500", "judge_http_error"),
])
def test_malformed_or_failed_response_blocks(stub, mode, error):
    _Stub.mode = mode
    r = _call(stub)
    assert r.verdict == "BLOCK"
    assert r.error == error
    assert r.confidence is None
    assert r.reasoning.startswith("Fail-closed")


def test_ollama_unreachable_blocks():
    with socket.socket() as s:  # grab a free port, then close it: nothing listens there
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    r = _call(f"http://127.0.0.1:{port}")
    assert r.verdict == "BLOCK" and r.error == "judge_unavailable"


def test_well_formed_stub_answer_is_normalised(stub):
    _Stub.mode = "ok"
    r = _call(stub)
    assert r.verdict == "ALLOW" and r.error is None
    assert r.confidence is None  # stub returns no logprobs


def test_long_input_is_truncated_in_prompt():
    p = l4.build_prompt("x" * 10000, "t", "d")
    assert p.endswith("Tool response to inspect: " + "x" * l4.MAX_TEXT_CHARS + " [...truncated]")
