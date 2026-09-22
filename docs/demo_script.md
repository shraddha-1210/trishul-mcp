# Trishul Demo Script

Six beats, 6-8 minutes. Beats 4 and 5 are the approved drafts, unchanged.

## Pre-flight (order matters)

1. Start Ollama **first**: `ollama serve` (it must be running before the backend starts).
   Then check `ollama ps`: if any model other than `llama3.1:8b` is resident, unload it
   (`ollama stop <model>`). A second model on CPU competes for RAM and pushes judge latency
   toward the 15 s timeout.
2. Start the mock MCP server: `python -m mock_server` (port 8765, rug pull ON). The console
   should print `mock MCP server: http://127.0.0.1:8765/mcp (rug pull ON)`.
3. Start the backend: `uvicorn backend.main:app --port 8002`.
   Port 8000 is taken by Docker Desktop on this laptop, which is why the demo runs on 8002.
   At startup the backend preloads `llama3.1:8b` (cold load ~16 s). Check the log for
   `judge model llama3.1:8b loaded in N s`. If you see `judge warmup FAILED` instead, Ollama
   was not up. Every judge call will then fail closed to BLOCK, and Attack 3's story breaks.
   Restart the backend after starting Ollama.
   Startup also records the approved tool manifests into the Layer 5 snapshot store
   (`workers/layer5_schema/snapshots.db`); look for `approved 4 tool manifests` in the log.
   Then look for `mock MCP server reachable at http://127.0.0.1:8765/mcp`. If it says
   `NOT reachable`, every catalog attack returns HTTP 502 (custom text still works). Start the
   mock server; no backend restart needed, since each simulate connects fresh.
4. Start the frontend: `cd frontend && npm run dev`, then open http://localhost:5173.
   The frontend talks to `http://127.0.0.1:8002` by default; override with `VITE_API_URL`
   in `frontend/.env.local` if you move the backend.
5. **Fire one warm-up attack before the audience is watching.** Fire Attack 3 and check the
   Layer 4 row shows real reasoning, not "Fail-closed (judge_timeout)".
   Background: the judge was capped at `num_predict` 64 (it only emits one short JSON object)
   after 2 of 10 calls at 128 tokens blew through the 15 s timeout and failed closed. Measured
   after the change: 8 of 8 calls in 6.9-8.1 s, no timeouts, same verdicts and wording.
   A fail-closed judge still returns BLOCK, so Attacks 1, 2 and 4 would survive it anyway; only
   Attack 3's beat depends on the judge's own reasoning.
6. Judge latency is ~7-9 s per call on this laptop (CPU only). The Attack Simulator waits on
   `/ws/live` `layer_complete` events, not fixed timers.
7. The Simulator header shows "live feed connected" when the WebSocket is up. If it reads
   "live feed offline" the pipeline still runs (the POST carries the full trace), but the
   nodes will not light up one at a time.

## Beat 1 (30 s): Dashboard

*Open http://localhost:5173 — the Dashboard.*

> "This is Trishul monitoring MCP tool responses in real time. Every response a tool sends back
> to my agent gets inspected before the agent sees it. Here is the last 24 hours: total
> requests, how many were blocked, and the attack success rate, which is zero. Average latency
> is dominated by the AI judge; the deterministic layers run in well under a millisecond."

Point at the Recent Blocked Attacks table: each row is a real verdict written to SQLite, with
the layer that caught it. The 25 oldest rows are seeded demo history (flagged `seeded` in the
database); everything fired today is real.

## Beat 2 (90 s): Attack 1, Unicode tag smuggling

*Go to Attack Simulator. Point at the first card before firing.*

> "This is a real attack pattern documented by Invariant Labs in April 2025: hidden instructions
> in tool responses that tell the agent to exfiltrate credentials. This one rides in on a Sentry
> error log. To a human it reads 'NullPointerException at line 42' and nothing else, because the
> instruction is encoded in invisible Unicode tag characters. Watch."

*Fire Attack 1.*

> "Layer 5 checks the tool's manifest first and passes it: Sentry hasn't changed. The call is
> forwarded, the response comes back, and Layer 1.5 strips 92 invisible characters and reveals
> the hidden instruction: read the AWS secret key and POST it to attacker.co. Layer 2a then
> matches three known patterns, and the judge agrees on intent. Blocked at Layer 1.5, the
> earliest layer that caught it."

Expected: L5 green, L1.5 red, L2a red, L4 red, final BLOCK at "1.5". Expand the Layer 1.5 row to
show the revealed instruction in the trace panel.

## Beat 3 (90 s): Attack 2, homoglyphs

> "Different technique, same goal. This GitHub issue body uses Cyrillic letters that look
> identical to Latin ones. A human reviewer reads 'ignore previous instructions'. A byte-level
> pattern match does not, because those are different bytes. Watch Layer 1.5's Unicode
> normalization fold them back to Latin."

*Fire Attack 2.*

> "Five homoglyphs folded, and now Layer 2a's patterns match text that was invisible to them a
> millisecond ago. Blocked at Layer 1.5 again."

Expected: L1.5 red ("5 homoglyphs folded to Latin"), L2a red, L4 red, final BLOCK at "1.5".

## Beat 4: Attack 3, novel encoding (ROT13)

> "This one is different. It's a ROT13-encoded injection, not a known obfuscation type.
> Watch what happens."

*Fire Attack 3.*

> "Layer 1.5 passes it: there's no known encoding to strip. Layer 2a passes it: no matching
> patterns, because the attack is encoded. But Layer 4, the AI judge, catches it on intent.
> The model recognizes suspicious structure even without decoding. This is why we stack
> deterministic layers with a semantic layer. And in production, even if the judge missed
> too, the Capability Layer's 30-second scoped tokens would bound the blast radius."

Expected on screen: L1.5 green, then L2a green, then L4 red. Final BLOCK, `blocked_at_layer`
"4". The reason starts with "Blocked at Layer 4 (Judge), deterministic layers 1.5 and 2a passed;
caught on semantic reasoning". The judge's verdict comes from a live LLM, not a script. It is
temperature 0 and seeded, and it blocked Attack 3 in the Step 4 and Step 5 live checks, but
that is not guaranteed. Rehearse it on the demo laptop.

## Beat 5: Attack 4, rug pull

> "Last one. The calendar server was approved when we connected it. Now it quietly changes
> its own tool description: it tells the agent to read the AWS credentials file and send it
> in a new `sync_token` parameter. The response it returns is completely clean."

*Fire Attack 4.*

> "Layer 5 compares the manifest against the snapshot we approved, and it's blocked in about a
> millisecond, before the call is even forwarded. Layers 1.5, 2a and the judge never run,
> because there's no response to inspect. That's also why they couldn't have caught it: the
> attack isn't in the response."

Expected on screen: L5 red; L1.5, 2a and 4 greyed out as "skipped" (`layer_skipped` events).
Final BLOCK at "5". The L5 detail shows a diff: approved description vs. live description
(the injected `<IMPORTANT>` block), `sync_token` added, `required` changed.

## Beat 6 (60 s): Architecture and close

*Open the Architecture page.*

> "Here is the whole design. Green is running: Layer 1.5, Layer 2a, the Layer 4 judge, Layer 5,
> the policy engine and the audit log. Amber is designed and specced but not built: Layer 2b,
> semantic similarity over a FAISS index; Layer 3, the cross-call aggregator for split payloads;
> Layer 6, rate and anomaly detection. Blue is enterprise scope: the Capability Layer and the
> HMAC-chained audit log."

Scroll to a live layer and point at its stats card: those numbers come from `/api/metrics`, so
they include the attacks just fired. Then scroll to the Training Data Pipeline section.

> "Training data: 250 hand-written attack seeds across 10 classes, 3,296 rows from four public
> datasets, 730 deterministic generator variants including 80 OCR images and 40 audio clips, and
> 130 LLM-generated examples we kept after filtering. Every number there is counted from the
> files in the repo."

Expand one class in the seed viewer to show real seed text.

Close:

> "Four layers plus the policy engine and audit log running today, three more specced. Next
> milestone is Layer 2b and Layer 3; the Capability Layer follows for enterprise deployment."

## If something goes wrong

- **Judge row says "Fail-closed (judge_timeout)".** The verdict is still BLOCK; say so plainly:
  "the judge ran out of its 15-second budget and the policy fails closed, which is the designed
  behaviour". Do not re-fire mid-beat.
- **Every attack returns 502.** The mock MCP server is down. Restart `python -m mock_server`;
  no backend restart needed.
- **Nodes don't light up one at a time.** The WebSocket dropped; the verdict and trace still
  arrive with the POST response. The header dot shows the connection state.
- **Dashboard numbers look stale.** It refetches every 5 s; give it a moment rather than
  reloading mid-demo.

## Architecture page notes

- **Live MCP flow (Step 6):** each catalog attack is a real MCP round trip to the mock server:
  `tools/list` (manifest), then Layer 5, then `tools/call` only if L5 passes. A `tool_call`
  WebSocket event marks the forward, between L5 `layer_complete` and L1.5 `layer_start`.
  Attack 4 never emits it. `/api/simulate` now returns `source` ("mcp" | "custom_text"),
  `forwarded` and `mcp_latency_ms` (~20-40 ms locally). `total_latency_ms` is Trishul's own
  time: it excludes waiting on the tool. Proof for Q&A: `GET http://127.0.0.1:8765/debug/calls`
  lists every forwarded call, and Attack 4's calendar call is never in it.
- **Layer 5 runs first (request side).** It checks the tool manifest before the call is
  forwarded, so the Attack Simulator must render L5 before L1.5. On an L5 BLOCK the response
  layers emit `layer_skipped`, not `layer_start`/`layer_complete`.
- **Layer 5 limits:** it detects change, not intent. A legitimate tool update is blocked until
  it is re-approved (by design). A tool seen for the first time is trusted on first use: a
  server that is malicious from day one isn't caught by L5. In the demo, L2a and L4 scan the
  response only, not the tool description, so a description poisoned from the start is not
  covered (spec §4.1 has 2a/4 scanning descriptions; not built).
- **AMBER (enterprise feature, not in the demo cascade):** "In production, low-confidence
  judge verdicts (<0.7) route to AMBER + human review lane instead of hard BLOCK. Not part of
  the demo cascade." The demo policy is only: any BLOCK means BLOCK at the earliest blocking
  layer, and all ALLOW means ALLOW (`policy/engine.py`).
- **Layer 4 detail:** input is truncated to 6000 chars before judging (prompt-size and CPU
  latency bound). A payload placed after char 6000 is not seen by the judge.
- **Known limit, judge input manipulation:** the judge reads attacker-controlled text, so a
  payload can try to talk the judge into ALLOW. L1.5 and L2a are the deterministic backstop,
  which is why they run first and why any BLOCK from them is final.
