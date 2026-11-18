# Test cases and expected output

Three layers. **Layers 1-2 run anywhere** (output captured in `unit_test_output.txt`);
**layer 3 needs Mininet + Open vSwitch + Ryu** and is run with `sudo ./demo.sh test`.

| Layer | Command | What it proves |
|---|---|---|
| 1 Unit | `python3 -m unittest discover -s tests -t .` | protocol parsing/validation, policy lookup, escalation engine, logger (bad input, dedupe, idle timeout, concurrency), event sender (logger down / restart / bounded queue), TCP app (concurrency, errors, timeouts) |
| 2 Controller glue | (same command, `tests/test_controller_glue.py`) | the real controller class driven with fake OpenFlow messages: exact flow priorities, timeouts, cookies, block + barrier + flow-removed life-cycle, static/nofw compilation. Uses stubs for Ryu, so it checks *our* logic, not Ryu's API |
| 3 End-to-end | `sudo python3 tests/mininet_functional.py [basic|autoblock|hard]` | everything below on real OVS + Ryu |

## Layer 3 checks and expected output

Every check prints `[PASS]`/`[FAIL]`; the run ends with `N checks, N passed, 0 failed`.
Timing assumes `FW_THRESHOLD=5 FW_WINDOW=10`, block time 8 s (basic/hard) or 12 s (autoblock).

### Group `basic`
| # | Action | Expected |
|---|---|---|
| 1 | `pingall` | 0 % loss (ICMP is allowed) |
| 2 | h1 -> server:5000 | success, `exit 0` |
| 3 | h1 -> server:5001 | `connect_timeout`, `exit 2` (SYN dropped, **not** refused) |
| 4 | `ovs-ofctl dump-flows s1` | `priority=200,tcp,nw_src=10.0.0.1,nw_dst=10.0.0.10,tp_src=<eph>,tp_dst=5001 actions=drop` and `priority=100,tcp,...,tp_dst=5000 actions=output:...` |
| 5 | h1 -> server:22 | timeout (default-deny; without the firewall this would be *refused*) |
| 6 | h2 -> :5002 / h1 -> :5002 | h2 ok / h1 timeout (per-source classification) |
| 7 | h1 -> logger:9999 | timeout (clients may not reach the logger) |
| 8 | logger log | `RULE_ADDED allow 10.0.0.1 -> 10.0.0.10:5000`, `RULE_ADDED deny ... :5001`, `:22`, `:5002`, logger `:9999`; no block yet (4 denies < 5) |

### Group `autoblock`
| # | Action | Expected |
|---|---|---|
| 1 | h1,h2,h3 each: 40 pings on :5000 plus one :5001 attempt, all at once | all 3 allowed sessions succeed; 3 forbidden attempts time out; logger has 1 allow + 1 deny **per client** |
| 2 | h3 sends 8 attempts to :5001 at 5/s | after the 5th a `priority=300,in_port=<h3>,dl_src=00:00:00:00:00:03 actions=drop`, `hard_timeout=12` rule appears (about 1 s after the first attempt) |
| 3 | while blocked | h3 cannot reach :5000, cannot ping; h1, h2 fine; no `nw_src=10.0.0.3` entries left; no block rule for h1/h2 |
| 4 | logger | `RULE_ESCALATED block 10.0.0.3 ... violations=5 detection_ms=...`; `CONTROLLER info ... what=block_active response_ms=... install_ms=...` |
| 5 | after ~12 s | prio-300 rule disappears by itself; `RULE_EXPIRED unblock 10.0.0.3 ... dropped_packets=N (N>=1) reason=hard_timeout`; h3 reaches :5000 again |
| 6 | 4 more denies from h3 | **no** re-block (counter was reset by recovery) |
| 7 | log completeness | every event has `ts, type, src, dst, port, action` + the logger's `recv_ts`; timestamps non-decreasing; unique `eid`; live lag < 1 s |

Flow-table snapshots (`results/functional/flows_*.png|txt`) show the rule appearing and disappearing.

### Group `hard` (port sweep + logger outage)
| # | Action | Expected |
|---|---|---|
| 1 | h1,h2 run legitimate sessions for 7 s; at t+1 s h3 sweeps ports 1000-1999 @200/s | h3 blocked within ~1 s; h1, h2 success rate **100 %**, no rule for them |
| 2 | attacker outcome | hundreds of attempts `dropped`; controller saw only about 5 deny events for 1000 attempts (the block rule absorbs the rest) |
| 3 | after timeout | h3 recovers; unblock event reports the dropped-packet count |
| 4 | logger **killed**, h3 sweeps ports 2000-2299 | h3 is still blocked within ~1 s; legit client unaffected; controller queues events and writes `controller_spool.jsonl` |
| 5 | logger restarted | queued events arrive; they keep their original `ts` while `recv_ts` is later; no loss, no duplicates |

## Limits of these tests
Mininet timings (a few ms) vary with the VM; assertions use generous bounds (5 s to block, 1 s event lag).
Absolute response-time/latency numbers come from `experiments/measure.py`, not from these tests.
