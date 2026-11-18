"""SYNTHETIC stand-in for topo.harness.Lab, used ONLY to test the measurement/plot pipeline
(CSV schema, aggregation, plotting) on machines without Mininet. Numbers it produces are
invented and must never be reported as results."""
import random
import time


class _Job(object):
    def __init__(self, data):
        self.data = data

    def result(self, timeout=0):
        return self.data


class _Net(object):
    def pingAll(self, timeout=None):
        return 0.0


class FakeLab(object):
    def __init__(self, mode, clients=6, out_dir=None, block_time=1, threshold=5, window=1, **kw):
        self.mode, self.block_time, self.window, self.threshold = mode, block_time, window, threshold
        self.net, self._events, self._block_until = _Net(), [], 0
        self._rate = 0
        random.seed(7)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        pass

    def wait_for(self, pred, timeout=10.0, step=0.1):
        t0 = time.time()
        while time.time() - t0 < timeout:
            if pred():
                return True, time.time() - t0
            time.sleep(0.01)
        return False, timeout

    def has_flow(self, needle, sw="s1"):
        return needle == "priority=300" and time.time() < self._block_until

    def flow_count(self, sw="s1"):
        return 6 + (3 if self.mode == "static" else 0) + (int(self._rate / 20) if self.mode == "nofw" else 0) \
            + (2 if self.mode == "dynamic" else 0)

    def events(self):
        return list(self._events)

    def client(self, host, port=5000, mode="ping", **kw):
        cold = self.mode == "dynamic" and not getattr(self, "_warm_" + host, False)
        setattr(self, "_warm_" + host, True)
        return {"ok": True, "connect_ms": (30.0 if cold else 0.9) + random.random(), "exit": 0}

    def legit(self, host, duration=5, pings=5, gap=0.05, background=False):
        pen = 0.0 + (self._rate / 400.0 if self.mode == "nofw" else 0)
        rtts = [0.3 + pen + random.random() * 0.4 for _ in range(200)]
        job = _Job({"sessions": 40, "ok": 40, "success_rate": 1.0, "rtts": rtts, "connects": rtts[:40]})
        return job if background else job.data

    def attack(self, host, mode="burst", port=5001, ports="", rate=100, count=0, duration=5.0, background=False):
        self._rate = rate
        now = time.time()
        out = {"connected": count or int(rate * duration)} if self.mode == "nofw" else \
              {"dropped": count or int(rate * duration)}
        if self.mode == "dynamic":
            self._block_until = now + 0.3
            det = 4000.0 / rate
            self._events.append({"type": "RULE_ESCALATED", "src": "10.0.0.6", "ts": now + 0.001,
                                 "detail": {"detection_ms": det}})
            self._events.append({"type": "CONTROLLER", "src": "10.0.0.6", "ts": now + 0.002,
                                 "detail": {"what": "block_active", "response_ms": det + 2.5, "install_ms": 2.5}})
        job = _Job({"attempts": count or int(rate * duration), "outcomes": out, "first_attempt_ts": now})
        return job if background else job.data

    def popen_json(self, host, args):
        return _Job({"ok": True, "mbps": 90.0 - (self._rate / 40.0 if self.mode == "nofw" else 0) + random.random()})
