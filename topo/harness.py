"""Lab: one call starts controller + network + logger + server, and offers
helpers that the functional tests, the measurements and the demo share.

Needs root, Mininet, Open vSwitch and Ryu.
"""
import json
import os
import shlex
import signal
import socket
import subprocess
import sys
import time

from mininet.log import setLogLevel

from topo import topo as T

ROOT = T.ROOT
OVS_FLAGS = ["-O", "OpenFlow13"]


class LabError(RuntimeError):
    pass


def percentile(values, p):
    if not values:
        return None
    s = sorted(values)
    k = (len(s) - 1) * p / 100.0
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


def last_json(text):
    for line in reversed(text.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            return json.loads(line)
    raise LabError("no JSON in output: %r" % text[-300:])


class Lab(object):
    def __init__(self, mode="dynamic", clients=6, out_dir=None, threshold=5, window=10.0,
                 block_time=8, bw=100, controller_port=6633, extra_env=None):
        self.mode, self.clients = mode, clients
        self.out_dir = os.path.abspath(out_dir or os.path.join(ROOT, "results", "run_%s" % mode))
        self.threshold, self.window, self.block_time = threshold, window, block_time
        self.bw, self.controller_port = bw, controller_port
        self.extra_env = extra_env or {}
        self.net = self.root = self.mgmt = None
        self.ctrl = None
        self.procs = {}
        self.started = None

    # ------------------------------------------------------------------
    def __enter__(self):
        return self.start()

    def __exit__(self, *exc):
        self.stop()

    def start(self):
        os.chdir(ROOT)
        os.makedirs(self.out_dir, exist_ok=True)
        for name in ("logger", "controller_spool.jsonl"):
            path = os.path.join(self.out_dir, name)
            if os.path.isdir(path):
                for f in os.listdir(path):
                    os.remove(os.path.join(path, f))
            elif os.path.exists(path):
                os.remove(path)
        setLogLevel("warning")
        self._start_controller()
        self.net, self.root, self.mgmt = T.build_net(self.clients, "127.0.0.1", self.controller_port, self.bw)
        self.net.start()
        T.finish_setup(self.net, self.root, self.mgmt)
        self.procs = T.start_services(self.net, self.out_dir)
        try:
            self.net.waitConnected(timeout=20)
        except Exception:
            pass
        self._wait_port(T.MGMT_LOGGER, T.LOGGER_PORT, 10)
        time.sleep(1.0)
        self.started = time.time()
        return self

    def _start_controller(self):
        env = dict(os.environ)
        env.update({
            "FW_MODE": self.mode, "FW_THRESHOLD": str(self.threshold), "FW_WINDOW": str(self.window),
            "FW_BLOCK_TIME": str(self.block_time), "LOGGER_HOST": T.MGMT_LOGGER,
            "LOGGER_PORT": str(T.LOGGER_PORT),
            "FW_SPOOL": os.path.join(self.out_dir, "controller_spool.jsonl"),
        })
        env.update({k: str(v) for k, v in self.extra_env.items()})
        self.ctrl_log = open(os.path.join(self.out_dir, "controller.log"), "w")
        self.ctrl = subprocess.Popen(
            ["ryu-manager", "--ofp-tcp-listen-port", str(self.controller_port),
             os.path.join(ROOT, "controller", "firewall_controller.py")],
            cwd=ROOT, env=env, stdout=self.ctrl_log, stderr=subprocess.STDOUT)
        end = time.time() + 20
        while time.time() < end:
            if self.ctrl.poll() is not None:
                raise LabError("ryu-manager exited early, see %s/controller.log" % self.out_dir)
            with socket.socket() as s:
                s.settimeout(0.3)
                if s.connect_ex(("127.0.0.1", self.controller_port)) == 0:
                    return
            time.sleep(0.2)
        raise LabError("controller did not start listening on %d" % self.controller_port)

    @staticmethod
    def _wait_port(host, port, timeout):
        end = time.time() + timeout
        while time.time() < end:
            with socket.socket() as s:
                s.settimeout(0.3)
                if s.connect_ex((host, port)) == 0:
                    return True
            time.sleep(0.2)
        return False

    def stop(self):
        for p in self.procs.values():
            try:
                p.terminate()
            except Exception:
                pass
        if self.net is not None:
            self.net.stop()
            self.net = None
        if self.ctrl is not None and self.ctrl.poll() is None:
            self.ctrl.send_signal(signal.SIGINT)
            try:
                self.ctrl.wait(5)
            except subprocess.TimeoutExpired:
                self.ctrl.kill()
        self.ctrl = None

    # ------------------------------------------------------------------
    # running things inside hosts
    # ------------------------------------------------------------------
    def host(self, name):
        return self.net.get(name)

    def _cmd(self, args):
        return " ".join(shlex.quote(str(a)) for a in args)

    def client(self, host, port=5000, mode="ping", count=5, interval=0.0, size=1000000,
               timeout=3.0, target=T.SRV_IP):
        """Run app/client.py in a host; returns its JSON dict plus 'exit'."""
        cmd = self._cmd(["python3", "app/client.py", "--host", target, "--port", port, "--mode", mode,
                         "--count", count, "--interval", interval, "--size", size, "--timeout", timeout])
        out = self.host(host).cmd(cmd + "; echo EXIT:$?")
        body, _, code = out.rpartition("EXIT:")
        res = last_json(body)
        res["exit"] = int(code.strip() or -1)
        return res

    def popen_json(self, host, args):
        """Start a command in a host; .result() later returns its JSON."""
        p = self.host(host).popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, cwd=ROOT)
        return PendingJson(p)

    def attack(self, host, mode="burst", port=5001, ports="1000-1999", rate=100, count=0, duration=5.0,
               background=False):
        args = ["python3", "experiments/attack.py", "--target", T.SRV_IP, "--mode", mode, "--port", str(port),
                "--ports", ports, "--rate", str(rate), "--count", str(count), "--duration", str(duration)]
        job = self.popen_json(host, args)
        return job if background else job.result()

    def legit(self, host, duration=5.0, pings=5, gap=0.05, background=False):
        args = ["python3", "experiments/legit_loop.py", "--host", T.SRV_IP, "--duration", str(duration),
                "--pings", str(pings), "--gap", str(gap)]
        job = self.popen_json(host, args)
        return job if background else job.result()

    def ping(self, src, dst_ip, count=1, wait=1):
        out = self.host(src).cmd("ping -c %d -W %d -q %s; echo EXIT:$?" % (count, wait, dst_ip))
        return int(out.rpartition("EXIT:")[2].strip() or 1) == 0

    # ------------------------------------------------------------------
    # switch / log inspection
    # ------------------------------------------------------------------
    @staticmethod
    def ovs(*args):
        return subprocess.run(["ovs-ofctl"] + OVS_FLAGS + list(args), capture_output=True, text=True,
                              timeout=10).stdout

    def dump_flows(self, sw="s1"):
        return [l.strip() for l in self.ovs("dump-flows", sw).splitlines() if "cookie=" in l]

    def flow_count(self, sw="s1"):
        out = self.ovs("dump-aggregate", sw)
        for tok in out.replace(",", " ").split():
            if tok.startswith("flow_count="):
                return int(tok.split("=")[1])
        return -1

    def has_flow(self, needle, sw="s1"):
        return any(needle in l for l in self.dump_flows(sw))

    def wait_for(self, predicate, timeout=10.0, step=0.1):
        """Poll predicate(); returns (True, seconds_waited) or (False, timeout)."""
        t0 = time.time()
        while time.time() - t0 < timeout:
            if predicate():
                return True, time.time() - t0
            time.sleep(step)
        return False, timeout

    @property
    def events_path(self):
        return os.path.join(self.out_dir, "logger", "events.jsonl")

    def events(self):
        if not os.path.exists(self.events_path):
            return []
        out = []
        with open(self.events_path) as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except ValueError:
                        pass
        return out

    def spool(self):
        path = os.path.join(self.out_dir, "controller_spool.jsonl")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            return [json.loads(l) for l in fh if l.strip()]

    # -- logger lifecycle (for the 'logger unreachable' scenario) ---------
    def kill_logger(self):
        p = self.procs.get("logger")
        if p and p.poll() is None:
            p.terminate()
            p.wait(5)

    def start_logger(self):
        log_out = open(os.path.join(self.out_dir, "logger.stdout"), "ab")
        self.procs["logger"] = self.host("logger").popen(
            [sys.executable, os.path.join(ROOT, "logger", "logger_server.py"), "--port", str(T.LOGGER_PORT),
             "--out-dir", os.path.join(self.out_dir, "logger"), "--quiet"],
            stdout=log_out, stderr=log_out, cwd=ROOT)
        self._wait_port(T.MGMT_LOGGER, T.LOGGER_PORT, 10)


class PendingJson(object):
    def __init__(self, proc):
        self.proc = proc

    def result(self, timeout=120):
        out, _ = self.proc.communicate(timeout=timeout)
        return last_json(out.decode("utf-8", "replace"))
