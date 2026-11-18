#!/usr/bin/env python3
"""Mininet topology for the dynamic-firewall project.

                              c0  (Ryu, 127.0.0.1:6633)
                              |  OpenFlow 1.3
                              |       |
      h1 .. h6 --- s1 (edge/firewall) --- s2 (core) --- srv     10.0.0.10   ports 5000 5001 5002
      10.0.0.1..6                          |
                                           +--------- logger  10.0.0.100  port 9999
                                                         |  second NIC (management)
                                                         +-- root namespace 192.168.99.1  <- controller
                                                                          (logger = 192.168.99.2)

h1-h3 are the three standard clients, h4-h5 extra legitimate clients for the
scaling experiments, h6 is the dedicated attacker for the measurements.

Usage (needs root, Mininet and OVS; start the controller first):
    FW_MODE=dynamic ryu-manager controller/firewall_controller.py     # terminal 1
    sudo python3 topo/topo.py                                          # terminal 2
"""
import argparse
import os
import sys

from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import Node, OVSKernelSwitch, RemoteController

from topo.constants import (LOGGER_IP, LOGGER_PORT, MGMT_LOGGER, MGMT_ROOT, ROOT,  # noqa: E402,F401
                            SERVER_PORTS, SRV_IP, client_ip)


def build_net(n_clients=6, controller_ip="127.0.0.1", controller_port=6633, bw=100, core_bw=1000):
    """Create (but do not start) the network. Returns (net, root_node)."""
    net = Mininet(controller=None, switch=OVSKernelSwitch, link=TCLink,
                  autoSetMacs=False, autoStaticArp=False, build=False)
    net.addController("c0", controller=RemoteController, ip=controller_ip, port=controller_port)
    s1 = net.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13", failMode="secure")
    s2 = net.addSwitch("s2", dpid="0000000000000002", protocols="OpenFlow13", failMode="secure")
    for i in range(1, n_clients + 1):
        h = net.addHost("h%d" % i, ip=client_ip(i) + "/24", mac="00:00:00:00:00:%02x" % i)
        net.addLink(h, s1, bw=bw)
    srv = net.addHost("srv", ip=SRV_IP + "/24", mac="00:00:00:00:00:0a")
    logger = net.addHost("logger", ip=LOGGER_IP + "/24", mac="00:00:00:00:00:64")
    net.addLink(s1, s2, bw=core_bw)
    net.addLink(srv, s2, bw=core_bw)
    net.addLink(logger, s2, bw=bw)

    # management path: root namespace <-> logger (the controller lives in the root namespace)
    root = Node("root", inNamespace=False)
    mgmt = net.addLink(root, logger, intfName1="fwmgmt0", intfName2="logger-mgmt")
    root.setIP(MGMT_ROOT + "/24", intf=mgmt.intf1)
    return net, root, mgmt


def finish_setup(net, root, mgmt):
    net.get("logger").setIP(MGMT_LOGGER + "/24", intf=mgmt.intf2)
    for h in net.hosts:
        h.cmd("sysctl -qw net.ipv6.conf.all.disable_ipv6=1")      # keep the control plane quiet
    root.cmd("ip link set fwmgmt0 up")


def start_services(net, out_dir, quiet=True):
    """Start logger and application server inside their Mininet hosts."""
    os.makedirs(out_dir, exist_ok=True)
    procs = {}
    log_out = open(os.path.join(out_dir, "logger.stdout"), "ab")
    srv_out = open(os.path.join(out_dir, "server.stdout"), "ab")
    procs["logger"] = net.get("logger").popen(
        [sys.executable, os.path.join(ROOT, "logger", "logger_server.py"), "--port", str(LOGGER_PORT),
         "--out-dir", os.path.join(out_dir, "logger")] + (["--quiet"] if quiet else []),
        stdout=log_out, stderr=log_out, cwd=ROOT)
    procs["srv"] = net.get("srv").popen(
        [sys.executable, os.path.join(ROOT, "app", "server.py"), "--ports"] + [str(p) for p in SERVER_PORTS],
        stdout=srv_out, stderr=srv_out, cwd=ROOT)
    return procs


class FirewallCLI(CLI):
    """Mininet CLI with a few project shortcuts."""

    def do_flows(self, line):
        """flows [s1|s2]  -- dump the OpenFlow table of a switch."""
        sw = line.strip() or "s1"
        os.system("ovs-ofctl -O OpenFlow13 dump-flows %s | sed 's/^ //'" % sw)

    def do_attack(self, line):
        """attack <host> [rate] [ports]  -- port sweep from a host, e.g. 'attack h3 100 1000-1200'."""
        parts = line.split()
        if not parts:
            print("usage: attack <host> [rate] [ports]")
            return
        host = self.mn.get(parts[0])
        rate = parts[1] if len(parts) > 1 else "100"
        ports = parts[2] if len(parts) > 2 else "1000-1300"
        print(host.cmd("python3 experiments/attack.py --target %s --mode sweep --ports %s --rate %s --count 300"
                       % (SRV_IP, ports, rate)))


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--clients", type=int, default=6)
    ap.add_argument("--controller-ip", default="127.0.0.1")
    ap.add_argument("--controller-port", type=int, default=6633)
    ap.add_argument("--bw", type=float, default=100, help="client link bandwidth, Mbit/s")
    ap.add_argument("--out-dir", default=os.path.join(ROOT, "logs"))
    ap.add_argument("--no-services", action="store_true", help="do not start logger/server")
    args = ap.parse_args()

    os.chdir(ROOT)
    setLogLevel("info")
    net, root, mgmt = build_net(args.clients, args.controller_ip, args.controller_port, args.bw)
    net.start()
    finish_setup(net, root, mgmt)
    procs = {} if args.no_services else start_services(net, args.out_dir, quiet=False)
    try:
        net.waitConnected(timeout=15)
    except Exception:
        pass
    print("\nhosts: h1..h%d (clients)  srv=%s  logger=%s\n"
          "try:   h1 python3 app/client.py --host %s --port 5000\n"
          "       h3 python3 app/client.py --host %s --port 5001      (forbidden)\n"
          "       attack h3 100 1000-1300     |     flows s1\n"
          % (args.clients, SRV_IP, LOGGER_IP, SRV_IP, SRV_IP))
    try:
        FirewallCLI(net)
    finally:
        for p in procs.values():
            p.terminate()
        net.stop()


if __name__ == "__main__":
    main()
