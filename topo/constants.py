"""Addresses shared by the topology, the tests and the measurements (no Mininet import)."""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRV_IP, LOGGER_IP = "10.0.0.10", "10.0.0.100"
MGMT_ROOT, MGMT_LOGGER = "192.168.99.1", "192.168.99.2"
LOGGER_PORT = 9999
SERVER_PORTS = (5000, 5001, 5002)


def client_ip(i):
    return "10.0.0.%d" % i
