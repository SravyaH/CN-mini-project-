#!/usr/bin/env bash
# Reproducible demo / full verification. Usage:
#   sudo ./demo.sh            narrated demo (~1 min)
#   sudo ./demo.sh test       unit tests + Mininet functional tests (~5 min)
#   sudo ./demo.sh measure    quick measurement grid + graphs (~10 min); add "full" for the whole grid
set -euo pipefail
cd "$(dirname "$0")"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
for t in mn ovs-ofctl ryu-manager python3; do command -v "$t" >/dev/null || { echo "missing: $t (see README)"; exit 1; }; done
mn -c >/dev/null 2>&1 || true
case "${1:-demo}" in
  demo)    python3 demo/demo.py ;;
  test)    python3 -m unittest discover -s tests -t . -v 2>&1 | tail -5
           python3 tests/mininet_functional.py ;;
  measure) if [ "${2:-quick}" = full ]; then python3 experiments/measure.py; else python3 experiments/measure.py --quick; fi
           python3 experiments/plot.py ;;
  *) echo "usage: $0 [demo|test|measure [full]]"; exit 1 ;;
esac
mn -c >/dev/null 2>&1 || true
