"""Tests for portwarden.py.

Every external command (ss, wg, nft) goes through subprocess.run, which these
tests replace with FakeHost: canned `ss` output in the exact formats iproute2
prints, plus a small in-memory nftables that understands the handful of
commands portwarden issues. Nothing touches the real firewall or processes.

Run: python -m pytest
"""

import argparse
import json
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import portwarden as pw  # noqa: E402

# A desktop as root sees it: CUPS, CoolerControl and an editor helper bound to
# loopback only, avahi on mDNS, a WireGuard tunnel (kernel socket, no owner),
# and two services that really are exposed: a dev web server and a UDP daemon.
SS_LISTEN = """\
udp UNCONN 0      0        0.0.0.0:5353  0.0.0.0:* users:(("avahi-daemon",pid=966,fd=12))
udp UNCONN 0      0        0.0.0.0:49805 0.0.0.0:*
udp UNCONN 0      0        0.0.0.0:7777  0.0.0.0:* users:(("udpsvc",pid=4242,fd=5))
udp UNCONN 0      0           [::]:5353     [::]:* users:(("avahi-daemon",pid=966,fd=13))
udp UNCONN 0      0           [::]:49805    [::]:*
tcp LISTEN 0      128    127.0.0.1:11987 0.0.0.0:* users:(("coolercontrold",pid=1971,fd=9))
tcp LISTEN 0      4096   127.0.0.1:631   0.0.0.0:* users:(("cupsd",pid=1200,fd=7))
tcp LISTEN 0      512    127.0.0.1:34023 0.0.0.0:* users:(("claude",pid=30004,fd=23))
tcp LISTEN 0      128      0.0.0.0:8000  0.0.0.0:* users:(("python3",pid=2231,fd=3))
tcp LISTEN 0      4096       [::1]:631      [::]:* users:(("cupsd",pid=1200,fd=6))
tcp LISTEN 0      128        [::1]:11987    [::]:* users:(("coolercontrold",pid=1971,fd=10))
"""

# UDP sockets incl. unconnected ones, as `ss -uanH` prints them (State column first).
SS_UDP_ALL = """\
ESTAB  0      0      192.168.1.20%wlan0:68    192.168.1.1:67
UNCONN 0      0                   0.0.0.0:5353      0.0.0.0:*
UNCONN 0      0                   0.0.0.0:49805     0.0.0.0:*
UNCONN 0      0                   0.0.0.0:7777      0.0.0.0:*
UNCONN 0      0                      [::]:5353         [::]:*
UNCONN 0      0                      [::]:49805        [::]:*
"""

# `ss -unH` lists connected UDP sockets only, and without a State column.
SS_UDP_CONNECTED = "0      0      192.168.1.20%wlan0:68 192.168.1.1:67\n"

# Outbound HTTPS through the tunnel: established, but not to any listener.
SS_TCP_EST = "0      0      10.0.0.2:38824 203.0.113.10:443\n"


class FakeHost:
    def __init__(self, root=True, wg="wg0\t49805\n"):
        self.root = root
        self.wg = wg
        self.listen = SS_LISTEN
        self.tcp_est = SS_TCP_EST
        self.udp_all = SS_UDP_ALL
        self.tables = {}     # name -> {chain: [rule dicts]}
        self.handle = 0
        self.killed = []

    # -- nftables ---------------------------------------------------------
    def rules(self, chain):
        return self.tables.get("portwarden", {}).get(chain, [])

    def rule_for(self, chain, comment):
        return next((r for r in self.rules(chain) if r["comment"] == comment), None)

    def bump(self, proto, port, packets):
        """Simulate inbound traffic seen by the watch rule of proto:port."""
        r = self.rule_for("watch", f"pw-watch-{proto}-{port}")
        if r:
            r["packets"] += packets

    def nft(self, argv):
        args = list(argv[1:])
        flags = []
        while args and args[0].startswith("-"):
            flags.append(args.pop(0))
        verb, obj = args[0], args[1]
        rest = args[2:]
        if obj == "table":
            name = rest[1]
            if verb == "list":
                return (0, "") if name in self.tables else (1, "No such file")
            if verb == "add":
                self.tables.setdefault(name, {})
                return 0, ""
            if verb == "delete":
                return (0, "") if self.tables.pop(name, None) is not None else (1, "")
        if obj == "chain":
            name, chain = rest[1], rest[2]
            tbl = self.tables.get(name)
            if verb == "add":
                if tbl is None:
                    return 1, ""
                tbl.setdefault(chain, [])
                return 0, ""
            if verb == "list":
                if tbl is None or chain not in tbl:
                    return 1, "No such file or directory"
                if "-j" in flags:
                    items = [{"metainfo": {}}, {"chain": {"name": chain}}]
                    for r in tbl[chain]:
                        expr = [{"match": {"text": r["text"]}}]
                        if r["counter"]:
                            expr.append({"counter": {"packets": r["packets"], "bytes": 0}})
                        items.append({"rule": {"chain": chain, "handle": r["handle"],
                                               "comment": r["comment"], "expr": expr}})
                    return 0, json.dumps({"nftables": items})
                lines = [f"table inet {name} {{", f"\tchain {chain} {{"]
                for r in tbl[chain]:
                    lines.append(f'\t\t{r["text"]} comment "{r["comment"]}" # handle {r["handle"]}')
                lines += ["\t}", "}"]
                return 0, "\n".join(lines)
        if obj == "rule":
            name, chain = rest[1], rest[2]
            tbl = self.tables.get(name)
            if tbl is None or chain not in tbl:
                return 1, "No such file or directory"
            if verb == "add":
                expr = rest[3:]
                comment = ""
                if "comment" in expr:
                    i = expr.index("comment")
                    if i != len(expr) - 2:
                        # like real nft 1.x: the comment must come last
                        return 1, f"Error: syntax error, unexpected {expr[i + 2]}"
                    comment = expr[i + 1].strip('"')
                    expr = expr[:i] + expr[i + 2:]
                self.handle += 1
                tbl[chain].append({"handle": self.handle, "comment": comment,
                                   "text": " ".join(expr), "counter": "counter" in expr,
                                   "packets": 0})
                return 0, ""
            if verb == "delete":
                h = int(rest[4])
                tbl[chain] = [r for r in tbl[chain] if r["handle"] != h]
                return 0, ""
        return 1, f"fake nft: unsupported {argv}"

    # -- subprocess.run replacement ---------------------------------------
    def run(self, cmd, shell=False, **kw):
        argv = shlex.split(cmd) if isinstance(cmd, str) else list(cmd)
        out, rc = "", 0
        if argv[:2] == ["ss", "-tulnpH"]:
            out = self.listen
        elif argv[:2] == ["ss", "-tnH"]:
            out = self.tcp_est
        elif argv[:2] == ["ss", "-uanH"]:
            out = self.udp_all
        elif argv[:2] == ["ss", "-unH"]:
            out = SS_UDP_CONNECTED
        elif argv == ["wg", "show", "all", "listen-port"]:
            rc, out = (0, self.wg) if self.root else (1, "")
        elif argv[:2] == ["wg", "show"]:
            rc, out = 1, "Invalid parameter"    # real wg rejects anything else
        elif argv[0] == "nft":
            if not self.root:
                rc, out = 1, ""
            else:
                rc, out = self.nft(argv)
        else:
            rc = 127
        return subprocess.CompletedProcess(cmd, rc, out if rc == 0 else "", out if rc else "")


@pytest.fixture
def host(monkeypatch, tmp_path):
    h = FakeHost()
    monkeypatch.setattr(pw.subprocess, "run", h.run)
    monkeypatch.setattr(pw, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(pw, "LOG_FILE", tmp_path / "portwarden.log")
    monkeypatch.setattr(pw.os, "geteuid", lambda: 0 if h.root else 1000)

    def fake_kill(pid, sig):
        h.killed.append(pid)
    monkeypatch.setattr(pw.os, "kill", fake_kill)
    return h


def args(action="report", threshold=1, allow_port=(), allow_proc=()):
    return argparse.Namespace(action=action, threshold=threshold, force=False,
                              allow_port=list(allow_port), allow_proc=list(allow_proc))


def blocked_ports(h):
    return {r["comment"] for r in h.rules("input")}


def runs(h, a, n):
    for _ in range(n):
        pw.run(a)


# --- the hazards found on a real desktop ----------------------------------

def test_wireguard_tunnel_port_is_never_blocked(host):
    runs(host, args("block"), 4)
    assert "pw-udp-49805" not in blocked_ports(host)


def test_wireguard_port_is_labelled(host, capsys):
    pw.run(args("report"))
    line = next(l for l in capsys.readouterr().out.splitlines() if "udp:49805" in l)
    assert line.endswith("WIREGUARD")


def test_ownerless_udp_socket_is_never_blocked_even_without_wg_tool(host):
    host.wg = ""             # e.g. wireguard-tools not installed
    runs(host, args("block"), 4)
    assert "pw-udp-49805" not in blocked_ports(host)


def test_loopback_only_listeners_are_never_killed(host):
    runs(host, args("kill"), 4)
    assert 1971 not in host.killed     # coolercontrold (fan and pump control)
    assert 30004 not in host.killed    # local editor/agent helper


def test_loopback_only_listeners_are_never_blocked(host):
    runs(host, args("block"), 4)
    assert "pw-tcp-11987" not in blocked_ports(host)
    assert "pw-tcp-34023" not in blocked_ports(host)


def test_busy_udp_listener_is_not_treated_as_idle(host):
    a = args("block")
    for _ in range(5):
        pw.run(a)
        host.bump("udp", 7777, 40)     # traffic arrives between runs
    assert "pw-udp-7777" not in blocked_ports(host)


def test_udp_is_never_acted_on_without_counters(host):
    host.root = False                  # no nftables access, so no counters
    host.listen = SS_LISTEN.replace("4242", "31337")
    runs(host, args("kill"), 5)
    assert 31337 not in host.killed


def test_unblock_removes_only_the_exact_port(host):
    pw.nft_block("tcp", 80)
    pw.nft_block("tcp", 8080)
    pw.nft_unblock("tcp", 80)
    assert blocked_ports(host) == {"pw-tcp-8080"}


# --- enforcement still works where it should -------------------------------

def test_idle_exposed_tcp_listener_is_blocked_except_loopback(host):
    runs(host, args("block"), 1)
    rule = host.rule_for("input", "pw-tcp-8000")
    assert rule is not None
    assert 'iifname != "lo"' in rule["text"] or "iifname != lo" in rule["text"]


def test_quiet_udp_listener_is_blocked_once_counters_show_no_traffic(host):
    a = args("block", threshold=2)
    pw.run(a)                          # watch rule added, no baseline yet
    assert "pw-udp-7777" not in blocked_ports(host)
    pw.run(a)                          # idle x1
    assert "pw-udp-7777" not in blocked_ports(host)
    pw.run(a)                          # idle x2 -> threshold
    assert "pw-udp-7777" in blocked_ports(host)


def test_idle_exposed_tcp_listener_is_killed(host):
    runs(host, args("kill"), 1)
    assert host.killed == [2231]


def test_report_mode_never_blocks_or_kills(host):
    runs(host, args("report"), 5)
    assert blocked_ports(host) == set()
    assert host.killed == []


def test_blocked_port_is_unblocked_when_used_over_loopback(host):
    runs(host, args("block"), 1)
    assert "pw-tcp-8000" in blocked_ports(host)
    host.tcp_est = SS_TCP_EST + "0      0      127.0.0.1:8000 127.0.0.1:51514\n"
    pw.run(args("block"))
    assert "pw-tcp-8000" not in blocked_ports(host)


def test_blocked_port_is_unblocked_when_allowlisted(host):
    runs(host, args("block"), 1)
    assert "pw-tcp-8000" in blocked_ports(host)
    pw.run(args("block", allow_port=[8000]))
    assert "pw-tcp-8000" not in blocked_ports(host)


def test_unblock_command_lifts_block_and_resets_idle(host):
    runs(host, args("block"), 1)
    pw.unblock(["tcp:8000"])
    assert "pw-tcp-8000" not in blocked_ports(host)
    st = json.loads(pw.STATE_FILE.read_text())
    assert ["tcp", 8000] not in st["blocked"]
    assert "tcp:8000" not in st["idle"]


def test_unblock_rejects_bad_spec(host):
    with pytest.raises(SystemExit):
        pw.unblock(["icmp:8000"])


# --- parsing helpers -------------------------------------------------------

@pytest.mark.parametrize("local,host_,port", [
    ("127.0.0.1:631", "127.0.0.1", 631),
    ("[::1]:631", "::1", 631),
    ("127.0.0.53%lo:53", "127.0.0.53", 53),
    ("192.168.1.20%wlan0:68", "192.168.1.20", 68),
    ("[fe80::1%wlan0]:546", "fe80::1", 546),
    ("*:5353", "*", 5353),
    ("0.0.0.0:*", None, None),
])
def test_split_addr(local, host_, port):
    assert pw.split_addr(local) == (host_, port)


@pytest.mark.parametrize("addr,expected", [
    ("127.0.0.1", True), ("127.0.0.53", True), ("::1", True),
    ("::ffff:127.0.0.1", True), ("0.0.0.0", False), ("::", False),
    ("*", False), ("192.168.1.20", False),
])
def test_is_loopback(addr, expected):
    assert pw.is_loopback(addr) is expected


def test_listeners_merge_v4_and_v6_addresses(host):
    lst = pw.listeners()
    assert sorted(lst[("tcp", 631)]["addrs"]) == ["127.0.0.1", "::1"]
    assert lst[("udp", 49805)]["pid"] is None
    assert pw.local_only(lst[("tcp", 11987)])
    assert not pw.local_only(lst[("udp", 5353)])


def test_snapshot_activity_reads_udp_state_column(host):
    host.udp_all = SS_UDP_ALL + "UNCONN 512    0                   0.0.0.0:9999      0.0.0.0:*\n"
    act = pw.snapshot_activity()
    assert ("udp", 68) in act        # connected
    assert ("udp", 9999) in act      # bytes queued
    assert ("udp", 5353) not in act  # plain listener: unknown from ss alone
