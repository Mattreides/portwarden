#!/usr/bin/env python3
"""
portwarden.py — periodic listening-port audit with optional enforcement.

Each run:
  1. Enumerates listening TCP/UDP sockets (ss).
  2. Never acts on listeners that are allowlisted, bound to loopback only (not
     reachable from the network), WireGuard tunnel ports, or sockets with no
     owning process (kernel sockets). These are reported with their reason.
  3. Measures activity for the rest: established TCP connections and connected
     or busy UDP sockets right now, plus (as root) inbound packets counted by
     counting-only nftables rules since the previous run.
  4. Tracks consecutive idle runs per listener in a state file.
  5. For listeners idle >= --threshold runs, applies --action:
       report  : log only (default)
       block   : add nftables drop rule for inbound non-loopback traffic to that port
       kill    : SIGTERM the listening process (SIGKILL on --force)
  6. Lifts a block when the port is used again over loopback, becomes
     allowlisted, or its listener goes away; --unblock lifts one by hand.

A UDP listener with no counter data (first run, or not root) is reported as
"no data" and never acted on: ss alone cannot tell a busy UDP listener from an
idle one.

Run as root for block/kill. Designed for a systemd timer (see --install).
"""

import argparse, ipaddress, json, os, re, signal, subprocess, sys, time
from pathlib import Path

BANNER = r"""
 ____   ___  ____ _____ __        ___    ____  ____  _____ _   _
|  _ \ / _ \|  _ \_   _|\ \      / / \  |  _ \|  _ \| ____| \ | |
| |_) | | | | |_) || |   \ \ /\ / / _ \ | |_) | | | |  _| |  \| |
|  __/| |_| |  _ < | |    \ V  V / ___ \|  _ <| |_| | |___| |\  |
|_|    \___/|_| \_\|_|     \_/\_/_/   \_\_| \_\____/|_____|_| \_|
        listening-port audit  ::  report | block | kill
"""

STATE_FILE = Path("/var/lib/portwarden/state.json")
LOG_FILE   = Path("/var/log/portwarden.log")
NFT_TABLE  = "portwarden"
PROTOS     = ("tcp", "udp")   # only these ever reach an nft command line
SAFE_ARG   = re.compile(r"[A-Za-z0-9._@:+-]+")   # values safe to embed in a unit file
KEY_RE     = re.compile(r"(tcp|udp):(\d{1,5})")
WATCH_RE   = re.compile(r"pw-watch-(tcp|udp)-(\d+)")

# ----- defaults: never touch these ---------------------------------------
DEFAULT_ALLOW_PORTS = {22, 53, 67, 68, 123, 631}       # ssh dns dhcp ntp cups
DEFAULT_ALLOW_PROCS = {"sshd", "systemd-resolve", "systemd-resolved",
                       "NetworkManager", "dhclient", "chronyd", "ntpd",
                       "avahi-daemon", "cupsd", "dbus-daemon", "systemd"}
# -------------------------------------------------------------------------

def sh(cmd, check=False):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, check=check)

def nft(*args):
    """Run nft with an argument list (no shell involved)."""
    try:
        return subprocess.run(["nft", *args], text=True, capture_output=True)
    except FileNotFoundError:
        return subprocess.CompletedProcess(["nft", *args], 127, "", "nft not found")

def is_root():
    return os.geteuid() == 0

def log(msg):
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} {msg}"
    try:
        print(line, flush=True)
    except BrokenPipeError:
        pass
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(line + "\n")
    except PermissionError:
        pass

def row(key, proc, pid, tag):
    return f"{key:<10} {proc or '?':<20} pid={pid or '-':<7} {tag}"

# ----- socket discovery --------------------------------------------------
def split_addr(local):
    """'127.0.0.53%lo:53' -> ('127.0.0.53', 53); '[::1]:631' -> ('::1', 631).
    Returns (None, None) when there is no numeric port."""
    host, _, port = local.rpartition(":")
    if not port.isdigit():
        return None, None
    return host.strip("[]").split("%", 1)[0], int(port)

def is_loopback(host):
    """True for 127.0.0.0/8, ::1 and IPv4-mapped loopback. '*', '0.0.0.0'
    and '::' (all interfaces) are reachable from the network."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    mapped = getattr(ip, "ipv4_mapped", None)
    return (mapped or ip).is_loopback

def listeners():
    """Return dict keyed by (proto, port) -> {pid, proc, addrs}.
    IPv4 and IPv6 sockets on the same port are merged; every bound address
    is kept so loopback-only listeners can be told apart."""
    res = {}
    for ln in sh("ss -tulnpH").stdout.splitlines():
        parts = ln.split()
        if len(parts) < 5 or parts[0] not in PROTOS:
            continue
        host, port = split_addr(parts[4])
        if port is None:
            continue
        e = res.setdefault((parts[0], port), {"pid": None, "proc": None, "addrs": []})
        e["addrs"].append(host)
        pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', ln)
        if pm and e["pid"] is None:
            e["proc"], e["pid"] = pm.group(1), int(pm.group(2))
    return res

def local_only(info):
    return bool(info["addrs"]) and all(is_loopback(a) for a in info["addrs"])

def wireguard_ports():
    """UDP ports of WireGuard interfaces (needs root; empty otherwise).
    Their sockets belong to the kernel, so ss shows no owner for them."""
    ports = set()
    r = sh("wg show all listen-port")
    if r.returncode == 0:
        for ln in r.stdout.splitlines():
            parts = ln.split()
            if len(parts) == 2 and parts[1].isdigit():
                ports.add(int(parts[1]))
    return ports

def _ss_rows(cmd):
    """Yield (state, recv_q, send_q, local) per ss -H row. ss prints a State
    column only when more than one state is selected, so detect it."""
    for ln in sh(cmd).stdout.splitlines():
        parts = ln.split()
        state = parts.pop(0) if parts and not parts[0].isdigit() else ""
        if len(parts) >= 3:
            yield state, parts[0], parts[1], parts[2]

def snapshot_activity():
    """(proto, port) pairs in use right now: established TCP connections, and
    UDP sockets that are connected or have queued bytes. A plain UDP listener
    (UNCONN, empty queues) looks the same here busy or idle, which is why
    watch_counters() exists."""
    active = set()
    for _, _, _, local in _ss_rows("ss -tnH state established"):
        _, port = split_addr(local)
        if port is not None:
            active.add(("tcp", port))
    for state, rq, sq, local in _ss_rows("ss -uanH"):
        _, port = split_addr(local)
        if port is not None and (state == "ESTAB" or rq != "0" or sq != "0"):
            active.add(("udp", port))
    return active

def exempt_reason(proto, port, info, allow_ports, allow_procs, wg_ports):
    """Why a listener must never be blocked or killed, or None."""
    if port in allow_ports or info["proc"] in allow_procs:
        return "ALLOW"
    if local_only(info):
        return "LOCAL"        # loopback only: not reachable from the network
    if proto == "udp" and port in wg_ports:
        return "WIREGUARD"
    if info["pid"] is None:
        return "NO-OWNER"     # kernel socket, or another user's without root
    return None

# ----- nftables ----------------------------------------------------------
def nft_rules(chain):
    """[(handle, comment, packets)] for the rules in one of our chains."""
    r = nft("-j", "list", "chain", "inet", NFT_TABLE, chain)
    if r.returncode != 0:
        return []
    try:
        items = json.loads(r.stdout).get("nftables", [])
    except ValueError:
        return []
    out = []
    for it in items:
        rule = it.get("rule") if isinstance(it, dict) else None
        if not rule:
            continue
        packets = 0
        for e in rule.get("expr", []):
            if isinstance(e, dict) and "counter" in e:
                packets = e["counter"].get("packets", 0)
        out.append((rule.get("handle"), rule.get("comment", ""), packets))
    return out

def nft_ensure_table():
    """Table with two accept-policy chains: 'watch' only counts packets,
    'input' holds the drop rules for blocked ports."""
    if nft("list", "table", "inet", NFT_TABLE).returncode != 0:
        nft("add", "table", "inet", NFT_TABLE)
    for chain, prio in (("watch", -20), ("input", -10)):
        if nft("list", "chain", "inet", NFT_TABLE, chain).returncode != 0:
            nft("add", "chain", "inet", NFT_TABLE, chain,
                "{ type filter hook input priority %d; policy accept; }" % prio)

def nft_block(proto, port):
    """Drop inbound traffic to the port, except over loopback: local clients
    keep working, and their use is what can lift the block again."""
    nft_ensure_table()
    r = nft("add", "rule", "inet", NFT_TABLE, "input", "iifname", "!=", '"lo"',
            proto, "dport", str(port), "counter", "drop",
            "comment", f'"pw-{proto}-{port}"')
    if r.returncode != 0:
        log(f"  ! nft could not block {proto}:{port}: {r.stderr.strip()}")
        return False
    return True

def nft_delete(chain, comment):
    for handle, c, _ in nft_rules(chain):
        if c == comment and handle is not None:    # exact: pw-tcp-80 != pw-tcp-8080
            nft("delete", "rule", "inet", NFT_TABLE, chain, "handle", str(handle))

def nft_unblock(proto, port):
    nft_delete("input", f"pw-{proto}-{port}")

def watch_counters(keys):
    """Inbound packet counts per listener from counting-only nftables rules
    (root only; the rules accept everything). Adds a rule for each key that
    lacks one and drops rules for keys no longer watched. TCP counts packets
    of established connections, UDP counts every inbound packet. Returns
    {key: packets}, or None when nftables is not usable."""
    if not is_root():
        return None
    nft_ensure_table()
    if nft("list", "chain", "inet", NFT_TABLE, "watch").returncode != 0:
        return None
    have = {}
    for handle, comment, packets in nft_rules("watch"):
        m = WATCH_RE.fullmatch(comment or "")
        if m:
            have[f"{m.group(1)}:{m.group(2)}"] = (handle, packets)
    counts = {}
    for key in sorted(keys):
        if key in have:
            counts[key] = have[key][1]
            continue
        proto, port = key.split(":")
        match = ["ct", "state", "established"] if proto == "tcp" else []
        r = nft("add", "rule", "inet", NFT_TABLE, "watch", *match, proto, "dport",
                port, "counter", "comment", f'"pw-watch-{proto}-{port}"')
        if r.returncode == 0:
            counts[key] = 0                          # new counter starts at zero
    for key, (handle, _) in have.items():
        if key not in keys and handle is not None:
            nft("delete", "rule", "inet", NFT_TABLE, "watch", "handle", str(handle))
    return counts

def kill_pid(pid, force=False):
    try:
        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        log(f"  ! no permission to kill pid {pid}")
        return False

# ----- state -------------------------------------------------------------
def load_state():
    try:
        st = json.loads(STATE_FILE.read_text())
    except Exception:
        st = {}
    st.setdefault("idle", {})
    st.setdefault("blocked", [])
    st.setdefault("counters", {})
    return st

def save_state(st):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=1))
        os.replace(tmp, STATE_FILE)          # atomic: no half-written state
    except OSError as e:
        log(f"  ! state not saved to {STATE_FILE} ({e.strerror}); run as root")

def blocked_set(st):
    return {(p, int(n)) for p, n in st.get("blocked", []) if p in PROTOS}

# ----- main --------------------------------------------------------------
def run(args):
    allow_ports = DEFAULT_ALLOW_PORTS | set(args.allow_port)
    allow_procs = DEFAULT_ALLOW_PROCS | set(args.allow_proc)
    st = load_state()
    idle, prev = st["idle"], st["counters"]
    blocked = blocked_set(st)

    lst = listeners()
    snap = snapshot_activity()
    wg = wireguard_ports()

    exempt = {}
    for (proto, port), info in lst.items():
        reason = exempt_reason(proto, port, info, allow_ports, allow_procs, wg)
        if reason:
            exempt[f"{proto}:{port}"] = reason
    watched = {f"{p}:{n}" for (p, n) in lst} - set(exempt)
    counts = watch_counters(watched)
    seen = set()

    for (proto, port), info in sorted(lst.items(), key=lambda x: x[0][1]):
        key = f"{proto}:{port}"
        seen.add(key)
        proc, pid = info["proc"], info["pid"]

        if key in exempt:
            idle.pop(key, None)
            if (proto, port) in blocked:
                nft_unblock(proto, port); blocked.discard((proto, port))
                log(f"UNBLOCK {key} ({proc}) — exempt now ({exempt[key]})")
            log(row(key, proc, pid, exempt[key]))
            continue

        if (proto, port) in blocked:
            # Remote traffic is dropped, so only local use can show up here.
            if (proto, port) in snap:
                nft_unblock(proto, port); blocked.discard((proto, port))
                idle[key] = 0
                log(f"UNBLOCK {key} ({proc}) — used again over loopback")
                log(row(key, proc, pid, "ACTIVE"))
            else:
                log(row(key, proc, pid, "BLOCKED"))
            continue

        delta = None
        if counts is not None and key in counts and key in prev \
                and counts[key] >= prev[key]:
            delta = counts[key] - prev[key]

        if (proto, port) in snap or (delta or 0) > 0:
            idle[key] = 0
            tag = "ACTIVE"
        elif delta is not None or proto == "tcp":
            idle[key] = idle.get(key, 0) + 1
            tag = f"idle x{idle[key]}"
        else:
            # UDP without a counter baseline: busy and idle look the same.
            log(row(key, proc, pid, "no data"))
            continue
        log(row(key, proc, pid, tag))

        if tag == "ACTIVE" or idle[key] < args.threshold:
            continue

        # --- enforcement ---
        if args.action == "report":
            log("  -> idle past threshold; --action block|kill would act (report mode)")
        elif args.action == "block":
            if nft_block(proto, port):
                blocked.add((proto, port))
                log(f"  -> BLOCKED inbound {key} (loopback still allowed)")
        elif args.action == "kill":
            if pid and pid > 1 and kill_pid(pid, args.force):
                log(f"  -> KILLED {proc} pid={pid} (owner of {key})")
                idle.pop(key, None)

    # forget listeners that vanished
    for p, n in sorted(blocked):
        if f"{p}:{n}" not in seen:
            nft_unblock(p, n); blocked.discard((p, n))
            log(f"UNBLOCK {p}:{n} — listener gone")
    for k in list(idle):
        if k not in seen:
            idle.pop(k)

    st["idle"] = idle
    st["blocked"] = sorted(list(x) for x in blocked)
    st["counters"] = counts if counts is not None else {}
    save_state(st)

def unblock(specs):
    """Lift portwarden's block on each 'proto:port' and restart its idle count.
    It will be blocked again if it stays idle; allowlist it to keep it open."""
    parsed = []
    for spec in specs:
        m = KEY_RE.fullmatch(spec)
        if not m:
            sys.exit(f"--unblock {spec!r}: expected tcp:PORT or udp:PORT")
        parsed.append((m.group(1), int(m.group(2))))
    st = load_state()
    blocked = blocked_set(st)
    for proto, port in parsed:
        nft_unblock(proto, port)
        blocked.discard((proto, port))
        st["idle"].pop(f"{proto}:{port}", None)
        log(f"UNBLOCK {proto}:{port} — by hand")
    st["blocked"] = sorted(list(x) for x in blocked)
    save_state(st)

SERVICE = """[Unit]
Description=portwarden listening-port audit

[Service]
Type=oneshot
ExecStart=/usr/local/bin/portwarden.py {args}
"""
TIMER = """[Unit]
Description=Run portwarden every {interval}

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval}
AccuracySec=30s

[Install]
WantedBy=timers.target
"""

def service_args(args):
    """Command-line flags for the installed service, so the timer runs with the
    same allowlist and options as the --install invocation."""
    out = ["--action", args.action, "--threshold", str(args.threshold)]
    if args.force:
        out.append("--force")
    for p in args.allow_port:
        out += ["--allow-port", str(p)]
    for name in args.allow_proc:
        if not SAFE_ARG.fullmatch(name):
            sys.exit(f"--allow-proc {name!r}: with --install, names may only "
                     "contain letters, digits and . _ @ : + -")
        out += ["--allow-proc", name]
    return " ".join(out)

def install(args):
    if os.geteuid() != 0:
        sys.exit("run --install as root")
    if not re.fullmatch(r"[0-9A-Za-z. ]+", args.interval):
        sys.exit(f"--interval {args.interval!r}: expected a systemd time span like 10min")
    exec_args = service_args(args)
    Path("/usr/local/bin/portwarden.py").write_text(Path(__file__).read_text())
    os.chmod("/usr/local/bin/portwarden.py", 0o755)
    Path("/etc/systemd/system/portwarden.service").write_text(
        SERVICE.format(args=exec_args))
    Path("/etc/systemd/system/portwarden.timer").write_text(
        TIMER.format(interval=args.interval))
    r = sh("systemctl daemon-reload && systemctl enable --now portwarden.timer")
    if r.returncode != 0:
        sys.exit(f"systemctl failed: {r.stderr.strip()}")
    print(f"installed: every {args.interval}, {exec_args}")
    print("  journalctl -u portwarden   |   tail -f /var/log/portwarden.log")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--action", choices=["report", "block", "kill"], default="report",
                    help="what to do with idle listeners (default report)")
    ap.add_argument("--threshold", type=int, default=3,
                    help="consecutive idle runs before acting (default 3)")
    ap.add_argument("--force", action="store_true", help="SIGKILL instead of SIGTERM")
    ap.add_argument("--allow-port", type=int, action="append", default=[],
                    help="never act on this port (repeatable)")
    ap.add_argument("--allow-proc", action="append", default=[],
                    help="never act on listeners owned by this process name (repeatable)")
    ap.add_argument("--unblock", metavar="PROTO:PORT", action="append", default=[],
                    help="lift portwarden's block on a port, e.g. tcp:8080 (repeatable)")
    ap.add_argument("--install", action="store_true", help="install systemd service+timer")
    ap.add_argument("--interval", default="10min", help="timer interval for --install")
    ap.add_argument("--reset", action="store_true", help="clear state and nft rules")
    ap.add_argument("--no-banner", action="store_true", help="suppress ASCII banner")
    a = ap.parse_args()
    if sys.stdout.isatty() and not a.no_banner:
        print(BANNER)
    if (a.reset or a.install or a.unblock or a.action == "block") and os.geteuid() != 0:
        sys.exit("--reset, --install, --unblock and --action block need root")
    if a.reset:
        nft("delete", "table", "inet", NFT_TABLE)
        STATE_FILE.unlink(missing_ok=True); print("reset"); sys.exit()
    if a.unblock:
        unblock(a.unblock)
    elif a.install:
        install(a)
    else:
        run(a)
