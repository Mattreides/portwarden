#!/usr/bin/env python3
"""
portwarden.py — periodic listening-port audit with optional enforcement.

Each run:
  1. Enumerates listening TCP/UDP sockets (ss).
  2. Counts established connections per listening port.
  3. Tracks consecutive idle runs per listener in a state file.
  4. For listeners idle >= --threshold runs and not allowlisted, applies --action:
       report  : log only (default)
       block   : add nftables drop rule for inbound traffic to that port
       kill    : SIGTERM the listening process (SIGKILL on --force)
  5. Listeners that become active again are un-blocked automatically.

Run as root for block/kill. Designed for a systemd timer (see --install).
"""

import argparse, json, os, re, signal, subprocess, sys, time
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

# ----- defaults: never touch these ---------------------------------------
DEFAULT_ALLOW_PORTS = {22, 53, 67, 68, 123, 631}       # ssh dns dhcp ntp cups
DEFAULT_ALLOW_PROCS = {"sshd", "systemd-resolve", "systemd-resolved",
                       "NetworkManager", "dhclient", "chronyd", "ntpd",
                       "avahi-daemon", "cupsd", "dbus-daemon", "systemd"}
# -------------------------------------------------------------------------

def sh(cmd, check=False):
    return subprocess.run(cmd, shell=True, text=True, capture_output=True, check=check)

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

def listeners():
    """Return dict keyed by (proto, port) -> {pid, proc, addr}."""
    out = sh("ss -tulnpH").stdout
    res = {}
    for ln in out.splitlines():
        parts = ln.split()
        if len(parts) < 5:
            continue
        proto, local = parts[0], parts[4]
        if proto not in PROTOS:
            continue
        m = re.search(r":(\d+)$", local)
        if not m:
            continue
        port = int(m.group(1))
        pid = proc = None
        pm = re.search(r'users:\(\("([^"]+)",pid=(\d+)', ln)
        if pm:
            proc, pid = pm.group(1), int(pm.group(2))
        key = (proto, port)
        # keep first entry per proto/port (v4+v6 duplicates)
        res.setdefault(key, {"pid": pid, "proc": proc, "addr": local})
    return res

def active_ports():
    """Set of (proto, local_port) with established/active connections."""
    active = set()
    for ln in sh("ss -tnH state established").stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 4:
            m = re.search(r":(\d+)$", parts[2])
            if m:
                active.add(("tcp", int(m.group(1))))
    # UDP has no "established"; treat any socket with queued bytes as active
    for ln in sh("ss -unH").stdout.splitlines():
        parts = ln.split()
        if len(parts) >= 4 and (parts[0] != "0" or parts[1] != "0"):
            m = re.search(r":(\d+)$", parts[2])
            if m:
                active.add(("udp", int(m.group(1))))
    return active

def load_state():
    try:
        return json.loads(STATE_FILE.read_text())
    except Exception:
        return {"idle": {}, "blocked": []}

def save_state(st):
    try:
        STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(st, indent=1))
        os.replace(tmp, STATE_FILE)          # atomic: no half-written state
    except OSError as e:
        log(f"  ! state not saved to {STATE_FILE} ({e.strerror}); run as root")

# ----- enforcement -------------------------------------------------------
def nft_ensure_table():
    if sh(f"nft list table inet {NFT_TABLE}").returncode != 0:
        sh(f"nft add table inet {NFT_TABLE}")
        sh(f"nft add chain inet {NFT_TABLE} input "
           "'{ type filter hook input priority -10; policy accept; }'")

def nft_block(proto, port):
    nft_ensure_table()
    r = sh(f"nft add rule inet {NFT_TABLE} input {proto} dport {port} "
           f"comment \"pw-{proto}-{port}\" drop")
    if r.returncode != 0:
        log(f"  ! nft could not block {proto}:{port}: {r.stderr.strip()}")
        return False
    return True

def nft_unblock(proto, port):
    out = sh(f"nft -a list chain inet {NFT_TABLE} input").stdout
    for ln in out.splitlines():
        if f'pw-{proto}-{port}' in ln:
            h = re.search(r"handle (\d+)", ln)
            if h:
                sh(f"nft delete rule inet {NFT_TABLE} input handle {h.group(1)}")

def kill_pid(pid, force=False):
    try:
        os.kill(pid, signal.SIGKILL if force else signal.SIGTERM)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        log(f"  ! no permission to kill pid {pid}")
        return False

# ----- main --------------------------------------------------------------
def run(args):
    allow_ports = DEFAULT_ALLOW_PORTS | set(args.allow_port)
    allow_procs = DEFAULT_ALLOW_PROCS | set(args.allow_proc)
    st = load_state()
    idle = st["idle"]
    blocked = {(p, int(n)) for p, n in st.get("blocked", []) if p in PROTOS}

    lst = listeners()
    act = active_ports()
    seen = set()

    for (proto, port), info in sorted(lst.items(), key=lambda x: x[0][1]):
        key = f"{proto}:{port}"
        seen.add(key)
        proc, pid = info["proc"], info["pid"]
        allowed = port in allow_ports or (proc in allow_procs)
        is_active = (proto, port) in act

        if is_active:
            idle[key] = 0
            if (proto, port) in blocked:
                nft_unblock(proto, port); blocked.discard((proto, port))
                log(f"UNBLOCK {key} ({proc}) — active again")
        else:
            idle[key] = idle.get(key, 0) + 1

        tag = "ALLOW" if allowed else ("ACTIVE" if is_active else f"idle x{idle[key]}")
        log(f"{key:<10} {proc or '?':<20} pid={pid or '-':<7} {tag}")

        if allowed or is_active or idle[key] < args.threshold:
            continue

        # --- enforcement ---
        if args.action == "report":
            log("  -> idle past threshold; --action block|kill would act (report mode)")
        elif args.action == "block":
            if (proto, port) not in blocked and nft_block(proto, port):
                blocked.add((proto, port))
                log(f"  -> BLOCKED inbound {key}")
        elif args.action == "kill":
            if pid and pid > 1 and kill_pid(pid, args.force):
                log(f"  -> KILLED {proc} pid={pid} (owner of {key})")
                idle.pop(key, None)

    # forget listeners that vanished
    for k in list(idle):
        if k not in seen:
            idle.pop(k)
            p, prt = k.split(":"); prt = int(prt)
            if (p, prt) in blocked:
                nft_unblock(p, prt); blocked.discard((p, prt))

    st["idle"] = idle
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
    ap.add_argument("--install", action="store_true", help="install systemd service+timer")
    ap.add_argument("--interval", default="10min", help="timer interval for --install")
    ap.add_argument("--reset", action="store_true", help="clear state and nft rules")
    ap.add_argument("--no-banner", action="store_true", help="suppress ASCII banner")
    a = ap.parse_args()
    if sys.stdout.isatty() and not a.no_banner:
        print(BANNER)
    if (a.reset or a.install or a.action == "block") and os.geteuid() != 0:
        sys.exit("--reset, --install and --action block need root")
    if a.reset:
        sh(f"nft delete table inet {NFT_TABLE}")
        STATE_FILE.unlink(missing_ok=True); print("reset"); sys.exit()
    if a.install:
        install(a)
    else:
        run(a)
