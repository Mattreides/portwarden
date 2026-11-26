# portwarden

A small Linux tool that audits listening TCP/UDP ports on a schedule and spots
services that sit open but are never used. It reports them by default. It can
also block them with an nftables rule or stop the process that owns them.

Single file, Python 3 standard library only. It reads socket state from `ss`.

## Why

Every listening port is attack surface. Dev servers, forgotten debug
listeners, and services installed "just to try" often stay open long after
anyone needs them. portwarden keeps a running count of how many consecutive
runs each network-reachable listener has gone without traffic. It flags the
ones that stay idle past a threshold, and it never touches allowlisted ports
or processes, loopback-only services, or kernel sockets such as VPN tunnels.

## How it works

Each run:

1. Lists listening sockets with `ss -tulnpH` (protocol, bound addresses,
   owning process and PID). IPv4 and IPv6 sockets on the same port count as
   one listener.
2. Sets aside listeners it must never act on, and says why:
   - `ALLOW`: allowlisted port or process name
   - `LOCAL`: bound to loopback only (`127.0.0.0/8`, `::1`), so not reachable
     from the network
   - `WIREGUARD`: the UDP port of a WireGuard interface (`wg show all listen-port`)
   - `NO-OWNER`: `ss` shows no owning process. As root that means a kernel
     socket (WireGuard, NFS and similar); without root it can also be another
     user's socket
3. Measures activity for the rest:
   - right now: an established TCP connection, or a UDP socket on that port that
     is connected or has queued bytes (`ss -tnH state established`, `ss -uanH`);
   - since the last run (root only): inbound packets counted by
     counting-only nftables rules, one per listener. For TCP it counts packets
     of established connections; for UDP, every inbound packet.
4. Increments an idle counter for every listener that showed no activity, and
   resets it to 0 for listeners that did. Counters are stored in
   `/var/lib/portwarden/state.json`.
   A UDP listener with no counter data yet (the first run after it appears,
   or any run without root) is reported as `no data` and left alone, because
   `ss` alone cannot tell a busy UDP listener from an idle one.
5. For each listener that has been idle for `--threshold` consecutive runs, it
   applies `--action`:
   - `report`: log only (the default)
   - `block`: add an nftables rule that drops inbound traffic to that port
     from every interface except loopback
   - `kill`: send SIGTERM to the owning process (SIGKILL with `--force`)
6. Removes a port's block rule when the port is used again over loopback,
   when it becomes exempt (for example you allowlist it), or when its listener
   goes away. `--unblock` removes one by hand.

Output goes to stdout and is appended to `/var/log/portwarden.log`.

### Example output (illustrative)

These lines were built by hand from the script's log format. They are not a
capture from a real host.

```
2026-01-01 12:00:00 tcp:22     sshd                 pid=612     ALLOW
2026-01-01 12:00:00 udp:53     systemd-resolve      pid=401     ALLOW
2026-01-01 12:00:00 tcp:631    cupsd                pid=1200    ALLOW
2026-01-01 12:00:00 tcp:3000   node                 pid=2290    idle x3
2026-01-01 12:00:00   -> idle past threshold; --action block|kill would act (report mode)
2026-01-01 12:00:00 udp:5353   avahi-daemon         pid=455     ALLOW
2026-01-01 12:00:00 tcp:5432   postgres             pid=988     ACTIVE
2026-01-01 12:00:00 udp:7777   gamesrv              pid=3120    no data
2026-01-01 12:00:00 tcp:8000   python3              pid=2231    idle x1
2026-01-01 12:00:00 tcp:11987  coolercontrold       pid=1971    LOCAL
2026-01-01 12:00:00 udp:51820  ?                    pid=-       WIREGUARD
```

With `--action block` the line after an idle listener reads
`-> BLOCKED inbound tcp:3000 (loopback still allowed)`, and later runs show
the listener as `BLOCKED`. With `--action kill` it reads
`-> KILLED node pid=2290 (owner of tcp:3000)`.

## Requirements

- Linux with Python 3.8+
- `ss` (iproute2)
- `nft` (nftables), for `--action block`, `--unblock`, `--reset`, and the
  packet counters used when running as root
- `wg` (wireguard-tools), optional: labels WireGuard ports. Without it they
  are still left alone, as `NO-OWNER`
- systemd, only for `--install`

## Usage

```sh
# Audit only (safe): log listeners and how long each has been idle
sudo ./portwarden.py

# Treat 8080 and anything run by "myapp" as always allowed
sudo ./portwarden.py --allow-port 8080 --allow-proc myapp

# Block listeners that stay idle for 6 consecutive runs
sudo ./portwarden.py --action block --threshold 6

# Lift portwarden's block on one port
sudo ./portwarden.py --unblock tcp:8080

# Install as a systemd timer that runs every 15 minutes in report mode
sudo ./portwarden.py --install --interval 15min

# Remove portwarden's nftables table and clear its state
sudo ./portwarden.py --reset
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `--action {report,block,kill}` | `report` | What to do with listeners idle past the threshold |
| `--threshold N` | `3` | Consecutive idle runs before acting |
| `--force` | off | With `kill`, send SIGKILL instead of SIGTERM |
| `--allow-port PORT` | | Never act on this port (repeatable) |
| `--allow-proc NAME` | | Never act on listeners owned by this process name (repeatable) |
| `--unblock PROTO:PORT` | | Remove portwarden's block on a port, e.g. `tcp:8080`, and restart its idle count (repeatable) |
| `--install` | | Install the script and a systemd service and timer |
| `--interval SPAN` | `10min` | Timer interval for `--install` (systemd time span) |
| `--reset` | | Delete the `inet portwarden` nftables table and the state file |
| `--no-banner` | | Hide the ASCII banner (it is only shown on a terminal anyway) |

Never acted on, whatever the options:

- **Ports:** 22 (ssh), 53 (dns), 67/68 (dhcp), 123 (ntp), 631 (cups)
- **Processes:** `sshd`, `systemd`, `systemd-resolve(d)`, `NetworkManager`,
  `dhclient`, `chronyd`, `ntpd`, `avahi-daemon`, `cupsd`, `dbus-daemon`
- **Listeners bound to loopback only**, WireGuard ports, and sockets with no
  owning process (see step 2 above)

## Running it on a timer

`--install` (as root) does four things:

1. Copies the script to `/usr/local/bin/portwarden.py`.
2. Writes `/etc/systemd/system/portwarden.service`, a oneshot unit that runs the
   script with the same `--action`, `--threshold`, `--force`, `--allow-port`
   and `--allow-proc` values you passed to `--install`.
3. Writes `/etc/systemd/system/portwarden.timer`: first run 2 minutes after
   boot, then every `--interval`.
4. Runs `systemctl daemon-reload` and `systemctl enable --now portwarden.timer`.

Check on it with `journalctl -u portwarden` or `tail -f /var/log/portwarden.log`.

To uninstall:

```sh
sudo systemctl disable --now portwarden.timer
sudo rm /etc/systemd/system/portwarden.service /etc/systemd/system/portwarden.timer /usr/local/bin/portwarden.py
sudo systemctl daemon-reload
sudo ./portwarden.py --reset
```

## Privileges

- **Root is recommended for every mode.** Without root, `ss` cannot show which
  process owns other users' sockets (they show as `NO-OWNER` and are left
  alone), UDP listeners stay at `no data` because the packet counters need
  nftables, and the state file under `/var/lib` cannot be saved, so idle
  counts never build up.
- `--action block`, `--unblock`, `--install` and `--reset` refuse to run
  without root.
- `--action kill` without root can only signal your own processes.

## Safety notes

- **The default is `report`, which never blocks or kills anything.** Run in
  report mode for a while and read the log before you turn on `block` or
  `kill`.
- **As root, every mode keeps an `inet portwarden` nftables table.** Its
  `watch` chain only counts packets and accepts everything. Its `input` chain
  holds the drop rules for blocked ports and is empty unless you use `block`.
  `--reset` deletes the table.
- **"Idle" means no traffic seen.** As root that covers the whole interval
  between runs. Without root it is only the moment of the run, so a service
  used briefly and rarely, such as a nightly backup target, can look idle.
  Raise `--threshold` or allowlist it.
- **Any inbound packet keeps a UDP listener active,** including scans and
  broadcast noise. portwarden errs towards leaving a UDP port open rather than
  blocking one that might be in use.
- **`block` drops inbound traffic from every interface except loopback.**
  Local clients keep working, and a local connection lifts the block on the
  next run. Remote traffic cannot lift it, because it is dropped before it
  reaches the service: use `--unblock`, or allowlist the port to keep it open
  for good.
- **`kill` signals the first PID that `ss` reports for the socket.** If several
  processes share the socket, others may keep it open. PID 1 is never signalled.
- **Process-name allowlisting trusts the process name**, which any program can
  set. Treat `--allow-proc` as a convenience, not a security boundary.
- The `inet portwarden` table is kept separate from your own firewall rules.

## Tests

```sh
python -m pytest
```

The tests replace `ss`, `wg` and `nft` with a fake host (canned `ss` output
and a small in-memory nftables), so they need no root and touch nothing on
the machine.

## License

MIT. See [LICENSE](LICENSE).
