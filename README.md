# portwarden

A small Linux tool that audits listening TCP/UDP ports on a schedule and spots
services that sit open but are never used. It reports them by default. It can
also block them with an nftables rule or stop the process that owns them.

Single file, Python 3 standard library only. It reads socket state from `ss`.

## Why

Every listening port is attack surface. Dev servers, forgotten debug
listeners, and services installed "just to try" often stay open long after
anyone needs them. portwarden keeps a running count of how many consecutive
runs each listener has gone without an established connection. It flags the
ones that stay idle past a threshold, and it never touches allowlisted ports
or processes.

## How it works

Each run:

1. Lists listening sockets with `ss -tulnpH` (protocol, port, owning process and PID).
2. Marks a port as active if it has an established TCP connection
   (`ss -tnH state established`), or a UDP socket on that port with queued bytes.
3. Increments an idle counter for every listener that was not active, and
   resets it to 0 for listeners that were. Counters are stored in
   `/var/lib/portwarden/state.json`.
4. For each listener that has been idle for `--threshold` consecutive runs and
   is not allowlisted, it applies `--action`:
   - `report`: log only (the default)
   - `block`: add an nftables rule that drops inbound traffic to that port
   - `kill`: send SIGTERM to the owning process (SIGKILL with `--force`)
5. Removes a port's block rule when the port shows activity again or its
   listener goes away.

Output goes to stdout and is appended to `/var/log/portwarden.log`.

### Example output (illustrative)

These lines were built by hand from the script's log format. They are not a
capture from a real host.

```
2026-01-01 12:00:00 tcp:22     sshd                 pid=612     ALLOW
2026-01-01 12:00:00 udp:53     systemd-resolve      pid=401     ALLOW
2026-01-01 12:00:00 tcp:3000   node                 pid=2290    idle x3
2026-01-01 12:00:00   -> idle past threshold; --action block|kill would act (report mode)
2026-01-01 12:00:00 udp:5353   avahi-daemon         pid=455     ALLOW
2026-01-01 12:00:00 tcp:5432   postgres             pid=988     ACTIVE
2026-01-01 12:00:00 tcp:8000   python3              pid=2231    idle x1
```

With `--action block` the line after an idle listener reads
`-> BLOCKED inbound tcp:3000`. With `--action kill` it reads
`-> KILLED node pid=2290 (owner of tcp:3000)`.

## Requirements

- Linux with Python 3.8+
- `ss` (iproute2)
- `nft` (nftables), only for `--action block` and `--reset`
- systemd, only for `--install`

## Usage

```sh
# Audit only (safe): log listeners and how long each has been idle
sudo ./portwarden.py

# Treat 8080 and anything run by "myapp" as always allowed
sudo ./portwarden.py --allow-port 8080 --allow-proc myapp

# Block listeners that stay idle for 6 consecutive runs
sudo ./portwarden.py --action block --threshold 6

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
| `--install` | | Install the script and a systemd service and timer |
| `--interval SPAN` | `10min` | Timer interval for `--install` (systemd time span) |
| `--reset` | | Delete the `inet portwarden` nftables table and the state file |
| `--no-banner` | | Hide the ASCII banner (it is only shown on a terminal anyway) |

Always allowed, whatever the options:

- **Ports:** 22 (ssh), 53 (dns), 67/68 (dhcp), 123 (ntp), 631 (cups)
- **Processes:** `sshd`, `systemd`, `systemd-resolve(d)`, `NetworkManager`,
  `dhclient`, `chronyd`, `ntpd`, `avahi-daemon`, `cupsd`, `dbus-daemon`

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
  process owns other users' sockets, and the state file under `/var/lib` cannot
  be saved, so idle counts never build up.
- `--action block`, `--install` and `--reset` refuse to run without root.
- `--action kill` without root can only signal your own processes.

## Safety notes

- **The default is `report`, which changes nothing.** Run in report mode for a
  while and read the log before you turn on `block` or `kill`.
- **"Idle" means no established connection at the moment the run happens.**
  A service that is used briefly and rarely, such as a nightly backup target,
  can look idle. Raise `--threshold` or allowlist it.
- **UDP activity detection is approximate.** UDP has no connections. A UDP
  listener only counts as active when a socket on its port has queued bytes,
  so most UDP listeners that are not allowlisted will count as idle.
- **`block` drops all inbound traffic to the port, loopback included.** Local
  clients of that service are cut off too. Because inbound traffic is dropped,
  a blocked port rarely shows new activity. In practice the block is lifted when
  the listener goes away or when you run `--reset`.
- **`kill` signals the first PID that `ss` reports for the socket.** If several
  processes share the socket, others may keep it open. PID 1 is never signalled.
- **Process-name allowlisting trusts the process name**, which any program can
  set. Treat `--allow-proc` as a convenience, not a security boundary.
- The `inet portwarden` table is kept separate from your own firewall rules.
  `--reset` deletes it.

## License

MIT. See [LICENSE](LICENSE).
