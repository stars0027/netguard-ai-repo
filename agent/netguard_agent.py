#!/usr/bin/env python3
"""
NetGuard AI agent: runs on the machine you want to protect.

  * measures real traffic (packets/s), open connections and listening ports
  * optional packet sniffer (Linux, root) for per-source rates, SYN counts and port-scan detection
  * tails the SSH / login log for failed logins (Linux)
  * reports everything to your NetGuard server and receives the list of IPs to block
  * with --enforce, drops traffic from those IPs in the OS firewall (iptables / Windows Firewall)

Needs: Python 3.8+ and psutil  (pip install psutil).  Enforcement needs root / Administrator.
Safe by default: without --enforce the agent only monitors and never touches your firewall.
"""
import argparse, collections, ipaddress, json, os, platform, re, shutil, signal, socket, struct
import subprocess, sys, threading, time, urllib.error, urllib.request
from urllib.parse import urlparse

try:
    import psutil
except ImportError:
    sys.exit("psutil is required:  pip install psutil")

VERSION = "2.0"
CHAIN = "NETGUARD"
RULE_PREFIX = "NetGuard Block "
SYSTEM = platform.system()


def log(msg):
    print(time.strftime("%H:%M:%S"), msg, flush=True)


def valid_ip(s):
    try:
        return str(ipaddress.ip_address(s.strip()))
    except Exception:
        return None


# ----------------------------------------------------------------------------- host facts
def own_ips():
    ips = set()
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family in (socket.AF_INET, socket.AF_INET6):
                ip = valid_ip(a.address.split("%")[0])
                if ip:
                    ips.add(ip)
    return ips


def gateways_and_dns():
    out = set()
    try:
        if SYSTEM == "Linux":
            txt = subprocess.run(["ip", "route", "show", "default"], capture_output=True, text=True, timeout=3).stdout
            out |= set(re.findall(r"via\s+([0-9a-fA-F:.]+)", txt))
            if os.path.exists("/etc/resolv.conf"):
                out |= set(re.findall(r"^nameserver\s+(\S+)", open("/etc/resolv.conf").read(), re.M))
        elif SYSTEM == "Darwin":
            txt = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=3).stdout
            out |= set(re.findall(r"gateway:\s+(\S+)", txt))
        elif SYSTEM == "Windows":
            txt = subprocess.run(["ipconfig"], capture_output=True, text=True, timeout=5).stdout
            out |= set(re.findall(r"(?:Default Gateway|DNS Servers)[ .]*:\s*([0-9a-fA-F:.]+)", txt))
    except Exception:
        pass
    return {valid_ip(x) for x in out if valid_ip(x)}


# ----------------------------------------------------------------------------- counters / sockets
class Counters:
    def __init__(self):
        c = psutil.net_io_counters()
        self.last = (c.packets_recv + c.packets_sent, time.time())

    def pps(self):
        c = psutil.net_io_counters()
        total, t = c.packets_recv + c.packets_sent, time.time()
        dt = max(t - self.last[1], 0.001)
        rate = max(0.0, (total - self.last[0]) / dt)
        self.last = (total, t)
        return rate


TRUSTED_DNS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}
PROBE_STATES = {"SYN_RECV", "TIME_WAIT", "CLOSE_WAIT"}
SCAN_WINDOW = 30.0


def build_trusted(mine, extra=()):
    """Never treat these as attackers: this host, loopback, gateway, DNS resolvers."""
    t = set(mine) | set(extra) | TRUSTED_DNS | {"127.0.0.1", "::1"}
    return {x for x in t if x}


class ScanTracker:
    """Sliding 30 s window of distinct LOCAL ports each remote IP touched in a probing TCP state."""

    def __init__(self):
        self.seen = collections.defaultdict(dict)  # ip -> {port: last_seen}

    def add(self, ip, port, now):
        self.seen[ip][port] = now

    def report(self, now, threshold):
        out = {}
        for ip in list(self.seen):
            m = self.seen[ip]
            for p in [p for p, t in m.items() if now - t > SCAN_WINDOW]:
                del m[p]
            if not m:
                del self.seen[ip]
            elif len(m) >= threshold:
                out[ip] = sorted(m)[:300]
        return out


def sockets(trusted, scans=None):
    """Returns (connections, listening, syn_recv_per_ip). Trusted peers and the user's own
    outbound web traffic (ESTABLISHED to remote port 80/443) are excluded, so streaming and
    downloads can never look like a flood or a scan."""
    conns, listening, syn = [], [], collections.Counter()
    now = time.time()
    try:
        listen_ports = {c.laddr.port for c in psutil.net_connections(kind="inet") if c.status == "LISTEN" and c.laddr}
        for c in psutil.net_connections(kind="inet"):
            if c.status == "LISTEN" and c.laddr:
                proc = ""
                if c.pid:
                    try:
                        proc = psutil.Process(c.pid).name()
                    except Exception:
                        pass
                listening.append({"port": c.laddr.port, "addr": c.laddr.ip, "proc": proc})
            elif c.raddr and c.laddr:
                ip = valid_ip(c.raddr.ip)
                if not ip or ip in trusted or ipaddress.ip_address(ip).is_loopback:
                    continue
                if c.status == "ESTABLISHED" and c.raddr.port in (80, 443) and c.laddr.port not in listen_ports:
                    continue  # our own browser/app talking to a website or CDN
                if c.status == "SYN_RECV":
                    syn[ip] += 1
                # probing evidence: inbound peer in a half-open/closing state against one of OUR ports
                if scans is not None and c.status in PROBE_STATES and (c.status == "SYN_RECV" or c.laddr.port in listen_ports):
                    scans.add(ip, c.laddr.port, now)
                conns.append({"ip": ip, "lport": c.laddr.port, "state": c.status})
    except (psutil.AccessDenied, PermissionError):
        pass
    return conns[:3000], listening[:500], dict(syn)


# ----------------------------------------------------------------------------- packet sniffer
class Sniffer(threading.Thread):
    """Linux AF_PACKET sniffer (IPv4 TCP/UDP). Needs root. Aggregates per source IP."""

    def __init__(self, mine, include_loopback=False):
        super().__init__(daemon=True)
        self.mine, self.lo, self.lock = mine, include_loopback, threading.Lock()
        self.data = collections.defaultdict(lambda: {"pkts": 0, "syns": 0, "ports": set()})
        self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

    def run(self):
        while True:
            try:
                buf, addr = self.sock.recvfrom(65535)
                if addr[2] == socket.PACKET_OUTGOING:
                    continue
                if not self.lo and addr[0] == "lo":
                    continue
                if len(buf) < 34 or struct.unpack("!H", buf[12:14])[0] != 0x0800:
                    continue  # not IPv4 (all captured frames carry a 14-byte Ethernet header, lo included)
                ip = buf[14:]
                if len(ip) < 20 or ip[0] >> 4 != 4:
                    continue
                ihl = (ip[0] & 0x0F) * 4
                proto, src, dst = ip[9], socket.inet_ntoa(ip[12:16]), socket.inet_ntoa(ip[16:20])
                if src in self.mine and not self.lo:
                    continue
                dport, syn = 0, False
                if proto in (6, 17) and len(ip) >= ihl + 4:
                    dport = struct.unpack("!H", ip[ihl + 2:ihl + 4])[0]
                    if proto == 6 and len(ip) >= ihl + 14:
                        flags = ip[ihl + 13]
                        syn = bool(flags & 0x02) and not (flags & 0x10)
                with self.lock:
                    d = self.data[src]
                    d["pkts"] += 1
                    d["syns"] += 1 if syn else 0
                    if dport and len(d["ports"]) < 300:
                        d["ports"].add(dport)
            except Exception:
                time.sleep(0.01)

    def flush(self, dt):
        with self.lock:
            snap, self.data = self.data, collections.defaultdict(lambda: {"pkts": 0, "syns": 0, "ports": set()})
        out = [{"ip": ip, "pkts": d["pkts"] / dt, "syns": d["syns"] / dt, "ports": sorted(d["ports"])}
               for ip, d in snap.items()]
        out.sort(key=lambda s: -s["pkts"])
        return out[:100]


# ----------------------------------------------------------------------------- auth log tail
class AuthTail:
    PATTERNS = [re.compile(r"Failed (?:password|publickey) for .* from ([0-9a-fA-F:.]+)"),
                re.compile(r"Invalid user .* from ([0-9a-fA-F:.]+)"),
                re.compile(r"authentication failure;.*rhost=([0-9a-fA-F:.]+)")]

    def __init__(self):
        self.path = next((p for p in ("/var/log/auth.log", "/var/log/secure") if os.path.exists(p)), None)
        self.f = None
        if self.path:
            try:
                self.f = open(self.path, "r", errors="replace")
                self.f.seek(0, os.SEEK_END)
            except Exception as e:
                log(f"cannot read {self.path}: {e} (login monitoring off)")
                self.f = None

    def poll(self):
        out = collections.Counter()
        if not self.f:
            return {}
        try:
            for line in self.f.readlines():
                for pat in self.PATTERNS:
                    m = pat.search(line)
                    if m and valid_ip(m.group(1)):
                        out[valid_ip(m.group(1))] += 1
                        break
        except Exception:
            pass
        return dict(out)


class WinAuth:
    """Windows Security log, Event ID 4625 (failed logon). Needs an elevated (Administrator) prompt."""
    CMD = ["wevtutil", "qe", "Security", "/q:*[System[(EventID=4625)]]", "/f:text", "/c:20", "/rd:true"]
    ADDR = re.compile(r"Source Network Address:\s*([0-9a-fA-F:.]+)")
    DATE = re.compile(r"Date:\s*(\S+)")

    def __init__(self):
        self.seen = set()
        self.ok = True
        self.poll(first=True)

    def poll(self, first=False):
        out = collections.Counter()
        try:
            txt = subprocess.run(self.CMD, capture_output=True, text=True, timeout=8).stdout
            if not txt and not first:
                return {}
            for block in txt.split("Event[")[1:]:
                key = (self.DATE.search(block) or [None, block[:60]])[1] + block[:40]
                m = self.ADDR.search(block)
                if key in self.seen:
                    continue
                self.seen.add(key)
                if first:
                    continue  # history before the agent started is ignored
                ip = valid_ip(m.group(1)) if m else None
                if ip:
                    out[ip] += 1
            if len(self.seen) > 2000:
                self.seen = set(list(self.seen)[-500:])
        except Exception:
            self.ok = False
        return dict(out)


class JournalAuth:
    """Linux without auth.log: follow `journalctl -u ssh`/`sshd` for failed logins."""
    def __init__(self):
        self.last = time.time()
        self.ok = bool(shutil.which("journalctl"))

    def poll(self):
        out = collections.Counter()
        if not self.ok:
            return {}
        since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.last))
        self.last = time.time()
        for unit in ("ssh", "sshd"):
            try:
                txt = subprocess.run(["journalctl", "-u", unit, "--since", since, "--no-pager", "-o", "cat"],
                                     capture_output=True, text=True, timeout=5).stdout
            except Exception:
                continue
            for line in txt.splitlines():
                for pat in AuthTail.PATTERNS:
                    m = pat.search(line)
                    if m and valid_ip(m.group(1)):
                        out[valid_ip(m.group(1))] += 1
                        break
        return dict(out)


# ----------------------------------------------------------------------------- firewall
class Firewall:
    """Reconciles OS firewall rules to the server's list. Only ever touches rules it created."""

    def __init__(self, enabled, protected):
        self.enabled, self.protected, self.applied = enabled, set(protected), set()
        self.kind = None
        if not enabled:
            return
        if SYSTEM == "Linux" and shutil.which("iptables"):
            self.kind = "iptables"
            self._ipt_setup()
        elif SYSTEM == "Windows":
            self.kind = "netsh"
        else:
            log(f"WARNING: enforcement is not supported on {SYSTEM} without iptables; running monitor-only")
            self.enabled = False

    def _run(self, *cmd):
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    def _bin(self, ip):
        return "ip6tables" if ":" in ip else "iptables"

    def _ipt_setup(self):
        for b in ("iptables", "ip6tables"):
            if not shutil.which(b):
                continue
            self._run(b, "-N", CHAIN)
            self._run(b, "-F", CHAIN)
            if self._run(b, "-C", "INPUT", "-j", CHAIN).returncode != 0:
                r = self._run(b, "-I", "INPUT", "1", "-j", CHAIN)
                if r.returncode != 0:
                    log(f"cannot install {b} chain (need root?): {r.stderr.strip()}")
                    self.enabled = False

    def _add(self, ip):
        if self.kind == "iptables":
            b = self._bin(ip)
            if self._run(b, "-C", CHAIN, "-s", ip, "-j", "DROP").returncode != 0:
                r = self._run(b, "-A", CHAIN, "-s", ip, "-j", "DROP")
                return r.returncode == 0
            return True
        if self.kind == "netsh":
            r = self._run("netsh", "advfirewall", "firewall", "add", "rule", f"name={RULE_PREFIX}{ip}",
                          "dir=in", "action=block", f"remoteip={ip}")
            return r.returncode == 0
        return False

    def _del(self, ip):
        if self.kind == "iptables":
            self._run(self._bin(ip), "-D", CHAIN, "-s", ip, "-j", "DROP")
        elif self.kind == "netsh":
            self._run("netsh", "advfirewall", "firewall", "delete", "rule", f"name={RULE_PREFIX}{ip}")

    def sync(self, desired):
        if not self.enabled:
            return
        want = set()
        for raw in desired:
            ip = valid_ip(raw)
            if not ip:
                continue
            a = ipaddress.ip_address(ip)
            if ip in self.protected or a.is_loopback or a.is_unspecified or a.is_multicast:
                log(f"refusing to block protected address {ip}")
                continue
            want.add(ip)
        for ip in want - self.applied:
            if self._add(ip):
                self.applied.add(ip)
                log(f"BLOCKED {ip}")
            else:
                log(f"failed to block {ip}")
        for ip in self.applied - want:
            self._del(ip)
            self.applied.discard(ip)
            log(f"unblocked {ip}")

    def cleanup(self, keep):
        if not self.enabled or keep:
            return
        for ip in list(self.applied):
            self._del(ip)
        if self.kind == "iptables":
            for b in ("iptables", "ip6tables"):
                if shutil.which(b):
                    self._run(b, "-D", "INPUT", "-j", CHAIN)
                    self._run(b, "-F", CHAIN)
                    self._run(b, "-X", CHAIN)


# ----------------------------------------------------------------------------- server link
def post(server, key, path, payload, timeout=6):
    req = urllib.request.Request(server + path, data=json.dumps(payload).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "Authorization": "Bearer " + key,
                                          "User-Agent": "netguard-agent/" + VERSION})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode())


def main():
    ap = argparse.ArgumentParser(description="NetGuard AI agent")
    ap.add_argument("--server", default=os.environ.get("NETGUARD_SERVER"), help="e.g. https://netguard.example.com")
    ap.add_argument("--key", default=os.environ.get("NETGUARD_KEY"), help="device API key (ng_...)")
    ap.add_argument("--interval", type=float, default=2.0, help="seconds between samples (default 2)")
    ap.add_argument("--enforce", action="store_true", help="actually block attacker IPs in the OS firewall")
    ap.add_argument("--sniff", action="store_true", help="packet sniffer for per-source stats (Linux, root)")
    ap.add_argument("--include-loopback", action="store_true", help="sniff loopback too (testing only)")
    ap.add_argument("--scan-ports", type=int, default=15, help="distinct local ports one remote IP must probe within 30 s to be reported as a port scan")
    ap.add_argument("--keep-rules", action="store_true", help="leave firewall rules in place on exit")
    ap.add_argument("--once", action="store_true", help="send one sample, print the reply and exit")
    a = ap.parse_args()
    if not a.server or not a.key:
        ap.error("--server and --key are required (or NETGUARD_SERVER / NETGUARD_KEY)")
    server = a.server.rstrip("/")
    if not server.startswith(("http://", "https://")):
        ap.error("--server must start with http:// or https://")
    if server.startswith("http://") and urlparse(server).hostname not in ("localhost", "127.0.0.1"):
        log("WARNING: plain http sends your API key unencrypted. Use https in production.")

    mine = own_ips()
    protected = mine | gateways_and_dns()
    try:  # never block the NetGuard server itself
        for info in socket.getaddrinfo(urlparse(server).hostname, None):
            ip = valid_ip(info[4][0])
            if ip:
                protected.add(ip)
    except Exception:
        pass

    fw = Firewall(a.enforce, protected)
    if a.enforce and fw.enabled:
        log(f"enforcement ON ({fw.kind}). Blocks from the server will be applied to this machine.")
    else:
        log("monitor-only mode (add --enforce to block attackers automatically)")
    sniffer = None
    if a.sniff:
        try:
            sniffer = Sniffer(mine, a.include_loopback)
            sniffer.start()
            log("packet sniffer ON")
        except Exception as e:
            log(f"sniffer unavailable ({e}); continuing without it (needs Linux + root)")
    auth_tail = None
    if SYSTEM == "Linux":
        auth_tail = AuthTail()
        if auth_tail.f:
            log(f"watching {auth_tail.path} for failed logins")
        else:
            auth_tail = JournalAuth()
            if auth_tail.ok:
                log("watching journalctl (ssh) for failed logins")
            else:
                auth_tail = None
    elif SYSTEM == "Windows":
        auth_tail = WinAuth()
        log("watching Windows Security log (Event ID 4625) for failed logons" if auth_tail.ok else "cannot read the Security log: run as Administrator for login monitoring")
    trusted = build_trusted(protected)
    scans = ScanTracker()

    stop = threading.Event()
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, lambda *_: stop.set())

    counters = Counters()
    hostname, osname = socket.gethostname(), f"{SYSTEM} {platform.release()}"
    last, backoff = time.time(), 0
    log(f"reporting to {server} every {a.interval:g}s")

    while not stop.is_set():
        stop.wait(a.interval)
        t = time.time()
        dt = max(t - last, 0.001)
        last = t
        conns, listening, syn_recv = sockets(trusted, scans)
        payload = {
            "pps": counters.pps(), "hostname": hostname, "os": osname, "agent_version": VERSION,
            "enforce": fw.enabled, "interval": a.interval, "own_ips": sorted(protected),
            "connections": conns, "listening": listening, "enforced": sorted(fw.applied),
            "sources": sniffer.flush(dt) if sniffer else [],
            "auth_failures": auth_tail.poll() if auth_tail else {},
            "syn_recv": syn_recv, "scans": scans.report(t, a.scan_ports),
        }
        try:
            reply = post(server, a.key, "/api/agent/telemetry", payload)
            backoff = 0
            fw.sync(reply.get("blocks", []))
            if a.once:
                print(json.dumps(reply))
                break
        except urllib.error.HTTPError as e:
            if e.code == 401:
                log("server rejected the API key. Check --key. Exiting.")
                break
            log(f"server error {e.code}")
            backoff = min(30, backoff * 2 or 2)
        except Exception as e:
            log(f"cannot reach server: {e}")
            backoff = min(30, backoff * 2 or 2)  # keep the last firewall rules while offline
        if backoff:
            stop.wait(backoff)

    fw.cleanup(a.keep_rules)
    log("agent stopped" + (" (firewall rules kept)" if a.keep_rules else ""))


if __name__ == "__main__":
    main()
