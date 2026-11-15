"""Quick checks for the agent's statistics and safety rules. Run: python3 test/agent_test.py"""
import os, subprocess, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agent"))
import netguard_agent as a

ok = True
def check(cond, name):
    global ok
    ok &= bool(cond)
    print(("  PASS " if cond else "  FAIL ") + name)

d = a.Anomaly(floor=300)
for i in range(30):
    d.feed(100 + i % 5)
check(d.feed(250) is None, "a burst below the floor is not an anomaly")
hit = d.feed(5000)
check(hit and hit["z"] > 3.5, "a huge spike above floor AND z > 3.5 is an anomaly")
m = d.mean
for _ in range(5):
    d.feed(5000)
check(d.mean == m, "attack samples do not poison the baseline")
check(a.Anomaly(floor=10).feed(5000) is None, "nothing is flagged while still learning")
check(a.is_lan("10.1.2.3") and a.is_lan("172.16.0.9") and a.is_lan("192.168.0.1") and not a.is_lan("172.32.0.1") and not a.is_lan("8.8.8.8"), "RFC-1918 detection")
check(set(a.OT_PORTS) == {502, 102, 20000, 4840}, "OT ports: Modbus 502, S7 102, DNP3 20000, OPC-UA 4840")
fw = a.Firewall(False, set())
fw.enabled, fw.kind = True, "iptables"
added = []
fw._add = lambda ip: added.append(ip) or True
fw._del = lambda ip: None
fw.sync(["192.168.1.1", "10.0.0.7", "203.0.113.5"])
check(added == ["203.0.113.5"], "private LAN addresses are never blocked by default")
fw2 = a.Firewall(False, set(), allow_lan=True); fw2.enabled, fw2.kind = True, "iptables"; got = []
fw2._add = lambda ip: got.append(ip) or True; fw2._del = lambda ip: None
fw2.sync(["192.168.1.1"])
check(got == ["192.168.1.1"], "--allow-lan-block lifts that rule")
out = subprocess.run([sys.executable, os.path.join(os.path.dirname(__file__), "..", "agent", "netguard_agent.py"), "--server", "https://x.example", "--key", "ng_" + "a" * 24, "--install-service", "--dry-run", "--enforce"], capture_output=True, text=True)
check("netguard-agent.service" in out.stdout or "schtasks" in out.stdout, "--install-service --dry-run shows the systemd unit / scheduled task")
check("ng_aaaa" not in out.stdout.replace("(contains the API key, private)", ""), "the API key is never printed or put on a command line")
sys.exit(0 if ok else 1)
