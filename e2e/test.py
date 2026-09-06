import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

ROLE = os.environ["ROLE"]
NAME = "protected.example.test"
ORDINARY = "ordinary.example.test"
REAL = "172.30.0.10"
RESULTS = []
SUMMARY_REPORTED = False

def summary():
    global SUMMARY_REPORTED
    if SUMMARY_REPORTED:
        return
    SUMMARY_REPORTED = True
    passed = RESULTS.count("PASS")
    failed = RESULTS.count("FAIL")
    expected_failures = RESULTS.count("XFAIL")
    print("E2E %s summary: %d passed, %d failed, %d expected failures" % (ROLE, passed, failed, expected_failures), flush=True)

def check(name, command):
    print("E2E %s: %s ... " % (ROLE, name), end="", flush=True)
    try:
        result = command()
    except Exception as error:
        RESULTS.append("FAIL")
        print("FAIL (%s: %s)" % (type(error).__name__, error), flush=True)
        raise
    RESULTS.append("PASS")
    print("PASS", flush=True)
    return result

def expected_red(name, command):
    print("E2E %s: %s ... " % (ROLE, name), end="", flush=True)
    try:
        command()
    except socket.timeout:
        RESULTS.append("XFAIL")
        print("XFAIL (UDP proxy is not implemented)", flush=True)
        return
    except Exception as error:
        RESULTS.append("FAIL")
        print("FAIL (%s: %s)" % (type(error).__name__, error), flush=True)
        raise
    RESULTS.append("FAIL")
    print("FAIL (unexpectedly succeeded; update this probe)", flush=True)
    raise AssertionError("UDP unexpectedly succeeded; update this probe")

def run(*args): return subprocess.check_output(args, text=True).strip()
def wait_for(command, timeout=90):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            value = command()
            if value: return value
        except Exception: pass
        time.sleep(1)
    raise RuntimeError("timed out waiting for tailnet")

def socks_connect(ip, port):
    conn = socket.create_connection(("127.0.0.1", 1055), 10)
    conn.sendall(b"\x05\x01\x00")
    assert conn.recv(2) == b"\x05\x00"
    conn.sendall(b"\x05\x01\x00\x01" + socket.inet_aton(ip) + struct.pack("!H", port))
    response = conn.recv(10)
    assert response[:2] == b"\x05\x00", response
    return conn

def socks_udp(ip, port, payload):
    control = socket.create_connection(("127.0.0.1", 1055), 10)
    control.sendall(b"\x05\x01\x00")
    assert control.recv(2) == b"\x05\x00"
    control.sendall(b"\x05\x03\x00\x01\0\0\0\0\0\0")
    response = control.recv(10)
    assert response[:2] == b"\x05\x00", response
    relay_ip, relay_port = socket.inet_ntoa(response[4:8]), struct.unpack("!H", response[8:10])[0]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); udp.settimeout(5)
    udp.sendto(b"\0\0\0\x01" + socket.inet_aton(ip) + struct.pack("!H", port) + payload, (relay_ip, relay_port))
    response, _ = udp.recvfrom(4096)
    udp.close(); control.close()
    assert response[:3] == b"\0\0\0" and response[3] == 1, response
    return response[10:]

def query(resolver, name, qtype=1):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    request = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0" + labels + struct.pack("!HH", qtype, 1)
    response = socks_udp(resolver, 53, request)
    if response[3] & 15: raise AssertionError("DNS rcode %d" % (response[3] & 15))
    ancount = struct.unpack("!H", response[6:8])[0]
    if not ancount: return None
    pos = 12
    while response[pos]: pos += response[pos] + 1
    pos += 5
    pos += 2 + 8
    size = struct.unpack("!H", response[pos:pos+2])[0]; pos += 2
    if qtype == 1: return socket.inet_ntoa(response[pos:pos+size])
    if qtype == 12:
        parts = []
        while response[pos]:
            size = response[pos]; pos += 1; parts.append(response[pos:pos+size].decode()); pos += size
        return ".".join(parts)

def peer_ip(host):
    status = json.loads(run("tailscale", "status", "--json"))
    for peer in status["Peer"].values():
        if peer["HostName"] == host: return peer["TailscaleIPs"][0]
    raise RuntimeError("missing peer " + host)

def http(ip, tls=False):
    conn = socks_connect(ip, 443 if tls else 80)
    if tls:
        ctx = ssl._create_unverified_context(); conn = ctx.wrap_socket(conn, server_hostname=NAME)
    conn.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % NAME).encode())
    data = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk: break
        data += chunk
    conn.close()
    assert b"200" in data and b"upstream-ok" in data, data
    return True

def connect():
    wait_for(lambda: os.path.exists("/auth/ready"))
    subprocess.Popen(["tailscaled", "--tun=userspace-networking", "--socks5-server=127.0.0.1:1055", "--state=/state/tailscaled.state", "--socket=/var/run/tailscale/tailscaled.sock"])
    wait_for(lambda: os.path.exists("/var/run/tailscale/tailscaled.sock"))
    run("tailscale", "up", "--login-server=http://headscale:8080", "--auth-key=" + open("/auth/" + ROLE).read().strip(), "--accept-routes", "--accept-dns=false")
    return wait_for(lambda: peer_ip("e2e-dns"))

def synthetic_address(dns):
    synthetic = wait_for(lambda: query(dns, NAME))
    assert synthetic.startswith("10.254."), synthetic
    return synthetic

def real_address(dns):
    assert query(dns, NAME) == REAL

def ordinary_address(dns):
    assert query(dns, ORDINARY) == REAL

def ptr_record(dns, synthetic):
    reverse = ".".join(reversed(synthetic.split("."))) + ".in-addr.arpa"
    assert wait_for(lambda: query(dns, reverse, 12)) == NAME

def main():
    dns = check("connect to tailnet", connect)
    if ROLE == "client":
        synthetic = check("authorized synthetic DNS", lambda: synthetic_address(dns))
        check("ordinary DNS passthrough", lambda: ordinary_address(dns))
        check("synthetic PTR record", lambda: ptr_record(dns, synthetic))
        check("HTTP through gateway", lambda: wait_for(lambda: http(synthetic)))
        check("HTTPS through gateway", lambda: wait_for(lambda: http(synthetic, tls=True)))
        # UDP forwarding is not implemented by the gateway yet; retain a visible expected-red probe.
        expected_red("UDP through gateway", lambda: socks_udp(synthetic, 9000, b"udp"))
        open("/auth/authorized-complete", "w").close()
        wait_for(lambda: os.path.exists("/auth/denied-complete"))
        wait_for(lambda: os.path.exists("/auth/gateway-dns-complete"))
    elif ROLE == "denied":
        wait_for(lambda: os.path.exists("/auth/authorized-complete"))
        check("denied DNS returns real address", lambda: real_address(dns))
        open("/auth/denied-complete", "w").close()
    else:
        # Keep this verifier behind the authorizing client.  Compose treats
        # every successful test-container exit as terminal, so allowing this
        # short DNS-only check to finish first would abort the HTTP tests.
        wait_for(lambda: os.path.exists("/auth/authorized-complete"))
        check("gateway DNS returns real address", lambda: real_address(dns))
        open("/auth/gateway-dns-complete", "w").close()
    print("E2E %s passed (dns=%s)" % (ROLE, dns))
    if ROLE != "client":
        # The client is the compose test coordinator.  These peer-specific
        # checkers remain alive until it observes their completion; otherwise
        # --abort-on-container-exit would stop the suite at the first pass.
        summary()
        while True:
            time.sleep(60)

if __name__ == "__main__":
    try:
        main()
    finally:
        summary()
