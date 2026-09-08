import json
import os
import socket
import ssl
import struct
import subprocess
import sys
import time


NAME = "protected.example.test"
ORDINARY = "ordinary.example.test"
REAL = "172.30.0.10"


def run(*args):
    return subprocess.check_output(args, text=True).strip()


def wait_for(command, timeout=90):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            value = command()
            if value:
                return value
        except (AssertionError, OSError, subprocess.CalledProcessError, ValueError, KeyError) as error:
            last_error = error
        time.sleep(1)
    raise RuntimeError("timed out waiting for tailnet: %s" % last_error)


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
    relay_ip = socket.inet_ntoa(response[4:8])
    relay_port = struct.unpack("!H", response[8:10])[0]
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.settimeout(5)
    try:
        udp.sendto(b"\0\0\0\x01" + socket.inet_aton(ip) + struct.pack("!H", port) + payload, (relay_ip, relay_port))
        response, _ = udp.recvfrom(4096)
    finally:
        udp.close()
        control.close()
    assert response[:3] == b"\0\0\0" and response[3] == 1, response
    return response[10:]


def query(resolver, name, qtype=1):
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0"
    request = b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0" + labels + struct.pack("!HH", qtype, 1)
    response = socks_udp(resolver, 53, request)
    if response[3] & 15:
        raise AssertionError("DNS rcode %d" % (response[3] & 15))
    if not struct.unpack("!H", response[6:8])[0]:
        return None
    pos = 12
    while response[pos]:
        pos += response[pos] + 1
    pos += 5 + 10
    size = struct.unpack("!H", response[pos:pos + 2])[0]
    pos += 2
    if qtype == 1:
        return socket.inet_ntoa(response[pos:pos + size])
    if qtype == 12:
        labels = []
        while response[pos]:
            size = response[pos]
            pos += 1
            labels.append(response[pos:pos + size].decode())
            pos += size
        return ".".join(labels)


def peer_ip(host):
    status = json.loads(run("tailscale", "status", "--json"))
    for peer in status["Peer"].values():
        if peer["HostName"] == host:
            return peer["TailscaleIPs"][0]
    raise RuntimeError("missing peer " + host)


def http(ip, tls=False):
    conn = socks_connect(ip, 443 if tls else 80)
    if tls:
        conn = ssl._create_unverified_context().wrap_socket(conn, server_hostname=NAME)
    conn.sendall(("GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n" % NAME).encode())
    data = b""
    while chunk := conn.recv(4096):
        data += chunk
    conn.close()
    assert b"200" in data and b"upstream-ok" in data, data


def connect():
    subprocess.Popen([
        "tailscaled", "--tun=userspace-networking", "--socks5-server=127.0.0.1:1055",
        "--state=/state/tailscaled.state", "--socket=/var/run/tailscale/tailscaled.sock",
    ])
    wait_for(lambda: os.path.exists("/var/run/tailscale/tailscaled.sock"))
    run(
        "tailscale", "up", "--login-server=http://headscale:8080", "--auth-key=" + os.environ["AUTH_KEY"],
        "--hostname=" + os.environ["CLIENT_NAME"], "--accept-routes", "--accept-dns=false",
    )
    return wait_for(lambda: peer_ip("e2e-dns"))


def authorized(dns):
    synthetic = wait_for(lambda: query(dns, NAME))
    assert synthetic.startswith("10.254."), synthetic
    assert wait_for(lambda: query(dns, ORDINARY)) == REAL
    reverse = ".".join(reversed(synthetic.split("."))) + ".in-addr.arpa"
    assert wait_for(lambda: query(dns, reverse, 12)) == NAME
    wait_for(lambda: http(synthetic))
    wait_for(lambda: http(synthetic, tls=True))
    try:
        socks_udp(synthetic, 9000, b"udp")
    except socket.timeout:
        print("E2E: UDP forwarding remains expected-red", flush=True)
    else:
        raise AssertionError("UDP unexpectedly succeeded; update this probe")


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: client.py <authorized|denied|gateway-dns>")
    dns = connect()
    probe = sys.argv[1]
    if probe == "authorized":
        authorized(dns)
    elif probe in {"denied", "gateway-dns"}:
        assert query(dns, NAME) == REAL
    else:
        raise SystemExit("unknown probe " + probe)
    print("E2E %s passed (dns=%s)" % (probe, dns), flush=True)


if __name__ == "__main__":
    main()
