"""Bounded, authenticated probes. Inputs are environment Secrets, never CLI data.

No network occurs on import. Public output contains indexed results, counts,
booleans and fixed reason codes only. Execution location needs Actions evidence.
"""
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
import re
import socket
import sys
import time

MAX_BYTES = 512
PORT_TIMEOUT = 3.0
TOTAL_TIMEOUT = 35.0
SECRET_NAMES = ("XNP_TARGET_IPV4", "XNP_TCP_PORTS", "XNP_UDP_PORTS", "XNP_PROBE_NONCE")


class InvalidSecrets(Exception):
    pass


@dataclass(frozen=True)
class Targets:
    ipv4: str = field(repr=False)
    tcp_ports: tuple = field(repr=False)
    udp_ports: tuple = field(repr=False)
    nonce: str = field(repr=False)


def read_targets(environment):
    values = [environment.get(name, "") for name in SECRET_NAMES]
    if any(not isinstance(value, str) or not value for value in values):
        raise InvalidSecrets("MissingSecrets")
    if any(len(value) > 1024 for value in values):
        raise InvalidSecrets("InvalidSecrets")
    try:
        address = ipaddress.IPv4Address(values[0])
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError
    except (ValueError, TypeError):
        raise InvalidSecrets("InvalidIPv4") from None
    ports = []
    try:
        for raw in values[1:3]:
            parsed = json.loads(raw)
            if (not isinstance(parsed, list) or not 1 <= len(parsed) <= 5
                    or any(type(port) is not int or not 1 <= port <= 65535 for port in parsed)
                    or len(set(parsed)) != len(parsed)):
                raise ValueError
            ports.append(tuple(parsed))
    except (ValueError, TypeError, RecursionError):
        raise InvalidSecrets("InvalidPorts") from None
    if re.fullmatch(r"[0-9a-f]{64}", values[3]) is None:
        raise InvalidSecrets("InvalidNonce")
    return Targets(str(address), ports[0], ports[1], values[3])


def source_matches(peer, endpoint):
    try:
        return (isinstance(peer, tuple) and len(peer) == 2
                and str(ipaddress.IPv4Address(peer[0])) == endpoint[0]
                and type(peer[1]) is int and peer[1] == endpoint[1])
    except (ValueError, TypeError):
        return False


def probe_port(targets, protocol, port, index, overall_deadline, *, socket_factory=None, clock=None):
    socket_factory = socket_factory or socket.socket
    clock = clock or time.monotonic
    result = {"index": index, "status": "FAIL", "reason": "NoResponse", "attempts": 0}
    deadline = min(clock() + PORT_TIMEOUT, overall_deadline)
    endpoint = (targets.ipv4, port)
    request = (targets.nonce + "\n").encode("ascii")
    digest = hashlib.sha256(targets.nonce.encode("ascii")).hexdigest()[:16]
    expected = (f"XNP-VAST-{protocol.upper()}-OK:{digest}\n").encode("ascii")
    sock = None

    def set_remaining_timeout():
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(remaining)

    try:
        if deadline <= clock():
            result["reason"] = "OverallDeadline"
            return result
        if len(request) > MAX_BYTES:
            result["reason"] = "SizeLimit"
            return result
        kind = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
        sock = socket_factory(socket.AF_INET, kind)
        set_remaining_timeout()
        result["attempts"] = 1
        if protocol == "tcp":
            sock.connect(endpoint)
            if not source_matches(sock.getpeername(), endpoint):
                result["reason"] = "SourceMismatch"
                return result
            set_remaining_timeout()
            sock.sendall(request)
            received = bytearray()
            complete = False
            while len(received) <= MAX_BYTES:
                set_remaining_timeout()
                chunk = sock.recv(MAX_BYTES + 1 - len(received))
                if not chunk:
                    complete = True
                    break
                received.extend(chunk)
                if len(received) > MAX_BYTES:
                    break
            data = bytes(received)
            if not complete and len(data) <= MAX_BYTES:
                result["reason"] = "NoResponse"
                return result
        else:
            sent = sock.sendto(request, endpoint)
            if sent != len(request):
                result["reason"] = "IncompleteSend"
                return result
            set_remaining_timeout()
            data, peer = sock.recvfrom(MAX_BYTES + 1)
            if not source_matches(peer, endpoint):
                result["reason"] = "SourceMismatch"
                return result
        if len(data) > MAX_BYTES:
            result["reason"] = "SizeLimit"
        elif data != expected:
            result["reason"] = "ProtocolMismatch"
        elif clock() > deadline:
            result["reason"] = "Timeout"
        else:
            result["status"] = "PASS"
            result["reason"] = "Validated"
    except (TimeoutError, socket.timeout):
        result["reason"] = "Timeout"
    except ConnectionRefusedError:
        result["reason"] = "ConnectionRefused"
    except OSError:
        result["reason"] = "NetworkError"
    except Exception:
        # Exception strings, tracebacks and payloads may contain Secrets.
        result["reason"] = "InternalError"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                result["status"] = "FAIL"
                result["reason"] = "SocketCloseError"
    return result


def five_continuous(ports):
    ordered = sorted(ports)
    return len(ordered) == 5 and ordered == list(range(ordered[0], ordered[0] + 5))


def base_report():
    return {"schema": "XNP_GHA_PROBE_v21_1", "status": "NOT_RUN", "reason": "MissingSecrets",
            "tcp": [], "udp": [], "tcp_configured_count": 0, "udp_configured_count": 0,
            "tcp_all_pass": False, "udp_all_pass": False,
            "tcp_five_continuous": False, "udp_five_continuous": False,
            "tcp_udp_same_five_range": False, "range_status": "NOT_EVALUATED",
            "external_execution_verified_by_script": False, "vast_network_gate": False}


def run(environment, *, socket_factory=None, clock=None):
    report = base_report()
    try:
        targets = read_targets(environment)
    except InvalidSecrets as error:
        report["reason"] = str(error)
        return report
    clock = clock or time.monotonic
    overall_deadline = clock() + TOTAL_TIMEOUT
    for protocol, ports in (("tcp", targets.tcp_ports), ("udp", targets.udp_ports)):
        report[protocol + "_configured_count"] = len(ports)
        report[protocol] = [probe_port(targets, protocol, port, index, overall_deadline,
                                       socket_factory=socket_factory, clock=clock)
                            for index, port in enumerate(ports, 1)]
        report[protocol + "_all_pass"] = all(item["status"] == "PASS" for item in report[protocol])
        report[protocol + "_five_continuous"] = five_continuous(ports)
    report["tcp_udp_same_five_range"] = (report["tcp_five_continuous"] and report["udp_five_continuous"]
                                         and set(targets.tcp_ports) == set(targets.udp_ports))
    report["range_status"] = ("INSUFFICIENT_PORT_COUNT" if len(targets.tcp_ports) < 5 or len(targets.udp_ports) < 5
                               else "CONTINUOUS_FIVE_PER_PROTOCOL" if report["tcp_five_continuous"] and report["udp_five_continuous"]
                               else "PUBLIC_PORTS_NOT_CONTINUOUS")
    passed = report["tcp_all_pass"] and report["udp_all_pass"]
    report["status"] = "PASS" if passed else "FAIL"
    report["reason"] = "ConfiguredPortsValidated" if passed else "ConfiguredPortsNotAllValidated"
    return report


def emit_redacted(report):
    for protocol in ("tcp", "udp"):
        for item in report[protocol]:
            print(f"{protocol.upper()}[{item['index']}]={item['status']} reason={item['reason']}")
    print(f"OVERALL={report['status']} reason={report['reason']}")
    print("XNP_RESULT_JSON=" + json.dumps(report, separators=(",", ":"), sort_keys=True))


def main(argv=None, environment=None, **offline_injections):
    try:
        args = sys.argv[1:] if argv is None else argv
        if args:
            report = base_report()
            report["reason"] = "ArgumentsUnsupported"
        else:
            report = run(os.environ if environment is None else environment, **offline_injections)
    except Exception:
        report = base_report()
        report["reason"] = "InternalError"
    emit_redacted(report)
    return 0 if report["status"] == "PASS" else 2 if report["status"] == "NOT_RUN" else 1


if __name__ == "__main__":
    sys.exit(main())
