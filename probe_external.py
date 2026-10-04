"""Bounded synchronized diagnostic. Import never creates a socket.

All household inputs are Secrets. Output is indexed status, fixed reason codes,
counts, boolean checks and UTC timing, without endpoints or nonce material.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
TOTAL_TIMEOUT = 72.0
MAX_ATTEMPTS = 2
TCP_CONTROL_ENDPOINT = ("1.1.1.1", 443)
UDP_CONTROL_ENDPOINT = ("1.1.1.1", 53)
DNS_QUESTION = b"\x07example\x03com\x00\x00\x01\x00\x01"
SECRET_NAMES = ("XNP_TARGET_IPV4", "XNP_TCP_PORTS", "XNP_UDP_PORTS", "XNP_PROBE_NONCE")
ATTEMPT_REASONS = frozenset(("Validated", "OverallDeadline", "SizeLimit", "SourceMismatch",
    "IncompleteSend", "ProtocolMismatch", "Timeout", "ConnectionRefused", "NetworkError",
    "InternalError", "SocketCloseError"))
CONTROL_REASONS = ATTEMPT_REASONS | frozenset(("Connected", "DNSValidated", "InvalidDNSResponse"))


class InvalidSecrets(Exception):
    pass


@dataclass(frozen=True)
class Targets:
    ipv4: str = field(repr=False)
    tcp_ports: tuple = field(repr=False)
    udp_ports: tuple = field(repr=False)
    nonce: str = field(repr=False)


def utc_timestamp(utc_now=None):
    value = (utc_now or (lambda: datetime.now(timezone.utc)))()
    if not isinstance(value, datetime) or value.tzinfo is None:
        raise ValueError("InvalidUTCClock")
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


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


def bounded_exchange(protocol, endpoint, deadline, *, request=None, expected=None,
                     socket_factory=None, clock=None, dns_control=False, utc_now=None):
    """One entire connect/send/receive attempt, sharing a three-second deadline."""
    socket_factory = socket_factory or socket.socket
    clock = clock or time.monotonic
    result = {"status": "FAIL", "reason": "OverallDeadline", "attempts": 0,
              "started_at": utc_timestamp(utc_now), "completed_at": None}
    sock = None

    def set_remaining_timeout():
        remaining = deadline - clock()
        if remaining <= 0:
            raise TimeoutError
        sock.settimeout(min(PORT_TIMEOUT, remaining))

    try:
        if deadline <= clock():
            return result
        if request is not None and len(request) > MAX_BYTES:
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
            if request is None:
                if clock() >= deadline:
                    result["reason"] = "Timeout"
                else:
                    result["status"] = "PASS"
                    result["reason"] = "Connected"
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
                result["reason"] = "ProtocolMismatch"
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
        elif dns_control and not valid_dns_response(data, request):
            result["reason"] = "InvalidDNSResponse"
        elif not dns_control and data != expected:
            result["reason"] = "ProtocolMismatch"
        elif clock() >= deadline:
            result["reason"] = "Timeout"
        else:
            result["status"] = "PASS"
            result["reason"] = "DNSValidated" if dns_control else "Validated"
    except (TimeoutError, socket.timeout):
        result["reason"] = "Timeout"
    except ConnectionRefusedError:
        result["reason"] = "ConnectionRefused"
    except OSError:
        result["reason"] = "NetworkError"
    except Exception:
        # Never print exception strings, tracebacks, payloads or endpoints.
        result["reason"] = "InternalError"
    finally:
        if sock is not None:
            try:
                sock.close()
            except Exception:
                result["status"] = "FAIL"
                result["reason"] = "SocketCloseError"
        result["completed_at"] = utc_timestamp(utc_now)
    return result


def valid_dns_response(data, request):
    """Validate ordinary DNS response identity, flags and exact safe question."""
    if not isinstance(data, bytes) or len(data) < 12 + len(DNS_QUESTION):
        return False
    flags = int.from_bytes(data[2:4], "big")
    count = int.from_bytes(data[6:8], "big")
    if not (data[:2] == request[:2] and bool(flags & 0x8000)
            and (flags & 0x7800) == 0 and (flags & 0x0200) == 0 and (flags & 0x000F) == 0
            and int.from_bytes(data[4:6], "big") == 1 and 1 <= count <= 32
            and data[12:12 + len(DNS_QUESTION)] == DNS_QUESTION):
        return False
    offset = 12 + len(DNS_QUESTION)
    has_ipv4_answer = False
    for _ in range(count):
        offset = dns_name_end(data, offset)
        if offset is None or offset + 10 > len(data):
            return False
        record_type = int.from_bytes(data[offset:offset + 2], "big")
        record_class = int.from_bytes(data[offset + 2:offset + 4], "big")
        length = int.from_bytes(data[offset + 8:offset + 10], "big")
        offset += 10
        if offset + length > len(data):
            return False
        if record_type == 1 and record_class == 1:
            if length != 4:
                return False
            has_ipv4_answer = True
        offset += length
    return has_ipv4_answer


def dns_name_end(data, start, depth=0):
    if depth > 16:
        return None
    offset = start
    name_bytes = 0
    while offset < len(data) and name_bytes <= 255:
        size = data[offset]
        if size == 0:
            return offset + 1
        if size & 0xC0 == 0xC0:
            if offset + 1 >= len(data):
                return None
            target = ((size & 0x3F) << 8) | data[offset + 1]
            if target >= offset or dns_name_end(data, target, depth + 1) is None:
                return None
            return offset + 2
        if size > 63 or offset + 1 + size >= len(data):
            return None
        name_bytes += size + 1
        offset += size + 1
    return None


def runner_control(protocol, overall_deadline, *, socket_factory=None, clock=None, utc_now=None,
                   random_bytes=None):
    clock = clock or time.monotonic
    deadline = min(clock() + PORT_TIMEOUT, overall_deadline)
    if protocol == "tcp":
        return bounded_exchange("tcp", TCP_CONTROL_ENDPOINT, deadline,
                                socket_factory=socket_factory, clock=clock, utc_now=utc_now)
    transaction = (random_bytes or os.urandom)(2)
    if not isinstance(transaction, bytes) or len(transaction) != 2:
        raise ValueError("InvalidDNSRandom")
    query = transaction + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + DNS_QUESTION
    return bounded_exchange("udp", UDP_CONTROL_ENDPOINT, deadline, request=query, dns_control=True,
                            socket_factory=socket_factory, clock=clock, utc_now=utc_now)


def probe_port(targets, protocol, port, index, overall_deadline, *, socket_factory=None, clock=None,
               utc_now=None):
    clock = clock or time.monotonic
    result = {"index": index, "status": "FAIL", "reason": "OverallDeadline", "attempts": 0,
              "validated_count": 0, "started_at": utc_timestamp(utc_now), "completed_at": None,
              "attempt_results": []}
    request = (targets.nonce + "\n").encode("ascii")
    digest = hashlib.sha256(targets.nonce.encode("ascii")).hexdigest()[:16]
    expected = (f"XNP-VAST-{protocol.upper()}-OK:{digest}\n").encode("ascii")
    for attempt in range(1, MAX_ATTEMPTS + 1):
        deadline = min(clock() + PORT_TIMEOUT, overall_deadline)
        current = bounded_exchange(protocol, (targets.ipv4, port), deadline, request=request,
                                   expected=expected, socket_factory=socket_factory, clock=clock,
                                   utc_now=utc_now)
        performed = current.pop("attempts")
        result["reason"] = current["reason"]
        # An expired cumulative deadline or socket creation failure is a
        # diagnostic, not a performed network attempt. Avoid invented attempts
        # and stop rather than retrying a local resource failure.
        if performed == 0:
            break
        result["attempts"] += performed
        current["attempt"] = attempt
        result["attempt_results"].append(current)
        if current["status"] == "PASS":
            result["status"] = "PASS"
            result["validated_count"] = 1
            break
        if clock() >= overall_deadline:
            break
    result["completed_at"] = utc_timestamp(utc_now)
    return result


def skipped_udp(index, utc_now=None):
    moment = utc_timestamp(utc_now)
    return {"index": index, "status": "SKIPPED", "reason": "RunnerUDPControlFailed", "attempts": 0,
            "validated_count": 0, "started_at": moment, "completed_at": moment,
            "attempt_results": [], "adjudication": "NON_ADJUDICATIVE"}


def five_continuous(ports):
    ordered = sorted(ports)
    return len(ordered) == 5 and ordered == list(range(ordered[0], ordered[0] + 5))


def base_report():
    return {"schema": "XNP_GHA_PROBE_v22_1", "status": "NOT_RUN", "reason": "MissingSecrets",
            "started_at": None, "completed_at": None,
            "tcp_control": {"status": "NOT_RUN", "reason": "NotStarted", "attempts": 0,
                            "started_at": None, "completed_at": None},
            "udp_control": {"status": "NOT_RUN", "reason": "NotStarted", "attempts": 0,
                            "started_at": None, "completed_at": None},
            "tcp": [], "udp": [], "tcp_configured_count": 0, "udp_configured_count": 0,
            "tcp_all_pass": False, "udp_all_pass": False,
            "tcp_adjudicative": False, "udp_adjudicative": False,
            "udp_adjudication": "NON_ADJUDICATIVE", "tcp_five_continuous": False,
            "udp_five_continuous": False, "tcp_udp_same_five_range": False,
            "range_status": "NOT_EVALUATED", "external_execution_verified_by_script": False,
            "vast_network_gate": False}


def run(environment, *, socket_factory=None, clock=None, utc_now=None, random_bytes=None,
        event_sink=None):
    report = base_report()
    report["started_at"] = utc_timestamp(utc_now)
    try:
        targets = read_targets(environment)
    except InvalidSecrets as error:
        report["reason"] = str(error)
        report["completed_at"] = utc_timestamp(utc_now)
        return report
    clock = clock or time.monotonic
    overall_deadline = clock() + TOTAL_TIMEOUT
    for protocol in ("tcp", "udp"):
        control = runner_control(protocol, overall_deadline, socket_factory=socket_factory,
                                 clock=clock, utc_now=utc_now, random_bytes=random_bytes)
        report[protocol + "_control"] = control
        report[protocol + "_adjudicative"] = control["status"] == "PASS"
        if event_sink is not None:
            event_sink("control", protocol, control)
    report["udp_adjudication"] = ("ADJUDICATIVE" if report["udp_adjudicative"] else "NON_ADJUDICATIVE")
    for protocol, ports in (("tcp", targets.tcp_ports), ("udp", targets.udp_ports)):
        report[protocol + "_configured_count"] = len(ports)
        for index, port in enumerate(ports, 1):
            item = (skipped_udp(index, utc_now) if protocol == "udp" and not report["udp_adjudicative"]
                    else probe_port(targets, protocol, port, index, overall_deadline,
                                    socket_factory=socket_factory, clock=clock, utc_now=utc_now))
            report[protocol].append(item)
            if event_sink is not None:
                event_sink("port", protocol, item)
        report[protocol + "_all_pass"] = all(item["status"] == "PASS" for item in report[protocol])
        report[protocol + "_five_continuous"] = five_continuous(ports)
    report["tcp_udp_same_five_range"] = (report["tcp_five_continuous"] and report["udp_five_continuous"]
                                         and set(targets.tcp_ports) == set(targets.udp_ports))
    report["range_status"] = ("INSUFFICIENT_PORT_COUNT" if len(targets.tcp_ports) < 5 or len(targets.udp_ports) < 5
                              else "CONTINUOUS_FIVE_PER_PROTOCOL" if report["tcp_five_continuous"] and report["udp_five_continuous"]
                              else "PUBLIC_PORTS_NOT_CONTINUOUS")
    if not report["udp_adjudicative"]:
        report["status"], report["reason"] = "INCONCLUSIVE", "RunnerUDPControlFailed"
    elif not report["tcp_adjudicative"] and not report["tcp_all_pass"]:
        report["status"], report["reason"] = "INCONCLUSIVE", "RunnerTCPControlFailed"
    else:
        passed = report["tcp_all_pass"] and report["udp_all_pass"]
        report["status"] = "PASS" if passed else "FAIL"
        report["reason"] = "ConfiguredPortsValidated" if passed else "ConfiguredPortsNotAllValidated"
    report["completed_at"] = utc_timestamp(utc_now)
    return report


def emit_event(kind, protocol, item):
    if kind == "control":
        print(f"RUNNER_{protocol.upper()}_EGRESS_CONTROL={item['status']}", flush=True)
    else:
        print(f"{protocol.upper()}[{item['index']}]={item['status']} reason={item['reason']} "
              f"started_at={item['started_at']} completed_at={item['completed_at']}", flush=True)


def emit_redacted(report):
    print(f"OVERALL={report['status']} reason={report['reason']}", flush=True)
    print("XNP_RESULT_JSON=" + json.dumps(report, separators=(",", ":"), sort_keys=True), flush=True)


def main(argv=None, environment=None, **offline_injections):
    try:
        args = sys.argv[1:] if argv is None else argv
        if args:
            report = base_report()
            report["reason"] = "ArgumentsUnsupported"
        else:
            report = run(os.environ if environment is None else environment,
                         event_sink=emit_event, **offline_injections)
    except Exception:
        report = base_report()
        report["reason"] = "InternalError"
    emit_redacted(report)
    return 0 if report["status"] == "PASS" else 2 if report["status"] == "NOT_RUN" else 1


if __name__ == "__main__":
    sys.exit(main())
