# XNP synchronized temporary external connectivity probe

These three public files serve one authorized manual diagnostic in
`XN-PHL/XNP-VastAI-External-Probe-Temp`, on one standard GitHub-hosted
`ubuntu-latest` job. Local preparation does not authorize household data transfer.
Before this new round, obtain the user's explicit authorization for its new
household IPv4, at most five actual mapped TCP ports and five mapped UDP ports,
a new random nonce, and protocol labels to that exact destination.

The public repository contains exactly `README.md`, `probe_external.py`, and
`.github/workflows/probe.yml`. The local `probe.yml.template` becomes that workflow;
it is not a fourth uploaded file. Local tests, reports, network configuration and
private input files never belong in the public repository or Git history.

Set only four temporary Secrets: `XNP_TARGET_IPV4` (one actual global unicast IPv4),
`XNP_TCP_PORTS` and `XNP_UDP_PORTS` (JSON arrays of 1–5 distinct integer ports,
1–65535), and `XNP_PROBE_NONCE` (64 lowercase hex characters from 32 random bytes).
Missing, invalid, duplicated or excessive inputs stop before any socket opens.
No private input is accepted through command-line arguments.

The parent session must first verify its localhost and LAN TCP/UDP responders,
task-owned firewall protection, live mappings, exact public endpoints and cleanup
watchdog. Generate the nonce close to dispatch and enforce its lifetime at most
ten minutes. Keep the mappings/listeners alive while the job is queued or running;
cancel a job that has not started within five minutes. An independent twelve-minute
watchdog must close the session if coordination fails. Any early local closure
makes later failures inconclusive.

The reviewed dispatch commit is checked out by the pinned official
[actions/checkout v4.3.1 commit](https://github.com/actions/checkout/commit/34e114876b0b11c390a56381ad16ebd13914f8d5),
without persisted credentials. The workflow verifies the exact public Python
SHA256 before the probe step receives Secrets. Only manual `workflow_dispatch`
is enabled, with `contents: read`, one job, a five-minute job limit, and no matrix,
cache, artifact, external callback, or paid runner. The Python process has an
85-second timeout; its cumulative socket budget is 72 seconds. Review and update
the workflow checksum whenever the probe changes.

Before household tests, fixed runner controls perform one TCP connect to
Cloudflare's `1.1.1.1:443` and one normal UDP DNS query for `example.com` A to
`1.1.1.1:53`. Each has a three-second total deadline. The DNS response must come
from the actual fixed endpoint and match transaction, response flags and exact
question. The controls disclose no household data. Their public output is
`RUNNER_TCP_EGRESS_CONTROL=PASS/FAIL` and `RUNNER_UDP_EGRESS_CONTROL=PASS/FAIL`.

Each supplied household endpoint gets at most two attempts, stopping after an
authenticated success. Each attempt has a three-second whole connect/send/receive
deadline; request and response are at most 512 bytes. UDP gets at most two packets
per endpoint. TCP checks the actual peer and requires the exact complete reply and
EOF; UDP checks the actual source IPv4 and port. The request is ASCII nonce plus
one LF. The only valid reply is:

```text
XNP-VAST-TCP-OK:<SHA256(nonce ASCII) first 16 lowercase hex characters>\n
XNP-VAST-UDP-OK:<SHA256(nonce ASCII) first 16 lowercase hex characters>\n
```

If the UDP control fails, no household UDP packet is sent: each UDP result is
`SKIPPED`, `RunnerUDPControlFailed`, zero attempts, and `NON_ADJUDICATIVE`. A
failed TCP control prevents a failed household TCP result from proving an ingress
problem. A real authenticated household success still proves that endpoint's
reachability. These controls do not identify a household ISP or NAT cause.

Port results print immediately with only their protocol/index, status, fixed
reason and UTC start/end timing. Final `XNP_RESULT_JSON` uses schema
`XNP_GHA_PROBE_v22_1`, indexed attempt results, control outcomes, counts, UTC
timing, and range booleans. No household IPv4, actual port value/list, nonce,
response digest, exception text, traceback, or packet payload is printed. Do not
enable shell tracing, debug environment dumps or artifact uploads. GitHub masking
is supplemental to the program's own omission of private data.

A PASS is a verified nonce roundtrip for every supplied endpoint during this
bounded round. The parent must independently prove the real hosted runner,
trusted commit, exact endpoints and mapping lifetime. The script cannot prove
external execution by itself, and `external_execution_verified_by_script` and
`vast_network_gate` remain false. Reachability and five-port continuity are separate
checks. Five successful random mappings do not establish a continuous range,
long-term stability, throughput, dedicated public IPv4, or Vast compatibility.

After the workflow completes, the parent reads redacted results, removes only
the four Secrets it created, stops its mappings/listeners, removes its temporary
firewall/routes, expires the nonce and verifies cleanup. For forced cancellation,
cancel and wait for this run before local cleanup. Existing VPNs, mappings,
credentials and unrelated network rules are preserved. No repository deletion,
platform registration, disk change or purchase is performed by this public code.

Offline tests stay local and forbid real sockets. They verify controls, bounded
attempts, response identity and framing, sender/peer checks, skipped UDP, cumulative
deadlines, invalid input handling, immediate safe output and workflow integrity.
Those tests do not establish that a real Actions job or public ingress succeeded.
