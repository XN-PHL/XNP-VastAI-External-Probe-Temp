# XNP temporary external connectivity probe

This repository contains public probe code only. Its authorized destination is `XN-PHL/XNP-VastAI-External-Probe-Temp`, using one standard GitHub-hosted `ubuntu-latest` job. Creating these files does not authorize sending private inputs or establish that a real probe has run.

The repository must contain exactly:

```text
README.md
.github/workflows/probe.yml
probe_external.py
```

The local `probe.yml.template` is copied to `.github/workflows/probe.yml`; it is not a fourth repository file. Local offline tests, evidence, inputs and this project's other files are never uploaded.

## Private inputs and consent

Obtain the specific user authorization for current public IPv4, temporary mapped TCP/UDP ports and this round's nonce to this exact repository's GitHub-hosted runner before adding any real Secrets. Keep the repository public and the runner standard; stop before any charge or destination change. No IP, actual port list, nonce, password, credential, private key or household configuration belongs in repository files or commit history.

Set only these temporary Actions Secrets:

- `XNP_TARGET_IPV4`: one actual global unicast IPv4 literal. No hostname, private/shared address or fake-IP.
- `XNP_TCP_PORTS`: a JSON array of 1–5 distinct integer public TCP ports in the range 1–65535.
- `XNP_UDP_PORTS`: the equivalent JSON array for UDP. The lists can have different mapped values.
- `XNP_PROBE_NONCE`: this round's random 64 lowercase hexadecimal characters, generated from 32 random bytes.

For the intended v2.1 experiment, supply all five current mappings per protocol. General code accepts 1–5, but fewer than five cannot meet the five-port gate. Strings, comma lists, duplicates, empty arrays, extra ports and missing/invalid Secrets fail closed before any socket is created. `XNP_EXPECTED_HASH` is optional and unused: the code derives the expected reply from the nonce and does not read this Secret. No private value is passed as a command-line argument.

## One bounded manual round

Before dispatch, the operator must review the exact repository commit and workflow, verify the local listener/mapping round is active, and confirm the approved data/destination. The workflow checks out the dispatch commit (`github.sha`) and verifies the probe file against its reviewed SHA256 before a separate step receives the four Secrets. The checkout action is pinned to the full official [v4.3.1 commit](https://github.com/actions/checkout/commit/34e114876b0b11c390a56381ad16ebd13914f8d5); credentials are not persisted. Any code change requires a new review and matching workflow checksum. Do not dispatch arbitrary branches or unreviewed workflow changes.

Only `workflow_dispatch` is enabled. There is one job, no matrix, no third-party input, no artifact upload, `contents: read`, and a five-minute job limit. The Python step has a separate 40-second process timeout with a two-second forced termination allowance; probes have a 35-second cumulative budget, at most one application request per supplied port, and a three-second whole connect/send/receive limit per port. Each request and response is limited to 512 bytes. There are at most five TCP connections and five UDP sends, no retries, DNS, neighboring-port checks, scan or throughput load.

The public output consists only of indexed `TCP[n]` / `UDP[n]` PASS/FAIL, fixed reason codes, counts and boolean range checks. `XNP_RESULT_JSON={...}` is the final machine-readable redacted result. Neither raw socket exceptions nor tracebacks, complete target IP, actual ports, nonce or its response digest are logged. Do not enable shell tracing, environment dumps, debug payloads or artifact uploads. GitHub's masking is supplementary; the program itself never prints the private values.

The dedicated local responders must accept exactly ASCII nonce plus one LF and validate the complete nonce before replying:

```text
XNP-VAST-TCP-OK:<first 16 lowercase hex characters of SHA256(nonce ASCII)>\n
XNP-VAST-UDP-OK:<first 16 lowercase hex characters of SHA256(nonce ASCII)>\n
```

The digest excludes the request's LF. TCP must close the connection after its single reply; the probe reads to EOF within the deadline, rejects later trailing chunks and checks the real socket peer. UDP checks the actual `recvfrom` IPv4 and source port, not a claim in the body. A matching reply from another source or with a wrong digest/protocol/terminator fails.

## Evidence and cleanup

Secrets do not carry an expiry field. The parent session must independently enforce a nonce/listener window of at most ten minutes, invalidate the nonce when the round ends, and cancel a workflow that has not started within five minutes. A queued runner must never justify extending the window or reusing an old nonce. Preparing or running the Python program locally does not prove external execution; the operator must retain the real GitHub run URL, trusted commit, standard hosted runner metadata and timing. Environment flags alone are not proof.

`status=PASS` means all supplied ports returned the authenticated expected replies in this round. It does not itself prove five continuous ports, a common TCP/UDP range, long-term stability, throughput or Vast compatibility. Range booleans and `PUBLIC_PORTS_NOT_CONTINUOUS` honestly describe the complete input lists without printing values. `vast_network_gate` remains false; the parent task decides later gates using official requirements and real runner evidence. A UDP failure from one runner is not a permanent household NAT verdict; a second authorized independent source may still be needed.

Whether the round passes, fails, times out or is canceled, the operator must promptly remove all four temporary Secrets and optional `XNP_EXPECTED_HASH`, verify zero remain, stop owned listeners/mappings and remove only new task-owned network rules/routes if any were created. No repository deletion or credential deletion is performed by this public program. The repository may remain with the manual workflow disabled. The parent task records cleanup and any incident before continuing deployment.

## Local preparation verification

The v2.1 preparation passed 17 offline boundary tests with real socket creation forbidden during import and each test. These covered the complete ten-port round, one attempt per port, fragmented TCP EOF, actual UDP source, response limits, cumulative deadlines, invalid inputs before sockets, noncontinuous ranges and stdout/stderr secrecy. Python AST/compilation and static workflow structure/checksum checks passed. No real network probe or Actions execution is claimed by those tests; the test file stays outside the three-file public repository.
