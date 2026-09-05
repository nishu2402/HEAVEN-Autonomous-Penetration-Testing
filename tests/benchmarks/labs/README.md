# HEAVEN domain labs

Reproducible, self-contained `docker compose` stacks of **genuinely vulnerable
services**, one per scan domain, so HEAVEN's detectors can be scored against a
real target instead of a mock. This is the machine-checked form of the project's
honesty rule:

> A scan mode only earns its "10/10" when it is green against a real,
> reproducible vulnerable lab for its domain, and its label promises exactly
> what it delivers, no more.

Each lab runs real software with a real misconfiguration — not a responder tuned
to return whatever HEAVEN wants to see. The scanner performs its normal,
protocol-correct probe and the service answers as it would in the wild.

## The labs

| Lab | Compose file | Real vulnerable service(s) | HEAVEN detects (live) |
|-----|--------------|----------------------------|-----------------------|
| **cloud** | `cloud-compose.yml` | MinIO (real S3 API) with a public, listable bucket | `exposed_storage_bucket` (critical) via `<ListBucketResult>` |
| **container** | `container-compose.yml` | Docker-in-Docker API on :2375 (no TLS) + anonymous Registry v2 on :5000 | `docker_api_exposed` (critical) + `registry_exposed` (high) |
| **iot** | `iot-compose.yml` | Mosquitto with `allow_anonymous true` + real pymodbus server + real MediaMTX RTSP server | anonymous MQTT (critical) + unauthenticated Modbus (critical) + exposed RTSP |
| **ot** | `ot-compose.yml` | Real pymodbus server on ICS port 502 + real asyncua OPC-UA server on 4840 | Modbus TCP ICS reachable (critical) + OPC-UA ICS reachable |
| **malware (webshell)** | `webshell-compose.yml` | nginx serving inert webshell-signature decoys (no PHP, nothing executes) | `webshell_detected` (critical) for each shell via named signatures + the generic YARA path |
| **cloud (metadata SSRF)** | `cloud-ssrf-compose.yml` | An SSRF-vulnerable app on the link-local subnet + a fake IMDS pinned to 169.254.169.254 | metadata-SSRF confirmed (`validate_ssrf` reaches `/latest/meta-data/`) |
| **wireless (posture)** | `wireless-compose.yml` | nginx serving an unauthenticated MikroTik RouterOS webfig panel (inert decoy) | `wireless_mgmt_unauthenticated` (high), vendor-fingerprinted |
| **email (VRFY)** | `smtp-vrfy-compose.yml` | Real aiosmtpd MTA with VRFY enabled against a genuine local-user set | `smtp_user_enumeration` (250 valid vs 550 unknown) |
| **dos** | `dos-compose.yml` | Single-threaded `http.server` (no header timeout) + memcached with UDP enabled | `slow_http_dos` (medium); memcached amplification best-effort |
| **web (DOM XSS)** | `juiceshop-compose.yml` | OWASP Juice Shop (real Angular SPA): search `q` rendered to an innerHTML sink via `bypassSecurityTrustHtml` | `xss_dom_execution` proven live — the payload's JavaScript runs in headless Chromium (token-carrying dialog), a client-side DOM sink an HTTP-only scan cannot see |
| **api** | `vampi-compose.yml` | VAmPI (real third-party OWASP API Top 10) publishing its own OpenAPI contract | `excessive_data_exposure` (`/users/v1/_debug` leaks passwords), `api_broken_auth` (`/users/v1`), `api_docs_exposed` — all via genuine spec-driven endpoint discovery |

## Safety

Every service binds to **loopback only** (`127.0.0.1`). These stacks are
deliberately insecure — never publish them on `0.0.0.0`. The container lab's
exposed Docker daemon is the *nested* dind daemon, isolated from the host
daemon; nothing on the host is exposed. The cloud bucket holds a single benign
marker object, nothing sensitive.

## Running

The labs are gated behind `HEAVEN_RUN_BENCHMARKS=1` and Docker, exactly like the
DVWA benchmark, so a normal `pytest` run never pulls an image or starts a
container:

```bash
HEAVEN_RUN_BENCHMARKS=1 pytest tests/benchmarks/test_domain_labs.py -v
```

Each test brings its stack up, waits for the service to actually answer its
protocol handshake (not merely accept a TCP connection), runs the real scanner,
asserts the expected finding, and always tears the stack down (`down -v`).

To bring one up by hand:

```bash
docker compose -f tests/benchmarks/labs/iot-compose.yml up -d --build
# ... scan 127.0.0.1 ...
docker compose -f tests/benchmarks/labs/iot-compose.yml down -v
```

## Honest scope

* **cloud** is green on the public-bucket detector against a real S3-compatible
  store (MinIO / Ceph RGW / LocalStack pattern), reached via HEAVEN's
  `--endpoint` / `HEAVEN_S3_ENDPOINT` override. The metadata-SSRF path and the
  authenticated account audit are unit-tested; a seeded multi-account lab is
  future work.
* **iot / ot** prove the MQTT and Modbus read-only probes end to end. The
  RTSP / SNMP / CoAP / BACnet / SSDP / S7comm / DNP3 / IEC-104 / OPC-UA probes
  share the same harness and are unit-tested; broader multi-protocol breadth
  (e.g. a Conpot / OpenPLC honeypot) is future work.
* **dos** proves Slow-HTTP (Slowloris) susceptibility live. The lab also runs
  memcached with the UDP listener enabled (CVE-2018-1000115); its amplification
  is detected on a native-Linux Docker host, but Docker Desktop for Mac's
  userspace UDP NAT drops the reflected datagram, so that vector is asserted
  best-effort. The mode's label promises a susceptibility assessment, never a
  flood — and it never floods.
* **api** proves the REST scanner against a third-party app HEAVEN did not
  author (the always-on native fixture is HEAVEN's own). HEAVEN reads VAmPI's
  published OpenAPI contract and probes the endpoints it declares, then confirms
  the password leak, the unauthenticated user collection and the public spec
  live. BOLA on VAmPI's string-keyed objects is intentionally not asserted — the
  numeric-ID BOLA probe honestly does not fire on `{username}`/`{book_title}`
  keys, and the lab does not pretend otherwise.

See `heaven/labs.py` for the ledger these labs back, and run `heaven labs` to
print the current status of every mode.
