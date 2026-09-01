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
| **iot** | `iot-compose.yml` | Mosquitto with `allow_anonymous true` + real pymodbus server | anonymous MQTT (critical) + unauthenticated Modbus (critical) |
| **ot** | `ot-compose.yml` | Real pymodbus server on ICS port 502 | Modbus TCP ICS reachable (critical) |
| **dos** | `dos-compose.yml` | Single-threaded `http.server` (no header timeout) + memcached with UDP enabled | `slow_http_dos` (medium); memcached amplification best-effort |

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

See `heaven/labs.py` for the ledger these labs back, and run `heaven labs` to
print the current status of every mode.
