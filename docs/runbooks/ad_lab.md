# HEAVEN — Active Directory Lab Runbook

This is a step-by-step guide for validating `heaven/recon/ad_scanner.py` against a real Active Directory environment. The AD scanner module exists and imports cleanly, but it has no unit tests because AD recon requires a live domain controller, valid domain credentials, and Kerberos working end-to-end.

This runbook gets you to the point where `heaven scan --ad-domain ... --ad-dc ...` produces meaningful output you can validate.

---

## Option A — GOAD (Game Of Active Directory) — recommended

[GOAD](https://github.com/Orange-Cyberdefense/GOAD) is a turnkey vulnerable AD environment from Orange Cyberdefense. Two domains, three DCs, six member servers, all preconfigured with realistic misconfigurations. License: GPL-3.0.

### Prerequisites

- A host with **at least 24 GB RAM and 100 GB disk** (GOAD spins up 6+ Windows VMs).
- VirtualBox or VMware Workstation.
- Vagrant (`brew install vagrant` / `apt install vagrant`).
- Ansible 2.10+ (provisioning takes ~2 hours).

### Steps

```bash
git clone https://github.com/Orange-Cyberdefense/GOAD.git
cd GOAD
./goad.sh -t install -l GOAD -p virtualbox
# Wait ~2 hours. Coffee break, three times.
```

Once GOAD is up, you have:
- `north.sevenkingdoms.local` (forest root)
- `essos.local` (child domain via trust)
- Default user `khal.drogo:horse` on `essos.local`
- Default kerberoastable user `vagrant:vagrant` on the VM accounts

### Run HEAVEN against GOAD

```bash
export HEAVEN_AD_USER='khal.drogo'
export HEAVEN_AD_PASSWORD='horse'
export HEAVEN_AUTHORIZED_SCOPE='192.168.56.10,essos.local'

heaven scan \
    --ad-domain essos.local \
    --ad-dc 192.168.56.10 \
    --i-have-authorization \
    -o pdf --output-file goad_report.pdf
```

### What to verify

The AD scanner should at minimum produce:

1. **Domain enumeration:** users, groups, computers, OUs, GPOs.
2. **Kerberoastable accounts:** GOAD ships with several SPN-backed service accounts.
3. **AS-REP roastable accounts:** at least one user has `DONT_REQ_PREAUTH`.
4. **Unconstrained delegation:** at least one machine in `north.sevenkingdoms.local`.
5. **Weak ACL paths:** GOAD has `GenericWrite` / `WriteOwner` paths between users.

If the scanner returns fewer than 3 of those 5, treat its output as suspect and dig into the specific module that failed (typically `ad_scanner._enumerate_kerberoastable` or `_check_delegation`).

---

## Option B — Samba DC (lightweight, single VM)

For a smaller environment without GOAD's six-VM footprint:

```bash
docker run -it --rm \
    -p 53:53/udp -p 88:88 -p 135:135 -p 389:389 -p 445:445 -p 464:464 \
    -p 636:636 -p 3268:3268 -p 3269:3269 \
    -e SAMBA_DOMAIN=HEAVEN -e SAMBA_REALM=heaven.lab \
    -e SAMBA_ADMIN_PASSWORD='Password123!' \
    instantlinux/samba-dc:latest
```

This gives you a single AD DC at `127.0.0.1` with the realm `heaven.lab`. You'll need to add some kerberoastable accounts manually:

```bash
docker exec -it <container> samba-tool user create svc_sql Password123! \
    --description='SQL Service Account' \
    --service-principal-name='MSSQLSvc/sql.heaven.lab:1433'
```

Then run:

```bash
heaven scan \
    --ad-domain heaven.lab \
    --ad-dc 127.0.0.1 \
    --i-have-authorization
```

---

## Validation criteria

A successful run produces a JSON report containing at least:

- `assets[]` with `asset_type: "ad_user"` for each enumerated user
- `vulnerabilities[]` entries with `type` in:
  - `ad_kerberoastable`
  - `ad_asrep_roastable`
  - `ad_unconstrained_delegation`
  - `ad_weak_acl`
  - `ad_password_policy`

If any of those types are completely absent **and** GOAD/Samba is correctly configured, file an issue against the module — that's a real bug in the AD scanner, not a config issue.

---

## Common failure modes

| Symptom | Cause | Fix |
|---|---|---|
| `Connection refused` on DC | LDAP not exposed | Open port 389 (LDAP) and 88 (Kerberos) |
| `KRB_AP_ERR_SKEW` | Clock drift > 5 min between scanner host and DC | `sudo ntpdate <dc-ip>` |
| `LDAP bind failed` with valid creds | Domain in env doesn't match `--ad-domain` | Set `--ad-domain` to the actual realm (case-sensitive) |
| Empty user list | LDAP search base wrong | Module derives base from `--ad-domain` — check `heaven/recon/ad_scanner.py:_get_search_base` |

---

## Out-of-scope

This runbook does NOT cover:
- Lateral movement (HEAVEN doesn't do that — see README disclaimer)
- Pass-the-hash or pass-the-ticket attacks (out of scope for a scanner)
- DCSync (out of scope; would require Domain Admin)
- Golden Ticket / Silver Ticket (out of scope)

If you need any of the above for a real engagement, use BloodHound + impacket directly. HEAVEN's job ends at "here are the misconfigurations a privileged attacker would chain."
