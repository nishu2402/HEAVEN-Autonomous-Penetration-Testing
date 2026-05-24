# DB Layer Split — Plan & Risk Notes

`heaven/db/models.py` (1238 lines) and `heaven/db/repository.py` (1191 lines)
are scheduled for entity-grouped decomposition. This document captures the
plan and the safe execution order so a follow-up PR can land it without
breaking SQLAlchemy's ORM mapper resolution.

## Why not split this session?

The model classes have **>40 cross-module `relationship()` calls** with
string forward-references (e.g., `Mapped[List["Asset"]]`). SQLAlchemy
resolves these against `Base.metadata` at mapper-configure time, which
requires every class to be imported in the same `Base.registry` BEFORE
the first session operation.

A naïve split can subtly break this in three ways:
1. Forward references pointing at strings that no class registers
   (silent: relationships return empty lists instead of raising).
2. `cascade="all, delete-orphan"` requires the back-populated side to
   exist at delete time — async sessions surface this as a runtime
   `AmbiguousForeignKeysError` only on cascade.
3. Polymorphic discriminator columns (if added later) must see all
   subclasses registered before they're queried.

The existing test suite (`tests/test_db_layer.py`) exercises (1) but
not (2) or (3). Splitting without first extending that suite would
trade clean files for a hidden runtime bug.

## Target layout

```
heaven/db/
├── __init__.py                    # re-exports, unchanged public API
├── connection.py                  # unchanged
├── models/                        # new package
│   ├── __init__.py                # re-exports every class for back-compat
│   ├── _base.py                   # Base, mixins
│   ├── _enums.py                  # asset_type_enum, scan_status_enum, ...
│   ├── scan.py                    # Scan, ScanFinding, ScanCheckpoint
│   ├── asset.py                   # Asset, Port, NetworkTopology
│   ├── network.py                 # DnsRecord, SslCertificate, WebPath
│   ├── vuln.py                    # Vulnerability, Validation, RiskScore, VulnChain
│   ├── engagement.py              # Engagement, EngagementScope
│   ├── creds.py                   # Secret, Credential
│   ├── intel.py                   # MitreTechnique, CloudResource
│   ├── reporting.py               # Report, Tag, FindingTag, OperatorNote, Notification
│   └── audit.py                   # AuditLog
└── repository/                    # new package, mirrors models/
    ├── __init__.py                # re-exports + get_repository_factory
    ├── _base.py                   # BaseRepository
    ├── scan.py                    # ScanRepository
    ├── asset.py                   # AssetRepository
    ├── vuln.py                    # VulnerabilityRepository
    ├── engagement.py              # EngagementRepository
    ├── webpath.py                 # WebPathRepository
    ├── notification.py            # NotificationRepository
    ├── audit.py                   # AuditRepository
    └── report.py                  # ReportRepository
```

## Class-to-file mapping (canonical)

| Class | File |
|---|---|
| `Base` | models/_base.py |
| `asset_type_enum`, `scan_status_enum`, ... (all 13 Enum names) | models/_enums.py |
| `Scan`, `ScanFinding`, `ScanCheckpoint` | models/scan.py |
| `Asset`, `Port`, `NetworkTopology` | models/asset.py |
| `DnsRecord`, `SslCertificate`, `WebPath` | models/network.py |
| `Vulnerability`, `Validation`, `RiskScore`, `VulnChain` | models/vuln.py |
| `Engagement`, `EngagementScope` | models/engagement.py |
| `Secret`, `Credential` | models/creds.py |
| `MitreTechnique`, `CloudResource` | models/intel.py |
| `Report`, `Tag`, `FindingTag`, `OperatorNote`, `Notification` | models/reporting.py |
| `AuditLog` | models/audit.py |

## Safe execution order

1. **Extend the test suite first.** Add to `tests/test_db_layer.py`:
   - A test that creates one of every entity, exercises every
     `relationship`, and asserts no `WarnDeprecationWarning` from SQLAlchemy.
   - A cascade-delete test for every parent→child pair.
   - An async session test that opens, queries every model, closes.
2. Confirm new tests pass against the current `models.py` (this proves
   the test is correct).
3. Create `models/__init__.py` that does `from heaven.db.models_canonical import *`
   (rename the existing file to `models_canonical.py` first). This is a
   no-op for SQLAlchemy and proves the package layer works.
4. **Per entity group** (one PR each — small, reviewable):
   - Move the relevant classes to the new file.
   - Update `models/__init__.py` to import from the new file.
   - Delete those classes from `models_canonical.py`.
   - Run the test suite.
5. When `models_canonical.py` only contains the deprecation shim,
   delete it.
6. Repeat the per-entity loop for `repository/`.

## Imports that need updating

Search results from `grep -rn "from heaven.db.models import"`:

- `heaven/db/__init__.py:54` — bulk re-export, will keep working via
  the package's `__init__.py` re-exports.
- `heaven/db/repository.py:45` — `Asset, Scan, Vulnerability`, will
  keep working.
- `tests/test_db_layer.py:35,54,63,67,71,78,90` — same, no change needed.

No code outside `heaven/db/` reaches in for individual classes by their
old import path. The split is invisible to all consumers.

## Risk register

| Risk | Mitigation |
|---|---|
| Relationship forward-ref doesn't resolve | Test (1) above will catch it. Run on every per-entity PR. |
| Cascade-delete behaviour changes | Test (2) covers every parent→child. |
| Async-session race when registry is touched mid-query | The package layer is import-time only; no runtime registry mutation. |
| Existing migrations break because `__tablename__` changes | Class names + table names are preserved exactly. Verified via the `models/__init__.py` re-export tests. |
| New contributor imports a class from the wrong path | Every entity file gets a top-of-file comment noting "canonical location for class X — import via `from heaven.db.models import X`." |

## Status

- **2026-05-24**: Plan drafted. Not yet executed because the test suite
  needs the extensions in step 1 first. Tracking issue: TBD.
