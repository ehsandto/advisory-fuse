# AdvisoryFuse

A reusable, evidence-grounded software advisory circuit breaker for GenLayer.
Immutable artifact configuration; independently interpreted public advisories;
latched trips; two-observation recovery. **Not another graph or certificate.**

## Live StudioNet deployment

[Final contract](https://explorer-studio.genlayer.com/address/0x3886d8aAfb14772546951136022d63c23aED5ebb).
[17 finalized transactions](LIVE_PROOFS.md): 15 successful executions and two
intentional rejection proofs. [Proof matrix](docs/proof-matrix.md).
32 direct/unit/adversarial tests and GenVM lint/SDK validation pass.
The deployed source is byte-equal after documented line-ending normalization.
[Submission fields and evidence](SUBMISSION.md).

## Problem

A manifest version number does not tell a consumer what a disclosed vulnerability
does. Static severity scores cannot distinguish a command-execution disclosure
from a denial-of-service issue under an application's chosen impact policy.
Ordinary deterministic contracts cannot fetch and interpret those evolving reports.
AdvisoryFuse makes semantic interpretation consequential: the independently derived
technical impact determines whether the configured breaker trips.

## Architecture

```text
Pinned upstream package.json ----> bytes/hash/name/version
Reviewed advisory database -----> bytes/hash/affected ranges/prose
                                      |
                           independent validator fetch + AI
                                      |
                        exact evidence/impact report agreement
                                      |
                           policy-selected impact -> trip latch
                                      |
                      root + freshness bound consumer gate
```

The contract fetches documents inside the nondeterministic flow. Validators repeat
both acquisition and reasoning. Caller-supplied summaries, scores, outcomes and
AI classifications are absent from the API. A hash mismatch prevents semantic
evaluation; a correct hash alone can never open an affected-impact gate.

## State machine

```text
UNASSESSED -> SCANNING -> OPEN / HELD / TRIPPED
OPEN       -> SCANNING -> OPEN / HELD / TRIPPED
TRIPPED    -> SCANNING -> RECOVERY_PENDING -> SCANNING -> OPEN
                           first clean                  second clean
```

Every arm closes the gate **before** consensus. Failed consensus leaves SCANNING
closed. An abandoned scan expires after 300 seconds and anyone can arm a new ID.
Two clean observations must be at least 60 seconds apart, within the observation
TTL. Uncertainty, renewed risk or abandoned resolution resets recovery. An expired
OPEN assessment returns false without needing a maintenance transaction.

## Consensus boundary

Deterministic code validates stable npm three-part version ranges. Unsupported
version/range formats yield UNKNOWN, not a speculative safe answer. For affected
versions, leader and validators independently classify advisory prose into
EXECUTION, TAMPERING, DISCLOSURE, AVAILABILITY, OTHER or UNKNOWN. Execution takes
precedence when explicitly supported. A bounded exact source quote anchors the
classification. Full report equality binds source statuses, byte counts, hashes,
manifest match, package identity, version membership, semantic vector, scan ID,
observation time, policy root and deterministic report root. There is no confidence
tolerance. The deterministic transition reconstructs the decision from the vector.

Each differing validator votes against that report. The network uses majority
consensus, not contract-enforced unanimity. If consensus fails, resolution does not
apply and the already-armed gate remains closed. Direct tests run leader logic only;
live receipt tests are required to assess actual consensus behavior.

## Consumer API

| Method | Purpose |
|---|---|
| `register` | Fix artifact, selected advisories, blocked impacts and TTL permanently |
| `arm_scan` | Close gate, bind a new fuse-scoped scan ID; permissionless |
| `resolve_scan` | Refetch and interpret all material evidence; permissionless |
| `gate(fuse_id, root)` | True only for current unexpired OPEN evidence, no pending scan or trip |
| `get_fuse`, `get_scan` | Read state and immutable resolved evidence reports |
| `event_count`, `get_event` | Append-only transition log |

Consumers must bind the exact registered software artifact and current root. This
is a read gate, **not enforcement of an external execution or service delivery**.
It says only that the selected advisories do not establish a policy-blocked impact.
It is not a complete vulnerability scan or proof that a remote deployment runs the
manifest version. GitHub and its advisory authors remain trusted data sources.

## Security and limits

- No owner reset, mutable evidence policy, token balance, adapter or capability.
- Fuse/scan/spec/contract binding prevents cross-fuse substitution and root reuse.
- Scan IDs are never reused; terminal reports and old roots cannot be rewritten.
- Manifest commits are immutable; entire response SHA-256 is checked.
- Fresh observation TTL is not confused with advisory publication age.
- Up to four reviewed advisories; bounded response and prompt sizes.
- Permissionless arming intentionally permits safety closure: it can be abused for
  denial of service. Consumers requiring availability should mediate monitoring.
- Exact quote/report equality can reduce liveness; uncertainty never clears a trip.
- Malformed transport/model responses can revert resolution, leaving the gate closed.

See [architecture](docs/architecture.md), [threat model](SECURITY.md),
[novelty comparison](docs/novelty.md) and [proof ledger](LIVE_PROOFS.md).

## Install and test

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
npm ci
npm install -g genlayer@0.39.2
genvm-lint check contracts/AdvisoryFuse.py --json
pytest tests -v -s
```

Python 3.12 recommended. The Windows test shim defers only the known SDK open-temp-file
unlink error; it does not bypass contract tests. GenVM is pinned to a concrete runner.

## Deployment and interaction

StudioNet is experimental and gasless. No funding, private-key export or plaintext
credential files are required. Use an encrypted, dedicated test wallet.

```powershell
genlayer network set studionet
genlayer account use YOUR_TEST_KEYSTORE
genlayer deploy --contract contracts/AdvisoryFuse.py
genlayer write ADDRESS register --args legacy lodash lodash ded9bc66583ed0b4e3b7dc906206d40757b4a90a 9d2bf980f3ce2409b5e30162442e161d4c6c0e4dd897a6354fd2e90e58bdf333 2021/05/GHSA-35jh-r3h4-6jhm EXECUTION 3600
genlayer write ADDRESS arm_scan --args legacy scan1
genlayer write ADDRESS resolve_scan --args legacy scan1
genlayer call ADDRESS get_scan --args legacy scan1
genlayer call ADDRESS gate --args legacy REPORT_ROOT
```

Enter keystore passwords privately at the prompt. For concurrent local deployments,
`scripts/pin_cli_context.cjs` overrides only process-local public account/network
selection for CLI 0.39.2; it does not alter shared config or export keys.

## Real demonstration and verification

The intended demonstration compares official Lodash 4.17.20 and 4.17.21 manifests
with [GHSA-35jh-r3h4-6jhm](https://github.com/advisories/GHSA-35jh-r3h4-6jhm).
These are real upstream documents, not contract-generated evidence fixtures.
OSV range interpretation follows the [OSV schema](https://ossf.github.io/osv-schema/).
Wrong commitments and scan replay must fail closed. Recovery/withdrawal cases are
mock tests only unless real corresponding live receipts are explicitly listed.

```powershell
node scripts/verify_source.mjs ADDRESS
node scripts/verify_receipts.mjs TX_HASH
npm run verify:live
```

FINALIZED alone is not success: verify leader execution, validator votes, readback,
report-root reconstruction and Explorer/GitHub source equality. The proof ledger
must distinguish successful semantic outcomes from expected execution rejections.
No assurance of steward acceptance or points; no production audit claimed.
