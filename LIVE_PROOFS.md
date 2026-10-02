# Final-source StudioNet proofs

Contract: [0x3886d8aAfb14772546951136022d63c23aED5ebb](https://explorer-studio.genlayer.com/address/0x3886d8aAfb14772546951136022d63c23aED5ebb).
Normalized deployed source SHA-256:
`d886940b895eaf90463399fbcf5d0735a4c773e0e8616b2c051773d1e67c86bc`.
Source equals `contracts/AdvisoryFuse.py`, after CRLF/LF and final-newline normalization.
This ledger cites only the final audited deployment, not the superseded preliminary one.

All transactions below finalized. Fifteen executed successfully. Two deliberately
invalid calls finalized with execution ERROR; those are rejection proofs, not
successful service/semantic executions. A read-only verifier rechecks receipts,
successful agreeing validator executions, sender identities, state and evidence roots.

Consensus was **majority agreement, not unanimity**. Several receipts include idle
validators. The fresh watchdog rescan had three agree votes, one disagree and one
idle; the accepted result retained TRIPPED. Every approving validator must pass
the contract's exact report comparison, but the network controls the voting quorum.
Absent consensus, resolution cannot apply and the armed gate stays closed.

| Step | Result | Explorer transaction |
|---|---|---|
| Deploy final source | SUCCESS | [Deployment](https://explorer-studio.genlayer.com/tx/0x9da045d9f9c3251393a50c6294eea7fd676ebf79379270522bb804f4f2be08a9) |
| Register affected Lodash 4.17.20 | Immutable artifact and EXECUTION policy | [Registration](https://explorer-studio.genlayer.com/tx/0x73a582dd601ab41cbe947fccf6503daf7bec2c67e2d16a74d7d59e2ced67e257) |
| Arm affected scan | SCANNING; gate closed | [Arm](https://explorer-studio.genlayer.com/tx/0x5f3a4f67504a54cbb9a6e2a533b6138e0fbe0305d560b735647f6673f9494a85) |
| Resolve actual advisory | AFFECTED / EXECUTION -> TRIPPED | [Semantic trip](https://explorer-studio.genlayer.com/tx/0x21620167b1bfc9926a228d354a06a7bc83eedf94cde505ef584b2b578639659e) |
| Register Lodash 4.17.21 | Patched manifest; 120-second TTL | [Registration](https://explorer-studio.genlayer.com/tx/0x906cb054131eea60a98cd562de047ce9ac95d87ef6ed5fe63a83e64255f28a7d) |
| Arm patched scan | SCANNING | [Arm](https://explorer-studio.genlayer.com/tx/0xbe5d2056d68db2a651e9579e3eb388ef6a8597685450be692efdefa057ec524c) |
| Resolve patched scan | UNAFFECTED -> OPEN | [Clean result](https://explorer-studio.genlayer.com/tx/0xc552c0388b866403a2651b354e876aed84e38ca54e743363b7c070d7a7d311d6) |
| Register availability-only policy | Same affected manifest, distinct impact policy | [Registration](https://explorer-studio.genlayer.com/tx/0x7761fdda34031e3e4fed03c83f72b0dd2dad5173574ba67af9bba0d8def1169f) |
| Arm policy contrast | SCANNING | [Arm](https://explorer-studio.genlayer.com/tx/0x8f061d899e3871a2be4749b7087c507423e7fc4f63eb2abddde9ab9370bec6f1) |
| Resolve policy contrast | AFFECTED / EXECUTION; not AVAILABILITY -> policy-relative OPEN | [Semantic contrast](https://explorer-studio.genlayer.com/tx/0x16d2c666a8df368502a261ef96804a7c259545087022a61030bc81350e868651) |
| Register forged commitment | Expected hash intentionally wrong | [Registration](https://explorer-studio.genlayer.com/tx/0x7e1a3266a8145967d76555cbba251991f972062b206e71b6ccf7792e92a8f3f1) |
| Arm forged-commitment scan | SCANNING | [Arm](https://explorer-studio.genlayer.com/tx/0xde8e972491f462c4e7d4743de5f2e02fca04f887865b41244ca5b7845b4a447a) |
| Resolve forged commitment | Actual hash mismatch -> UNKNOWN / HELD | [Failure closed](https://explorer-studio.genlayer.com/tx/0xeead024ae669942df7f265bc87a2ce7c4367f5507e1da2996eeaa7a840a6b1a6) |
| Fresh random watchdog arms existing fuse | Different sender, permissionless operation | [Watchdog arm](https://explorer-studio.genlayer.com/tx/0x9fdfac33c05c4a8a8c14eaffcfc5e56e3e6606aef5dfcdd706a76fcd03783298) |
| Watchdog resolves fresh scan | TRIPPED retained; old report immutable | [Watchdog scan](https://explorer-studio.genlayer.com/tx/0x403da1f82f81cde010776c10f622958ea054c9aa41ce229640c0c200f9836e34) |
| Watchdog reuses old scan ID | EXPECTED ERROR: invalid or reused scan ID | [Replay rejection](https://explorer-studio.genlayer.com/tx/0x18323ff0bcc136bedb0993637826618a1bbb39165ff844ed8a4be98e1e13a185) |
| Watchdog passes scan2 under patched fuse | EXPECTED ERROR: wrong fuse, terminal or expired scan | [Resolution rejection](https://explorer-studio.genlayer.com/tx/0xf501fa7de94176ac4cc59a269b23da444ad667e36cf58db3f5374bf29bfb0bf9) |

## Independently acquired evidence

- [Lodash 4.17.20 manifest](https://raw.githubusercontent.com/lodash/lodash/ded9bc66583ed0b4e3b7dc906206d40757b4a90a/package.json):
  2046 bytes; SHA-256 `9d2bf980f3ce2409b5e30162442e161d4c6c0e4dd897a6354fd2e90e58bdf333`.
- [Lodash 4.17.21 manifest](https://raw.githubusercontent.com/lodash/lodash/f299b52f39486275a9e6483b60a410e06520c538/package.json):
  2046 bytes; SHA-256 `0d486d8dd5d67f09a44aa72a6acecba39a5a66c07ec4f988e9c2ee3075563a5e`.
- [Reviewed GHSA-35jh-r3h4-6jhm record](https://raw.githubusercontent.com/github/advisory-database/main/advisories/github-reviewed/2021/05/GHSA-35jh-r3h4-6jhm/GHSA-35jh-r3h4-6jhm.json):
  observed 4272 bytes; SHA-256 `3060fadb9a686e5041d53fe5c20c7844b2a0a49ce8d7b3d89d70703be02ec4f1`.
  Semantic impact was EXECUTION, anchored to the exact phrase "Command Injection".

These are upstream public records, not repository-authored demo evidence. They do
not prove that a remote host is running that version or that every vulnerability
has been checked. The availability-only contrast is intentionally **not a universal
security approval**: it shows why independently interpreted impact affects policy.

## Readback and expiry

`patched` reached OPEN with observation time `1790948022` and TTL 120. Its exact-root
gate returned false after `1790948142`, while the stored immutable report remained
OPEN. Expiry is a read-time safeguard, not a new transaction or destroyed report.
Wrong-root gates also return false. Run `npm run verify:live` to reproduce current
freshness-sensitive checks; OPEN gates naturally expire as time passes.

The newly created encrypted watchdog wallet is
`0x948B4141547457D99f319AA5Cf072EB8C7e5f5aa`. It had zero GEN and still executed
the StudioNet calls. No private key, password or encrypted keystore is published.

## Test scope

32 direct/unit/adversarial tests pass; GenVM lint and SDK validation pass.
Actual consensus and acquisition are checked by these live receipts and readback.
Advisory withdrawal, two-clean-scan recovery, transport errors, malformed AI and
boolean/integer substitution are local mocked/unit tests—not claimed live outcomes.
See [proof matrix](docs/proof-matrix.md) and [machine-readable ledger](docs/proof-manifest.json).
