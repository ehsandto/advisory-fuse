# Contribution Type

Builder -> Intelligent Contracts

# Title

AdvisoryFuse — Evidence-Grounded Circuit Breaker

# Notes / Description

AdvisoryFuse is a reusable GenLayer advisory circuit breaker, not a graph or certificate. Immutable configuration binds an upstream manifest commit/hash, reviewed advisories, impact policy and TTL. Scan arming closes the gate before consensus. Leader and validators independently fetch documents, check affected-version ranges and semantically classify impacts. Exact canonical report equality binds hashes, membership and impact; deterministic code reconstructs the decision and evidence root. Blocked impacts latch TRIPPED. Uncertainty holds the gate closed; two fresh clean scans are required to clear a trip. Expired scans allow retry; stale roots and expired observations cannot open the gate. StudioNet proofs demonstrate affected-version trips, patched-version opening/expiry, policy contrast, wrong-hash failure, third-party rescanning and replay rejection. Lint/SDK validation and 32 tests pass. Recovery is mock-tested; selected-advisory coverage is not a complete security audit.

# Evidence URLs

- [Repository](https://github.com/ehsandto/advisory-fuse)
- [Contract source](https://github.com/ehsandto/advisory-fuse/blob/main/contracts/AdvisoryFuse.py)
- [README](https://github.com/ehsandto/advisory-fuse/blob/main/README.md)
- [Full live proof ledger](https://github.com/ehsandto/advisory-fuse/blob/main/LIVE_PROOFS.md)
- [Proof matrix and test scope](https://github.com/ehsandto/advisory-fuse/blob/main/docs/proof-matrix.md)
- [Final deployed contract](https://explorer-studio.genlayer.com/address/0x3886d8aAfb14772546951136022d63c23aED5ebb)
- [Deployment](https://explorer-studio.genlayer.com/tx/0x9da045d9f9c3251393a50c6294eea7fd676ebf79379270522bb804f4f2be08a9)
- [Real semantic execution-risk trip](https://explorer-studio.genlayer.com/tx/0x21620167b1bfc9926a228d354a06a7bc83eedf94cde505ef584b2b578639659e)
- [Patched-version result](https://explorer-studio.genlayer.com/tx/0xc552c0388b866403a2651b354e876aed84e38ca54e743363b7c070d7a7d311d6)
- [Semantic impact-policy contrast](https://explorer-studio.genlayer.com/tx/0x16d2c666a8df368502a261ef96804a7c259545087022a61030bc81350e868651)
- [Wrong commitment fails closed](https://explorer-studio.genlayer.com/tx/0xeead024ae669942df7f265bc87a2ce7c4367f5507e1da2996eeaa7a840a6b1a6)
- [Fresh random watchdog rescans; trip persists](https://explorer-studio.genlayer.com/tx/0x403da1f82f81cde010776c10f622958ea054c9aa41ce229640c0c200f9836e34)
- [Expected rejection: reused scan ID](https://explorer-studio.genlayer.com/tx/0x18323ff0bcc136bedb0993637826618a1bbb39165ff844ed8a4be98e1e13a185)
- [Expected rejection: wrong-fuse/nonpending resolution](https://explorer-studio.genlayer.com/tx/0xf501fa7de94176ac4cc59a269b23da444ad667e36cf58db3f5374bf29bfb0bf9)

# Submission cautions

Use the actual contribution date. The last two transactions are intentional execution
rejections, not successful semantic executions. Recovery/withdrawal tests are local
mock tests, not live withdrawal proofs. OPEN is relative to the selected advisories
and impact policy and expires automatically. No production audit or points guaranteed.
