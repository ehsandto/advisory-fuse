# Proof matrix

| Invariant | Local test | Live evidence |
|---|---|---|
| Semantic output materially determines the breaker | Trip, impact-policy and UNKNOWN tests | Affected EXECUTION trips; same evidence with AVAILABILITY policy does not |
| Acquisition is independent of caller text | Web mocks exercise full-body fetch/parse/hash path | Official Lodash and reviewed GHSA sources are fetched in VM |
| Wrong hash cannot authorize | Fake manifest commitment | `bad-commitment` -> HELD |
| Exact validator report; no tolerance | Vector/decision/hash/type-substitution tests | Successful validator executions and majority consensus for real scans |
| Decision/root rebuilt deterministically | Decision reconstruction and canonical equality tests | SDK readback reconstructs each complete report SHA-256 |
| Close before consensus | `test_arm_closes_previous_open_before_consensus` | Every live scan is armed separately before resolution |
| Trip cannot be manually reset | Immutable specification; no reset API | New random watchdog rescans and trip persists |
| Two fresh clean scans before recovery | Hysteresis, stale first observation, minimum-gap tests | MOCK-ONLY; no real advisory withdrawal claimed |
| Uncertainty cannot clear latch | Uncertainty resets recovery | Wrong commitment holds gate closed; existing-latch uncertainty MOCK-ONLY |
| Replay protection | Terminal resolution and reused-ID tests | Random watchdog reused scan ID rejected with execution ERROR |
| Fuse association | Cross-fuse resolution test | Passing legacy scan2 under patched fuse rejected |
| Old reports immutable | Hysteresis test preserves first record | Legacy scan1 root remains unchanged after scan2 and adversarial calls |
| Evidence expiry | Exact TTL boundary tests | Patched report remains OPEN but gate becomes false after 120 seconds |
| Root substitution | Wrong-root read tests | Read-only integration checks substituted roots for every fuse |
| Abandoned scan recovery | Permissionless expiry recovery test | MOCK-ONLY; not claimed as a finalized live recovery |
| Different caller can maintain the fuse | Bob resolves after expiry in direct test | Fresh random watchdog arms and resolves a fuse registered by another address |

The local suite runs leader logic plus pure normalization/equivalence tests, not a
mocked full validator network. The read-only integration checker verifies actual
StudioNet receipts, agreeing successful validator executions, source equality,
state, scope binding and roots. Experimental deployment, not production audit.
