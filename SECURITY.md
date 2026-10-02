# Security policy

Experimental StudioNet prototype. Do not use as sole protection for production funds
or as a complete vulnerability scanner. Report issues using a private GitHub security
advisory; do not disclose private keys or credentials.

## Trust boundary

Registered manifest coordinates identify an artifact, not an observed running host.
An attacker can register their own artifact or select too few advisories. Consumers
must trust the chosen specification and bind their actual artifact; they cannot
infer safety from an arbitrary OPEN fuse. Canonical advisory URLs are reconstructed
inside the contract from the official reviewed GitHub database, never a caller URL.
GitHub HTTPS, upstream repository ownership and advisory correctness are assumptions.

## Safety and liveness

Arming closes a gate before nondeterministic calls. Bad hashes, unsupported ranges,
insufficient prose, uncertain impact and malformed responses cannot open it. Exact
validator report disagreement produces a negative vote. The network's majority
rule can still accept a report with some dissent; unanimity is not enforced. Failure
to obtain consensus retains the already-closed scan state.
A known blocked impact dominates uncertainty in other advisories. No owner reset
exists. Clearing a trip requires two fresh consensus-clean scans within the TTL,
spaced at least 60 seconds apart. A failed abandoned scan resets recovery on rearm.

Permissionless watchdogs can close gates maliciously; this is an explicit availability
tradeoff, not an access-control bypass. Network/model outages and strict equality can
reduce liveness. Pending scans expire after 300 seconds for permissionless replacement.
Time uses consensus message datetime, not model or provider clocks. Stale roots and
expired OPEN assessments return false. Broad incident monitoring requires wider data
coverage than this bounded selected-advisory primitive.

## Out of scope

No funds, token transfers, signatures, external dispatch, host attestation or service
settlement. Solidity-specific analyzers do not apply to this Python GenVM contract.
Tests are not an independent audit. Prompt-injection defenses reduce but do not
eliminate model error; independently recomputed evidence is necessary, not omniscience.
