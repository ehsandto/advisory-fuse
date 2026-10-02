# AdvisoryFuse architecture

## Mechanism
An immutable software-artifact circuit breaker, not a graph, proposal engine,
service escrow, decision certificate, or consumable capability. Integrators use
an exact current evidence root and a freshness-bounded OPEN gate. No token moves.

## Evidence and trust
Registration fixes an upstream GitHub repository, full commit, package.json
SHA-256, selected reviewed GitHub advisory paths, impact policy, and observation
TTL. Registration is configuration, not proof that software is deployed anywhere.
The VM fetches the entire manifest and official advisory JSON. Consumers must
independently bind the installed artifact to that registered manifest; this
contract does not inspect a remote host or certify all vulnerabilities absent.
GitHub HTTPS and advisory authors are trusted sources, not independent authorities.

## Consequential nondeterminism
For affected versions, each validator separately interprets the fetched advisory
prose into EXECUTION/TAMPERING/DISCLOSURE/AVAILABILITY/OTHER/UNKNOWN. A policy-selected
impact trips the breaker. No caller impact, score, summary, confidence or outcome
is accepted. Deterministic npm three-part version membership guards the AI; unsupported
ranges fail closed. Exact report comparison binds every response hash and impact.

## State and liveness
UNASSESSED -> SCANNING -> OPEN / HELD / TRIPPED.
TRIPPED -> SCANNING -> RECOVERY_PENDING -> SCANNING -> OPEN only after two
clean observations at least 60 seconds apart. Uncertainty resets recovery and
preserves the trip latch. Expired OPEN gates close without a transaction.
Scan arming commits a unique scan ID and closes the gate before consensus.
Resolution is permissionless. Failed consensus leaves SCANNING closed; anyone
can rearm after the 300-second scan deadline. No owner can manually clear a latch.

## Storage and security
Immutable fuse specifications; mutable bounded latch/scan state; append-only
reports keyed by fuse and scan; global append-only events. Scan IDs cannot repeat.
Report roots bind contract address, fuse, specification, scan and observation time.
Every gate read checks the exact current root, pending state, latch and TTL.
Permissionless arming intentionally favors safety over availability; a malicious
watchdog can cause closure but cannot force opening. Deployments needing stronger
availability should restrict monitoring in their consumer wrapper.

## Validation
Lint and SDK validation, direct-mode tests with mocked acquisition/AI, pure
equivalence/normalization adversarial tests, then gasless StudioNet receipts,
source equality, affected/safe/wrong-hash scenarios and exact gate readback.
Direct mode does not exercise validator consensus. No claimed production audit.
