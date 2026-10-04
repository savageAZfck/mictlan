# Threat model — mictlan

An executor acts before death — execution requires a DeathCertificate, which requires heartbeat silence + distinct custodian attestations at quorum. A forged certificate — bound to the will digest and signed attestation set. An order exceeds scope — orders are explicit ids with invocation bounds; anything else refuses. An attacker claims the owner wanted more — unsigned additions are not in the will body and cannot execute. The execution record is denied — hash-chained log.

## What this crate guarantees

- No order executes without a valid DeathCertificate bound to the will digest.
- Certification requires heartbeat silence AND distinct-custodian quorum.
- Execution is bounded to signed, in-scope orders with invocation limits — refusal is the default.

## What it does not guarantee

- Protection against a verifier who never calls `verify()`.
- Integrity of inputs produced by other systems — this crate verifies
  signatures and chains over what it is given; garbage that verifies is
  still garbage.
