# mictlan

**Posthumous agency — a will that executes itself, in scope, on the record.**

Named for Mictlan — the Aztec land of the dead, which the dead still crossed with purpose.

## Why this exists

Dead-man switches answer "what happens to my secrets when I'm gone." They don't answer *what does the organism do after* — the owner's intent doesn't die with the owner. `mictlan` lets an organism keep executing it: narrowly, provably, and only after death is *proven*.

## The ceremony

1. **While alive** — the owner signs `StandingOrder`s (bounded, scoped, expiry-capped, invocation-limited) into a `Will`, and signs `Heartbeat`s proving life.
2. **Death is proven, not assumed** — the `DeadManSwitch` issues a `DeathCertificate` only when heartbeats have been silent past the will's threshold **and** a quorum of distinct custodians signs unreachable-attestations. No premature execution.
3. **The executor is a narrower self** — `Executor::execute` refuses without a valid certificate, refuses unknown or expired orders, enforces `max_invocations`, and chains every act into the `ExecutionLog`. Posthumous agency is the will — not the whole mind.

## Honest limits

- Orders are *capabilities*, not open-ended agency: the will can't grow new scope.
- Custodian honesty is a quorum assumption — put them where `nagi` puts custodians.
- Tampering fails closed: forged wills, forged certs, forged log entries all fail verification.

## Try it

```bash
cargo run --example will
cargo test
```

## Pair with

- `nagi` — the escrow that hands memory to the successor while the will runs
- `sibyl` — gates the will's release conditions can satisfy
- `kola` — witnesses that notarize the death certificate and the execution log
