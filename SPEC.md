# SPEC — mictlan (posthumous agency)

## Will

`Will::sign(owner, orders, silence_secs, quorum)` — ed25519-signed.

```json
{
  "owner": "pubkey",
  "orders": [{ "id": "…", "action": "scoped-string",
               "params": {…}, "max_invocations": n }],
  "silence_secs": 0, "quorum": 0,
  "ts": 0, "signature": "…"
}
```

Orders are an explicit allow-list with invocation bounds — refusal is
the default.

## Death certification

- `Heartbeat` — owner-signed liveness timestamp.
- `UnreachableAttestation` — custodian-signed "I cannot reach the
  owner" with attempt window; signature bound to the owner pubkey.
- `DeadManSwitch.certify(last_heartbeat, certified_at)` — requires
  `certified_at ≥ last_heartbeat + silence_secs` AND ≥ `quorum`
  distinct custodian attestations, all verified. The certificate binds
  the will digest — it cannot be replayed against a different will.

## Execution

`Executor::execute(will, cert, order_id, params)`:

1. Verify cert signature set, digest binding, silence, quorum.
2. Look up `order_id` — unknown ⇒ refuse.
3. Check invocation count < `max_invocations` ⇒ refuse when spent.
4. Execute and commit to the hash-chained `ExecutionLog`.

## Invariants

- Death is proven, not declared — silence + independent custodians.
- The will cannot grow — anything unsigned is out of scope by construction.
- Every posthumous act is on chain.
