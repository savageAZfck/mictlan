//! A will that executes itself: signed orders, proven death, scoped acts.
use mictlan::*;
use serde_json::json;

fn main() {
    let owner = Identity::generate();
    let custodians: Vec<Identity> = (0..3).map(|_| Identity::generate()).collect();

    // The will: two standing orders, 1h silence threshold, 2-of-3 quorum.
    let orders = vec![
        StandingOrder::sign(
            &owner,
            "publish-final-checkpoint",
            json!({"ledger": "main"}),
            1,
            0,
        ),
        StandingOrder::sign(
            &owner,
            "reply-condolences",
            json!({"scope": "close-family", "tone": "gentle"}),
            50,
            0,
        ),
    ];
    let will = Will::sign(&owner, orders, 3600, 2);
    will.verify().expect("will verifies");
    println!("will signed — {} orders, quorum 2-of-3", will.orders.len());

    // While alive: heartbeats.
    let hb = Heartbeat::sign(&owner);
    hb.verify().expect("heartbeat verifies");
    println!("last heartbeat at {}", hb.ts);

    // Time passes. Custodians attest unreachable.
    let mut switch = DeadManSwitch::new(&will);
    for c in &custodians[..2] {
        switch
            .record_unreachable(UnreachableAttestation::sign(c, &will.owner, hb.ts, 9))
            .unwrap();
    }
    let certified_at = hb.ts + 4000;
    let cert = switch
        .certify(hb.ts, certified_at)
        .expect("death certified");
    println!(
        "\ndeath certified — 2 custodians, silence {}s",
        certified_at - hb.ts
    );

    // The executor runs the will — in scope, on chain.
    let mut executor = Executor::new();
    for order in &will.orders {
        match executor.execute(
            &will,
            &cert,
            &order.id,
            json!({"performed": order.action, "in_scope": true}),
        ) {
            Ok(e) => println!("executed: {} (seq {})", order.action, e.seq),
            Err(e) => println!("refused: {} — {e}", order.action),
        }
    }

    // And it refuses what the will didn't sign for.
    match executor.execute(&will, &cert, "erase-everything", json!({})) {
        Ok(_) => println!("UNEXPECTED: unauthorized act"),
        Err(e) => println!("\nrefused out-of-scope act: {e}"),
    }

    executor.log.verify().expect("execution log verifies");
    println!(
        "execution log: {} acts, verified",
        executor.log.entries.len()
    );
}
