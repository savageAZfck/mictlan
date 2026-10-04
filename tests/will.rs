use mictlan::*;
use serde_json::json;

fn setup() -> (Identity, Will) {
    let owner = Identity::generate();
    let order = StandingOrder::sign(
        &owner,
        "publish-final-checkpoint",
        json!({"ledger": "main"}),
        2,
        0,
    );
    let will = Will::sign(&owner, vec![order], 100, 2);
    (owner, will)
}

fn dead_cert(will: &Will, custodians: &[Identity], last_hb: u64, at: u64) -> DeathCertificate {
    let mut switch = DeadManSwitch::new(will);
    for c in custodians {
        switch
            .record_unreachable(UnreachableAttestation::sign(c, &will.owner, last_hb, 5))
            .unwrap();
    }
    switch.certify(last_hb, at).unwrap()
}

#[test]
fn will_and_orders_verify() {
    let (_owner, will) = setup();
    will.verify().unwrap();
    for o in &will.orders {
        o.verify(&will.owner).unwrap();
    }
}

#[test]
fn heartbeat_proves_life() {
    let owner = Identity::generate();
    let hb = Heartbeat::sign(&owner);
    hb.verify().unwrap();
    assert_eq!(hb.owner, owner.public_key());
}

#[test]
fn no_cert_inside_silence_window() {
    let (_owner, will) = setup();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let mut switch = DeadManSwitch::new(&will);
    for c in &custodians {
        switch
            .record_unreachable(UnreachableAttestation::sign(c, &will.owner, 1000, 3))
            .unwrap();
    }
    // Only 50s of silence — will requires 100.
    assert!(switch.certify(1000, 1050).is_err());
}

#[test]
fn no_cert_without_quorum() {
    let (_owner, will) = setup();
    let c1 = Identity::generate();
    let mut switch = DeadManSwitch::new(&will);
    switch
        .record_unreachable(UnreachableAttestation::sign(&c1, &will.owner, 1000, 3))
        .unwrap();
    // One custodian < quorum of two — even past the silence window.
    assert!(switch.certify(1000, 2000).is_err());
}

#[test]
fn executor_runs_orders_after_death() {
    let (_owner, will) = setup();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let cert = dead_cert(&will, &custodians, 1000, 2000);
    cert.verify(&will).unwrap();

    let mut executor = Executor::new();
    let order_id = will.orders[0].id.clone();
    let e = executor
        .execute(&will, &cert, &order_id, json!({"checkpoint": "published"}))
        .unwrap();
    assert_eq!(e.order_id, order_id);
    executor.log.verify().unwrap();
}

#[test]
fn executor_refuses_without_valid_cert() {
    let (_owner, will) = setup();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let mut cert = dead_cert(&will, &custodians, 1000, 2000);
    // Forge: certify inside the silence window.
    cert.certified_at = 1050;
    let mut executor = Executor::new();
    let order_id = will.orders[0].id.clone();
    assert!(executor
        .execute(&will, &cert, &order_id, json!({}))
        .is_err());
}

#[test]
fn executor_enforces_invocation_limits() {
    let (_owner, will) = setup();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let cert = dead_cert(&will, &custodians, 1000, 2000);
    let mut executor = Executor::new();
    let order_id = will.orders[0].id.clone();
    executor
        .execute(&will, &cert, &order_id, json!({"n": 1}))
        .unwrap();
    executor
        .execute(&will, &cert, &order_id, json!({"n": 2}))
        .unwrap();
    // max_invocations = 2 — the third refuses.
    assert!(executor
        .execute(&will, &cert, &order_id, json!({"n": 3}))
        .is_err());
}

#[test]
fn executor_refuses_unknown_orders() {
    let (_owner, will) = setup();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let cert = dead_cert(&will, &custodians, 1000, 2000);
    let mut executor = Executor::new();
    assert!(executor
        .execute(&will, &cert, "nonexistent-order", json!({}))
        .is_err());
}

#[test]
fn expired_orders_refuse() {
    let owner = Identity::generate();
    let order = StandingOrder::sign(&owner, "x", json!({}), 5, 1); // expired long ago
    let will = Will::sign(&owner, vec![order], 100, 1);
    let c = Identity::generate();
    let mut switch = DeadManSwitch::new(&will);
    switch
        .record_unreachable(UnreachableAttestation::sign(&c, &will.owner, 10, 3))
        .unwrap();
    let cert = switch.certify(10, 1000).unwrap();
    let mut executor = Executor::new();
    assert!(executor
        .execute(&will, &cert, &will.orders[0].id, json!({}))
        .is_err());
}

#[test]
fn forged_order_in_will_fails_verification() {
    let (_owner, mut will) = setup();
    will.orders[0].params = json!({"ledger": "everything"});
    let mut executor = Executor::new();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let cert = dead_cert(&will, &custodians, 1000, 2000);
    // Will no longer verifies — executor refuses outright.
    assert!(executor
        .execute(&will, &cert, &will.orders[0].id.clone(), json!({}))
        .is_err());
}

#[test]
fn execution_chain_detects_tamper() {
    let (_owner, will) = setup();
    let custodians: Vec<Identity> = (0..2).map(|_| Identity::generate()).collect();
    let cert = dead_cert(&will, &custodians, 1000, 2000);
    let mut executor = Executor::new();
    executor
        .execute(&will, &cert, &will.orders[0].id, json!({"n": 1}))
        .unwrap();
    executor.log.entries[0].outcome = json!({"forged": true});
    assert!(executor.log.verify().is_err());
}

#[test]
fn duplicate_custodian_counts_once() {
    let (_owner, will) = setup();
    let c1 = Identity::generate();
    let mut switch = DeadManSwitch::new(&will);
    switch
        .record_unreachable(UnreachableAttestation::sign(&c1, &will.owner, 1000, 3))
        .unwrap();
    switch
        .record_unreachable(UnreachableAttestation::sign(&c1, &will.owner, 1000, 5))
        .unwrap();
    assert!(switch.certify(1000, 2000).is_err()); // still only 1 distinct
}
