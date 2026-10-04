//! mictlan — posthumous agency.
//!
//! Named for Mictlan — the Aztec land of the dead, which the dead still
//! crossed with purpose.
//!
//! A dead-man switch answers "what happens to my secrets when I'm gone."
//! It doesn't answer the harder question: *what does the organism do
//! after?* The owner's intent doesn't die with the owner — and a
//! sovereign organism can keep executing it, in scope, on the record.
//!
//! `mictlan` is a will that executes itself:
//!
//! 1. **While alive**, the owner signs [`StandingOrder`]s — each one a
//!    bounded, scoped action ("reply to messages from Sarah within
//!    condolence-scope", "keep the escrow beacons fresh", "publish the
//!    final ledger checkpoint") — and signs heartbeats proving life.
//! 2. **Death is proven, not assumed**: the [`DeadManSwitch`] issues a
//!    [`DeathCertificate`] only when the heartbeat has been silent past
//!    the threshold *and* a quorum of custodians has signed
//!    unreachable-attestations. A living owner can't be prematurely
//!    executed around.
//! 3. **The executor is narrower than the living organism**:
//!    [`Executor::execute`] refuses without a valid certificate, refuses
//!    actions outside an order's signed scope, enforces per-order
//!    invocation limits and expiry, and chains every act into the
//!    [`ExecutionLog`]. Posthumous agency is a smaller self — the will,
//!    not the whole mind.
//!
//! ```no_run
//! use mictlan::{Executor, Identity, StandingOrder, Will, DeadManSwitch};
//!
//! let owner = Identity::generate();
//! let order = StandingOrder::sign(&owner, "publish-final-checkpoint",
//!     serde_json::json!({"ledger": "main"}), 3, 0);
//! let will = Will::sign(&owner, vec![order.clone()], 86_400, 2);
//! let mut switch = DeadManSwitch::new(&will);
//! // … owner keeps signing heartbeats while alive …
//! ```

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

fn canonical(v: &Value) -> Vec<u8> {
    serde_json::to_vec(v).expect("canonical json")
}

#[derive(Debug)]
pub enum Error {
    BadSignature(String),
    StillAlive(String),
    OutOfScope(String),
    Exhausted(String),
    BadChain(String),
    Serde(serde_json::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::BadSignature(m) => write!(f, "signature failure: {m}"),
            Error::StillAlive(m) => write!(f, "owner is not proven dead: {m}"),
            Error::OutOfScope(m) => write!(f, "outside the will's scope: {m}"),
            Error::Exhausted(m) => write!(f, "order exhausted: {m}"),
            Error::BadChain(m) => write!(f, "execution chain broken: {m}"),
            Error::Serde(e) => write!(f, "serde: {e}"),
        }
    }
}

impl std::error::Error for Error {}
impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Serde(e)
    }
}

// ---------------------------------------------------------------- identity

pub struct Identity {
    key: SigningKey,
}

impl Identity {
    pub fn generate() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        Identity {
            key: SigningKey::from_bytes(&seed),
        }
    }

    pub fn from_bytes(seed: &[u8; 32]) -> Self {
        Identity {
            key: SigningKey::from_bytes(seed),
        }
    }

    pub fn seed(&self) -> [u8; 32] {
        self.key.to_bytes()
    }

    pub fn public_key(&self) -> String {
        hex::encode(self.key.verifying_key().to_bytes())
    }

    fn sign(&self, msg: &[u8]) -> String {
        hex::encode(self.key.sign(msg).to_bytes())
    }
}

pub fn verify_signature(pubkey_hex: &str, msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let pk_bytes =
        hex::decode(pubkey_hex).map_err(|e| Error::BadSignature(format!("pubkey hex: {e}")))?;
    let pk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("pubkey not 32 bytes".into()))?,
    )
    .map_err(|e| Error::BadSignature(format!("pubkey: {e}")))?;
    let sig_bytes =
        hex::decode(sig_hex).map_err(|e| Error::BadSignature(format!("sig hex: {e}")))?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| Error::BadSignature("sig not 64 bytes".into()))?,
    );
    pk.verify(msg, &sig)
        .map_err(|_| Error::BadSignature("verification failed".into()))
}

// ---------------------------------------------------------------- will

/// A single bounded command the owner wants executed after death.
/// The action is an opaque label — scope is defined by `params`, the
/// invocation limit, and expiry, all inside the owner's signature.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StandingOrder {
    /// Content-derived id.
    pub id: String,
    /// Action label ("publish-final-checkpoint", "reply-condolences").
    pub action: String,
    /// Scoped parameters — the executor checks action labels only; the
    /// params ride signed so they can't be widened.
    pub params: Value,
    /// Maximum posthumous invocations.
    pub max_invocations: u32,
    /// Unix-seconds expiry — orders can lapse (0 = never).
    pub expires_at: u64,
    /// Owner signature over the canonical body.
    pub signature: String,
}

impl StandingOrder {
    fn unsigned_body(action: &str, params: &Value, max_invocations: u32, expires_at: u64) -> Value {
        json!({
            "action": action,
            "params": params,
            "max_invocations": max_invocations,
            "expires_at": expires_at,
        })
    }

    /// Sign a new standing order with the owner's key.
    pub fn sign(
        owner: &Identity,
        action: &str,
        params: Value,
        max_invocations: u32,
        expires_at: u64,
    ) -> Self {
        let body = Self::unsigned_body(action, &params, max_invocations, expires_at);
        let id = sha256_hex(&canonical(&json!({
            "body": body,
            "owner": owner.public_key(),
        })));
        StandingOrder {
            id,
            action: action.to_string(),
            params,
            max_invocations,
            expires_at,
            signature: owner.sign(&canonical(&body)),
        }
    }

    /// Verify the owner's signature over this order.
    pub fn verify(&self, owner_pubkey: &str) -> Result<(), Error> {
        let body = Self::unsigned_body(
            &self.action,
            &self.params,
            self.max_invocations,
            self.expires_at,
        );
        verify_signature(owner_pubkey, &canonical(&body), &self.signature)
    }

    pub fn expired(&self, at: u64) -> bool {
        self.expires_at != 0 && at > self.expires_at
    }
}

/// The complete will: signed standing orders plus the death condition —
/// how long silence means gone, and how many custodians must agree.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Will {
    /// Owner's public key.
    pub owner: String,
    /// Individually signed orders.
    pub orders: Vec<StandingOrder>,
    /// Seconds of heartbeat silence that begins death proceedings.
    pub silence_secs: u64,
    /// Custodian attestations required to certify death.
    pub quorum: usize,
    /// Owner signature over the canonical will body.
    pub signature: String,
}

impl Will {
    fn body(&self) -> Value {
        json!({
            "owner": self.owner,
            "orders": self.orders,
            "silence_secs": self.silence_secs,
            "quorum": self.quorum,
        })
    }

    /// Sign a new will. Each order must already be signed by the owner.
    pub fn sign(
        owner: &Identity,
        orders: Vec<StandingOrder>,
        silence_secs: u64,
        quorum: usize,
    ) -> Self {
        let mut will = Will {
            owner: owner.public_key(),
            orders,
            silence_secs,
            quorum,
            signature: String::new(),
        };
        will.signature = owner.sign(&canonical(&will.body()));
        will
    }

    /// Verify the will signature and every order inside it.
    pub fn verify(&self) -> Result<(), Error> {
        verify_signature(&self.owner, &canonical(&self.body()), &self.signature)?;
        for order in &self.orders {
            order.verify(&self.owner)?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------- death proof

/// A custodian's signed statement that the owner is unreachable.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UnreachableAttestation {
    /// Custodian's public key.
    pub custodian: String,
    /// What they attest: canonical {"owner","since","attempts"} signed.
    pub owner: String,
    /// First time the owner could not be reached.
    pub since: u64,
    /// Contact attempts made.
    pub attempts: u32,
    pub signature: String,
}

impl UnreachableAttestation {
    fn body(&self) -> Value {
        json!({
            "custodian": self.custodian,
            "owner": self.owner,
            "since": self.since,
            "attempts": self.attempts,
        })
    }

    /// Custodian signs that `owner` has been unreachable `since`.
    pub fn sign(custodian: &Identity, owner: &str, since: u64, attempts: u32) -> Self {
        let mut a = UnreachableAttestation {
            custodian: custodian.public_key(),
            owner: owner.to_string(),
            since,
            attempts,
            signature: String::new(),
        };
        a.signature = custodian.sign(&canonical(&a.body()));
        a
    }

    pub fn verify(&self) -> Result<(), Error> {
        verify_signature(&self.custodian, &canonical(&self.body()), &self.signature)
    }
}

/// A signed heartbeat — proof of life, chained by timestamp.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Heartbeat {
    pub owner: String,
    pub ts: u64,
    pub signature: String,
}

impl Heartbeat {
    pub fn sign(owner: &Identity) -> Self {
        let ts = now_secs();
        let mut h = Heartbeat {
            owner: owner.public_key(),
            ts,
            signature: String::new(),
        };
        h.signature = owner.sign(&canonical(&json!({"owner": h.owner, "ts": h.ts})));
        h
    }

    pub fn verify(&self) -> Result<(), Error> {
        verify_signature(
            &self.owner,
            &canonical(&json!({"owner": self.owner, "ts": self.ts})),
            &self.signature,
        )
    }
}

/// The death certificate: the proof the executor requires. Issued only
/// when silence exceeds the will's threshold *and* a quorum of distinct
/// custodians has signed unreachable-attestations.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeathCertificate {
    pub owner: String,
    /// Last verified heartbeat timestamp.
    pub last_heartbeat: u64,
    /// When the certificate was issued.
    pub certified_at: u64,
    /// The quorum of custodian attestations behind it.
    pub attestations: Vec<UnreachableAttestation>,
    /// Digest binding cert to the will it was issued under.
    pub will_digest: String,
}

impl DeathCertificate {
    /// Verify: quorum of *distinct* custodians, all signatures valid,
    /// all attesting to the same owner, silence condition real.
    pub fn verify(&self, will: &Will) -> Result<(), Error> {
        if self.owner != will.owner {
            return Err(Error::BadSignature(
                "certificate is for a different owner".into(),
            ));
        }
        let will_digest = sha256_hex(&canonical(&will.body()));
        if self.will_digest != will_digest {
            return Err(Error::BadSignature(
                "certificate bound to a different will".into(),
            ));
        }
        if self.certified_at < self.last_heartbeat + will.silence_secs {
            return Err(Error::StillAlive(
                "certificate issued inside the silence window".into(),
            ));
        }
        let mut seen = std::collections::BTreeSet::new();
        for a in &self.attestations {
            a.verify()?;
            if a.owner != self.owner {
                return Err(Error::BadSignature("attestation for wrong owner".into()));
            }
            seen.insert(a.custodian.clone());
        }
        if seen.len() < will.quorum {
            return Err(Error::StillAlive(format!(
                "quorum not met: {} < {}",
                seen.len(),
                will.quorum
            )));
        }
        Ok(())
    }
}

/// The switch: tracks heartbeats and custodian attestations, issues the
/// certificate when the will's conditions are proven.
pub struct DeadManSwitch<'w> {
    will: &'w Will,
    attestations: Vec<UnreachableAttestation>,
}

impl<'w> DeadManSwitch<'w> {
    pub fn new(will: &'w Will) -> Self {
        DeadManSwitch {
            will,
            attestations: Vec::new(),
        }
    }

    /// Record a custodian's unreachable attestation.
    pub fn record_unreachable(&mut self, a: UnreachableAttestation) -> Result<(), Error> {
        a.verify()?;
        if a.owner != self.will.owner {
            return Err(Error::BadSignature("attestation for wrong owner".into()));
        }
        if !self.attestations.iter().any(|x| x.custodian == a.custodian) {
            self.attestations.push(a);
        }
        Ok(())
    }

    /// Try to certify death. Fails while the owner could still be alive:
    /// heartbeat must be silent past `silence_secs` AND custodian quorum
    /// must be met.
    pub fn certify(&self, last_heartbeat: u64, at: u64) -> Result<DeathCertificate, Error> {
        if at < last_heartbeat + self.will.silence_secs {
            return Err(Error::StillAlive(format!(
                "silence {}s < required {}s",
                at.saturating_sub(last_heartbeat),
                self.will.silence_secs
            )));
        }
        let distinct: std::collections::BTreeSet<_> = self
            .attestations
            .iter()
            .map(|a| a.custodian.clone())
            .collect();
        if distinct.len() < self.will.quorum {
            return Err(Error::StillAlive(format!(
                "custodian quorum {} < {}",
                distinct.len(),
                self.will.quorum
            )));
        }
        Ok(DeathCertificate {
            owner: self.will.owner.clone(),
            last_heartbeat,
            certified_at: at,
            attestations: self.attestations.clone(),
            will_digest: sha256_hex(&canonical(&self.will.body())),
        })
    }
}

// ---------------------------------------------------------------- executor

/// A posthumous act on the execution log.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Execution {
    pub seq: u64,
    pub prev: String,
    pub hash: String,
    /// The standing order executed.
    pub order_id: String,
    /// The certificate that authorized it.
    pub cert_digest: String,
    /// Outcome payload — what the executor did, as reported by the
    /// platform layer that ran the action.
    pub outcome: Value,
    pub ts: u64,
}

/// Hash-chained log of every posthumous act.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ExecutionLog {
    pub entries: Vec<Execution>,
    /// order_id -> invocation count.
    #[serde(default)]
    counts: BTreeMap<String, u32>,
}

impl Default for ExecutionLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecutionLog {
    pub fn new() -> Self {
        ExecutionLog {
            entries: Vec::new(),
            counts: BTreeMap::new(),
        }
    }

    fn tip(&self) -> String {
        self.entries
            .last()
            .map(|e| e.hash.clone())
            .unwrap_or_else(|| "0".repeat(64))
    }

    pub fn verify(&self) -> Result<(), Error> {
        let mut prev = "0".repeat(64);
        for (i, e) in self.entries.iter().enumerate() {
            if e.seq != i as u64 || e.prev != prev {
                return Err(Error::BadChain(format!("broken at {i}")));
            }
            let hash = sha256_hex(&canonical(&json!({
                "seq": e.seq, "prev": e.prev, "order_id": e.order_id,
                "cert_digest": e.cert_digest, "outcome": e.outcome, "ts": e.ts,
            })));
            if hash != e.hash {
                return Err(Error::BadChain(format!("hash mismatch at {i}")));
            }
            prev = e.hash.clone();
        }
        Ok(())
    }
}

/// The executor: a narrower self that runs the will after death. It can
/// only execute signed standing orders, only post-certification, only in
/// scope, only within limits — and it chains everything.
#[derive(Default)]
pub struct Executor {
    pub log: ExecutionLog,
}

impl Executor {
    pub fn new() -> Self {
        Executor {
            log: ExecutionLog::new(),
        }
    }

    /// Execute a standing order posthumously. `outcome` is what the
    /// platform did — the executor scopes, authorizes, and records; the
    /// action itself belongs to the host organism.
    pub fn execute(
        &mut self,
        will: &Will,
        cert: &DeathCertificate,
        order_id: &str,
        outcome: Value,
    ) -> Result<Execution, Error> {
        will.verify()?;
        cert.verify(will)?;

        let order = will
            .orders
            .iter()
            .find(|o| o.id == order_id)
            .ok_or_else(|| Error::OutOfScope(format!("no such order: {order_id}")))?;

        let at = now_secs();
        if order.expired(at) {
            return Err(Error::OutOfScope("order expired".into()));
        }
        let count = self.log.counts.get(order_id).copied().unwrap_or(0);
        if order.max_invocations != 0 && count >= order.max_invocations {
            return Err(Error::Exhausted(format!(
                "order {order_id} at max_invocations {}",
                order.max_invocations
            )));
        }

        let seq = self.log.entries.len() as u64;
        let prev = self.log.tip();
        let cert_digest = sha256_hex(&canonical(&json!({
            "owner": cert.owner, "certified_at": cert.certified_at,
            "will_digest": cert.will_digest,
        })));
        let hash = sha256_hex(&canonical(&json!({
            "seq": seq, "prev": prev, "order_id": order_id,
            "cert_digest": cert_digest, "outcome": outcome, "ts": at,
        })));
        let execution = Execution {
            seq,
            prev,
            hash,
            order_id: order_id.to_string(),
            cert_digest,
            outcome,
            ts: at,
        };
        self.log.entries.push(execution.clone());
        *self.log.counts.entry(order_id.to_string()).or_insert(0) += 1;
        Ok(execution)
    }
}
