//! External-command signer — signs by shelling out to a CLI (e.g. `waap-cli`), so an MPC/WaaP
//! account with no exportable private key can drive alkahest. Implements alloy's [`Signer`] and
//! [`TxSigner`], so it threads through `AlkahestClient::new_with_signer` and every module unchanged.
//!
//! Two signing paths:
//!  * **digest** (default): the command receives the 32-byte digest as a `0x`-hex string (the
//!    `{digest}` token) and prints a 65-byte ECDSA signature — e.g. `waap-cli sign-digest`
//!    (holonym-foundation/internal-docs#1256, requires the protector raw-digest variant).
//!  * **typed-data** (when `with_typed_data_command` is set): EIP-712 payloads are forwarded as
//!    JSON (the `{typed_data}` token) to a structured command — e.g. `waap-cli sign-typed-data
//!    --data {typed_data}` — which the WaaP policy engine can risk-assess. This is the preferred
//!    path: it uses the already-shipped `sign-typed-data` instead of un-assessable raw-digest.
//!    EIP-712 signing routes through alloy's `sign_dynamic_typed_data`, so callers that build a
//!    `TypedData` (see `clients::erc20` permit) hit this path.

use alloy::{
    consensus::SignableTransaction,
    dyn_abi::TypedData,
    network::TxSigner,
    primitives::{Address, ChainId, Signature, B256},
    signers::{Error as SignerError, Result as SignerResult, Signer},
};
use alloy::signers::local::PrivateKeySigner;
use async_trait::async_trait;
use std::process::Stdio;
use tokio::process::Command;

#[derive(Clone, Debug)]
pub struct CommandSigner {
    program: String,
    /// Each arg may contain the literal token `{digest}`, replaced with the 0x-hex digest.
    args: Vec<String>,
    /// When set, EIP-712 typed data is signed via these args (each may contain the `{typed_data}`
    /// token, replaced with the EIP-712 JSON) instead of falling back to raw-digest signing.
    typed_data_args: Option<Vec<String>>,
    address: Address,
    chain_id: Option<ChainId>,
}

impl CommandSigner {
    pub fn new(program: impl Into<String>, args: Vec<String>, address: Address) -> Self {
        Self {
            program: program.into(),
            args,
            typed_data_args: None,
            address,
            chain_id: None,
        }
    }

    /// Enable structured EIP-712 signing (preferred over raw-digest). `args` may contain the
    /// `{typed_data}` token, replaced with the EIP-712 JSON (e.g.
    /// `vec!["sign-typed-data", "--data", "{typed_data}"]`).
    pub fn with_typed_data_command(mut self, args: Vec<String>) -> Self {
        self.typed_data_args = Some(args);
        self
    }

    /// Spawn `program` with the given (already token-substituted) args; parse stdout as a 65-byte sig.
    async fn run(&self, args: Vec<String>) -> SignerResult<Signature> {
        let out = Command::new(&self.program)
            .args(&args)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .await
            .map_err(SignerError::other)?;
        if !out.status.success() {
            return Err(SignerError::other(format!(
                "signer command `{}` failed: {}",
                self.program,
                String::from_utf8_lossy(&out.stderr)
            )));
        }
        let s = String::from_utf8_lossy(&out.stdout);
        let s = s.trim().trim_start_matches("0x");
        let bytes = alloy::hex::decode(s).map_err(SignerError::other)?;
        Signature::try_from(bytes.as_slice()).map_err(SignerError::other)
    }

    async fn run_sign(&self, digest: B256) -> SignerResult<Signature> {
        let hexd = format!("0x{}", alloy::hex::encode(digest));
        let args = self
            .args
            .iter()
            .map(|a| a.replace("{digest}", &hexd))
            .collect();
        self.run(args).await
    }

    async fn run_sign_typed_data(&self, payload: &TypedData) -> SignerResult<Signature> {
        let json = serde_json::to_string(payload).map_err(SignerError::other)?;
        let args = self
            .typed_data_args
            .as_ref()
            .expect("typed_data_args set")
            .iter()
            .map(|a| a.replace("{typed_data}", &json))
            .collect();
        self.run(args).await
    }
}

#[async_trait]
impl Signer for CommandSigner {
    async fn sign_hash(&self, hash: &B256) -> SignerResult<Signature> {
        self.run_sign(*hash).await
    }
    /// EIP-712: forward the structured payload to the typed-data command when configured; else fall
    /// back to digest signing. alloy's generic `sign_typed_data<T>` default routes here via the
    /// `TypedData` callers build (it can't serialize `T` itself — no `Serialize` bound).
    async fn sign_dynamic_typed_data(&self, payload: &TypedData) -> SignerResult<Signature> {
        match self.typed_data_args {
            Some(_) => self.run_sign_typed_data(payload).await,
            None => {
                let hash = payload.eip712_signing_hash().map_err(SignerError::other)?;
                self.run_sign(hash).await
            }
        }
    }
    fn address(&self) -> Address {
        self.address
    }
    fn chain_id(&self) -> Option<ChainId> {
        self.chain_id
    }
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        self.chain_id = chain_id;
    }
}

#[async_trait]
impl TxSigner<Signature> for CommandSigner {
    fn address(&self) -> Address {
        self.address
    }
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> SignerResult<Signature> {
        let hash = tx.signature_hash();
        self.run_sign(hash).await
    }
}

/// The signer alkahest drives — either a local raw key (`PrivateKeySigner`) or an external command
/// (`CommandSigner`, e.g. `waap-cli` for a WaaP/MPC account with no exportable key). It implements
/// alloy's [`Signer`] and [`TxSigner`] by delegating to the inner variant, so it threads through
/// `AlkahestClient` and every module exactly where `PrivateKeySigner` used to — no generics, no dyn.
#[derive(Clone, Debug)]
pub enum AlkahestSigner {
    Local(PrivateKeySigner),
    Command(CommandSigner),
}

impl AlkahestSigner {
    /// The signer's address (inherent method so `signer.address()` stays unambiguous in modules,
    /// matching `PrivateKeySigner`'s inherent `address()`).
    pub fn address(&self) -> Address {
        match self {
            AlkahestSigner::Local(s) => s.address(),
            AlkahestSigner::Command(s) => Signer::address(s),
        }
    }
}

impl From<PrivateKeySigner> for AlkahestSigner {
    fn from(s: PrivateKeySigner) -> Self {
        AlkahestSigner::Local(s)
    }
}

impl From<CommandSigner> for AlkahestSigner {
    fn from(s: CommandSigner) -> Self {
        AlkahestSigner::Command(s)
    }
}

#[async_trait]
impl Signer for AlkahestSigner {
    async fn sign_hash(&self, hash: &B256) -> SignerResult<Signature> {
        match self {
            AlkahestSigner::Local(s) => Signer::sign_hash(s, hash).await,
            AlkahestSigner::Command(s) => Signer::sign_hash(s, hash).await,
        }
    }
    /// Delegate EIP-712 to the inner signer so the Command variant's typed-data path is used.
    async fn sign_dynamic_typed_data(&self, payload: &TypedData) -> SignerResult<Signature> {
        match self {
            AlkahestSigner::Local(s) => s.sign_dynamic_typed_data(payload).await,
            AlkahestSigner::Command(s) => s.sign_dynamic_typed_data(payload).await,
        }
    }
    fn address(&self) -> Address {
        match self {
            AlkahestSigner::Local(s) => Signer::address(s),
            AlkahestSigner::Command(s) => Signer::address(s),
        }
    }
    fn chain_id(&self) -> Option<ChainId> {
        match self {
            AlkahestSigner::Local(s) => Signer::chain_id(s),
            AlkahestSigner::Command(s) => Signer::chain_id(s),
        }
    }
    fn set_chain_id(&mut self, chain_id: Option<ChainId>) {
        match self {
            AlkahestSigner::Local(s) => Signer::set_chain_id(s, chain_id),
            AlkahestSigner::Command(s) => Signer::set_chain_id(s, chain_id),
        }
    }
}

#[async_trait]
impl TxSigner<Signature> for AlkahestSigner {
    fn address(&self) -> Address {
        match self {
            AlkahestSigner::Local(s) => TxSigner::address(s),
            AlkahestSigner::Command(s) => TxSigner::address(s),
        }
    }
    async fn sign_transaction(
        &self,
        tx: &mut dyn SignableTransaction<Signature>,
    ) -> SignerResult<Signature> {
        match self {
            AlkahestSigner::Local(s) => TxSigner::sign_transaction(s, tx).await,
            AlkahestSigner::Command(s) => TxSigner::sign_transaction(s, tx).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::dyn_abi::TypedData;
    use alloy::signers::local::PrivateKeySigner;
    use alloy::sol;
    use alloy::sol_types::eip712_domain;

    // Mock command (`echo <sig>`) → proves spawn → parse → Signature, and that it round-trips
    // through alloy and recovers to the expected address.
    #[tokio::test]
    async fn command_signer_roundtrips_via_mock() {
        let pk = PrivateKeySigner::random();
        let digest = B256::repeat_byte(0x11);
        let expected = pk.sign_hash(&digest).await.unwrap();
        let sig_hex = format!("0x{}", alloy::hex::encode(expected.as_bytes()));

        let signer = CommandSigner::new("echo", vec![sig_hex], pk.address());
        let got = Signer::sign_hash(&signer, &digest).await.unwrap();

        assert_eq!(got, expected);
        assert_eq!(
            got.recover_address_from_prehash(&digest).unwrap(),
            pk.address()
        );
    }

    // The AlkahestSigner enum must delegate signing to its Command variant (the WaaP path), so a
    // client built via `new_with_signer(AlkahestSigner::Command(..))` signs escrow exactly like a
    // local key would — recovering to the same address.
    #[tokio::test]
    async fn alkahest_signer_command_variant_delegates() {
        let pk = PrivateKeySigner::random();
        let digest = B256::repeat_byte(0x22);
        let expected = Signer::sign_hash(&pk, &digest).await.unwrap();
        let sig_hex = format!("0x{}", alloy::hex::encode(expected.as_bytes()));

        let signer: AlkahestSigner =
            CommandSigner::new("echo", vec![sig_hex], pk.address()).into();
        let got = Signer::sign_hash(&signer, &digest).await.unwrap();

        assert_eq!(got, expected);
        assert_eq!(signer.address(), pk.address());
        assert_eq!(
            got.recover_address_from_prehash(&digest).unwrap(),
            pk.address()
        );
    }

    #[test]
    fn alkahest_signer_local_variant_address() {
        let pk = PrivateKeySigner::random();
        let signer = AlkahestSigner::Local(pk.clone());
        assert_eq!(signer.address(), pk.address());
    }

    // Path B: with a typed-data command configured, EIP-712 signing forwards the TypedData JSON to
    // the command (not raw-digest). Mock echoes the locally-computed sig; assert it recovers to the
    // signer address — proving the serialize→command→parse path produces a valid EIP-712 signature.
    #[tokio::test]
    async fn command_signer_typed_data_via_mock() {
        sol! {
            #[derive(serde::Serialize)]
            struct Mail { string contents; }
        }
        let pk = PrivateKeySigner::random();
        let domain = eip712_domain! { name: "Test", version: "1", };
        let mail = Mail { contents: "hello".into() };
        let td = TypedData::from_struct(&mail, Some(domain));

        let expected = pk.sign_dynamic_typed_data(&td).await.unwrap();
        let sig_hex = format!("0x{}", alloy::hex::encode(expected.as_bytes()));

        // program=echo, no digest args; typed-data command just echoes the sig.
        let signer: AlkahestSigner = CommandSigner::new("echo", vec![], pk.address())
            .with_typed_data_command(vec![sig_hex])
            .into();
        let got = signer.sign_dynamic_typed_data(&td).await.unwrap();

        assert_eq!(got, expected);
        let digest = td.eip712_signing_hash().unwrap();
        assert_eq!(got.recover_address_from_prehash(&digest).unwrap(), pk.address());
    }
}
