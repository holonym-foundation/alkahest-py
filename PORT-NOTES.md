# CommandSigner on alkahest 0.7.2 (Path B prerequisite)

Self-contained port of the external-command signer seam onto the **exact source behind
PyPI `alkahest_py==0.4.0`** (internally alkahest-rs **0.7.2**, alloy 1.2.1) — the version
the Simple Compute Market actually runs on.

## What & why
The SCM (`service/clients/alkahest.py`, storefront, buyer) is built against PyPI alkahest 0.4.0.
The prior WaaP-signer fork (`alkahest-rs feat/external-signer-scm`, 0.6.0 line) diverged from it
(different address schema, no `DefaultExtensionConfig` pyclass, no `erc20.util`), so its wheel
broke the SCM. This branch instead adds the signer to the SCM's *own* base, so it's a drop-in.

## Changes (see COMMAND-SIGNER-0.7.2.patch — 22 files, +502/-65)
- `rs/src/command_signer.rs` (new): `CommandSigner` (alloy `Signer`+`TxSigner` via external CLI,
  digest + EIP-712 typed-data paths) and `AlkahestSigner { Local | Command }` enum.
- Threaded `AlkahestSigner` where `PrivateKeySigner` was the client signer (lib.rs, types.rs,
  extensions.rs, all clients) — back-compat constructors `.into()` so local-key callers are unchanged.
- `rs/src/clients/obligations/erc20/util.rs`: permit now signs via `sign_dynamic_typed_data`
  (Path B — WaaP policy-engine-assessable) instead of generic `sign_typed_data`.
- `py/src/lib.rs`: `AlkahestClient.with_command_signer(program, args, address, rpc_url,
  address_config=None, typed_data_args=None)`.

## Build & validate
    maturin build --release -i python3.12        # cp312 manylinux wheel
    # → drop into the SCM venv; service/tests/integration/test_waap_escrow_roundtrip.py passes
    cd rs && cargo test --lib command_signer     # 4/4 (incl. typed-data round-trip)

## Status
Validated: WaaP-signed escrow round-trip green on anvil with the SCM's pristine test.
**SOE review pending (holonym-foundation/internal-docs#1348) before any deploy.**
