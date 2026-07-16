<!-- public repo — do not add internal topology, secrets, deploy/runbook, strategy, or absolute host paths -->
# clavenar-chaos-catalog — pure-data attack catalog (path-dep consumed by clavenar-chaos-monkey)

Canonical, runner-free source of truth for Clavenar's canned red-team / demo
scenarios. Lifted out of `clavenar-chaos-monkey` so multiple callers
(`clavenar-chaos-monkey`, eventually `clavenar-console`'s `/demo/fire`) fire the
same scenarios. Everything here is plain data — `Clone`/`Debug` structs and
`fn` (not `Fn`) pointers; no async, no HTTP client, no NATS.

## Build, test, lint
```
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
cargo deny check all          # advisories / licenses / bans / sources
```
Edition 2024. `publish = false` — workspace-internal data dependency, not a
crates.io package. Run: library, no binary — exported via `catalog()`. Host
builds: this repo's `target/` may be root-owned from prior docker builds — pass
`CARGO_TARGET_DIR=/tmp/clavenar-chaos-catalog-target` when building on the host.

## Layout
- `src/lib.rs` — the whole crate: type defs, all per-scenario payload-builder
  `fn`s, the `catalog()` / `catalog_policy_inputs()` entry points, and the
  `#[cfg(test)] mod tests` at file bottom. Exported surface:
  - `catalog() -> Vec<Attack>` — the canonical scenario list (84+ attacks).
  - `catalog_policy_inputs() -> Vec<Value>` — each Rego-decidable attack
    projected to a policy-engine `PolicyInput` for an offline Rego-only
    backtest. Only `Denylist` / `BusinessHours` / `Control` survive the filter;
    the other 8 categories return `None`: `Injection`/`SupplyChain`/`MultiTurn`
    (need brain), `Hil` (live roundtrip), `Identity` (identity layer),
    `Velocity`/`Attestation` (per-request state), `AgentCert` (standing
    controls spread across layers).
  - `Attack { id, category, description, expected, mode }` — `payload_builder` /
    `headers_builder` are private `fn` pointers; reach them via
    `build_payload(request_id)`, `build_headers()`, `policy_input()`, and
    `rejection_contract()`.
  - `RejectionContract` — exact HTTP status, coarse proxy verdict, and
    enforcement layer for every deny-capable attack. Transport/5xx results are
    never contracts, and tests require every denial to have one.
  - `Category` — 12 variants (`Denylist`, `Injection`, `Velocity`,
    `BusinessHours`, `Control`, `Hil`, `Attestation`, `Identity`, `SupplyChain`,
    `AgentCert`, `MultiTurn`, `Deception`); wire string via `as_str()`.
  - `Expected` — `Allow` | `Deny { reason_keywords }` | `BusinessHoursConditional { reason_keywords }`.
  - `Mode` — `Single` | `Burst { count }` | `SingleWithHil(HilSideAction)` | `MultiTurn { primers }`.
  - `HilSideAction` — `Deny` (POST `/decide` to drive the pending to Denied) | `DoNothing` (let the proxy poll-timeout fire).
- `src/headers.rs` — private (`pub(crate)`) JOSE-shaped header builders for the
  header-bearing attacks: identity, attestation, the agent-cert grant-replay,
  and the expansion-domain denylist cases. Tokens are UNSIGNED on purpose (the attacks
  exercise rejection paths, not signature crypto); wall-clock claims
  (`expires_at`, `iat`, `exp`) are stamped at fire-time, not at catalog
  construction, so a long run never ships a stale claim.
- `Cargo.toml` — deps: `serde_json`, `chrono`, `base64`. `deny.toml` is synced
  verbatim from `clavenar-specs` — edit it there first, then mirror the exact
  bytes. CI (`.github/workflows/ci.yml`): `cargo check`/`test`/`clippy -D warnings`
  + cargo-deny + a CycloneDX SBOM upload.

## Conventions & invariants

- **Formatting is an owning-CI gate.** Run `cargo fmt --all -- --check`
  before pushing Rust changes; CI runs it before check, test, and clippy.
- After adding or updating a feature, also update the relevant `MANUAL_TESTS*` file(s) when needed.
Every payload is valid JSON-RPC except `agent_cert_malformed_mcp`
(intentionally missing `method`; the `payloads_are_valid_jsonrpc` test exempts
it by id). Adding a scenario is non-breaking; renaming a `Category` / `Expected`
/ `Mode` variant is a breaking change that forces a coordinated bump on every
consumer. Attack `id`s are also load-bearing: `catalog_has_expected_attacks`
pins ~20 ids and `payloads_are_valid_jsonrpc` exempts `agent_cert_malformed_mcp`
by literal id; consumers key on ids too. Renaming an id is breaking.

Rust house rules: clippy `-D warnings` is the floor; tests stay in
`#[cfg(test)] mod tests` at file bottom.

- Commit subjects must start with a lowercase letter.

## Pointers
README.md.
