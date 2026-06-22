# clavenar-chaos-catalog

Pure-data attack catalog for Clavenar's red-team and demo flows.

Lifted out of `clavenar-chaos-monkey` so multiple callers can share one
canonical source of truth for the canned scenarios:

- **`clavenar-chaos-monkey`** — the CLI red-team runner. Iterates
  `catalog()`, POSTs each attack to the proxy, classifies the verdict
  against the `Expected` field on each `Attack`.
- **`clavenar-console`** — the `/demo/fire` page (in the
  `vanteguardlabs` demo experience). Currently has its own
  HIL-pending-shaped scenarios; routing through the catalog is a
  future refactor.

## What's in here

```rust
use clavenar_chaos_catalog::{
    Attack,         // pure data; Clone+Debug. payload_builder and
                    // headers_builder are private — go through
                    // build_payload(request_id) and build_headers()
    Category,       // 11 variants: Denylist, Injection, Velocity,
                    // BusinessHours, Control, Hil, Attestation, Identity,
                    // SupplyChain, AgentCert, MultiTurn
    Expected,       // Allow | Deny { reason_keywords } | BusinessHoursConditional
    Mode,           // Single | Burst { count } | SingleWithHil(HilSideAction)
                    // | MultiTurn { primers }
    HilSideAction,  // Deny | DoNothing
    catalog,        // -> Vec<Attack> (84 today)
};
```

Every payload + header builder is a plain `fn` pointer (no captured
state). Time-dependent values (attestation `expires_at`, JWT `exp`)
are stamped at fire-time by the `build_headers()` accessor rather
than at catalog construction, so a long catalog run doesn't ship
stale claims.

## What's NOT in here

- The runner — HTTP client, async dispatch, verdict classification.
  Lives in `clavenar-chaos-monkey/src/runner.rs` and stays there.
- The identity-scenario catalog — those scenarios reference
  `IdentityRunner` which carries an HTTP client; lifting them into a
  pure-data crate would force a runner trait we don't need yet.
  Still in `clavenar-chaos-monkey/src/identity_attack.rs`.
- The CLI / report formatter — binary concerns, stay in
  `clavenar-chaos-monkey`.

## Versioning + breaking changes

This crate is a workspace-internal data dependency for the clavenar tree.
Adding new scenarios is non-breaking; renaming variants of `Category` /
`Expected` / `Mode` IS breaking and triggers a coordinated bump on
every consumer (today: just `clavenar-chaos-monkey`; tomorrow probably
`clavenar-console`).

## Run

```bash
cargo build
cargo test
cargo clippy --all-targets -- -D warnings
```

No binary — this is a library crate.

## License

Apache-2.0.
