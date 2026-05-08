# warden-chaos-catalog

Pure-data attack catalog for Agent Warden's red-team and demo flows.

Lifted out of `warden-chaos-monkey` so multiple callers can share one
canonical source of truth for the canned scenarios:

- **`warden-chaos-monkey`** — the CLI red-team runner. Iterates
  `catalog()`, POSTs each attack to the proxy, classifies the verdict
  against the `Expected` field on each `Attack`.
- **`warden-console`** — the `/demo/fire` page (in the
  `vanteguardlabs` demo experience). Currently has its own
  HIL-pending-shaped scenarios; routing through the catalog is a
  future refactor.

## What's in here

```rust
pub use lib::{
    Attack,                    // pure data; Clone+Debug
    Category,                  // 8 variants: Denylist/Injection/Velocity/...
    Expected,                  // Allow | Deny { reasons } | BusinessHoursConditional
    Mode,                      // Single | Burst { count } | SingleWithHil(...)
    HilSideAction,             // Deny | DoNothing
    catalog,                   // -> Vec<Attack> (13 today)
};
```

Every payload + header builder is a plain `fn` pointer (no captured
state). Time-dependent values (attestation `expires_at`, JWT `exp`)
are stamped at fire-time, not at catalog construction.

## What's NOT in here

- The runner — HTTP client, async dispatch, verdict classification.
  Lives in `warden-chaos-monkey/src/runner.rs` and stays there.
- The identity-scenario catalog — those scenarios reference
  `IdentityRunner` which carries an HTTP client; lifting them into a
  pure-data crate would force a runner trait we don't need yet.
  Still in `warden-chaos-monkey/src/identity_attack.rs`.
- The CLI / report formatter — binary concerns, stay in
  `warden-chaos-monkey`.

## Versioning + breaking changes

This crate is a workspace-internal data dependency for the warden tree.
Adding new scenarios is non-breaking; renaming variants of `Category` /
`Expected` / `Mode` IS breaking and triggers a coordinated bump on
every consumer (today: just `warden-chaos-monkey`; tomorrow probably
`warden-console`).

## Run

```bash
cargo build --release
cargo test
```

No binary — this is a library crate.

## License

Apache-2.0.
