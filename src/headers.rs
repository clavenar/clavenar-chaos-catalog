//! Header builders for identity and deny-only attestation attacks.
//!
//! The identity-oriented builders ship adversarial tokens on purpose so the
//! attacks exercise rejection paths (expired grant, unknown peer bundle,
//! etc.). Attestation negative coverage uses only a one-way absent marker;
//! callers cannot inject attestation claims.
//!
//! Each builder is called once per fire so wall-clock claims
//! (`iat`, `exp`) reflect the time of firing rather than the time the catalog
//! was constructed — a long catalog run otherwise ships stale freshness
//! claims that get rejected for the wrong reason.

use base64::Engine as _;
use serde_json::json;

/// The four template-deny `*_unattested` scenarios
/// (`phi_egress_unattested`, `iam_grant_unattested_deny`,
/// `transcript_bulk_unattested`, `cross_agent_impersonation`) need the
/// proxy to present `input.attestation = null` so the template's
/// unattested hard-deny fires. The dev proxy auto-attests every SVID via
/// its attestation cache, so this explicit marker forces the proxy's
/// `resolve_attestation` to `None`. It can only tighten the verdict,
/// never bypass.
pub(crate) fn absent_attestation_header() -> Vec<(&'static str, String)> {
    vec![("x-clavenar-attestation-absent", "1".to_string())]
}

/// JOSE-compact JWT helper. Hand-builds the header.payload.sig segments
/// without signing — the chaos targets (proxy → identity /actor-token/
/// redeem; proxy → grant parser) decode the payload but don't verify
/// the signature in v1, so a placeholder sig is enough to drive the
/// rejection path.
pub(crate) fn craft_unsigned_jwt(claims: &serde_json::Value) -> String {
    let header_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload_b64 =
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes());
    let sig_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"chaos-fake-sig");
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

/// `invalid_actor_token`: ship a structurally JWT-shaped but unsigned inbound
/// A2A token. This deliberately tests authentication rejection only; genuine
/// replay coverage requires minting and successfully redeeming an authorized
/// token before presenting the exact same JTI a second time.
pub(crate) fn invalid_actor_token_header() -> Vec<(&'static str, String)> {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss": "spiffe://clavenar.local",
        "sub": "spiffe://clavenar.local/tenant/acme/agent/x/instance/y",
        "aud": "spiffe://clavenar.local",
        "scope": ["call_tool"],
        "iat": now,
        // 30s ahead — fresh enough that the rejection isn't on `expired`.
        "exp": now + 30,
        "jti": "chaos-invalid-actor-token",
    });
    vec![("x-clavenar-actor-token", craft_unsigned_jwt(&claims))]
}

/// `expired_grant`: ship a delegation grant whose `exp` is firmly in
/// the past. The proxy parses x-clavenar-grant, sees the past exp, and
/// returns 403 grant_expired (per the clavenar-specs/TECH_SPEC.md#identity-service §10 posture: an
/// expired grant means consent has lapsed, request must not proceed).
pub(crate) fn expired_grant_header() -> Vec<(&'static str, String)> {
    let claims = json!({
        "iss":  "clavenar-identity",
        "sub":  "spiffe://clavenar.local/tenant/acme/agent/x",
        "act":  { "sub": "user:alice@acme.com" },
        "scope": ["mcp:read"],
        "iat":  100,
        // exp = 200 vs. wall clock — guaranteed past. The proxy's
        // grant.rs uses chrono::Utc::now().timestamp() so a tiny exp
        // in the past will reliably trip GrantParseError::Expired.
        "exp":  200,
        "jti":  "chaos-expired-grant",
    });
    vec![("x-clavenar-grant", craft_unsigned_jwt(&claims))]
}

/// `agent_cert_grant_replay`: ship a delegation grant that will never
/// validate — modelling an agent retrying a revoked/forged grant. The
/// proxy verifies grant signatures against identity's JWKS, so this
/// unsigned token is rejected at the grant gate (`grant_invalid`); a
/// past `exp` keeps it denied even where signature verification is off
/// (`grant_expired`). Either reason is "the gate refused the grant,"
/// which is what the certification gauntlet asserts.
pub(crate) fn revoked_grant_header() -> Vec<(&'static str, String)> {
    let claims = json!({
        "iss":  "clavenar-identity",
        "sub":  "spiffe://clavenar.local/tenant/acme/agent/x",
        "act":  { "sub": "user:alice@acme.com" },
        "scope": ["mcp:read"],
        "iat":  100,
        "exp":  200,
        "jti":  "chaos-cert-revoked-grant",
    });
    vec![("x-clavenar-grant", craft_unsigned_jwt(&claims))]
}

/// `cross_tenant_unfederated`: ship an A2A token whose `iss` is a
/// trust domain that the receiving identity service has never
/// federated with (and never will — `attacker.local` is unique
/// enough that no real deploy would peer with it). The wired path
/// fails on peer_bundle_unknown:attacker.local; the unwired path
/// fails on a2a_unavailable.
pub(crate) fn unfederated_actor_token_header() -> Vec<(&'static str, String)> {
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "iss":  "spiffe://attacker.local",
        "sub":  "spiffe://attacker.local/tenant/evil/agent/x/instance/y",
        "aud":  "spiffe://clavenar.local",
        "scope": ["call_tool"],
        "iat":  now,
        "exp":  now + 30,
        "jti":  "chaos-cross-tenant-unfederated",
    });
    vec![("x-clavenar-actor-token", craft_unsigned_jwt(&claims))]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn craft_unsigned_jwt_produces_three_segments() {
        // The proxy / identity decode the JOSE-compact form by
        // splitting on '.' and base64-decoding the middle segment.
        // A future change that emits 2 or 4 segments would silently
        // break the rejection paths the catalog probes — the attack-
        // level tests would still see a header attached but identity
        // would 400 on bad-shape instead of reaching the expected
        // a2a_redeem_failed/grant_expired branches.
        let token = craft_unsigned_jwt(&json!({"hello": "world"}));
        let segments: Vec<&str> = token.split('.').collect();
        assert_eq!(segments.len(), 3);
        for seg in &segments {
            assert!(!seg.is_empty(), "every JOSE segment must be non-empty");
        }
    }
}
