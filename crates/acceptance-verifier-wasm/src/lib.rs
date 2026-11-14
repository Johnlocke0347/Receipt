//! Deterministic acceptance verifier executed inside OutLayer's TDX CVM.
//!
//! Reads canonical JSON from stdin, evaluates `deliverable_payload` against `acceptance_rules`,
//! and prints a `RECEIPT_ACCEPTANCE_OUT_V1` JSON document to stdout. No clocks, randomness,
//! environment, or network access are used, so output is a pure function of input.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Version string reported in the output.
pub const WASM_SELF_VERSION: &str = "1.0.0";
/// Output schema tag.
pub const OUTPUT_SCHEMA: &str = "RECEIPT_ACCEPTANCE_OUT_V1";

/// Verifier failure modes (malformed input, as opposed to a `FAIL` outcome).
#[derive(Debug, PartialEq, Eq)]
pub enum VerifierError {
    /// Input is not valid JSON of the expected shape.
    Parse(String),
    /// A field that must be 32-byte hex is not.
    BadHex32(&'static str),
    /// A numeric field is out of range.
    OutOfRange(&'static str),
}

impl std::fmt::Display for VerifierError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "parse error: {e}"),
            Self::BadHex32(field) => write!(f, "{field} must be 64 hex characters"),
            Self::OutOfRange(field) => write!(f, "{field} out of range"),
        }
    }
}

impl std::error::Error for VerifierError {}

/// Deliverable submitted by the provider.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeliverablePayload {
    /// Free-form findings (hashed, not interpreted).
    pub audit_findings: Vec<Value>,
    /// Number of invariants checked.
    pub invariants_checked: u32,
    /// Hex32 digest of the test suite that was run.
    pub test_suite_digest: String,
    /// Deterministic score, 0..=100.
    pub deterministic_score: u32,
}

/// Buyer's acceptance rules.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptanceRules {
    /// Minimum invariants.
    pub min_invariants: u32,
    /// Required hex32 test-suite digest.
    pub required_test_digest: String,
    /// Minimum score, 0..=100.
    pub min_score: u32,
}

/// Verifier input.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierInput {
    /// Hex32 commitment to the agreed job spec.
    pub job_spec_commitment: String,
    /// Hex32 settlement commitment.
    pub confidential_settlement_commitment: String,
    /// The deliverable.
    pub deliverable_payload: DeliverablePayload,
    /// The rules.
    pub acceptance_rules: AcceptanceRules,
}

/// Evaluated metrics echoed in the output.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct EvaluatedMetrics {
    /// Invariants checked.
    pub invariants_checked: u32,
    /// Score.
    pub score: u32,
}

/// Verifier output (field order is the canonical JSON order).
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct VerifierOutput {
    /// Always [`OUTPUT_SCHEMA`].
    pub schema: String,
    /// `PASS` or `FAIL`.
    pub outcome: String,
    /// Always [`WASM_SELF_VERSION`].
    pub wasm_self_version: String,
    /// Echo of the settlement commitment.
    pub confidential_settlement_commitment: String,
    /// SHA-256 of the canonical deliverable JSON (keys sorted).
    pub deliverable_hash: String,
    /// SHA-256 of the canonical rules JSON (keys sorted).
    pub criteria_hash: String,
    /// Metrics.
    pub evaluated_metrics: EvaluatedMetrics,
}

fn check_hex32(value: &str, field: &'static str) -> Result<(), VerifierError> {
    let ok = value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if ok {
        Ok(())
    } else {
        Err(VerifierError::BadHex32(field))
    }
}

/// Canonical hash: serialize through `serde_json::Value` (sorted-key maps), then SHA-256.
fn canonical_hash<T: Serialize>(value: &T) -> Result<String, VerifierError> {
    let v = serde_json::to_value(value).map_err(|e| VerifierError::Parse(e.to_string()))?;
    let s = serde_json::to_string(&v).map_err(|e| VerifierError::Parse(e.to_string()))?;
    Ok(hex::encode(Sha256::digest(s.as_bytes())))
}

/// Evaluate parsed input.
///
/// # Errors
/// Malformed hex fields or scores above 100.
pub fn evaluate(input: &VerifierInput) -> Result<VerifierOutput, VerifierError> {
    check_hex32(&input.job_spec_commitment, "job_spec_commitment")?;
    check_hex32(
        &input.confidential_settlement_commitment,
        "confidential_settlement_commitment",
    )?;
    check_hex32(
        &input.deliverable_payload.test_suite_digest,
        "test_suite_digest",
    )?;
    check_hex32(
        &input.acceptance_rules.required_test_digest,
        "required_test_digest",
    )?;
    if input.deliverable_payload.deterministic_score > 100 {
        return Err(VerifierError::OutOfRange("deterministic_score"));
    }
    if input.acceptance_rules.min_score > 100 {
        return Err(VerifierError::OutOfRange("min_score"));
    }
    let d = &input.deliverable_payload;
    let r = &input.acceptance_rules;
    let pass = d.invariants_checked >= r.min_invariants
        && d.test_suite_digest == r.required_test_digest
        && d.deterministic_score >= r.min_score;
    Ok(VerifierOutput {
        schema: OUTPUT_SCHEMA.into(),
        outcome: if pass { "PASS" } else { "FAIL" }.into(),
        wasm_self_version: WASM_SELF_VERSION.into(),
        confidential_settlement_commitment: input.confidential_settlement_commitment.clone(),
        deliverable_hash: canonical_hash(&input.deliverable_payload)?,
        criteria_hash: canonical_hash(&input.acceptance_rules)?,
        evaluated_metrics: EvaluatedMetrics {
            invariants_checked: d.invariants_checked,
            score: d.deterministic_score,
        },
    })
}

/// Parse stdin text, evaluate, and render the canonical output JSON.
///
/// # Errors
/// Propagates parse and validation errors.
pub fn run(stdin_text: &str) -> Result<String, VerifierError> {
    let input: VerifierInput =
        serde_json::from_str(stdin_text).map_err(|e| VerifierError::Parse(e.to_string()))?;
    let out = evaluate(&input)?;
    serde_json::to_string(&out).map_err(|e| VerifierError::Parse(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(score: u32, invariants: u32, digest: &str) -> String {
        format!(
            r#"{{"job_spec_commitment":"{h}","confidential_settlement_commitment":"{h}",
"deliverable_payload":{{"audit_findings":[{{"id":1,"sev":"low"}}],"invariants_checked":{invariants},
"test_suite_digest":"{digest}","deterministic_score":{score}}},
"acceptance_rules":{{"min_invariants":10,"required_test_digest":"{h}","min_score":90}}}}"#,
            h = "ab".repeat(32)
        )
    }

    fn outcome(text: &str) -> String {
        let out: VerifierOutput = serde_json::from_str(&run(text).unwrap()).unwrap();
        out.outcome
    }

    #[test]
    fn passes_when_all_rules_met() {
        assert_eq!(outcome(&input(98, 12, &"ab".repeat(32))), "PASS");
    }

    #[test]
    fn boundary_values_pass() {
        assert_eq!(outcome(&input(90, 10, &"ab".repeat(32))), "PASS");
    }

    #[test]
    fn fails_on_low_score_invariants_or_digest() {
        assert_eq!(outcome(&input(89, 12, &"ab".repeat(32))), "FAIL");
        assert_eq!(outcome(&input(98, 9, &"ab".repeat(32))), "FAIL");
        assert_eq!(outcome(&input(98, 12, &"cd".repeat(32))), "FAIL");
    }

    #[test]
    fn output_is_deterministic_and_schema_tagged() {
        let i = input(98, 12, &"ab".repeat(32));
        let a = run(&i).unwrap();
        assert_eq!(a, run(&i).unwrap());
        assert!(a.starts_with(r#"{"schema":"RECEIPT_ACCEPTANCE_OUT_V1","outcome":"PASS""#));
    }

    #[test]
    fn hashes_are_independent_of_input_key_order() {
        let a = input(98, 12, &"ab".repeat(32));
        let b = a.replace(r#""invariants_checked":12,"#, "").replace(
            r#""audit_findings""#,
            r#""invariants_checked":12,"audit_findings""#,
        );
        let oa: VerifierOutput = serde_json::from_str(&run(&a).unwrap()).unwrap();
        let ob: VerifierOutput = serde_json::from_str(&run(&b).unwrap()).unwrap();
        assert_eq!(oa.deliverable_hash, ob.deliverable_hash);
    }

    #[test]
    fn deliverable_hash_changes_with_findings() {
        let a = input(98, 12, &"ab".repeat(32));
        let b = a.replace(r#""sev":"low""#, r#""sev":"high""#);
        let oa: VerifierOutput = serde_json::from_str(&run(&a).unwrap()).unwrap();
        let ob: VerifierOutput = serde_json::from_str(&run(&b).unwrap()).unwrap();
        assert_ne!(oa.deliverable_hash, ob.deliverable_hash);
        assert_eq!(oa.criteria_hash, ob.criteria_hash);
    }

    #[test]
    fn rejects_malformed_input() {
        assert!(matches!(run("{"), Err(VerifierError::Parse(_))));
        assert!(matches!(
            run(&input(101, 12, &"ab".repeat(32))),
            Err(VerifierError::OutOfRange(_))
        ));
        assert!(matches!(
            run(&input(98, 12, "zz")),
            Err(VerifierError::BadHex32(_))
        ));
        let unknown = input(98, 12, &"ab".repeat(32)).replace("min_score", "min_scor");
        assert!(matches!(run(&unknown), Err(VerifierError::Parse(_))));
    }

    #[test]
    fn uppercase_hex_rejected_to_keep_canonical_form() {
        let upper = "AB".repeat(32);
        assert!(matches!(
            run(&input(98, 12, &upper)),
            Err(VerifierError::BadHex32(_))
        ));
    }
}
