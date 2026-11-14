//! Intel TDX DCAP quote v4 parser, OutLayer attestation verification, and full Intel DCAP
//! verification via `dcap-qvl`.
//!
//! Layout (TD10 report body, offsets from the quote start):
//!
//! | Range      | Field                          |
//! |------------|--------------------------------|
//! | `0..48`    | header (`version`, `att_key_type`, `tee_type`, ...) |
//! | `184..232` | `MRTD`                         |
//! | `376..568` | `RTMR0..3` (4 x 48 bytes)      |
//! | `568..632` | `report_data`                  |
//! | `632..636` | signature-data length          |
//! | `636..`    | ECDSA sig (64) + attestation key (64) + certification data |
//!
//! # Validation Levels
//! 1. **Structural + Attestation-Key / QE Binding** ([`verify_attestation`]): checks the ECDSA
//!    P-256 signature of the attestation key over `header || body`, checks that the QE report
//!    commits to `SHA256(attestation_key || qe_auth_data)`, checks that `(mrtd, rtmr0..3)` is in
//!    the approved worker measurement list, and verifies `report_data[0..32] == task_hash`.
//! 2. **Full Intel DCAP Verification** ([`verify_dcap_quote`] / [`verify_full_dcap_attestation`]):
//!    uses `dcap-qvl` (`0.3.11`, the same verifier used by `worker.outlayer.testnet` and NEAR MPC
//!    nodes) to validate the PCK X.509 certificate chain up to the pinned Intel SGX Root CA,
//!    check Root CA and PCK CRL revocations, verify QE Identity and TCB Info signatures and
//!    validity windows against genuine Intel collateral, and enforce TCB status (`UpToDate`).

use borsh::{BorshDeserialize, BorshSerialize};
#[cfg(feature = "dcap")]
use dcap_qvl::QuoteCollateralV3;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
#[cfg(feature = "dcap")]
use serde_json::Value;

use crate::error::ReceiptError;
use crate::hashing::{self, sha256_concat};
use crate::hexser;

/// Expected quote version.
pub const QUOTE_VERSION: u16 = 4;
/// `tee_type` for Intel TDX.
pub const TEE_TYPE_TDX: u32 = 0x0000_0081;
/// `att_key_type` for ECDSA-256-with-P-256.
pub const ATT_KEY_ECDSA_P256: u16 = 2;
/// Length of header (48) + TD10 body (584).
pub const SIGNED_LEN: usize = 632;
const QE_REPORT_LEN: usize = 384;
const CERT_TYPE_QE_REPORT: u16 = 6;

/// The five TDX measurements approved by `worker.outlayer.testnet`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq, Hash)]
pub struct Measurements {
    /// Build-time TD measurement.
    pub mrtd: [u8; 48],
    /// Runtime measurement registers 0..3.
    pub rtmr: [[u8; 48]; 4],
}

/// Hex-encoded measurement entry as returned by `worker.outlayer.testnet::get_approved_measurements`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HexMeasurements {
    /// 96-character hex MRTD.
    pub mrtd: String,
    /// 96-character hex RTMR0.
    pub rtmr0: String,
    /// 96-character hex RTMR1.
    pub rtmr1: String,
    /// 96-character hex RTMR2.
    pub rtmr2: String,
    /// 96-character hex RTMR3.
    pub rtmr3: String,
}

fn decode_hex48(s: &str, field: &'static str) -> Result<[u8; 48], ReceiptError> {
    let bytes = hex::decode(s.trim())
        .map_err(|e| ReceiptError::InvalidInput(format!("invalid hex in {field}: {e}")))?;
    <[u8; 48]>::try_from(bytes.as_slice()).map_err(|_| {
        ReceiptError::InvalidInput(format!("{field} must be 48 bytes, got {}", bytes.len()))
    })
}

impl Measurements {
    /// `SHA256(mrtd || rtmr0..3)`, stored as `ReceiptV1::verifier_measurement`.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        hashing::verifier_measurement(&self.mrtd, &self.rtmr)
    }

    /// Construct from five 96-char hex strings.
    ///
    /// # Errors
    /// [`ReceiptError::InvalidInput`] if any string is not 48 bytes of valid hex.
    pub fn from_hex_strs(
        mrtd: &str,
        rtmr0: &str,
        rtmr1: &str,
        rtmr2: &str,
        rtmr3: &str,
    ) -> Result<Self, ReceiptError> {
        Ok(Self {
            mrtd: decode_hex48(mrtd, "mrtd")?,
            rtmr: [
                decode_hex48(rtmr0, "rtmr0")?,
                decode_hex48(rtmr1, "rtmr1")?,
                decode_hex48(rtmr2, "rtmr2")?,
                decode_hex48(rtmr3, "rtmr3")?,
            ],
        })
    }
}

impl TryFrom<&HexMeasurements> for Measurements {
    type Error = ReceiptError;

    fn try_from(h: &HexMeasurements) -> Result<Self, Self::Error> {
        Self::from_hex_strs(&h.mrtd, &h.rtmr0, &h.rtmr1, &h.rtmr2, &h.rtmr3)
    }
}

/// QE report certification data (cert type 6).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QeCertData {
    /// 384-byte enclave report of the quoting enclave.
    pub qe_report: [u8; QE_REPORT_LEN],
    /// ECDSA signature of the QE report by the PCK key.
    pub qe_report_signature: [u8; 64],
    /// QE authentication data.
    pub qe_auth_data: Vec<u8>,
    /// Inner certification data type (5 = PCK cert chain PEM).
    pub inner_cert_type: u16,
    /// Inner certification data (PCK chain).
    pub inner_cert_data: Vec<u8>,
}

/// A parsed TDX v4 quote.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TdxQuote {
    /// Quote version (always 4 after parsing).
    pub version: u16,
    /// Measurements.
    pub measurements: Measurements,
    /// 64-byte `report_data`.
    pub report_data: [u8; 64],
    /// `header || body` (the bytes the attestation key signed).
    pub signed_region: Vec<u8>,
    /// ECDSA signature (`r || s`).
    pub signature: [u8; 64],
    /// Attestation public key (`x || y`).
    pub attestation_key: [u8; 64],
    /// QE certification data when present.
    pub qe: Option<QeCertData>,
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], ReceiptError> {
        let end = self.pos.checked_add(n).filter(|e| *e <= self.data.len());
        let end = end.ok_or_else(|| ReceiptError::Quote("truncated quote".into()))?;
        let out = &self.data[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], ReceiptError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u16(&mut self) -> Result<u16, ReceiptError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, ReceiptError> {
        Ok(u32::from_le_bytes(self.array()?))
    }
}

impl TdxQuote {
    /// Parse a raw binary quote.
    ///
    /// # Errors
    /// [`ReceiptError::Quote`] on any structural violation.
    pub fn parse(raw: &[u8]) -> Result<Self, ReceiptError> {
        let mut r = Reader { data: raw, pos: 0 };
        let version = r.u16()?;
        if version != QUOTE_VERSION {
            return Err(ReceiptError::Quote(format!(
                "unsupported version {version}"
            )));
        }
        let att_key_type = r.u16()?;
        if att_key_type != ATT_KEY_ECDSA_P256 {
            return Err(ReceiptError::Quote(format!(
                "unsupported attestation key type {att_key_type}"
            )));
        }
        let tee_type = r.u32()?;
        if tee_type != TEE_TYPE_TDX {
            return Err(ReceiptError::Quote(format!(
                "tee_type {tee_type:#x} is not TDX"
            )));
        }
        if raw.len() < SIGNED_LEN + 4 {
            return Err(ReceiptError::Quote("truncated quote".into()));
        }
        let mut body = Reader {
            data: raw,
            pos: 184,
        };
        let mrtd = body.array::<48>()?;
        body.pos = 376;
        let rtmr = [
            body.array::<48>()?,
            body.array::<48>()?,
            body.array::<48>()?,
            body.array::<48>()?,
        ];
        let report_data = body.array::<64>()?;

        let mut sig = Reader {
            data: raw,
            pos: SIGNED_LEN,
        };
        let sig_len =
            usize::try_from(sig.u32()?).map_err(|_| ReceiptError::Quote("bad sig len".into()))?;
        let sig_end = sig
            .pos
            .checked_add(sig_len)
            .filter(|e| *e <= raw.len())
            .ok_or_else(|| ReceiptError::Quote("signature data length exceeds quote".into()))?;
        if raw[sig_end..].iter().any(|b| *b != 0) {
            return Err(ReceiptError::Quote(
                "non-zero trailing bytes after signature data".into(),
            ));
        }
        let signature = sig.array::<64>()?;
        let attestation_key = sig.array::<64>()?;
        let cert_type = sig.u16()?;
        let cert_size =
            usize::try_from(sig.u32()?).map_err(|_| ReceiptError::Quote("bad cert size".into()))?;
        let cert = sig.take(cert_size)?;
        if sig.pos != sig_end {
            return Err(ReceiptError::Quote(
                "certification data does not match signature data length".into(),
            ));
        }
        let qe = if cert_type == CERT_TYPE_QE_REPORT {
            Some(parse_qe(cert)?)
        } else {
            None
        };

        Ok(Self {
            version,
            measurements: Measurements { mrtd, rtmr },
            report_data,
            signed_region: raw[..SIGNED_LEN].to_vec(),
            signature,
            attestation_key,
            qe,
        })
    }

    /// Decode base64 or hex quote text into raw bytes.
    ///
    /// # Errors
    /// [`ReceiptError::Quote`] if neither hex nor standard base64 decodes.
    pub fn decode_bytes(text: &str) -> Result<Vec<u8>, ReceiptError> {
        use base64::Engine as _;
        let t = text.trim();
        hex::decode(t)
            .or_else(|_| base64::engine::general_purpose::STANDARD.decode(t))
            .map_err(|_| ReceiptError::Quote("quote is neither hex nor base64".into()))
    }

    /// Parse a quote supplied as base64 or hex text.
    ///
    /// # Errors
    /// Fails if neither encoding decodes or the quote is malformed.
    pub fn parse_encoded(text: &str) -> Result<Self, ReceiptError> {
        let raw = Self::decode_bytes(text)?;
        Self::parse(&raw)
    }

    /// Verify that the QE report commits to the attestation key:
    /// `qe_report.report_data[0..32] == SHA256(attestation_key || qe_auth_data)`.
    ///
    /// # Errors
    /// [`ReceiptError::QuoteSignature`] if absent or mismatched.
    pub fn verify_qe_binding(&self) -> Result<(), ReceiptError> {
        let qe = self.qe.as_ref().ok_or_else(|| {
            ReceiptError::QuoteSignature("no QE report certification data".into())
        })?;
        let expected = sha256_concat(&[&self.attestation_key, &qe.qe_auth_data]);
        if qe.qe_report[320..352] == expected {
            Ok(())
        } else {
            Err(ReceiptError::QuoteSignature(
                "QE report does not bind attestation key".into(),
            ))
        }
    }
}

fn parse_qe(cert: &[u8]) -> Result<QeCertData, ReceiptError> {
    let mut r = Reader { data: cert, pos: 0 };
    let qe_report = r.array::<QE_REPORT_LEN>()?;
    let qe_report_signature = r.array::<64>()?;
    let auth_len = usize::from(r.u16()?);
    let qe_auth_data = r.take(auth_len)?.to_vec();
    let inner_cert_type = r.u16()?;
    let inner_len =
        usize::try_from(r.u32()?).map_err(|_| ReceiptError::Quote("bad inner len".into()))?;
    let inner_cert_data = r.take(inner_len)?.to_vec();
    Ok(QeCertData {
        qe_report,
        qe_report_signature,
        qe_auth_data,
        inner_cert_type,
        inner_cert_data,
    })
}

/// Verify the attestation key's ECDSA P-256 signature over `header || body`.
///
/// # Errors
/// [`ReceiptError::QuoteSignature`] if the key is invalid or the signature does not verify.
pub fn verify_quote_signature(quote: &TdxQuote) -> Result<(), ReceiptError> {
    let mut sec1 = [0u8; 65];
    sec1[0] = 0x04;
    sec1[1..].copy_from_slice(&quote.attestation_key);
    let key = VerifyingKey::from_sec1_bytes(&sec1)
        .map_err(|e| ReceiptError::QuoteSignature(format!("bad attestation key: {e}")))?;
    let sig = Signature::from_slice(&quote.signature)
        .map_err(|e| ReceiptError::QuoteSignature(format!("bad signature encoding: {e}")))?;
    key.verify(&quote.signed_region, &sig)
        .map_err(|e| ReceiptError::QuoteSignature(e.to_string()))
}

/// Inputs to OutLayer's V1 `task_hash` (`worker/src/tdx_attestation.rs::generate_task_attestation`).
///
/// Important: OutLayer hashes `wasm_hash`, `input_hash`, and `output_hash` as **lowercase ASCII
/// hex strings** (64 bytes of UTF-8 text), whereas `task_id`, `block_height`, and `timestamp` are
/// 8-byte little-endian integers. Absent optional fields are skipped.
#[derive(
    BorshSerialize, BorshDeserialize, Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq,
)]
pub struct TaskHashInputs {
    /// Task type, e.g. `execute`.
    pub task_type: String,
    /// Task id.
    pub task_id: u64,
    /// Source repo URL (`repo_url` in OutLayer API).
    pub repo: Option<String>,
    /// Source commit hash (`commit_hash` in OutLayer API).
    pub commit: Option<String>,
    /// Build target (e.g. `wasm32-wasip2`).
    pub build_target: Option<String>,
    /// WASM SHA-256 digest (32 bytes, formatted as 64 lowercase hex chars when hashing).
    #[serde(with = "hexser::option")]
    pub wasm_hash: Option<[u8; 32]>,
    /// Input SHA-256 digest (32 bytes, formatted as 64 lowercase hex chars when hashing).
    #[serde(with = "hexser::option")]
    pub input_hash: Option<[u8; 32]>,
    /// Output SHA-256 digest (32 bytes, formatted as 64 lowercase hex chars when hashing).
    #[serde(with = "hexser")]
    pub output_hash: [u8; 32],
    /// NEAR block height.
    pub block_height: Option<u64>,
    /// Caller account (`caller_account_id` in V1).
    pub caller_account_id: Option<String>,
    /// Project id (`project_id` in V1).
    pub project_id: Option<String>,
    /// Secrets reference (`secrets_ref` in V1).
    pub secrets_ref: Option<String>,
    /// Timestamp (UNIX seconds; `Some(ts)` for V1 attestations, `None` for legacy V0 attestations).
    pub timestamp: Option<u64>,
    /// Attached USD string in minimal token units (e.g. `"0"`).
    pub attached_usd: Option<String>,
}

/// JSON record returned by `GET https://testnet-api.outlayer.ai/attestations/{id}`.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct OutLayerAttestationRecord {
    /// Attestation record ID.
    pub id: u64,
    /// Task ID.
    pub task_id: u64,
    /// Task type (`execute`, `compile`, etc.).
    pub task_type: String,
    /// Base64-encoded Intel TDX quote v4.
    pub tdx_quote: String,
    /// Worker measurement identifier reported by coordinator.
    pub worker_measurement: Option<String>,
    /// Execution request ID.
    pub request_id: Option<u64>,
    /// Caller NEAR account ID.
    pub caller_account_id: Option<String>,
    /// NEAR transaction hash.
    pub transaction_hash: Option<String>,
    /// NEAR block height.
    pub block_height: Option<u64>,
    /// Source repository URL.
    pub repo_url: Option<String>,
    /// Source git commit hash.
    pub commit_hash: Option<String>,
    /// WASM build target.
    pub build_target: Option<String>,
    /// 64-char hex SHA-256 of WASM binary.
    pub wasm_hash: Option<String>,
    /// 64-char hex SHA-256 of execution input.
    pub input_hash: Option<String>,
    /// 64-char hex SHA-256 of execution output.
    pub output_hash: String,
    /// Project ID if applicable.
    pub project_id: Option<String>,
    /// Secrets reference if applicable.
    pub secrets_ref: Option<String>,
    /// Attached USD amount string if present.
    pub attached_usd: Option<String>,
    /// Job creation UNIX timestamp (seconds).
    pub timestamp: u64,
}

fn decode_hex32(s: &str, field: &'static str) -> Result<[u8; 32], ReceiptError> {
    let raw = hex::decode(s.trim())
        .map_err(|e| ReceiptError::InvalidInput(format!("invalid hex in {field}: {e}")))?;
    <[u8; 32]>::try_from(raw.as_slice()).map_err(|_| {
        ReceiptError::InvalidInput(format!("{field} must be 32 bytes, got {}", raw.len()))
    })
}

impl OutLayerAttestationRecord {
    /// Convert this record into V1 [`TaskHashInputs`].
    ///
    /// # Errors
    /// [`ReceiptError::InvalidInput`] if any hash field is not valid 32-byte hex.
    pub fn to_v1_task_inputs(&self) -> Result<TaskHashInputs, ReceiptError> {
        Ok(TaskHashInputs {
            task_type: self.task_type.clone(),
            task_id: self.task_id,
            repo: self.repo_url.clone(),
            commit: self.commit_hash.clone(),
            build_target: self.build_target.clone(),
            wasm_hash: self
                .wasm_hash
                .as_deref()
                .map(|s| decode_hex32(s, "wasm_hash"))
                .transpose()?,
            input_hash: self
                .input_hash
                .as_deref()
                .map(|s| decode_hex32(s, "input_hash"))
                .transpose()?,
            output_hash: decode_hex32(&self.output_hash, "output_hash")?,
            block_height: self.block_height,
            caller_account_id: self.caller_account_id.clone(),
            project_id: self.project_id.clone(),
            secrets_ref: self.secrets_ref.clone(),
            timestamp: Some(self.timestamp),
            attached_usd: self.attached_usd.clone(),
        })
    }

    /// Convert this record into legacy V0 [`TaskHashInputs`] (which hashed only up to `block_height`).
    ///
    /// # Errors
    /// [`ReceiptError::InvalidInput`] if any hash field is not valid 32-byte hex.
    pub fn to_v0_task_inputs(&self) -> Result<TaskHashInputs, ReceiptError> {
        let mut v1 = self.to_v1_task_inputs()?;
        v1.caller_account_id = None;
        v1.project_id = None;
        v1.secrets_ref = None;
        v1.timestamp = None;
        v1.attached_usd = None;
        Ok(v1)
    }
}

/// Compute OutLayer's `task_hash`:
/// `SHA256(task_type || task_id_le8 || repo? || commit? || build_target? || hex(wasm_hash)? ||
/// hex(input_hash)? || hex(output_hash) || block_height_le8? || caller_account_id? ||
/// project_id? || secrets_ref? || timestamp_le8? || attached_usd?)`.
#[must_use]
pub fn compute_task_hash(i: &TaskHashInputs) -> [u8; 32] {
    let task_id = i.task_id.to_le_bytes();
    let timestamp = i.timestamp.map(u64::to_le_bytes);
    let height = i.block_height.map(u64::to_le_bytes);
    let opt_str = |s: &Option<String>| s.as_deref().map_or(&[][..], str::as_bytes).to_vec();
    let opt_hex32 = |h: &Option<[u8; 32]>| h.map_or_else(Vec::new, |v| hex::encode(v).into_bytes());
    let output_hex = hex::encode(i.output_hash).into_bytes();
    let parts: Vec<Vec<u8>> = vec![
        i.task_type.as_bytes().to_vec(),
        task_id.to_vec(),
        opt_str(&i.repo),
        opt_str(&i.commit),
        opt_str(&i.build_target),
        opt_hex32(&i.wasm_hash),
        opt_hex32(&i.input_hash),
        output_hex,
        height.map_or_else(Vec::new, |h| h.to_vec()),
        opt_str(&i.caller_account_id),
        opt_str(&i.project_id),
        opt_str(&i.secrets_ref),
        timestamp.map_or_else(Vec::new, |t| t.to_vec()),
        opt_str(&i.attached_usd),
    ];
    let refs: Vec<&[u8]> = parts.iter().map(Vec::as_slice).collect();
    sha256_concat(&refs)
}

/// Verify `report_data[0..32] == task_hash` and `report_data[32..64] == 0`.
///
/// # Errors
/// [`ReceiptError::ReportDataMismatch`] on mismatch.
pub fn verify_report_data(quote: &TdxQuote, task_hash: &[u8; 32]) -> Result<(), ReceiptError> {
    if quote.report_data[..32] == task_hash[..] && quote.report_data[32..].iter().all(|b| *b == 0) {
        Ok(())
    } else {
        Err(ReceiptError::ReportDataMismatch)
    }
}

/// Allowlist of approved measurement sets (synced from `worker.outlayer.testnet`).
#[derive(Clone, Debug, Default)]
pub struct ApprovedMeasurements {
    sets: Vec<Measurements>,
}

impl ApprovedMeasurements {
    /// Build from a list of sets.
    #[must_use]
    pub fn new(sets: Vec<Measurements>) -> Self {
        Self { sets }
    }

    /// Parse the JSON array returned by `worker.outlayer.testnet::get_approved_measurements`.
    ///
    /// # Errors
    /// Fails if the JSON is malformed or any measurement is not 48-byte hex.
    pub fn from_json_str(json: &str) -> Result<Self, ReceiptError> {
        let entries: Vec<HexMeasurements> =
            serde_json::from_str(json).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
        let mut sets = Vec::with_capacity(entries.len());
        for entry in &entries {
            sets.push(Measurements::try_from(entry)?);
        }
        Ok(Self { sets })
    }

    /// Number of approved 5-measurement sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.sets.len()
    }

    /// Whether the allowlist is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Whether `m` is approved.
    #[must_use]
    pub fn contains(&self, m: &Measurements) -> bool {
        self.sets.contains(m)
    }
}

/// Structural + signature + QE-binding + measurement-allowlist + `report_data` check.
///
/// Note: This does **not** validate the PCK X.509 chain or Intel TCB collateral; use
/// [`verify_full_dcap_attestation`] when collateral is available.
///
/// # Errors
/// Returns the first failing check.
pub fn verify_attestation(
    quote: &TdxQuote,
    approved: &ApprovedMeasurements,
    task: &TaskHashInputs,
) -> Result<(), ReceiptError> {
    verify_quote_signature(quote)?;
    quote.verify_qe_binding()?;
    if !approved.contains(&quote.measurements) {
        return Err(ReceiptError::MeasurementNotApproved);
    }
    verify_report_data(quote, &compute_task_hash(task))
}

/// Result of full Intel DCAP quote verification via `dcap-qvl`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DcapVerificationSummary {
    /// TCB status reported by `dcap-qvl` (e.g. `"UpToDate"`).
    pub status: String,
    /// Security advisory IDs reported by `dcap-qvl` (empty when `UpToDate`).
    pub advisory_ids: Vec<String>,
    /// Extracted 5 measurements from the verified TD10 report.
    pub measurements: Measurements,
    /// Extracted 64-byte `report_data` from the verified TD10 report.
    pub report_data: [u8; 64],
}

/// Parse Intel DCAP [`QuoteCollateralV3`] from either a raw collateral JSON object or the
/// wrapper object returned by `GET https://testnet-api.outlayer.ai/public/collateral`
/// (which nests the collateral under `"collateral"`).
///
/// # Errors
/// [`ReceiptError::Serialization`] or [`ReceiptError::InvalidInput`] if required fields are
/// missing or malformed.
#[cfg(feature = "dcap")]
pub fn parse_collateral_json(json_str: &str) -> Result<QuoteCollateralV3, ReceiptError> {
    let root: Value =
        serde_json::from_str(json_str).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
    let inner_owned: Value;
    let v = match root.get("collateral") {
        Some(Value::String(s)) => {
            inner_owned =
                serde_json::from_str(s).map_err(|e| ReceiptError::Serialization(e.to_string()))?;
            &inner_owned
        }
        Some(obj @ Value::Object(_)) => obj,
        _ => &root,
    };

    let get_str = |key: &'static str| -> Result<String, ReceiptError> {
        v.get(key)
            .and_then(Value::as_str)
            .map(String::from)
            .ok_or_else(|| ReceiptError::InvalidInput(format!("missing collateral field: {key}")))
    };
    let get_hex = |key: &'static str| -> Result<Vec<u8>, ReceiptError> {
        let s = get_str(key)?;
        hex::decode(s.trim()).map_err(|e| {
            ReceiptError::InvalidInput(format!("invalid hex in collateral field {key}: {e}"))
        })
    };

    Ok(QuoteCollateralV3 {
        tcb_info_issuer_chain: get_str("tcb_info_issuer_chain")?,
        tcb_info: get_str("tcb_info")?,
        tcb_info_signature: get_hex("tcb_info_signature")?,
        qe_identity_issuer_chain: get_str("qe_identity_issuer_chain")?,
        qe_identity: get_str("qe_identity")?,
        qe_identity_signature: get_hex("qe_identity_signature")?,
        pck_crl_issuer_chain: get_str("pck_crl_issuer_chain")?,
        root_ca_crl: get_hex("root_ca_crl")?,
        pck_crl: get_hex("pck_crl")?,
        pck_certificate_chain: v
            .get("pck_certificate_chain")
            .and_then(Value::as_str)
            .map(String::from),
    })
}

/// Perform full Intel DCAP quote verification using `dcap-qvl`:
/// validates the PCK certificate chain against the Intel SGX Root CA, checks Root CA and PCK CRLs,
/// verifies TCB Info and QE Identity signatures and validity windows at `now_unix_secs`, and
/// verifies the QE report and TD10 quote signature.
///
/// # Errors
/// [`ReceiptError::DcapVerification`] if `dcap-qvl` rejects the quote/collateral or the report is
/// not TD10.
#[cfg(feature = "dcap")]
pub fn verify_dcap_quote(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_unix_secs: u64,
) -> Result<DcapVerificationSummary, ReceiptError> {
    let verified = dcap_qvl::verify::verify(raw_quote, collateral, now_unix_secs)
        .map_err(|e| ReceiptError::DcapVerification(e.to_string()))?;
    let td10 = verified
        .report
        .as_td10()
        .ok_or_else(|| ReceiptError::DcapVerification("verified report is not TD10".into()))?;
    Ok(DcapVerificationSummary {
        status: verified.status,
        advisory_ids: verified.advisory_ids,
        measurements: Measurements {
            mrtd: td10.mr_td,
            rtmr: [td10.rt_mr0, td10.rt_mr1, td10.rt_mr2, td10.rt_mr3],
        },
        report_data: td10.report_data,
    })
}

/// Complete end-to-end attestation verification combining:
/// 1. Full Intel DCAP verification (`dcap-qvl`: PCK cert chain, Intel Root CA, CRLs, QE identity,
///    TCB collateral) and strict `status == "UpToDate"` + empty advisories check.
/// 2. Structural parser consistency check ([`TdxQuote::parse`], [`verify_quote_signature`],
///    [`TdxQuote::verify_qe_binding`]).
/// 3. Worker measurement allowlist check (`worker.outlayer.testnet`).
/// 4. OutLayer `task_hash` binding check (`report_data[0..32] == task_hash` and
///    `report_data[32..64] == 0`).
///
/// # Errors
/// Returns the first failing check.
#[cfg(feature = "dcap")]
pub fn verify_full_dcap_attestation(
    raw_quote: &[u8],
    collateral: &QuoteCollateralV3,
    now_unix_secs: u64,
    approved: &ApprovedMeasurements,
    task: &TaskHashInputs,
) -> Result<DcapVerificationSummary, ReceiptError> {
    let parsed = TdxQuote::parse(raw_quote)?;
    verify_attestation(&parsed, approved, task)?;
    let summary = verify_dcap_quote(raw_quote, collateral, now_unix_secs)?;
    if summary.status != "UpToDate" {
        return Err(ReceiptError::DcapVerification(format!(
            "TCB status `{}` is not UpToDate",
            summary.status
        )));
    }
    if !summary.advisory_ids.is_empty() {
        return Err(ReceiptError::DcapVerification(format!(
            "outstanding advisories: {:?}",
            summary.advisory_ids
        )));
    }
    Ok(summary)
}

#[cfg(test)]
pub(crate) mod testutil {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;

    /// Build a synthetic but structurally exact TDX v4 quote signed with a fresh P-256 key.
    pub fn synth_quote(m: &Measurements, report_data: [u8; 64], seed: u8) -> Vec<u8> {
        let mut q = vec![0u8; SIGNED_LEN];
        q[0..2].copy_from_slice(&4u16.to_le_bytes());
        q[2..4].copy_from_slice(&2u16.to_le_bytes());
        q[4..8].copy_from_slice(&TEE_TYPE_TDX.to_le_bytes());
        q[184..232].copy_from_slice(&m.mrtd);
        for (i, r) in m.rtmr.iter().enumerate() {
            q[376 + i * 48..424 + i * 48].copy_from_slice(r);
        }
        q[568..632].copy_from_slice(&report_data);

        let sk = SigningKey::from_bytes(&[seed; 32].into()).unwrap();
        let sig: Signature = sk.sign(&q);
        let pt = sk.verifying_key().to_encoded_point(false);
        let att_key = &pt.as_bytes()[1..];

        let auth = b"auth".to_vec();
        let mut qe_report = [0u8; QE_REPORT_LEN];
        let bind = sha256_concat(&[att_key, &auth]);
        qe_report[320..352].copy_from_slice(&bind);

        let mut cert = Vec::new();
        cert.extend_from_slice(&qe_report);
        cert.extend_from_slice(&[0u8; 64]);
        cert.extend_from_slice(&u16::try_from(auth.len()).unwrap().to_le_bytes());
        cert.extend_from_slice(&auth);
        cert.extend_from_slice(&5u16.to_le_bytes());
        cert.extend_from_slice(&3u32.to_le_bytes());
        cert.extend_from_slice(b"pem");

        let mut sigdata = Vec::new();
        sigdata.extend_from_slice(&sig.to_bytes());
        sigdata.extend_from_slice(att_key);
        sigdata.extend_from_slice(&6u16.to_le_bytes());
        sigdata.extend_from_slice(&u32::try_from(cert.len()).unwrap().to_le_bytes());
        sigdata.extend_from_slice(&cert);

        q.extend_from_slice(&u32::try_from(sigdata.len()).unwrap().to_le_bytes());
        q.extend_from_slice(&sigdata);
        q
    }

    pub fn sample_measurements() -> Measurements {
        Measurements {
            mrtd: [1; 48],
            rtmr: [[2; 48], [3; 48], [4; 48], [5; 48]],
        }
    }

    pub fn sample_task() -> TaskHashInputs {
        TaskHashInputs {
            task_type: "execute".into(),
            task_id: 7,
            wasm_hash: Some([1; 32]),
            input_hash: Some([2; 32]),
            output_hash: [3; 32],
            timestamp: Some(1_700_000_000),
            ..TaskHashInputs::default()
        }
    }

    pub fn report_data_for(task: &TaskHashInputs) -> [u8; 64] {
        let mut rd = [0u8; 64];
        rd[..32].copy_from_slice(&compute_task_hash(task));
        rd
    }
}

#[cfg(test)]
mod tests {
    use super::testutil::*;
    use super::*;

    fn good() -> (Vec<u8>, ApprovedMeasurements, TaskHashInputs) {
        let task = sample_task();
        let m = sample_measurements();
        let raw = synth_quote(&m, report_data_for(&task), 9);
        (raw, ApprovedMeasurements::new(vec![m]), task)
    }

    #[test]
    fn parses_offsets() {
        let (raw, _, task) = good();
        let q = TdxQuote::parse(&raw).unwrap();
        assert_eq!(q.measurements, sample_measurements());
        assert_eq!(q.report_data[..32], compute_task_hash(&task));
        assert_eq!(q.qe.as_ref().unwrap().inner_cert_data, b"pem");
    }

    #[test]
    fn full_attestation_passes() {
        let (raw, ok, task) = good();
        verify_attestation(&TdxQuote::parse(&raw).unwrap(), &ok, &task).unwrap();
    }

    #[test]
    fn encoded_forms_parse() {
        use base64::Engine as _;
        let (raw, _, _) = good();
        assert!(TdxQuote::parse_encoded(&hex::encode(&raw)).is_ok());
        assert!(
            TdxQuote::parse_encoded(&base64::engine::general_purpose::STANDARD.encode(&raw))
                .is_ok()
        );
        assert!(TdxQuote::parse_encoded("!!!").is_err());
    }

    #[test]
    fn wrong_version_and_tee_type_rejected() {
        let (mut raw, _, _) = good();
        raw[0] = 3;
        assert!(matches!(TdxQuote::parse(&raw), Err(ReceiptError::Quote(_))));
        let (mut raw, _, _) = good();
        raw[4] = 0;
        assert!(matches!(TdxQuote::parse(&raw), Err(ReceiptError::Quote(_))));
    }

    #[test]
    fn truncated_quote_rejected_at_every_length() {
        let (raw, _, _) = good();
        for n in [0, 10, 100, 631, 635, 700, raw.len() - 1] {
            assert!(TdxQuote::parse(&raw[..n]).is_err(), "len {n}");
        }
    }

    #[test]
    fn tampered_body_breaks_signature() {
        let (mut raw, ok, task) = good();
        raw[190] ^= 1; // flip an MRTD bit
        let q = TdxQuote::parse(&raw).unwrap();
        assert!(matches!(
            verify_attestation(&q, &ok, &task),
            Err(ReceiptError::QuoteSignature(_))
        ));
    }

    #[test]
    fn unapproved_measurements_rejected() {
        let (raw, _, task) = good();
        let other = ApprovedMeasurements::new(vec![Measurements {
            mrtd: [0; 48],
            rtmr: [[0; 48]; 4],
        }]);
        assert_eq!(
            verify_attestation(&TdxQuote::parse(&raw).unwrap(), &other, &task),
            Err(ReceiptError::MeasurementNotApproved)
        );
    }

    #[test]
    fn wrong_output_hash_fails_report_data() {
        let (raw, ok, mut task) = good();
        task.output_hash = [0xee; 32];
        assert_eq!(
            verify_attestation(&TdxQuote::parse(&raw).unwrap(), &ok, &task),
            Err(ReceiptError::ReportDataMismatch)
        );
    }

    #[test]
    fn nonzero_upper_report_data_rejected() {
        let task = sample_task();
        let m = sample_measurements();
        let mut rd = report_data_for(&task);
        rd[63] = 1;
        let raw = synth_quote(&m, rd, 9);
        assert_eq!(
            verify_report_data(&TdxQuote::parse(&raw).unwrap(), &compute_task_hash(&task)),
            Err(ReceiptError::ReportDataMismatch)
        );
    }

    #[test]
    fn swapped_attestation_key_fails_qe_binding() {
        let (mut raw, _, _) = good();
        let key_off = SIGNED_LEN + 4 + 64;
        raw[key_off] ^= 1;
        let q = TdxQuote::parse(&raw).unwrap();
        assert!(q.verify_qe_binding().is_err());
    }

    #[test]
    fn task_hash_skips_absent_optionals() {
        let mut a = sample_task();
        let h1 = compute_task_hash(&a);
        a.repo = Some("r".into());
        assert_ne!(h1, compute_task_hash(&a));
    }

    #[test]
    fn measurement_digest_depends_on_every_register() {
        let m = sample_measurements();
        let mut m2 = m.clone();
        m2.rtmr[3][0] ^= 1;
        assert_ne!(m.digest(), m2.digest());
    }
}
