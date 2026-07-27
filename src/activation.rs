// App activation / licensing.
//
// A license is bound to exactly one machine. On activation the RemoteGuard WebAPI
// returns an Ed25519-signed token which we store (Windows registry; a config-dir
// file elsewhere) encrypted with a key derived from THIS machine's hardware/OS
// identity. Two independent checks make a copied value useless on another PC:
//   1. the machine-bound encryption key won't decrypt the blob elsewhere, and
//   2. the machine fingerprint is embedded in the signed token and re-checked
//      after decryption.
// The signed token carries an expiry (default 15 days). A daily online re-check
// refreshes it; if the server is unreachable the token simply expires after the
// grace window, and if the license was revoked the stored value is wiped.

use hbb_common::{
    config::Config,
    log,
    sodiumoxide::crypto::{secretbox, sign},
};
use serde_json::json;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// Ed25519 public key that verifies license tokens (raw 32 bytes, base64). The
// matching private key lives only on the RemoteGuard server.
const LICENSE_PUBLIC_KEY: &str = "eEfrnEwBlqexK1bBa6TRFpcyMDbVelJ4oIQOZwwSmEI=";
const ACTIVATE_URL: &str = "https://rd.puregroup.info/api/license/activate";
const VALIDATE_URL: &str = "https://rd.puregroup.info/api/license/validate";
#[cfg(windows)]
const REG_VALUE_NAME: &str = "LicenseData";
const HTTP_TIMEOUT: Duration = Duration::from_secs(10);
const FORMAT_V1: u8 = 1;

#[derive(serde::Deserialize)]
struct TokenClaims {
    k: String, // license key
    f: String, // machine fingerprint
    #[allow(dead_code)]
    #[serde(default)]
    iat: i64,
    #[serde(default)]
    exp: i64, // unix seconds
}

#[derive(serde::Deserialize, Default)]
struct ApiResp {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    token: Option<String>,
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

// ---- machine identity ----

fn fingerprint_bytes() -> Vec<u8> {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(hbb_common::get_uuid());
    // Exclude the volatile CPU frequency and the user-changeable RustDesk id so a
    // legitimate machine keeps the same fingerprint day to day.
    hasher.update(hbb_common::fingerprint::get_fingerprint(
        None,
        Some(vec!["speed_max".to_string(), "id".to_string()]),
    ));
    hasher.finalize().to_vec()
}

/// Stable, machine-bound fingerprint (hex) that identifies this PC.
pub fn machine_fingerprint() -> String {
    hex::encode(fingerprint_bytes())
}

fn derive_key() -> secretbox::Key {
    let digest = fingerprint_bytes(); // 32 bytes == secretbox::KEYBYTES
    let mut kb = [0u8; secretbox::KEYBYTES];
    kb.copy_from_slice(&digest);
    secretbox::Key(kb)
}

// ---- machine-bound encryption (no pk fallback, unlike password_security) ----

fn encrypt_blob(plain: &[u8]) -> String {
    let key = derive_key();
    let nonce = secretbox::gen_nonce();
    let cipher = secretbox::seal(plain, &nonce, &key);
    let mut out = Vec::with_capacity(1 + secretbox::NONCEBYTES + cipher.len());
    out.push(FORMAT_V1);
    out.extend_from_slice(&nonce.0);
    out.extend_from_slice(&cipher);
    crate::common::encode64(&out)
}

fn decrypt_blob(b64: &str) -> Option<Vec<u8>> {
    let data = crate::common::decode64(b64).ok()?;
    if data.first() != Some(&FORMAT_V1)
        || data.len() < 1 + secretbox::NONCEBYTES + secretbox::MACBYTES
    {
        return None;
    }
    let mut nb = [0u8; secretbox::NONCEBYTES];
    nb.copy_from_slice(&data[1..1 + secretbox::NONCEBYTES]);
    let nonce = secretbox::Nonce(nb);
    let key = derive_key();
    secretbox::open(&data[1 + secretbox::NONCEBYTES..], &nonce, &key).ok()
}

// ---- token verification (Ed25519, embedded public key) ----

fn license_pubkey() -> Option<sign::PublicKey> {
    let bytes = crate::common::decode64(LICENSE_PUBLIC_KEY).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Some(sign::PublicKey(arr))
}

// The server token is base64(signature(64) || jsonClaims) — the "attached" form
// sodiumoxide's sign::verify expects.
fn verify_token(token_b64: &str) -> Option<TokenClaims> {
    let signed = crate::common::decode64(token_b64).ok()?;
    let pk = license_pubkey()?;
    let msg = sign::verify(&signed, &pk).ok()?;
    serde_json::from_slice::<TokenClaims>(&msg).ok()
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ---- persistent storage (registry on Windows, file elsewhere) ----

#[cfg(windows)]
fn read_stored() -> String {
    crate::platform::windows::get_reg(REG_VALUE_NAME)
}

#[cfg(windows)]
fn write_stored(value: &str) -> Result<(), String> {
    crate::platform::windows::set_license_data(value).map_err(|e| e.to_string())
}

// Background re-check writes: never prompt for UAC. If not elevated, this fails
// and the token is simply left to expire naturally (which still enforces the
// grace window and revocation).
#[cfg(windows)]
fn write_stored_silent(value: &str) -> Result<(), String> {
    crate::platform::windows::set_license_data_silent(value).map_err(|e| e.to_string())
}

#[cfg(windows)]
fn clear_stored() {
    let _ = crate::platform::windows::set_license_data_silent("");
}

#[cfg(not(windows))]
fn license_file() -> std::path::PathBuf {
    Config::path("license.dat")
}

#[cfg(not(windows))]
fn read_stored() -> String {
    std::fs::read_to_string(license_file()).unwrap_or_default()
}

#[cfg(not(windows))]
fn write_stored(value: &str) -> Result<(), String> {
    std::fs::write(license_file(), value).map_err(|e| e.to_string())
}

#[cfg(not(windows))]
fn write_stored_silent(value: &str) -> Result<(), String> {
    // No elevation concept off Windows.
    write_stored(value)
}

#[cfg(not(windows))]
fn clear_stored() {
    let _ = std::fs::remove_file(license_file());
}

// ---- public API ----

/// Local, offline check: a valid, machine-matching, unexpired license is stored.
/// Cheap enough to call on the connection path.
pub fn is_activated() -> bool {
    stored_claims().is_some()
}

fn stored_claims() -> Option<TokenClaims> {
    let stored = read_stored();
    if stored.trim().is_empty() {
        return None;
    }
    // 1. machine-bound decryption (fails outright on a different PC).
    let token = String::from_utf8(decrypt_blob(&stored)?).ok()?;
    // 2. server signature + parse.
    let claims = verify_token(&token)?;
    // 3. fingerprint embedded in the signed token must match this machine.
    if claims.f != machine_fingerprint() {
        return None;
    }
    // 4. not expired (this is the offline grace window).
    if claims.exp != 0 && now_secs() > claims.exp {
        return None;
    }
    Some(claims)
}

fn device_body(key: &str) -> serde_json::Value {
    json!({
        "key": key,
        "machine_fingerprint": machine_fingerprint(),
        "hostname": crate::common::hostname(),
        "rustdesk_id": Config::get_id(),
        "os": std::env::consts::OS,
        "app_version": crate::VERSION,
    })
}

// Runs the blocking HTTP request on a dedicated thread so it never conflicts with
// an ambient async runtime.
fn post_json(url: &'static str, body: serde_json::Value) -> Result<ApiResp, String> {
    std::thread::spawn(move || -> Result<ApiResp, String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| e.to_string())?;
        let resp = client
            .post(url)
            .json(&body)
            .send()
            .map_err(|e| e.to_string())?;
        resp.json::<ApiResp>().map_err(|e| e.to_string())
    })
    .join()
    .map_err(|_| "activation request thread panicked".to_string())?
}

fn store_verified_token(token: &str, silent: bool) -> Result<(), String> {
    let claims = verify_token(token).ok_or_else(|| "Invalid token from server".to_string())?;
    if claims.f != machine_fingerprint() {
        return Err("Token is bound to a different machine".to_string());
    }
    let blob = encrypt_blob(token.as_bytes());
    if silent {
        write_stored_silent(&blob)
    } else {
        write_stored(&blob)
    }
}

/// Activate this machine with `key`. Returns Ok(()) on success, or a user-facing
/// error message. May trigger a UAC prompt to write the registry (Windows).
pub fn activate(key: &str) -> Result<(), String> {
    let key = key.trim();
    if key.is_empty() {
        return Err("Please enter an activation key".to_string());
    }
    let resp = post_json(ACTIVATE_URL, device_body(key))?;
    if !resp.success {
        return Err(resp.message.unwrap_or_else(|| match resp.reason.as_deref() {
            Some("invalid_key") => "Invalid activation key".to_string(),
            Some("revoked") => "This key has been revoked".to_string(),
            Some("seat_limit") => "This key is already in use on another PC".to_string(),
            _ => "Activation failed".to_string(),
        }));
    }
    let token = resp
        .token
        .ok_or_else(|| "Server did not return a token".to_string())?;
    store_verified_token(&token, false)?;
    log::info!("App activated successfully");
    Ok(())
}

/// Background daily re-check. Refreshes the token (extends the grace window) or
/// wipes it on explicit revocation. Network errors are ignored so the app keeps
/// working until the token naturally expires.
pub fn recheck() {
    let Some(claims) = stored_claims() else {
        return; // nothing stored / already inactive
    };
    let body = json!({
        "key": claims.k,
        "machine_fingerprint": machine_fingerprint(),
    });
    match post_json(VALIDATE_URL, body) {
        Ok(resp) if resp.success => {
            if let Some(token) = resp.token {
                if let Err(e) = store_verified_token(&token, true) {
                    log::debug!("license recheck: failed to store refreshed token: {}", e);
                }
            }
        }
        Ok(resp) => {
            // Explicit denial -> revoke access on this machine.
            if matches!(
                resp.reason.as_deref(),
                Some("revoked") | Some("not_activated") | Some("invalid_key")
            ) {
                log::info!("License no longer valid ({:?}); clearing.", resp.reason);
                clear_stored();
            }
        }
        Err(e) => {
            log::debug!("license recheck: network error (ignored): {}", e);
        }
    }
}

/// Start the daily background license re-check. Idempotent: only the first call
/// spawns the loop.
pub fn start_recheck() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return;
    }
    std::thread::spawn(|| {
        // Small initial delay so startup isn't slowed.
        std::thread::sleep(Duration::from_secs(60));
        loop {
            recheck();
            std::thread::sleep(Duration::from_secs(24 * 60 * 60));
        }
    });
}
