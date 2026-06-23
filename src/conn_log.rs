// Connection audit logging.
//
// Fire-and-forget POST of every connection event (start / end / auth_failed)
// for both incoming (someone controls this PC) and outgoing (this PC controls
// a remote) sessions to the RemoteGuard WebAPI. Best-effort and non-blocking:
// events are queued and sent by a single background thread with a short
// timeout; any failure is silently dropped so logging never affects the app.

use hbb_common::log;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        mpsc::{sync_channel, SyncSender},
        Mutex,
    },
    time::{Duration, Instant},
};

// RemoteGuard connection-log ingest endpoint.
const API_URL: &str = "https://rd.puregroup.info/api/connection-logs";
// Host:port used only to discover the local source IP (no packet is sent).
const API_HOST_PORT: &str = "rd.puregroup.info:443";
const HTTP_TIMEOUT: Duration = Duration::from_secs(3);

pub const DIR_INCOMING: &str = "incoming";
pub const DIR_OUTGOING: &str = "outgoing";

struct SessionRec {
    session_id: String,
    start: Instant,
    direction: String,
    conn_type: String,
}

lazy_static::lazy_static! {
    static ref TX: Mutex<SyncSender<String>> = Mutex::new(start_worker());
    // live-connection key -> record, used to pair start/end and compute duration.
    static ref SESSIONS: Mutex<HashMap<String, SessionRec>> = Mutex::new(HashMap::new());
    // local machine info, gathered once on first use (machine identity is stable).
    static ref LOCAL_INFO: Value = build_local_info();
}

fn start_worker() -> SyncSender<String> {
    // Bounded: if the API is slow/down and events back up, new events are
    // dropped rather than growing memory without bound.
    let (tx, rx) = sync_channel::<String>(256);
    std::thread::spawn(move || {
        let client = match reqwest::blocking::Client::builder()
            .timeout(HTTP_TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                log::debug!("conn_log: failed to build http client: {}", e);
                return;
            }
        };
        while let Ok(body) = rx.recv() {
            // Best-effort; ignore all errors so logging never affects the app.
            if let Err(e) = client
                .post(API_URL)
                .header("Content-Type", "application/json")
                .body(body)
                .send()
            {
                log::debug!("conn_log: post failed: {}", e);
            }
        }
    });
    tx
}

fn build_local_info() -> Value {
    use hbb_common::sysinfo::System;
    #[allow(unused_mut)]
    let mut system = System::new();
    let os = system.distribution_id();
    let os_version = system.long_os_version().unwrap_or_default();

    #[cfg(not(any(target_os = "android", target_os = "ios")))]
    let username = crate::platform::get_active_username();
    #[cfg(any(target_os = "android", target_os = "ios"))]
    let username = crate::common::username();

    json!({
        "rustdesk_id": hbb_common::config::Config::get_id(),
        "hostname": crate::common::hostname(),
        "username": username,
        "os": os,
        "os_version": os_version,
        "app_version": crate::VERSION,
        "ip": local_ip(),
    })
}

fn local_ip() -> String {
    // Determine the source IP used to reach the API host. `connect` on a UDP
    // socket only sets the default route; no packet is sent.
    use std::net::UdpSocket;
    UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect(API_HOST_PORT)?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_default()
}

fn enqueue(payload: Value) {
    if let Ok(tx) = TX.lock() {
        // Drop the event if the queue is full (best-effort logging).
        let _ = tx.try_send(payload.to_string());
    }
}

fn peer_json(id: &str, name: &str, platform: &str, ip: &str, version: &str) -> Value {
    json!({
        "rustdesk_id": id,
        "name": name,
        "platform": platform,
        "ip": ip,
        "version": version,
    })
}

fn send_event(
    session_id: &str,
    event: &str,
    direction: &str,
    conn_type: &str,
    result: Option<&str>,
    duration_ms: Option<i64>,
    peer: Value,
) {
    let payload = json!({
        "session_id": session_id,
        "event": event,
        "direction": direction,
        "conn_type": conn_type,
        "result": result,
        "duration_ms": duration_ms,
        "timestamp_utc": hbb_common::get_time(),
        "local": (*LOCAL_INFO).clone(),
        "peer": peer,
    });
    enqueue(payload);
}

// ---- public hooks ----

/// Record a connection "start". `key` uniquely identifies the live connection so
/// the matching `end` can compute duration.
#[allow(clippy::too_many_arguments)]
pub fn log_start(
    key: String,
    direction: &str,
    conn_type: &str,
    peer_id: &str,
    peer_name: &str,
    peer_platform: &str,
    peer_ip: &str,
    peer_version: &str,
) {
    let session_id = uuid::Uuid::new_v4().to_string();
    if let Ok(mut m) = SESSIONS.lock() {
        m.insert(
            key,
            SessionRec {
                session_id: session_id.clone(),
                start: Instant::now(),
                direction: direction.to_owned(),
                conn_type: conn_type.to_owned(),
            },
        );
    }
    send_event(
        &session_id,
        "start",
        direction,
        conn_type,
        Some("ok"),
        None,
        peer_json(peer_id, peer_name, peer_platform, peer_ip, peer_version),
    );
}

/// Record a connection "end" for a previously started connection identified by `key`.
/// No-op if there is no matching `start` (e.g. unauthorized connections).
pub fn log_end(key: &str, result: &str) {
    let rec = SESSIONS.lock().ok().and_then(|mut m| m.remove(key));
    if let Some(rec) = rec {
        let duration_ms = rec.start.elapsed().as_millis() as i64;
        send_event(
            &rec.session_id,
            "end",
            &rec.direction,
            &rec.conn_type,
            Some(result),
            Some(duration_ms),
            json!({}),
        );
    }
}

/// Record a failed/rejected authentication attempt (no live session is tracked).
#[allow(clippy::too_many_arguments)]
pub fn log_auth_failed(
    direction: &str,
    conn_type: &str,
    result: &str,
    peer_id: &str,
    peer_name: &str,
    peer_platform: &str,
    peer_ip: &str,
    peer_version: &str,
) {
    let session_id = uuid::Uuid::new_v4().to_string();
    send_event(
        &session_id,
        "auth_failed",
        direction,
        conn_type,
        Some(result),
        None,
        peer_json(peer_id, peer_name, peer_platform, peer_ip, peer_version),
    );
}
