//! GotaTun Android JNI shim — drop-in replacement for `libam-go.so`.
//!
//! Exposes the 7-symbol native interface that wgtunnel-android's
//! `org.amnezia.awg.GoBackend` Kotlin class loads via `ReLinker`. Each
//! exported `Java_org_amnezia_awg_GoBackend_awg*` function maps the
//! JNI call onto GotaTun's Rust API.
//!
//! Phase A scope (this crate):
//!
//! - `awgVersion` → returns build-time version string. **Implemented.**
//! - `awgTurnOn` → parses wg-quick INI, builds GotaTun device, returns
//!   handle. **Skeleton — UAPI submission TODO.**
//! - `awgTurnOff` → looks up handle, drops device. **Skeleton.**
//! - `awgGetSocketV4` / `V6` → returns raw UDP fd for VpnService.protect.
//!   **Skeleton — needs `udp_fd_accessor` upstream patch or workaround.**
//! - `awgGetConfig` → UAPI dump. **Skeleton.**
//! - `awgUpdateTunnelPeers` → live peer-table replace. **Skeleton.**
//!
//! Modules below are tested in isolation and ready to be wired into the
//! JNI surface as we iterate.

pub mod proxy_stubs;
pub mod registry;
pub mod runtime;
pub mod tun_bridge;
pub mod uapi_parser;
pub mod udp_factory;

use std::sync::atomic::Ordering;

use gotatun::device::DeviceBuilder;
use gotatun::device::uapi::{UapiServer, command::Request};
use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};

use crate::runtime::{TunnelEntry, runtime, tunnels};
use crate::udp_factory::FdRecordingUdpFactory;

/// Initialise logging once. The Android target sends logs to logcat
/// under the `AmneziaWG/Rust` tag (matches the existing Go side's
/// `AmneziaWG/...` convention so existing logcat greps keep working).
/// On non-Android targets (host tests) it falls back to env_logger.
fn init_logging() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        #[cfg(target_os = "android")]
        {
            android_logger::init_once(
                android_logger::Config::default()
                    .with_max_level(log::LevelFilter::Info)
                    .with_tag("AmneziaWG/Rust"),
            );
        }
        #[cfg(not(target_os = "android"))]
        {
            let _ = env_logger::try_init();
        }
    });
}

/// Build-time version string returned by `awgVersion`.
///
/// Format: `<gotatun-version>+catchseo-jni-<crate-version>`. The catchseo
/// suffix lets us bump the shim independently of GotaTun upstream so we
/// can correlate phone-side reports to a specific JNI build.
///
/// `GOTATUN_VERSION` env var is set by `build.rs` (added in task #7) by
/// reading the gotatun crate's `Cargo.toml`. Defaults to `dev` for the
/// scaffolding build.
fn version_string() -> String {
    format!(
        "gotatun-{}+catchseo-jni-{}",
        option_env!("GOTATUN_VERSION").unwrap_or("dev"),
        env!("CARGO_PKG_VERSION"),
    )
}

// ── JNI exports ──────────────────────────────────────────────────────
//
// Symbol naming follows Java's mangling rules: package path components
// are joined with underscores, the class name is appended, then the
// method name. Underscores in identifiers are escaped to `_1`. None of
// our names contain underscores so the mangling is straightforward.
//
// IMPORTANT: do NOT add or rename symbols without coordinating with
// `org.amnezia.awg.GoBackend.java`. The Kotlin side declares each as a
// `static native` and the loader resolves by exact symbol name.

/// Returns the build version string. Called by Kotlin once at first
/// `loadLibrary` to log which dataplane is in use.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgVersion(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    init_logging();
    let v = version_string();
    match env.new_string(v) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            log::error!("awgVersion: failed to allocate JString: {e}");
            std::ptr::null_mut()
        }
    }
}

/// Bring up a tunnel.
///
/// Mirrors `amneziawg-go`'s `awgTurnOn`: parse settings, wrap the raw
/// TUN fd, build a GotaTun Device, store the handle.
///
/// `iface_name` and `uapi_path` are unused — `iface_name` is purely
/// informational on the Go side (logging), and `uapi_path` is for
/// wg-tool's Unix-socket UAPI which we don't expose on Android (the
/// dispatcher uses Android broadcasts, not wg-tool).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgTurnOn(
    mut env: JNIEnv,
    _class: JClass,
    _iface_name: JString,
    tun_fd: jint,
    settings: JString,
    _uapi_path: JString,
) -> jint {
    init_logging();

    let settings_str: String = match env.get_string(&settings) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("awgTurnOn: failed to read settings JString: {e}");
            return -1;
        }
    };

    let parsed = match uapi_parser::parse(&settings_str) {
        Ok(p) => p,
        Err(e) => {
            log::error!("awgTurnOn: failed to parse settings: {e:#}");
            return -1;
        }
    };

    log::info!(
        "awgTurnOn: bringing up tunnel with {} peer(s) on tun fd {}",
        parsed.set.peers.len(),
        tun_fd,
    );

    // UAPI client for in-process Get/Set requests. Java side never talks
    // to a Unix socket — it goes through awgGetConfig / awgUpdateTunnelPeers,
    // which call into the client we keep in the registry.
    let (uapi_client, uapi_server) = UapiServer::new();

    // Custom UDP factory that records the bound socket fds so the Java
    // side's VpnService.protect() callsite (awgGetSocketV4 / V6) can
    // exempt the WG underlay from the VPN itself. This must be set on
    // DeviceBuilder via `with_udp(...)` instead of `with_default_udp()`.
    let udp_factory = FdRecordingUdpFactory::new();
    let (fd_v4_handle, fd_v6_handle) = udp_factory.handles();

    // Build + start the device on the shared Tokio runtime. The TUN
    // bridge MUST be constructed inside the runtime context — tun's
    // AsyncDevice wraps tokio::AsyncFd which calls Handle::current(),
    // panicking with "there is no reactor running" if called from a
    // synchronous JNI context. block_on with a runtime guard is what
    // makes this safe.
    let device_result = runtime().block_on(async {
        let tun = tun_bridge::tun_from_fd(tun_fd)?;
        let device = DeviceBuilder::new()
            .with_uapi(uapi_server)
            .with_udp(udp_factory)
            .with_ip(tun)
            .build()
            .await?;
        // Apply the parsed Set config. Must use the async send().await,
        // not send_sync — the latter calls tokio's blocking_send /
        // blocking_recv which panic when invoked from inside an async
        // runtime context (we're inside block_on here).
        uapi_client.send(Request::Set(parsed.set)).await?;
        Ok::<_, eyre::Report>(device)
    });

    let device = match device_result {
        Ok(d) => d,
        Err(e) => {
            log::error!("awgTurnOn: device build/configure failed: {e:#}");
            return -1;
        }
    };

    let entry = TunnelEntry {
        device: Box::new(device),
        uapi: uapi_client,
        udp_fd_v4: fd_v4_handle,
        udp_fd_v6: fd_v6_handle,
    };

    match tunnels().insert(entry) {
        Some(handle) => {
            log::info!("awgTurnOn: tunnel up, handle={handle}");
            handle
        }
        None => {
            log::error!("awgTurnOn: registry full — i32 handle space exhausted");
            -1
        }
    }
}

/// Tear down a tunnel by handle. Idempotent — Java may call this on a
/// handle that's already gone (and amneziawg-go silently ignores it).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgTurnOff(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) {
    init_logging();
    let Some(entry) = tunnels().remove(handle) else {
        log::info!("awgTurnOff: handle={handle} not in registry (already torn down)");
        return;
    };

    // Drop the UAPI client first so any pending in-flight requests
    // unblock with a "device gone" error rather than hanging on the
    // device's response channel.
    drop(entry.uapi);

    entry.device.stop_blocking();

    log::info!("awgTurnOff: handle={handle} torn down");
}

/// Returns the IPv4 UDP socket fd for VpnService.protect(). -1 if the
/// handle is unknown or the socket isn't bound yet.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgGetSocketV4(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jint {
    init_logging();
    tunnels()
        .with(handle, |entry| entry.udp_fd_v4.load(Ordering::Acquire))
        .unwrap_or(-1)
}

/// Returns the IPv6 UDP socket fd. Same contract as V4.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgGetSocketV6(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jint {
    init_logging();
    tunnels()
        .with(handle, |entry| entry.udp_fd_v6.load(Ordering::Acquire))
        .unwrap_or(-1)
}

/// Dump the current device configuration in UAPI text format.
///
/// The Kotlin caller (`org.amnezia.awg.GoBackend.getTunnelConfig`)
/// parses this string with `awg.config.Config.parse(...)` to extract
/// peer state for UI display. We rely on GotaTun's `GetResponse: Display`
/// impl which produces compliant UAPI lines.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgGetConfig(
    env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jstring {
    init_logging();
    use gotatun::device::uapi::command::{Get, Response};

    let result = tunnels().with(handle, |entry| {
        // `Get` is #[non_exhaustive], so use Default rather than struct literal.
        entry.uapi.send_sync(Request::Get(Get::default()))
    });

    let config_str = match result {
        Some(Ok(Response::Get(get))) => get.to_string(),
        Some(Ok(Response::Set(_))) => {
            log::error!("awgGetConfig: unexpected Set response from Get request");
            String::new()
        }
        Some(Err(e)) => {
            log::error!("awgGetConfig: UAPI Get failed: {e:#}");
            String::new()
        }
        None => {
            log::debug!("awgGetConfig: handle={handle} not in registry");
            String::new()
        }
    };

    match env.new_string(config_str) {
        Ok(s) => s.into_raw(),
        Err(e) => {
            log::error!("awgGetConfig: failed to allocate JString: {e}");
            std::ptr::null_mut()
        }
    }
}

/// Atomically replace the peer list on an active tunnel. Returns 0 on
/// success, -1 on failure.
///
/// The amneziawg-go behavior is "build a peer-only Set request and call
/// IpcSet" — preserves the existing private key + listen port, replaces
/// the peer table. We mirror that contract: parse the new settings, take
/// the `peers` list (and `replace_peers` flag), drop the interface-level
/// fields.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgUpdateTunnelPeers(
    mut env: JNIEnv,
    _class: JClass,
    handle: jint,
    settings: JString,
) -> jint {
    init_logging();
    let settings_str: String = match env.get_string(&settings) {
        Ok(s) => s.into(),
        Err(e) => {
            log::error!("awgUpdateTunnelPeers: failed to read settings JString: {e}");
            return -1;
        }
    };

    let parsed = match uapi_parser::parse(&settings_str) {
        Ok(p) => p,
        Err(e) => {
            log::error!("awgUpdateTunnelPeers: parse failed: {e:#}");
            return -1;
        }
    };

    // Strip interface-level fields — they're already set on the existing
    // device. Keep peers + replace_peers semantics. The parsed.set
    // already has replace_peers=true (set by parse() unconditionally).
    let mut peers_only = gotatun::device::uapi::command::Set::builder()
        .replace_peers()
        .build();
    peers_only.peers = parsed.set.peers;

    let result = tunnels().with(handle, |entry| {
        entry.uapi.send_sync(Request::Set(peers_only))
    });

    match result {
        Some(Ok(_)) => {
            log::info!("awgUpdateTunnelPeers: handle={handle} updated");
            0
        }
        Some(Err(e)) => {
            log::error!("awgUpdateTunnelPeers: UAPI Set failed: {e:#}");
            -1
        }
        None => {
            log::error!("awgUpdateTunnelPeers: handle={handle} not in registry");
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_string_includes_both_components() {
        let v = version_string();
        // Sanity: format keeps the "gotatun-" prefix and "+catchseo-jni-"
        // separator so dashboards/log greps can split reliably.
        assert!(v.starts_with("gotatun-"), "version: {v}");
        assert!(v.contains("+catchseo-jni-"), "version: {v}");
    }
}
