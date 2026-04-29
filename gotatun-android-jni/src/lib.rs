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

pub mod registry;
pub mod uapi_parser;

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jint, jstring};

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

/// Bring up a tunnel. See module docs for full semantics.
///
/// Phase A skeleton — currently parses the config and returns -1 (until
/// the device-spawn path is wired up in task #7's follow-up).
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgTurnOn(
    mut env: JNIEnv,
    _class: JClass,
    iface_name: JString,
    tun_fd: jint,
    settings: JString,
    uapi_path: JString,
) -> jint {
    init_logging();
    let _ = (&iface_name, tun_fd, &uapi_path); // silence unused-warnings pre-impl

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
        "awgTurnOn: parsed {} peer(s), {} address(es), mtu={:?}",
        parsed.set.peers.len(),
        parsed.interface_addresses.len(),
        parsed.interface_mtu,
    );

    // TODO(phase-a/task-7): build the GotaTun Device from `parsed.set` +
    // raw `tun_fd`, spawn its tasks on the shared Tokio runtime, store
    // the handle in `REGISTRY`, return the integer handle. Until then
    // we return -1 so the Kotlin layer surfaces a clean error rather
    // than silently believing the tunnel is up.
    -1
}

/// Tear down a tunnel by handle. Idempotent — Java may call this on a
/// handle that's already gone.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgTurnOff(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) {
    init_logging();
    log::info!("awgTurnOff: handle={handle} (skeleton, registry not yet wired)");
    // TODO(phase-a/task-7): REGISTRY.remove(handle) and drop the device.
}

/// Returns the IPv4 UDP socket fd for VpnService.protect(). -1 if the
/// handle is unknown or no IPv4 socket exists.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgGetSocketV4(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jint {
    init_logging();
    log::debug!("awgGetSocketV4: handle={handle} (skeleton)");
    // TODO(phase-a/task-8): expose GotaTun's bound UDP socket fd.
    -1
}

/// Returns the IPv6 UDP socket fd. Same contract as V4.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgGetSocketV6(
    _env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jint {
    init_logging();
    log::debug!("awgGetSocketV6: handle={handle} (skeleton)");
    -1
}

/// Dump the current device configuration in UAPI format.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_GoBackend_awgGetConfig(
    env: JNIEnv,
    _class: JClass,
    handle: jint,
) -> jstring {
    init_logging();
    log::debug!("awgGetConfig: handle={handle} (skeleton)");
    // TODO(phase-a/task-9): UapiClient::send_sync(Get) and serialize.
    match env.new_string("") {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// Atomically replace the peer list on an active tunnel. Returns 0 on
/// success, -1 on failure.
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

    let _parsed = match uapi_parser::parse(&settings_str) {
        Ok(p) => p,
        Err(e) => {
            log::error!("awgUpdateTunnelPeers: parse failed: {e:#}");
            return -1;
        }
    };

    log::info!("awgUpdateTunnelPeers: handle={handle} (skeleton, parser OK)");
    // TODO(phase-a/task-9): REGISTRY.with_mut(handle, |dev| dev.uapi_client.send_sync(parsed.set))
    -1
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
