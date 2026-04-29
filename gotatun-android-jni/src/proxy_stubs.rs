//! No-op stubs for `org.amnezia.awg.ProxyGoBackend` native methods.
//!
//! Phase A scope is VPN-only (TUN-mode WireGuard). The wgtunnel-android
//! Kotlin layer also has a ProxyGoBackend class for an in-app SOCKS5
//! proxy mode that we don't use, but the JVM resolves static native
//! methods at class-load time even if they're never called. If our
//! `.so` is missing these symbols the entire AbstractBackend class
//! fails to load with `UnsatisfiedLinkError`.
//!
//! Each stub here logs once on first call and returns a safe error
//! sentinel (-1 / null / void). If we ever decide to ship the in-app
//! proxy mode (Phase B / C), these become real implementations.
//!
//! `awgResetJNIGlobals` is the one stub that actually fires in normal
//! VPN operation — it's called on every backend mode change. Making it
//! a no-op is correct: GotaTun has no global JNI state to reset.

use jni::JNIEnv;
use jni::objects::{JClass, JObject, JString};
use jni::sys::{jint, jstring};

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_ProxyGoBackend_awgStartProxy(
    _env: JNIEnv,
    _class: JClass,
    _iface_name: JString,
    _config: JString,
    _uapi_path: JString,
    _bypass: jint,
) -> jint {
    log::warn!("awgStartProxy: not implemented in Phase A (VPN-only)");
    -1
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_ProxyGoBackend_awgUpdateProxyTunnelPeers(
    _env: JNIEnv,
    _class: JClass,
    _handle: jint,
    _settings: JString,
) -> jint {
    log::warn!("awgUpdateProxyTunnelPeers: not implemented in Phase A");
    -1
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_ProxyGoBackend_awgStopProxy(
    _env: JNIEnv,
    _class: JClass,
) {
    log::debug!("awgStopProxy: no-op (Phase A is VPN-only)");
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_ProxyGoBackend_awgGetProxyConfig(
    env: JNIEnv,
    _class: JClass,
    _handle: jint,
) -> jstring {
    log::debug!("awgGetProxyConfig: no-op (Phase A is VPN-only)");
    match env.new_string("") {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_ProxyGoBackend_awgSetSocketProtector(
    _env: JNIEnv,
    _class: JClass,
    _protector: JObject,
) {
    log::debug!("awgSetSocketProtector: no-op (Phase A doesn't use ProxyGoBackend mode)");
}

/// Called on every backend mode change. amneziawg-go uses this to reset
/// global cgo state; our Rust shim has no equivalent global state, so
/// this is a no-op. Must exist or AbstractBackend fails to class-load.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_amnezia_awg_ProxyGoBackend_awgResetJNIGlobals(
    _env: JNIEnv,
    _class: JClass,
) {
    log::debug!("awgResetJNIGlobals: no-op (Rust shim has no global JNI state)");
}
