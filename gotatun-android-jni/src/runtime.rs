//! Shared Tokio runtime + tunnel-handle storage.
//!
//! All async work in the JNI shim runs on a single multi-threaded
//! Tokio runtime that is created lazily on the first `awgTurnOn` call
//! and lives for the rest of the process. This matches what
//! amneziawg-go does (one `runtime` for the whole library) and avoids
//! the overhead of spinning up a runtime per tunnel.
//!
//! Each entry in the registry holds the GotaTun `Device`, the
//! associated `UapiClient` (for `awgGetConfig` / `awgUpdateTunnelPeers`
//! programmatic access), and the raw bound UDP socket fds (for
//! `awgGetSocketV4` / `awgGetSocketV6`'s VpnService.protect path).

use std::sync::OnceLock;
use std::sync::Arc;
use std::sync::atomic::AtomicI32;

use gotatun::device::uapi::UapiClient;
use tokio::runtime::Runtime;

use crate::registry::Registry;

/// One active tunnel's state. Stored in the registry behind an i32
/// handle that we hand back to Java.
///
/// `device` is type-erased behind a `Box<dyn DeviceShutdown>` so we
/// don't have to expose the concrete `Device<T>` (whose generic param
/// changes when we use a custom `UdpTransportFactory` for fd capture).
/// We only ever need `stop()` on it from the JNI surface.
pub struct TunnelEntry {
    pub device: Box<dyn DeviceShutdown>,
    pub uapi: UapiClient,
    /// UDP socket fds populated by `FdRecordingUdpFactory` at bind time.
    /// `-1` means the socket isn't bound (or the bind hasn't happened yet,
    /// which shouldn't be observable from Java by the time `awgTurnOn`
    /// returns).
    pub udp_fd_v4: Arc<AtomicI32>,
    pub udp_fd_v6: Arc<AtomicI32>,
}

/// Trait-object wrapper around `Device::stop`. Lets us hold a Device
/// of any concrete `DeviceTransports` type without parameterizing
/// `TunnelEntry`.
pub trait DeviceShutdown: Send + Sync {
    fn stop_blocking(self: Box<Self>);
}

impl<T: gotatun::device::DeviceTransports + Send + Sync + 'static> DeviceShutdown
    for gotatun::device::Device<T>
{
    fn stop_blocking(self: Box<Self>) {
        // We're already inside a tokio block_on by the time JNI calls
        // awgTurnOff, so spawn the stop on the runtime instead of
        // awaiting it directly (which would re-enter block_on).
        runtime().block_on(async move {
            (*self).stop().await;
        });
    }
}

/// Process-wide tunnel registry. Java handles index into this.
pub fn tunnels() -> &'static Registry<TunnelEntry> {
    static REG: OnceLock<Registry<TunnelEntry>> = OnceLock::new();
    REG.get_or_init(Registry::new)
}

/// Process-wide Tokio runtime. Created on first use, kept for the life
/// of the process. Multi-threaded so GotaTun's per-direction tasks can
/// run on separate cores.
pub fn runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        // Worker threads: pick a sane default for the phone. The big.LITTLE
        // architecture means too many workers thrash on efficiency cores; too
        // few leaves crypto serialized. tokio's default (num_cpus) is fine —
        // gotatun's task scheduler already pins crypto-heavy work to its
        // own task per direction.
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("gotatun-jni")
            .build()
            .expect("failed to build Tokio runtime — JNI shim cannot continue")
    })
}
