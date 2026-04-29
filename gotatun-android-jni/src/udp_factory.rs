//! UDP transport factory that records bound socket fds for
//! `VpnService.protect()`.
//!
//! Android's `VpnService` captures all the device's network traffic and
//! routes it into the TUN. WireGuard's underlay (UDP to the peer) must
//! be exempted — otherwise WG's own packets get pulled back into its
//! own tunnel, creating a routing loop.
//!
//! `VpnService.protect(int fd)` is the API that exempts a specific
//! socket. The Java side calls it with the fd we return from
//! `awgGetSocketV4` / `awgGetSocketV6`.
//!
//! GotaTun's default `UdpSocketFactory` doesn't expose the bound fds —
//! they're held inside `UdpSocket.inner: Arc<tokio::net::UdpSocket>`
//! which is a private field. But `UdpSocket` does implement `AsFd`,
//! which gives us a `BorrowedFd` we can extract the integer from.
//!
//! This module wraps `UdpSocketFactory`, delegates the `bind` call, and
//! captures the fds out of the returned `UdpSocket`s into atomic ints.
//! The JNI shim reads those atomics in `awgGetSocketV4` / `V6`.

use std::os::fd::{AsFd, AsRawFd};
use std::sync::Arc;
use std::sync::atomic::{AtomicI32, Ordering};

use gotatun::udp::socket::{UdpSocket, UdpSocketFactory};
use gotatun::udp::{UdpTransportFactory, UdpTransportFactoryParams};

/// Wraps `UdpSocketFactory` and captures the fds on bind.
///
/// `fd_v4` / `fd_v6` are populated atomically the first time `bind` is
/// called. Sentinel `-1` means "not yet bound" (or "bind failed").
pub struct FdRecordingUdpFactory {
    pub fd_v4: Arc<AtomicI32>,
    pub fd_v6: Arc<AtomicI32>,
}

impl FdRecordingUdpFactory {
    pub fn new() -> Self {
        Self {
            fd_v4: Arc::new(AtomicI32::new(-1)),
            fd_v6: Arc::new(AtomicI32::new(-1)),
        }
    }

    /// Cheap clone of the fd handles. Used by the JNI surface to read
    /// the fds back without holding a reference to the factory itself.
    pub fn handles(&self) -> (Arc<AtomicI32>, Arc<AtomicI32>) {
        (Arc::clone(&self.fd_v4), Arc::clone(&self.fd_v6))
    }
}

impl UdpTransportFactory for FdRecordingUdpFactory {
    type SendV4 = UdpSocket;
    type SendV6 = UdpSocket;
    type RecvV4 = UdpSocket;
    type RecvV6 = UdpSocket;

    async fn bind(
        &mut self,
        params: &UdpTransportFactoryParams,
    ) -> std::io::Result<((Self::SendV4, Self::RecvV4), (Self::SendV6, Self::RecvV6))> {
        let mut inner = UdpSocketFactory;
        let result = inner.bind(params).await?;

        // result is ((send_v4, recv_v4), (send_v6, recv_v6)). The same
        // UdpSocket is used for both directions on each address family,
        // so capturing the SendV4/V6 fd is sufficient.
        let fd_v4 = result.0.0.as_fd().as_raw_fd();
        let fd_v6 = result.1.0.as_fd().as_raw_fd();
        self.fd_v4.store(fd_v4, Ordering::Release);
        self.fd_v6.store(fd_v6, Ordering::Release);
        log::info!("UDP fds captured: v4={fd_v4}, v6={fd_v6}");

        Ok(result)
    }
}
