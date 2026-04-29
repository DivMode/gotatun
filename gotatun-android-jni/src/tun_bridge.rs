//! Wrap a raw Linux file descriptor (received from Android's
//! `VpnService.Builder().establish()`) as a GotaTun-compatible
//! `TunDevice`.
//!
//! The Android side hands us an integer fd over JNI. We feed it into
//! the `tun` crate's `Configuration::raw_fd()` builder, which produces
//! a `tun::AsyncDevice` that GotaTun's `TunDevice::from_tun_device`
//! accepts. The resulting type implements `IpSend + IpRecv` and slots
//! into `DeviceBuilder::with_ip()`.
//!
//! This module is the canonical answer to "how do I plug an
//! externally-allocated TUN fd into GotaTun on Android". It deliberately
//! does NOT attempt to configure the TUN's IP, MTU, or routing — those
//! were already set by the wgtunnel-android Kotlin layer when it called
//! `VpnService.Builder().addAddress() / setMtu() / addRoute() / establish()`
//! before passing us the fd.

use std::os::fd::RawFd;

use eyre::{Context, Result};
use gotatun::tun::tun_async_device::TunDevice;

/// Take ownership of `tun_fd` and wrap it as a GotaTun TUN device.
///
/// On error, the fd is closed by the `tun` crate's Drop impl — this
/// matches the amneziawg-go behavior where `awgTurnOn` is responsible
/// for the fd from the moment it's passed in.
pub fn tun_from_fd(tun_fd: RawFd) -> Result<TunDevice> {
    let mut config = tun::Configuration::default();
    config.raw_fd(tun_fd);
    // VpnService TUN on Android does not include packet info headers
    // (Android delivers raw IP packets) — the tun crate defaults match.
    let async_device = tun::create_as_async(&config)
        .wrap_err("failed to wrap raw TUN fd as tun::AsyncDevice")?;
    TunDevice::from_tun_device(async_device)
        .wrap_err("failed to construct GotaTun TunDevice from async device")
}
