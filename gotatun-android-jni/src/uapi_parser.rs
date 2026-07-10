//! Parse the wg-quick INI superset that the wgtunnel-android Kotlin layer
//! sends down through `awgTurnOn` / `awgUpdateTunnelPeers`.
//!
//! The Kotlin layer produces strings shaped like a standard wg-quick config
//! (`[Interface]` + one or more `[Peer]` sections). The amneziawg-go
//! reference implementation accepts the same shape via `wireproxyawg.
//! ParseConfigString` and converts to UAPI before calling the device. We
//! cut out the wireproxy middle layer and parse straight to GotaTun's
//! typed `command::Set` request.
//!
//! AmneziaWG obfuscation parameters (`Jc`, `Jmin`, `Jmax`, `S1`, `S2`,
//! `H1`-`H4`) are recognized and silently ignored — our deployment uses
//! plain WireGuard semantics (we own both endpoints; no DPI to bypass)
//! but configs may still carry these fields.
//!
//! This module is pure. No I/O, no JNI, no GotaTun runtime. Easy to
//! unit-test against golden inputs.

use std::net::SocketAddr;

use eyre::{Result, WrapErr, bail};
use gotatun::device::uapi::command::{Peer, Set, SetPeer};
use ipnetwork::IpNetwork;

/// Parsed config in the shape `awgTurnOn` and `awgUpdateTunnelPeers` need.
///
/// `set` carries the device-level Set request (private key, listen port,
/// peer table). The interface-level `address` and `mtu` fields are
/// extracted separately because GotaTun's UAPI doesn't carry them — they
/// are TUN-device properties, applied by the caller (wgtunnel app side
/// already configures these on the VpnService.Builder).
pub struct ParsedConfig {
    pub set: Set,
    pub interface_addresses: Vec<IpNetwork>,
    pub interface_mtu: Option<u16>,
}

/// Parse a wg-quick INI string into a structured config.
///
/// Returns Ok even if the config has unknown keys — those are logged and
/// skipped. Returns Err only for unrecoverable failures: missing required
/// fields, malformed key/IP/port values, etc.
pub fn parse(input: &str) -> Result<ParsedConfig> {
    let mut state = ParseState::Top;
    let mut interface = InterfaceSection::default();
    let mut peers: Vec<PeerSection> = Vec::new();

    for (lineno, raw) in input.lines().enumerate() {
        let line = strip_comment(raw).trim();
        if line.is_empty() {
            continue;
        }

        if let Some(section) = match_section_header(line) {
            state = match section {
                Section::Interface => ParseState::Interface,
                Section::Peer => {
                    peers.push(PeerSection::default());
                    ParseState::Peer
                }
            };
            continue;
        }

        let (key, value) = split_kv(line)
            .with_context(|| format!("line {}: expected `key = value`, got `{line}`", lineno + 1))?;

        match state {
            ParseState::Top => {
                bail!("line {}: key `{key}` outside of any section", lineno + 1);
            }
            ParseState::Interface => apply_interface_kv(&mut interface, key, value)?,
            ParseState::Peer => {
                let peer = peers
                    .last_mut()
                    .expect("peer section must have been pushed by header match");
                apply_peer_kv(peer, key, value)?;
            }
        }
    }

    let private_key = interface
        .private_key
        .ok_or_else(|| eyre::eyre!("[Interface] missing required `PrivateKey`"))?;

    if peers.is_empty() {
        bail!("config must declare at least one [Peer]");
    }

    // GotaTun's typed builder uses a typestate pattern where each setter
    // returns a different concrete type, so we can't conditionally chain
    // optional setters in a loop. Instead: build with the required fields
    // only, then mutate the public Option<_> fields directly.
    let mut set = Set::builder()
        .private_key(private_key)
        .replace_peers()
        .build();
    set.listen_port = interface.listen_port;

    for peer_section in peers {
        let public_key = peer_section
            .public_key
            .ok_or_else(|| eyre::eyre!("[Peer] missing required `PublicKey`"))?;
        let mut peer = Peer::builder().public_key(public_key).build();
        peer.endpoint = peer_section.endpoint;
        peer.persistent_keepalive_interval = peer_section.persistent_keepalive;
        peer.allowed_ip = peer_section.allowed_ips;

        let mut set_peer = SetPeer::builder().peer(peer).build();
        set_peer.replace_allowed_ips = peer_section.replace_allowed_ips;
        set = set.peer(set_peer);
    }

    Ok(ParsedConfig {
        set,
        interface_addresses: interface.addresses,
        interface_mtu: interface.mtu,
    })
}

#[derive(Clone, Copy)]
enum ParseState {
    Top,
    Interface,
    Peer,
}

#[derive(Clone, Copy)]
enum Section {
    Interface,
    Peer,
}

#[derive(Default)]
struct InterfaceSection {
    /// Stored as raw 32-byte arrays. GotaTun's `KeyBytes` lives in a
    /// `pub(crate)` module so we can't name it directly, but `[u8; 32]`
    /// converts via the `From` impl that's wired into the typed builder.
    private_key: Option<[u8; 32]>,
    listen_port: Option<u16>,
    addresses: Vec<IpNetwork>,
    mtu: Option<u16>,
}

#[derive(Default)]
struct PeerSection {
    public_key: Option<[u8; 32]>,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<u16>,
    allowed_ips: Vec<IpNetwork>,
    /// wg-quick semantics: every config restates the full peer config, so
    /// `awgUpdateTunnelPeers` should always replace allowed-ip lists. We
    /// hardcode this to true rather than parsing a key.
    replace_allowed_ips: bool,
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#').map_or(line, |(before, _)| before)
}

fn match_section_header(line: &str) -> Option<Section> {
    if !line.starts_with('[') || !line.ends_with(']') {
        return None;
    }
    let inner = &line[1..line.len() - 1];
    match inner.trim() {
        "Interface" => Some(Section::Interface),
        "Peer" => Some(Section::Peer),
        _ => None,
    }
}

fn split_kv(line: &str) -> Result<(&str, &str)> {
    let (key, value) = line
        .split_once('=')
        .ok_or_else(|| eyre::eyre!("missing `=` separator"))?;
    Ok((key.trim(), value.trim()))
}

fn apply_interface_kv(section: &mut InterfaceSection, key: &str, value: &str) -> Result<()> {
    match canonical_key(key).as_str() {
        "privatekey" => {
            section.private_key = Some(parse_key_b64(value)?);
        }
        "listenport" => {
            section.listen_port = Some(value.parse().wrap_err("invalid ListenPort")?);
        }
        "address" => {
            for entry in value.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    section.addresses.push(parse_ipnetwork(entry)?);
                }
            }
        }
        "mtu" => {
            section.mtu = Some(value.parse().wrap_err("invalid MTU")?);
        }
        // AmneziaWG obfuscation — silently ignored (we want plain WG).
        "jc" | "jmin" | "jmax" | "s1" | "s2" | "h1" | "h2" | "h3" | "h4" => {
            log::debug!("ignoring AmneziaWG obfuscation key `{key}`");
        }
        // wg-quick fields that don't map to UAPI — caller handles them.
        "dns" | "preup" | "predown" | "postup" | "postdown" | "table" | "saveconfig" => {
            log::debug!("ignoring wg-quick-only key `{key}`");
        }
        other => {
            log::debug!("unknown [Interface] key `{other}`, ignoring");
        }
    }
    Ok(())
}

fn apply_peer_kv(section: &mut PeerSection, key: &str, value: &str) -> Result<()> {
    match canonical_key(key).as_str() {
        "publickey" => {
            section.public_key = Some(parse_key_b64(value)?);
        }
        "endpoint" => {
            section.endpoint = Some(parse_endpoint(value)?);
        }
        "persistentkeepalive" => {
            section.persistent_keepalive = Some(value.parse().wrap_err("invalid PersistentKeepalive")?);
        }
        "allowedips" => {
            for entry in value.split(',') {
                let entry = entry.trim();
                if !entry.is_empty() {
                    section.allowed_ips.push(parse_ipnetwork(entry)?);
                }
            }
            section.replace_allowed_ips = true;
        }
        "presharedkey" => {
            // Skipped for now — phone1 doesn't use preshared keys. Add a
            // round-trip to `Peer.preshared_key` here if/when needed.
            log::debug!("PresharedKey present but currently unhandled");
        }
        other => {
            log::debug!("unknown [Peer] key `{other}`, ignoring");
        }
    }
    Ok(())
}

fn canonical_key(k: &str) -> String {
    k.chars().filter(|c| c.is_alphanumeric()).flat_map(char::to_lowercase).collect()
}

fn parse_key_b64(value: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::STANDARD
        .decode(value)
        .wrap_err("invalid base64 in key")?;
    raw.try_into()
        .map_err(|v: Vec<u8>| eyre::eyre!("WireGuard key must be 32 bytes after b64 decode, got {}", v.len()))
}

fn parse_endpoint(value: &str) -> Result<SocketAddr> {
    // wg-quick allows `host:port` or `[ipv6]:port`. SocketAddr::from_str
    // handles both numeric forms. For DNS hostnames we'd want to resolve
    // here, but the wgtunnel-android pipeline already injects a numeric
    // IP from Pulumi (server.ipv4Address) so DNS isn't in scope.
    value.parse().wrap_err("invalid Endpoint (expected ip:port or [ipv6]:port)")
}

fn parse_ipnetwork(value: &str) -> Result<IpNetwork> {
    // The `ipnetwork` crate's FromStr handles `addr/prefix`. Bare IPs
    // (no `/`) are not valid per the crate's parser, so we fall back to
    // tagging /32 or /128 ourselves.
    if value.contains('/') {
        value.parse().wrap_err("invalid IP/CIDR pair")
    } else {
        use std::net::IpAddr;
        let addr: IpAddr = value.parse().wrap_err("invalid IP address")?;
        let prefix = if addr.is_ipv4() { 32 } else { 128 };
        IpNetwork::new(addr, prefix).wrap_err("invalid IP/CIDR pair")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Phone1's actual production config from the oeili Ansible
    /// template. If parsing this regresses, slice 1 deployments break.
    const PHONE1_CONFIG: &str = "\
# WireGuard config for phone1 (PRD #1595, slice 1).
[Interface]
Address = 10.0.200.11/32
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=

[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = 5.78.99.99:51820
AllowedIPs = 10.0.200.0/24
PersistentKeepalive = 25
";

    #[test]
    fn parses_phone1_production_config() {
        let parsed = parse(PHONE1_CONFIG).expect("phone1 config must parse");

        assert_eq!(parsed.interface_addresses.len(), 1);
        assert_eq!(
            parsed.interface_addresses[0].to_string(),
            "10.0.200.11/32"
        );
        assert!(parsed.interface_mtu.is_none());

        assert_eq!(parsed.set.peers.len(), 1);
        let set_peer = &parsed.set.peers[0];
        assert!(!set_peer.remove);
        assert!(set_peer.replace_allowed_ips);

        let endpoint = set_peer.peer.endpoint.expect("endpoint must be set");
        assert_eq!(endpoint.to_string(), "5.78.99.99:51820");
        assert_eq!(set_peer.peer.persistent_keepalive_interval, Some(25));
        assert_eq!(set_peer.peer.allowed_ip.len(), 1);
        assert_eq!(set_peer.peer.allowed_ip[0].to_string(), "10.0.200.0/24");
    }

    #[test]
    fn rejects_missing_private_key() {
        let cfg = "[Interface]\nAddress = 10.0.0.1/32\n[Peer]\nPublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n";
        let err = match parse(cfg) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("PrivateKey"),
            "error should mention PrivateKey, got: {err}"
        );
    }

    #[test]
    fn rejects_missing_peer_section() {
        let cfg = "[Interface]\nPrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=\n";
        let err = match parse(cfg) {
            Ok(_) => panic!("must fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("[Peer]"),
            "error should mention [Peer], got: {err}"
        );
    }

    #[test]
    fn ignores_amneziawg_obfuscation_keys() {
        let cfg = "\
[Interface]
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=
Jc = 4
Jmin = 50
Jmax = 1000
S1 = 100
S2 = 100
H1 = 1
H2 = 2
H3 = 3
H4 = 4
[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
";
        let parsed = parse(cfg).expect("AmneziaWG-decorated config must parse");
        assert_eq!(parsed.set.peers.len(), 1);
    }

    #[test]
    fn allows_empty_allowed_ips_via_replace() {
        // wg-quick semantics: the peer entry has no AllowedIPs key. The
        // peer is still valid (will accept no inbound traffic, useful as
        // a deletion sentinel for awgUpdateTunnelPeers).
        let cfg = "\
[Interface]
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=
[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = 1.2.3.4:51820
";
        let parsed = parse(cfg).expect("must parse");
        assert_eq!(parsed.set.peers[0].peer.allowed_ip.len(), 0);
        // replace_allowed_ips false because AllowedIPs key was absent;
        // we only set true when we actually saw the key (slice-3 bulk
        // updates rely on this distinction).
        assert!(!parsed.set.peers[0].replace_allowed_ips);
    }

    #[test]
    fn case_insensitive_keys() {
        let cfg = "\
[Interface]
privatekey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=
[Peer]
public_key = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
endpoint = 1.2.3.4:51820
allowed_ips = 0.0.0.0/0
";
        let parsed = parse(cfg).expect("snake_case + lowercase must parse");
        assert_eq!(parsed.set.peers.len(), 1);
    }

    #[test]
    fn strips_comments_and_blank_lines() {
        let cfg = "\
# top comment
[Interface]    # inline comment
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=

  # indented comment

[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = 1.2.3.4:51820
AllowedIPs = 10.0.200.0/24
";
        let parsed = parse(cfg).expect("commented config must parse");
        assert_eq!(parsed.set.peers.len(), 1);
    }

    #[test]
    fn rejects_malformed_endpoint() {
        let cfg = "\
[Interface]
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=
[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = not-a-real-endpoint
AllowedIPs = 10.0.200.0/24
";
        let err = match parse(cfg) {
            Ok(_) => panic!("malformed endpoint must error"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("Endpoint"), "error: {err}");
    }

    #[test]
    fn parses_multiple_peers() {
        let cfg = "\
[Interface]
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=
[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = 1.2.3.4:51820
AllowedIPs = 10.0.200.0/24
[Peer]
PublicKey = G7omYmuvq9B7x7d5Ka9fyhdzYQ1bU//R2VSmsnh0KlU=
Endpoint = 5.6.7.8:51820
AllowedIPs = 10.0.201.0/24, 10.0.202.0/24
";
        let parsed = parse(cfg).expect("multi-peer config must parse");
        assert_eq!(parsed.set.peers.len(), 2);
        assert_eq!(parsed.set.peers[1].peer.allowed_ip.len(), 2);
    }

    #[test]
    fn parses_address_with_multiple_entries() {
        let cfg = "\
[Interface]
Address = 10.0.200.11/32, fd00:200::11/128
PrivateKey = CA7jRF1Tb55D2FCVnn/KBh+rxm0H22+4zFdD3mQ1aXk=
[Peer]
PublicKey = GLOShOWAqkAi1dqK4ppF6Gzyem5KKLWBxP0I+8hVbFY=
Endpoint = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0
";
        let parsed = parse(cfg).expect("dual-stack address must parse");
        assert_eq!(parsed.interface_addresses.len(), 2);
    }
}
