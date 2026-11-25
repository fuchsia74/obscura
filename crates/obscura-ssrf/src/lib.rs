//! The SSRF policy every Obscura transport shares: which IP addresses an
//! outbound request may never reach, and the process-wide env opt-in that
//! lifts the restriction for local testing.
//!
//! This crate has no dependencies on purpose. `obscura-net` (reqwest and wreq
//! transports) and `obscura-render` (the synchronous compatibility loader for
//! images and fonts) both enforce the same deny-set from here, so the checks
//! can never disagree.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Condvar, Mutex, OnceLock};

/// Process-wide opt-in via env var. Older flow that issue #4 introduced. The
/// new `--allow-private-network` CLI flag (issue #33) sets a per-client field
/// that is OR'd with this so existing scripts and Docker setups that pin the
/// env var keep working unchanged.
pub fn env_allows_private_network() -> bool {
    matches!(
        std::env::var("OBSCURA_ALLOW_PRIVATE_NETWORK")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref(),
        Some("1") | Some("true") | Some("yes") | Some("on")
    )
}

/// True when `ip` must never be the target of an outbound request from the
/// engine: loopback, RFC1918 private, link-local (incl. the 169.254.169.254
/// cloud-metadata endpoint), broadcast, documentation, the unspecified address
/// (0.0.0.0 / ::, which the OS routes to localhost), IPv6 unique-local
/// (fc00::/7), and any IPv4-mapped/compatible IPv6 form of the above.
/// Centralizes the SSRF deny-set so the literal-host check and the
/// DNS-resolution check (`SsrfGuardResolver`) can never disagree.
pub fn is_forbidden_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                || o[0] == 0
                // std's is_private() covers only RFC1918, so add the IANA
                // special-purpose ranges that also host internal services and
                // are common SSRF targets:
                //   100.64.0.0/10  CGNAT / RFC6598 — cloud metadata (e.g.
                //                  Alibaba 100.100.100.200) lives here.
                //   198.18.0.0/15  benchmarking / RFC2544.
                //   192.88.99.0/24 6to4 relay anycast / RFC7526.
                || (o[0] == 100 && (64..=127).contains(&o[1]))
                || (o[0] == 198 && (o[1] == 18 || o[1] == 19))
                || (o[0] == 192 && o[1] == 88 && o[2] == 99)
                // Most of 192.0.0.0/24 is special-purpose and not globally
                // reachable. Keep the two globally reachable PCP anycast
                // assignments usable rather than blocking the entire /24.
                || (o[0] == 192
                    && o[1] == 0
                    && o[2] == 0
                    && o[3] != 9
                    && o[3] != 10)
                // 240.0.0.0/4 is reserved (255.255.255.255 was already
                // covered by is_broadcast()).
                || o[0] >= 240
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.is_multicast()
            {
                return true;
            }
            // Unwrap IPv4-mapped (::ffff:a.b.c.d) and IPv4-compatible (::a.b.c.d)
            // forms and re-check the embedded v4 so e.g. [::ffff:127.0.0.1] or
            // [::ffff:169.254.169.254] cannot slip past the v6 arm.
            if let Some(v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_forbidden_ip(IpAddr::V4(v4));
            }

            let s = v6.segments();
            // IPv4/IPv6 translation prefix (RFC 6052). Only /96 has a fixed
            // embedded-address position; the local-use /48 is therefore
            // blocked outright below.
            if s[0] == 0x64
                && s[1] == 0xff9b
                && s[2] == 0
                && s[3] == 0
                && s[4] == 0
                && s[5] == 0
            {
                return is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(
                    (s[6] >> 8) as u8,
                    s[6] as u8,
                    (s[7] >> 8) as u8,
                    s[7] as u8,
                )));
            }
            // 6to4 carries its IPv4 endpoint in bits 16..48.
            if s[0] == 0x2002 {
                return is_forbidden_ip(IpAddr::V4(Ipv4Addr::new(
                    (s[1] >> 8) as u8,
                    s[1] as u8,
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                )));
            }
            // Teredo (RFC 4380, 2001:0::/32) carries the server's IPv4 in
            // bits 32..64 and the client's public IPv4, bit-inverted, in the
            // last 32 bits. Either one embedding a forbidden address is
            // refused, like the other IPv4-in-IPv6 forms above.
            if s[0] == 0x2001 && s[1] == 0 {
                let server = Ipv4Addr::new(
                    (s[2] >> 8) as u8,
                    s[2] as u8,
                    (s[3] >> 8) as u8,
                    s[3] as u8,
                );
                let client = Ipv4Addr::new(
                    !(s[6] >> 8) as u8,
                    !s[6] as u8,
                    !(s[7] >> 8) as u8,
                    !s[7] as u8,
                );
                return is_forbidden_ip(IpAddr::V4(server)) || is_forbidden_ip(IpAddr::V4(client));
            }

            // Discard-only, local-use NAT64, and documentation prefixes.
            (s[0] == 0x100 && s[1] == 0 && s[2] == 0 && s[3] == 0)
                || (s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1)
                || (s[0] == 0x2001 && s[1] == 0x0db8)
                || (s[0] == 0x3fff && s[1] & 0xf000 == 0)
        }
    }
}


/// Optional per-origin in-flight request cap shared by every transport in the
/// process (async reqwest navigation/API traffic and the renderer's blocking
/// image loader). Mirrors a browser's per-host connection limit.
///
/// `OBSCURA_MAX_CONN_PER_HOST=12` enables the cap; unset, `0`, or a
/// non-numeric value leaves it disabled.
pub fn max_connections_per_host() -> usize {
    static LIMIT: OnceLock<usize> = OnceLock::new();
    *LIMIT.get_or_init(|| {
        std::env::var("OBSCURA_MAX_CONN_PER_HOST")
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .unwrap_or(0)
    })
}

/// Counting gate for one origin.
pub struct ConnectionGate {
    limit: usize,
    in_use: Mutex<usize>,
    released: Condvar,
}

/// RAII permit; dropping it wakes one waiter.
pub struct ConnectionPermit {
    gate: Arc<ConnectionGate>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        if let Ok(mut in_use) = self.gate.in_use.lock() {
            *in_use = in_use.saturating_sub(1);
        }
        self.gate.released.notify_one();
    }
}

impl ConnectionGate {
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// Non-blocking attempt, for async contexts that poll and yield.
    pub fn try_acquire(self: &Arc<Self>) -> Option<ConnectionPermit> {
        let mut in_use = self.in_use.lock().unwrap();
        if *in_use < self.limit {
            *in_use += 1;
            Some(ConnectionPermit { gate: Arc::clone(self) })
        } else {
            None
        }
    }

    /// Blocking acquire, for synchronous transports (the renderer's ureq
    /// image loader already blocks on I/O in this thread).
    pub fn acquire(self: &Arc<Self>) -> ConnectionPermit {
        let mut in_use = self.in_use.lock().unwrap();
        while *in_use >= self.limit {
            in_use = self.released.wait(in_use).unwrap();
        }
        *in_use += 1;
        ConnectionPermit { gate: Arc::clone(self) }
    }
}

/// Process-wide gate for `host`, or `None` when the cap is disabled.
pub fn host_gate(host: &str) -> Option<Arc<ConnectionGate>> {
    let limit = max_connections_per_host();
    if limit == 0 {
        return None;
    }
    static GATES: OnceLock<Mutex<HashMap<String, Arc<ConnectionGate>>>> = OnceLock::new();
    let gates = GATES.get_or_init(|| Mutex::new(HashMap::new()));
    let key = host.trim().to_ascii_lowercase();
    let mut gates = gates.lock().unwrap();
    Some(
        gates
            .entry(key)
            .or_insert_with(|| {
                Arc::new(ConnectionGate {
                    limit,
                    in_use: Mutex::new(0),
                    released: Condvar::new(),
                })
            })
            .clone(),
    )
}
