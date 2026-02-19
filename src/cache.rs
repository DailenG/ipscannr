use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::app::HostInfo;
use crate::scanner::MacInfo;

const CACHE_FILE: &str = "ipscannr_cache.json";

#[derive(Serialize, Deserialize)]
struct CachedHost {
    ip: String,
    is_alive: bool,
    rtt_ms: Option<u64>,
    hostname: Option<String>,
    mac_address: Option<String>,
    mac_vendor: Option<String>,
    open_ports: Vec<u16>,
}

#[derive(Serialize, Deserialize)]
struct CacheEntry {
    scanned_at: u64,
    hosts: Vec<CachedHost>,
}

type CacheFile = HashMap<String, CacheEntry>;

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Load cached hosts for a given IP range. Returns empty Vec if no cache exists.
pub fn load_cache(range: &str) -> Vec<HostInfo> {
    let Ok(content) = std::fs::read_to_string(CACHE_FILE) else {
        return Vec::new();
    };
    let Ok(cache_file): Result<CacheFile, _> = serde_json::from_str(&content) else {
        return Vec::new();
    };
    let Some(entry) = cache_file.get(range) else {
        return Vec::new();
    };

    let scanned_at = entry.scanned_at;
    entry
        .hosts
        .iter()
        .filter_map(|h| {
            let ip: Ipv4Addr = h.ip.parse().ok()?;
            let mac = h.mac_address.as_ref().map(|addr| MacInfo {
                address: addr.clone(),
                vendor: h.mac_vendor.clone(),
            });
            Some(HostInfo {
                ip,
                is_alive: h.is_alive,
                rtt: h.rtt_ms.map(Duration::from_millis),
                hostname: h.hostname.clone(),
                mac,
                open_ports: h.open_ports.clone(),
                cached_at: Some(scanned_at),
            })
        })
        .collect()
}

/// Persist current scan results for the given IP range.
pub fn save_cache(range: &str, hosts: &[HostInfo]) {
    if hosts.is_empty() {
        return;
    }

    let cached_hosts: Vec<CachedHost> = hosts
        .iter()
        .map(|h| CachedHost {
            ip: h.ip.to_string(),
            is_alive: h.is_alive,
            rtt_ms: h.rtt.map(|d| d.as_millis() as u64),
            hostname: h.hostname.clone(),
            mac_address: h.mac.as_ref().map(|m| m.address.clone()),
            mac_vendor: h.mac.as_ref().and_then(|m| m.vendor.clone()),
            open_ports: h.open_ports.clone(),
        })
        .collect();

    let entry = CacheEntry {
        scanned_at: now_secs(),
        hosts: cached_hosts,
    };

    // Load existing file and merge, preserving entries for other ranges
    let mut cache_file: CacheFile = std::fs::read_to_string(CACHE_FILE)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default();

    cache_file.insert(range.to_string(), entry);

    if let Ok(json) = serde_json::to_string_pretty(&cache_file) {
        let _ = std::fs::write(CACHE_FILE, json);
    }
}

/// Format a Unix timestamp as a human-readable age relative to now.
pub fn format_cache_age(scanned_at: u64) -> String {
    let now = now_secs();
    let age = now.saturating_sub(scanned_at);
    if age < 60 {
        "just now".to_string()
    } else if age < 3600 {
        format!("{}m ago", age / 60)
    } else if age < 86400 {
        format!("{}h ago", age / 3600)
    } else {
        format!("{}d ago", age / 86400)
    }
}
