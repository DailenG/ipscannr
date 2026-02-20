use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::app::HostInfo;
use crate::scanner::{HostStatus, MacInfo, PingMethod};

const CACHE_FILE: &str = "ipscannr_cache.json";
const CACHE_FILE_ENV: &str = "IPSCANNR_CACHE_FILE";

#[derive(Serialize, Deserialize)]
struct CachedHost {
    ip: String,
    is_alive: bool,
    rtt_ms: Option<u64>,
    hostname: Option<String>,
    mac_address: Option<String>,
    mac_vendor: Option<String>,
    open_ports: Vec<u16>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn cache_file_path() -> std::path::PathBuf {
    std::env::var_os(CACHE_FILE_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(CACHE_FILE))
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
    let cache_path = cache_file_path();
    let Ok(content) = std::fs::read_to_string(cache_path) else {
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
            // Default to TCP/Online for legacy cached entries without method/status
            let method = h
                .method
                .as_deref()
                .and_then(|m| match m {
                    "ICMP" => Some(PingMethod::Icmp),
                    "TCP" => Some(PingMethod::Tcp),
                    _ => None,
                })
                .unwrap_or(PingMethod::Tcp);
            
            let status = h
                .status
                .as_deref()
                .and_then(|s| match s {
                    "Online" => Some(HostStatus::Online),
                    "OnlineNoIcmp" => Some(HostStatus::OnlineNoIcmp),
                    "Offline" => Some(HostStatus::Offline),
                    _ => None,
                })
                .unwrap_or(if h.is_alive {
                    HostStatus::Online
                } else {
                    HostStatus::Offline
                });

            Some(HostInfo {
                ip,
                is_alive: h.is_alive,
                rtt: h.rtt_ms.map(Duration::from_millis),
                hostname: h.hostname.clone(),
                mac,
                open_ports: h.open_ports.clone(),
                ports_scanned: !h.open_ports.is_empty(),
                cached_at: Some(scanned_at),
                method,
                status,
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
            method: Some(h.method.to_string()),
            status: Some(match h.status {
                HostStatus::Online => "Online".to_string(),
                HostStatus::OnlineNoIcmp => "OnlineNoIcmp".to_string(),
                HostStatus::Offline => "Offline".to_string(),
            }),
        })
        .collect();

    let entry = CacheEntry {
        scanned_at: now_secs(),
        hosts: cached_hosts,
    };

    // Load existing file and merge, preserving entries for other ranges
    let cache_path = cache_file_path();
    let mut cache_file: CacheFile = std::fs::read_to_string(&cache_path)
        .ok()
        .and_then(|content| serde_json::from_str(&content).ok())
        .unwrap_or_default();

    cache_file.insert(range.to_string(), entry);

    if let Ok(json) = serde_json::to_string_pretty(&cache_file) {
        let tmp_path = cache_path.with_extension("json.tmp");
        if std::fs::write(&tmp_path, json).is_ok() {
            let _ = std::fs::remove_file(&cache_path);
            if std::fs::rename(&tmp_path, &cache_path).is_err() {
                let _ = std::fs::copy(&tmp_path, &cache_path);
                let _ = std::fs::remove_file(&tmp_path);
            }
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};

    fn env_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn sample_host(ip: Ipv4Addr, is_alive: bool) -> HostInfo {
        HostInfo {
            ip,
            is_alive,
            rtt: Some(Duration::from_millis(10)),
            hostname: Some("host.local".to_string()),
            mac: Some(MacInfo {
                address: "AA:BB:CC:DD:EE:FF".to_string(),
                vendor: Some("Vendor".to_string()),
            }),
            open_ports: vec![80, 443],
            ports_scanned: true,
            cached_at: None,
            method: PingMethod::Icmp,
            status: if is_alive {
                HostStatus::Online
            } else {
                HostStatus::Offline
            },
        }
    }

    #[test]
    fn load_cache_returns_empty_for_malformed_json() {
        let _guard = env_lock().lock().expect("test env lock");
        let temp_path = std::env::temp_dir().join("ipscannr_cache_malformed_test.json");
        let _ = std::fs::remove_file(&temp_path);
        std::fs::write(&temp_path, "{ not-json").expect("write malformed cache");
        unsafe {
            std::env::set_var(CACHE_FILE_ENV, &temp_path);
        }

        let loaded = load_cache("192.168.1.0/24");
        assert!(loaded.is_empty());

        unsafe {
            std::env::remove_var(CACHE_FILE_ENV);
        }
        let _ = std::fs::remove_file(temp_path);
    }

    #[test]
    fn save_cache_preserves_other_ranges() {
        let _guard = env_lock().lock().expect("test env lock");
        let temp_path = std::env::temp_dir().join("ipscannr_cache_merge_test.json");
        let _ = std::fs::remove_file(&temp_path);
        unsafe {
            std::env::set_var(CACHE_FILE_ENV, &temp_path);
        }

        let range_a = "10.0.0.0/24";
        let range_b = "192.168.1.0/24";
        save_cache(range_a, &[sample_host(Ipv4Addr::new(10, 0, 0, 10), true)]);
        save_cache(
            range_b,
            &[sample_host(Ipv4Addr::new(192, 168, 1, 20), false)],
        );

        let loaded_a = load_cache(range_a);
        let loaded_b = load_cache(range_b);
        assert_eq!(loaded_a.len(), 1);
        assert_eq!(loaded_b.len(), 1);
        assert_eq!(loaded_a[0].ip, Ipv4Addr::new(10, 0, 0, 10));
        assert_eq!(loaded_b[0].ip, Ipv4Addr::new(192, 168, 1, 20));

        unsafe {
            std::env::remove_var(CACHE_FILE_ENV);
        }
        let _ = std::fs::remove_file(temp_path);
    }
}
