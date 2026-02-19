use std::time::Duration;

use crate::scanner::{PingerConfig, PortScannerConfig};

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub default_range: String,
    pub ping: PingerConfig,
    pub port_scan: PortScannerConfig,
    pub scan_ports_by_default: bool,
    pub resolve_hostnames: bool,
    pub detect_mac: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default_range: "192.168.1.0/24".to_string(),
            ping: PingerConfig {
                timeout: Duration::from_millis(1000),
                retries: 1,
                concurrent_limit: 100,
            },
            port_scan: PortScannerConfig {
                timeout: Duration::from_millis(500),
                concurrent_limit: 50,
            },
            scan_ports_by_default: false,
            resolve_hostnames: true,
            detect_mac: true,
        }
    }
}
