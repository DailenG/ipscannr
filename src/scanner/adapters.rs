use std::net::Ipv4Addr;
use std::process::Command;
use std::str::FromStr;

/// Type of network adapter
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AdapterType {
    Ethernet,  // Highest priority
    Wifi,
    Vpn,
    Other,
}

impl AdapterType {
    /// Determine adapter type from interface name/description
    fn from_name(name: &str) -> Self {
        let name_lower = name.to_lowercase();

        // Check for VPN adapters first
        if name_lower.contains("vpn")
            || name_lower.contains("virtual")
            || name_lower.contains("tap")
            || name_lower.contains("tun")
            || name_lower.contains("wireguard")
            || name_lower.contains("openvpn")
            || name_lower.contains("nordlynx")
            || name_lower.contains("zerotier")
        {
            return AdapterType::Vpn;
        }

        // Check for WiFi
        if name_lower.contains("wifi")
            || name_lower.contains("wi-fi")
            || name_lower.contains("wireless")
            || name_lower.contains("wlan")
            || name_lower.contains("802.11")
        {
            return AdapterType::Wifi;
        }

        // Check for Ethernet
        if name_lower.contains("ethernet")
            || name_lower.contains("local area connection")
            || name_lower.contains("realtek")
            || name_lower.contains("intel")
            || name_lower.contains("broadcom")
            || name_lower.contains("gigabit")
        {
            return AdapterType::Ethernet;
        }

        AdapterType::Other
    }
}

impl std::fmt::Display for AdapterType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdapterType::Ethernet => write!(f, "Ethernet"),
            AdapterType::Wifi => write!(f, "WiFi"),
            AdapterType::Vpn => write!(f, "VPN"),
            AdapterType::Other => write!(f, "Other"),
        }
    }
}

/// Information about a network adapter
#[derive(Debug, Clone)]
pub struct AdapterInfo {
    pub name: String,
    pub adapter_type: AdapterType,
    pub ip: Ipv4Addr,
    pub prefix_length: u8,
    pub subnet: String, // CIDR notation
}

impl AdapterInfo {
    /// Calculate subnet in CIDR notation from IP and prefix length
    fn calculate_subnet(ip: Ipv4Addr, prefix_len: u8) -> String {
        let ip_u32 = u32::from(ip);
        let mask = if prefix_len == 0 {
            0
        } else {
            !0u32 << (32 - prefix_len)
        };
        let network = Ipv4Addr::from(ip_u32 & mask);
        format!("{}/{}", network, prefix_len)
    }
}

/// Get all active network adapters with IPv4 addresses using PowerShell
pub fn get_active_adapters() -> Vec<AdapterInfo> {
    // Try pwsh first, fall back to powershell
    let output = Command::new("pwsh")
        .args([
            "-NoProfile",
            "-Command",
            r#"Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | ForEach-Object { $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; if ($adapter -and $adapter.Status -eq 'Up') { "$($adapter.Name)|$($_.IPAddress)|$($_.PrefixLength)" } }"#,
        ])
        .output()
        .or_else(|_| {
            // Fall back to Windows PowerShell
            Command::new("powershell")
                .args([
                    "-NoProfile",
                    "-Command",
                    r#"Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.IPAddress -ne '127.0.0.1' -and $_.PrefixOrigin -ne 'WellKnown' } | ForEach-Object { $adapter = Get-NetAdapter -InterfaceIndex $_.InterfaceIndex -ErrorAction SilentlyContinue; if ($adapter -and $adapter.Status -eq 'Up') { "$($adapter.Name)|$($_.IPAddress)|$($_.PrefixLength)" } }"#,
                ])
                .output()
        });

    let output = match output {
        Ok(o) => o,
        Err(_) => return Vec::new(),
    };

    let stdout = String::from_utf8_lossy(&output.stdout);

    let mut adapters: Vec<AdapterInfo> = stdout
        .lines()
        .filter_map(|line| {
            let parts: Vec<&str> = line.split('|').collect();
            if parts.len() >= 3 {
                let name = parts[0].trim().to_string();
                let ip = Ipv4Addr::from_str(parts[1].trim()).ok()?;
                let prefix_len: u8 = parts[2].trim().parse().ok()?;

                // Skip link-local addresses (169.254.x.x)
                if ip.octets()[0] == 169 && ip.octets()[1] == 254 {
                    return None;
                }

                Some(AdapterInfo {
                    adapter_type: AdapterType::from_name(&name),
                    name,
                    ip,
                    prefix_length: prefix_len,
                    subnet: AdapterInfo::calculate_subnet(ip, prefix_len),
                })
            } else {
                None
            }
        })
        .collect();

    // Sort by adapter type (Ethernet first, then WiFi, then VPN, then Other)
    adapters.sort_by(|a, b| a.adapter_type.cmp(&b.adapter_type));

    adapters
}

/// Get the default adapter (prefer Ethernet over WiFi)
pub fn get_default_adapter() -> Option<AdapterInfo> {
    get_active_adapters().into_iter().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_subnet_calculation() {
        let ip = Ipv4Addr::new(192, 168, 1, 100);
        assert_eq!(AdapterInfo::calculate_subnet(ip, 24), "192.168.1.0/24");

        let ip = Ipv4Addr::new(10, 0, 0, 50);
        assert_eq!(AdapterInfo::calculate_subnet(ip, 16), "10.0.0.0/16");
    }

    #[test]
    fn test_adapter_type_detection() {
        assert_eq!(AdapterType::from_name("Ethernet"), AdapterType::Ethernet);
        assert_eq!(AdapterType::from_name("Wi-Fi"), AdapterType::Wifi);
        assert_eq!(AdapterType::from_name("OpenVPN TAP"), AdapterType::Vpn);
        assert_eq!(AdapterType::from_name("WireGuard Tunnel"), AdapterType::Vpn);
    }
}
