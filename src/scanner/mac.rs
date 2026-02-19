use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;

/// MAC address information
#[derive(Debug, Clone)]
pub struct MacInfo {
    pub address: String,
    pub vendor: Option<String>,
}

/// Get MAC address for an IP on the local network using ARP
pub fn get_mac_address(ip: Ipv4Addr) -> Option<MacInfo> {
    // On Windows, use arp -a command
    #[cfg(target_os = "windows")]
    {
        get_mac_from_arp_windows(ip)
    }

    #[cfg(not(target_os = "windows"))]
    {
        get_mac_from_arp_unix(ip)
    }
}

#[cfg(target_os = "windows")]
fn get_mac_from_arp_windows(ip: Ipv4Addr) -> Option<MacInfo> {
    let output = Command::new("arp")
        .args(["-a", &ip.to_string()])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse ARP output to find MAC address
    for line in stdout.lines() {
        if line.contains(&ip.to_string()) {
            // Windows ARP format: "192.168.1.1    aa-bb-cc-dd-ee-ff   dynamic"
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 2 {
                let mac = parts[1].to_uppercase().replace('-', ":");
                // Validate MAC format
                if mac.len() == 17 && mac.chars().filter(|c| *c == ':').count() == 5 {
                    let vendor = lookup_vendor(&mac);
                    return Some(MacInfo {
                        address: mac,
                        vendor,
                    });
                }
            }
        }
    }

    None
}

#[cfg(not(target_os = "windows"))]
fn get_mac_from_arp_unix(ip: Ipv4Addr) -> Option<MacInfo> {
    let output = Command::new("arp")
        .args(["-n", &ip.to_string()])
        .output()
        .ok()?;

    let stdout = String::from_utf8_lossy(&output.stdout);

    for line in stdout.lines() {
        if line.contains(&ip.to_string()) {
            // Unix ARP format varies, but MAC is usually in format aa:bb:cc:dd:ee:ff
            for part in line.split_whitespace() {
                if part.len() == 17 && part.chars().filter(|c| *c == ':').count() == 5 {
                    let mac = part.to_uppercase();
                    let vendor = lookup_vendor(&mac);
                    return Some(MacInfo {
                        address: mac,
                        vendor,
                    });
                }
            }
        }
    }

    None
}

/// Lookup vendor from MAC address OUI (first 3 bytes)
/// This is a small embedded database of common vendors
fn lookup_vendor(mac: &str) -> Option<String> {
    let oui = mac.get(0..8)?.to_uppercase();

    OUI_DATABASE.get(oui.as_str()).map(|s| s.to_string())
}

lazy_static::lazy_static! {
    static ref OUI_DATABASE: HashMap<&'static str, &'static str> = {
        let mut m = HashMap::new();
        // Common vendor OUIs
        m.insert("00:00:5E", "IANA");
        m.insert("00:1A:2B", "Ayecom");
        m.insert("00:50:56", "VMware");
        m.insert("00:0C:29", "VMware");
        m.insert("00:15:5D", "Microsoft Hyper-V");
        m.insert("00:1C:42", "Parallels");
        m.insert("08:00:27", "VirtualBox");
        m.insert("52:54:00", "QEMU/KVM");
        m.insert("00:16:3E", "Xen");
        m.insert("00:03:FF", "Microsoft");
        m.insert("00:1D:D8", "Microsoft");
        m.insert("28:18:78", "Microsoft");
        m.insert("00:17:88", "Philips");
        m.insert("00:1E:C2", "Apple");
        m.insert("00:26:BB", "Apple");
        m.insert("3C:D0:F8", "Apple");
        m.insert("70:56:81", "Apple");
        m.insert("AC:87:A3", "Apple");
        m.insert("B8:C1:11", "Apple");
        m.insert("D4:61:9D", "Apple");
        m.insert("00:11:32", "Synology");
        m.insert("00:1F:A7", "Sony");
        m.insert("00:24:BE", "Sony");
        m.insert("00:1B:63", "Apple");
        m.insert("00:1E:52", "Apple");
        m.insert("00:1F:F3", "Apple");
        m.insert("00:21:E9", "Apple");
        m.insert("00:22:41", "Apple");
        m.insert("00:23:12", "Apple");
        m.insert("00:23:32", "Apple");
        m.insert("00:23:6C", "Apple");
        m.insert("00:23:DF", "Apple");
        m.insert("00:24:36", "Apple");
        m.insert("00:25:00", "Apple");
        m.insert("00:25:4B", "Apple");
        m.insert("00:25:BC", "Apple");
        m.insert("00:26:08", "Apple");
        m.insert("00:26:4A", "Apple");
        m.insert("00:1A:A0", "Dell");
        m.insert("00:14:22", "Dell");
        m.insert("00:21:9B", "Dell");
        m.insert("18:03:73", "Dell");
        m.insert("00:0D:56", "Dell");
        m.insert("D4:BE:D9", "Dell");
        m.insert("00:30:48", "Supermicro");
        m.insert("00:25:90", "Supermicro");
        m.insert("00:E0:4C", "Realtek");
        m.insert("52:54:00", "Realtek");
        m.insert("00:1B:21", "Intel");
        m.insert("00:1E:67", "Intel");
        m.insert("00:1F:3B", "Intel");
        m.insert("00:22:19", "Intel");
        m.insert("00:22:FA", "Intel");
        m.insert("00:24:D7", "Intel");
        m.insert("3C:97:0E", "Intel");
        m.insert("68:05:CA", "Intel");
        m.insert("84:3A:4B", "Intel");
        m.insert("A4:4C:C8", "Intel");
        m.insert("B4:96:91", "Intel");
        m.insert("C8:0A:A9", "Intel");
        m.insert("00:18:8B", "Dell");
        m.insert("00:1A:4B", "Hewlett Packard");
        m.insert("00:1E:0B", "Hewlett Packard");
        m.insert("00:21:5A", "Hewlett Packard");
        m.insert("00:22:64", "Hewlett Packard");
        m.insert("00:25:B3", "Hewlett Packard");
        m.insert("2C:27:D7", "Hewlett Packard");
        m.insert("2C:44:FD", "Hewlett Packard");
        m.insert("30:8D:99", "Hewlett Packard");
        m.insert("00:0B:CD", "Cisco");
        m.insert("00:0D:BC", "Cisco");
        m.insert("00:0E:38", "Cisco");
        m.insert("00:0E:D6", "Cisco");
        m.insert("00:0F:F7", "Cisco");
        m.insert("00:11:20", "Cisco");
        m.insert("00:11:BB", "Cisco");
        m.insert("00:12:D9", "Cisco");
        m.insert("00:1B:D4", "Cisco");
        m.insert("00:24:97", "Cisco");
        m.insert("00:1C:B3", "Apple");
        m.insert("00:1D:4F", "Apple");
        m.insert("00:1E:C2", "Apple");
        m.insert("00:22:41", "Apple");
        m.insert("30:10:B3", "Liteon");
        m.insert("74:E5:43", "Liteon");
        m.insert("00:24:D6", "Liteon");
        m.insert("00:06:5B", "Dell");
        m.insert("00:08:74", "Dell");
        m.insert("B8:27:EB", "Raspberry Pi");
        m.insert("DC:A6:32", "Raspberry Pi");
        m.insert("E4:5F:01", "Raspberry Pi");
        m.insert("00:0E:C6", "ASUS");
        m.insert("00:11:D8", "ASUS");
        m.insert("00:13:D4", "ASUS");
        m.insert("00:15:F2", "ASUS");
        m.insert("00:17:31", "ASUS");
        m.insert("00:1A:92", "ASUS");
        m.insert("00:1D:60", "ASUS");
        m.insert("00:1E:8C", "ASUS");
        m.insert("00:22:15", "ASUS");
        m.insert("00:23:54", "ASUS");
        m.insert("00:24:8C", "ASUS");
        m.insert("00:26:18", "ASUS");
        m.insert("00:1E:58", "D-Link");
        m.insert("00:1F:3C", "D-Link");
        m.insert("00:21:91", "D-Link");
        m.insert("00:22:B0", "D-Link");
        m.insert("00:24:01", "D-Link");
        m.insert("14:D6:4D", "D-Link");
        m.insert("1C:7E:E5", "D-Link");
        m.insert("28:10:7B", "D-Link");
        m.insert("00:1D:7E", "Linksys");
        m.insert("00:1E:E5", "Linksys");
        m.insert("00:21:29", "Linksys");
        m.insert("00:22:6B", "Linksys");
        m.insert("00:23:69", "Linksys");
        m.insert("00:25:9C", "Linksys");
        m.insert("20:AA:4B", "Linksys");
        m.insert("00:14:BF", "Linksys");
        m.insert("00:18:39", "Linksys");
        m.insert("00:1A:70", "Linksys");
        m.insert("68:7F:74", "Linksys");
        m.insert("C0:C1:C0", "Linksys");
        m.insert("00:18:E7", "Linksys");
        m.insert("00:1C:10", "Linksys");
        m.insert("00:22:75", "NETGEAR");
        m.insert("00:24:B2", "NETGEAR");
        m.insert("00:26:F2", "NETGEAR");
        m.insert("20:4E:7F", "NETGEAR");
        m.insert("28:C6:8E", "NETGEAR");
        m.insert("30:46:9A", "NETGEAR");
        m.insert("00:14:6C", "NETGEAR");
        m.insert("00:18:4D", "NETGEAR");
        m.insert("00:1B:2F", "NETGEAR");
        m.insert("00:1E:2A", "NETGEAR");
        m.insert("00:1F:33", "NETGEAR");
        m
    };
}
