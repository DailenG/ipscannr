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

        // ── Virtualization / Hypervisors ────────────────────────────────────
        m.insert("00:00:5E", "IANA");
        m.insert("00:50:56", "VMware");
        m.insert("00:0C:29", "VMware");
        m.insert("00:05:69", "VMware");
        m.insert("00:15:5D", "Hyper-V");
        m.insert("00:1C:42", "Parallels");
        m.insert("08:00:27", "VirtualBox");
        m.insert("52:54:00", "QEMU/KVM");
        m.insert("00:16:3E", "Xen");
        m.insert("00:03:FF", "Microsoft");
        m.insert("00:1D:D8", "Microsoft");
        m.insert("28:18:78", "Microsoft");

        // ── Apple ────────────────────────────────────────────────────────────
        m.insert("00:03:93", "Apple");
        m.insert("00:05:02", "Apple");
        m.insert("00:0A:27", "Apple");
        m.insert("00:0A:95", "Apple");
        m.insert("00:11:24", "Apple");
        m.insert("00:14:51", "Apple");
        m.insert("00:16:CB", "Apple");
        m.insert("00:17:F2", "Apple");
        m.insert("00:19:E3", "Apple");
        m.insert("00:1B:63", "Apple");
        m.insert("00:1C:B3", "Apple");
        m.insert("00:1D:4F", "Apple");
        m.insert("00:1E:52", "Apple");
        m.insert("00:1E:C2", "Apple");
        m.insert("00:1F:5B", "Apple");
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
        m.insert("00:26:BB", "Apple");
        m.insert("04:0C:CE", "Apple");
        m.insert("04:15:52", "Apple");
        m.insert("04:26:65", "Apple");
        m.insert("04:48:9A", "Apple");
        m.insert("04:54:53", "Apple");
        m.insert("04:F7:E4", "Apple");
        m.insert("08:70:45", "Apple");
        m.insert("0C:3E:9F", "Apple");
        m.insert("0C:74:C2", "Apple");
        m.insert("10:40:F3", "Apple");
        m.insert("10:9A:DD", "Apple");
        m.insert("14:8F:C6", "Apple");
        m.insert("18:AF:61", "Apple");
        m.insert("1C:91:48", "Apple");
        m.insert("20:C9:D0", "Apple");
        m.insert("24:A0:74", "Apple");
        m.insert("28:37:37", "Apple");
        m.insert("2C:F0:EE", "Apple");
        m.insert("34:15:9E", "Apple");
        m.insert("34:A3:95", "Apple");
        m.insert("38:0F:4A", "Apple");
        m.insert("38:C9:86", "Apple");
        m.insert("3C:07:54", "Apple");
        m.insert("3C:15:C2", "Apple");
        m.insert("3C:D0:F8", "Apple");
        m.insert("40:3C:FC", "Apple");
        m.insert("40:A6:D9", "Apple");
        m.insert("44:2A:60", "Apple");
        m.insert("44:D8:84", "Apple");
        m.insert("48:60:BC", "Apple");
        m.insert("4C:57:CA", "Apple");
        m.insert("4C:8D:79", "Apple");
        m.insert("50:EA:D6", "Apple");
        m.insert("54:26:96", "Apple");
        m.insert("54:AE:27", "Apple");
        m.insert("58:1F:AA", "Apple");
        m.insert("5C:96:9D", "Apple");
        m.insert("60:03:08", "Apple");
        m.insert("60:F8:1D", "Apple");
        m.insert("64:5A:ED", "Apple");
        m.insert("68:5B:35", "Apple");
        m.insert("6C:40:08", "Apple");
        m.insert("70:56:81", "Apple");
        m.insert("70:EC:E4", "Apple");
        m.insert("74:E1:B6", "Apple");
        m.insert("78:31:C1", "Apple");
        m.insert("78:CA:39", "Apple");
        m.insert("7C:6D:62", "Apple");
        m.insert("7C:D1:C3", "Apple");
        m.insert("80:00:6E", "Apple");
        m.insert("80:BE:05", "Apple");
        m.insert("84:38:35", "Apple");
        m.insert("84:78:8B", "Apple");
        m.insert("88:63:DF", "Apple");
        m.insert("8C:2D:AA", "Apple");
        m.insert("90:27:E4", "Apple");
        m.insert("90:72:40", "Apple");
        m.insert("98:01:A7", "Apple");
        m.insert("98:FE:94", "Apple");
        m.insert("9C:20:7B", "Apple");
        m.insert("A4:5E:60", "Apple");
        m.insert("A4:B1:97", "Apple");
        m.insert("A4:C3:61", "Apple");
        m.insert("A8:5C:2C", "Apple");
        m.insert("A8:86:DD", "Apple");
        m.insert("AC:87:A3", "Apple");
        m.insert("AC:BC:32", "Apple");
        m.insert("B0:34:95", "Apple");
        m.insert("B4:18:D1", "Apple");
        m.insert("B8:09:8A", "Apple");
        m.insert("B8:C1:11", "Apple");
        m.insert("BC:3B:AF", "Apple");
        m.insert("BC:52:B7", "Apple");
        m.insert("C0:CE:CD", "Apple");
        m.insert("C4:2C:03", "Apple");
        m.insert("C8:33:4B", "Apple");
        m.insert("C8:BC:C8", "Apple");
        m.insert("CC:29:F5", "Apple");
        m.insert("D0:03:4B", "Apple");
        m.insert("D0:23:DB", "Apple");
        m.insert("D4:61:9D", "Apple");
        m.insert("D4:9A:20", "Apple");
        m.insert("D8:00:4D", "Apple");
        m.insert("DC:2B:2A", "Apple");
        m.insert("E0:AC:CB", "Apple");
        m.insert("E4:CE:8F", "Apple");
        m.insert("E8:04:62", "Apple");
        m.insert("F0:18:98", "Apple");
        m.insert("F0:B4:79", "Apple");
        m.insert("F4:1B:A1", "Apple");
        m.insert("F8:1E:DF", "Apple");
        m.insert("FC:E9:98", "Apple");

        // ── Samsung ──────────────────────────────────────────────────────────
        m.insert("00:12:47", "Samsung");
        m.insert("00:15:99", "Samsung");
        m.insert("00:16:32", "Samsung");
        m.insert("00:17:C9", "Samsung");
        m.insert("00:1A:8A", "Samsung");
        m.insert("00:1D:25", "Samsung");
        m.insert("00:1E:7D", "Samsung");
        m.insert("00:21:19", "Samsung");
        m.insert("00:23:39", "Samsung");
        m.insert("00:24:54", "Samsung");
        m.insert("00:26:37", "Samsung");
        m.insert("08:08:C2", "Samsung");
        m.insert("08:D4:2B", "Samsung");
        m.insert("0C:14:20", "Samsung");
        m.insert("10:1D:C0", "Samsung");
        m.insert("14:49:E0", "Samsung");
        m.insert("18:1E:B0", "Samsung");
        m.insert("1C:5A:6B", "Samsung");
        m.insert("20:64:32", "Samsung");
        m.insert("24:4B:81", "Samsung");
        m.insert("28:27:BF", "Samsung");
        m.insert("2C:AE:2B", "Samsung");
        m.insert("34:31:11", "Samsung");
        m.insert("38:01:97", "Samsung");
        m.insert("3C:8B:FE", "Samsung");
        m.insert("40:0E:85", "Samsung");
        m.insert("44:78:3E", "Samsung");
        m.insert("48:5A:3F", "Samsung");
        m.insert("4C:3C:16", "Samsung");
        m.insert("50:A4:C8", "Samsung");
        m.insert("54:92:BE", "Samsung");
        m.insert("58:DB:C3", "Samsung");
        m.insert("5C:3C:27", "Samsung");
        m.insert("60:6B:BD", "Samsung");
        m.insert("64:77:91", "Samsung");
        m.insert("68:48:98", "Samsung");
        m.insert("6C:83:36", "Samsung");
        m.insert("70:F9:27", "Samsung");
        m.insert("78:1F:DB", "Samsung");
        m.insert("78:40:E4", "Samsung");
        m.insert("80:57:19", "Samsung");
        m.insert("84:25:DB", "Samsung");
        m.insert("88:32:9B", "Samsung");
        m.insert("8C:71:F8", "Samsung");
        m.insert("90:18:7C", "Samsung");
        m.insert("94:35:0A", "Samsung");
        m.insert("98:52:B1", "Samsung");
        m.insert("9C:02:98", "Samsung");
        m.insert("A0:0B:BA", "Samsung");
        m.insert("A4:07:B6", "Samsung");
        m.insert("AC:5F:3E", "Samsung");
        m.insert("B0:D0:9C", "Samsung");
        m.insert("B4:3A:28", "Samsung");
        m.insert("B4:EF:FA", "Samsung");
        m.insert("BC:14:85", "Samsung");
        m.insert("C0:BD:D1", "Samsung");
        m.insert("C4:42:02", "Samsung");
        m.insert("C8:A8:23", "Samsung");
        m.insert("CC:07:AB", "Samsung");
        m.insert("D0:22:BE", "Samsung");
        m.insert("D0:59:E4", "Samsung");
        m.insert("D4:E8:B2", "Samsung");
        m.insert("D8:31:CF", "Samsung");
        m.insert("DC:71:96", "Samsung");
        m.insert("E0:CB:4E", "Samsung");
        m.insert("E4:12:1D", "Samsung");
        m.insert("E8:03:9A", "Samsung");
        m.insert("EC:1F:72", "Samsung");
        m.insert("F0:72:8C", "Samsung");
        m.insert("F0:E7:7E", "Samsung");
        m.insert("FC:A1:3E", "Samsung");

        // ── Google ───────────────────────────────────────────────────────────
        m.insert("00:1A:11", "Google");
        m.insert("08:9E:08", "Google");
        m.insert("1C:F2:9A", "Google");
        m.insert("20:DF:B9", "Google");
        m.insert("48:D6:D5", "Google");
        m.insert("54:60:09", "Google");
        m.insert("6C:AD:F8", "Google");
        m.insert("A4:77:33", "Google");
        m.insert("D8:6C:63", "Google");
        m.insert("F4:F5:D8", "Google");
        m.insert("F8:8F:CA", "Google");

        // ── Huawei ───────────────────────────────────────────────────────────
        m.insert("00:18:82", "Huawei");
        m.insert("00:1E:10", "Huawei");
        m.insert("00:25:9E", "Huawei");
        m.insert("04:02:1F", "Huawei");
        m.insert("04:B0:E7", "Huawei");
        m.insert("04:C0:6F", "Huawei");
        m.insert("08:19:A6", "Huawei");
        m.insert("0C:37:DC", "Huawei");
        m.insert("10:47:80", "Huawei");
        m.insert("14:B9:68", "Huawei");
        m.insert("18:C5:8A", "Huawei");
        m.insert("1C:8E:5C", "Huawei");
        m.insert("20:08:ED", "Huawei");
        m.insert("20:F1:7C", "Huawei");
        m.insert("24:69:A5", "Huawei");
        m.insert("28:6E:D4", "Huawei");
        m.insert("2C:AB:00", "Huawei");
        m.insert("30:D1:7E", "Huawei");
        m.insert("34:6B:D3", "Huawei");
        m.insert("38:BC:01", "Huawei");
        m.insert("3C:F8:11", "Huawei");
        m.insert("40:4D:8E", "Huawei");
        m.insert("44:6A:B7", "Huawei");
        m.insert("48:0F:CF", "Huawei");
        m.insert("4C:1F:CC", "Huawei");
        m.insert("50:68:0A", "Huawei");
        m.insert("54:25:EA", "Huawei");
        m.insert("58:2A:F7", "Huawei");
        m.insert("5C:7D:5E", "Huawei");
        m.insert("68:13:24", "Huawei");
        m.insert("6C:8D:C1", "Huawei");
        m.insert("70:72:3C", "Huawei");
        m.insert("74:A5:28", "Huawei");
        m.insert("78:1D:BA", "Huawei");
        m.insert("80:B6:86", "Huawei");
        m.insert("84:A8:E4", "Huawei");
        m.insert("88:E3:AB", "Huawei");
        m.insert("8C:0D:76", "Huawei");
        m.insert("90:67:1C", "Huawei");
        m.insert("94:04:9C", "Huawei");
        m.insert("9C:28:EF", "Huawei");
        m.insert("A0:08:6F", "Huawei");
        m.insert("A4:A1:C2", "Huawei");
        m.insert("AC:4E:91", "Huawei");
        m.insert("B0:E5:ED", "Huawei");
        m.insert("B4:15:13", "Huawei");
        m.insert("BC:76:70", "Huawei");
        m.insert("C4:06:83", "Huawei");
        m.insert("C8:51:95", "Huawei");
        m.insert("CC:A2:23", "Huawei");
        m.insert("D0:3E:5C", "Huawei");
        m.insert("D4:6A:A8", "Huawei");
        m.insert("DC:D2:FC", "Huawei");
        m.insert("E0:19:1D", "Huawei");
        m.insert("E4:68:A3", "Huawei");
        m.insert("E8:CD:2D", "Huawei");
        m.insert("EC:CB:30", "Huawei");
        m.insert("F0:3E:90", "Huawei");
        m.insert("F4:9F:F3", "Huawei");
        m.insert("F8:01:13", "Huawei");
        m.insert("FC:48:EF", "Huawei");

        // ── Xiaomi ───────────────────────────────────────────────────────────
        m.insert("00:9E:C8", "Xiaomi");
        m.insert("04:CF:8C", "Xiaomi");
        m.insert("08:21:EF", "Xiaomi");
        m.insert("0C:1D:AF", "Xiaomi");
        m.insert("10:2A:B3", "Xiaomi");
        m.insert("14:F6:5A", "Xiaomi");
        m.insert("18:59:36", "Xiaomi");
        m.insert("20:82:C0", "Xiaomi");
        m.insert("28:6C:07", "Xiaomi");
        m.insert("34:80:B3", "Xiaomi");
        m.insert("38:A4:ED", "Xiaomi");
        m.insert("3C:BD:D8", "Xiaomi");
        m.insert("4C:49:E3", "Xiaomi");
        m.insert("50:64:2B", "Xiaomi");
        m.insert("58:44:98", "Xiaomi");
        m.insert("64:09:80", "Xiaomi");
        m.insert("64:CC:2E", "Xiaomi");
        m.insert("68:DF:DD", "Xiaomi");
        m.insert("74:23:44", "Xiaomi");
        m.insert("78:11:DC", "Xiaomi");
        m.insert("8C:BE:BE", "Xiaomi");
        m.insert("AC:C1:EE", "Xiaomi");
        m.insert("B0:E2:35", "Xiaomi");
        m.insert("C4:0B:CB", "Xiaomi");
        m.insert("D4:97:0B", "Xiaomi");
        m.insert("F4:8B:32", "Xiaomi");
        m.insert("FC:64:BA", "Xiaomi");

        // ── TP-Link ───────────────────────────────────────────────────────────
        m.insert("00:1D:0F", "TP-Link");
        m.insert("14:CF:92", "TP-Link");
        m.insert("18:A6:F7", "TP-Link");
        m.insert("1C:FA:68", "TP-Link");
        m.insert("20:DC:E6", "TP-Link");
        m.insert("24:31:54", "TP-Link");
        m.insert("2C:4D:54", "TP-Link");
        m.insert("30:FC:68", "TP-Link");
        m.insert("34:96:72", "TP-Link");
        m.insert("3C:52:A1", "TP-Link");
        m.insert("50:BD:5F", "TP-Link");
        m.insert("50:C7:BF", "TP-Link");
        m.insert("54:E6:FC", "TP-Link");
        m.insert("60:32:B1", "TP-Link");
        m.insert("64:70:02", "TP-Link");
        m.insert("6C:72:20", "TP-Link");
        m.insert("70:4F:57", "TP-Link");
        m.insert("74:DA:38", "TP-Link");
        m.insert("78:8A:20", "TP-Link");
        m.insert("80:35:C1", "TP-Link");
        m.insert("90:F6:52", "TP-Link");
        m.insert("94:0A:1C", "TP-Link");
        m.insert("98:DA:C4", "TP-Link");
        m.insert("A0:F3:C1", "TP-Link");
        m.insert("AC:84:C6", "TP-Link");
        m.insert("B0:4E:26", "TP-Link");
        m.insert("B8:27:EB", "TP-Link");
        m.insert("C4:6E:1F", "TP-Link");
        m.insert("D4:6E:0E", "TP-Link");
        m.insert("D8:0D:17", "TP-Link");
        m.insert("E4:D3:32", "TP-Link");
        m.insert("E8:DE:27", "TP-Link");
        m.insert("EC:17:2F", "TP-Link");
        m.insert("F4:F2:6D", "TP-Link");
        m.insert("FC:EC:DA", "TP-Link");

        // ── Ubiquiti ─────────────────────────────────────────────────────────
        m.insert("00:15:6D", "Ubiquiti");
        m.insert("00:27:22", "Ubiquiti");
        m.insert("04:18:D6", "Ubiquiti");
        m.insert("18:E8:29", "Ubiquiti");
        m.insert("24:A4:3C", "Ubiquiti");
        m.insert("44:D9:E7", "Ubiquiti");
        m.insert("68:72:51", "Ubiquiti");
        m.insert("74:83:C2", "Ubiquiti");
        m.insert("78:8A:20", "Ubiquiti");
        m.insert("80:2A:A8", "Ubiquiti");
        m.insert("9C:05:D6", "Ubiquiti");
        m.insert("B4:FB:E4", "Ubiquiti");
        m.insert("DC:9F:DB", "Ubiquiti");
        m.insert("F0:9F:C2", "Ubiquiti");
        m.insert("F4:92:BF", "Ubiquiti");
        m.insert("FC:EC:DA", "Ubiquiti");

        // ── MikroTik ─────────────────────────────────────────────────────────
        m.insert("00:0C:42", "MikroTik");
        m.insert("18:FD:74", "MikroTik");
        m.insert("2C:C8:1B", "MikroTik");
        m.insert("48:8F:5A", "MikroTik");
        m.insert("4C:5E:0C", "MikroTik");
        m.insert("64:D1:54", "MikroTik");
        m.insert("6C:3B:6B", "MikroTik");
        m.insert("74:4D:28", "MikroTik");
        m.insert("78:9A:18", "MikroTik");
        m.insert("B8:69:F4", "MikroTik");
        m.insert("C4:AD:34", "MikroTik");
        m.insert("CC:2D:E0", "MikroTik");
        m.insert("D4:CA:6D", "MikroTik");
        m.insert("DC:2C:6E", "MikroTik");
        m.insert("E4:8D:8C", "MikroTik");

        // ── Cisco ────────────────────────────────────────────────────────────
        m.insert("00:00:0C", "Cisco");
        m.insert("00:01:42", "Cisco");
        m.insert("00:0B:CD", "Cisco");
        m.insert("00:0D:BC", "Cisco");
        m.insert("00:0E:38", "Cisco");
        m.insert("00:0F:F7", "Cisco");
        m.insert("00:11:20", "Cisco");
        m.insert("00:11:BB", "Cisco");
        m.insert("00:12:D9", "Cisco");
        m.insert("00:1A:2F", "Cisco");
        m.insert("00:1B:D4", "Cisco");
        m.insert("00:1C:57", "Cisco");
        m.insert("00:1D:A1", "Cisco");
        m.insert("00:1E:14", "Cisco");
        m.insert("00:1F:9E", "Cisco");
        m.insert("00:21:A0", "Cisco");
        m.insert("00:22:BD", "Cisco");
        m.insert("00:23:AC", "Cisco");
        m.insert("00:24:97", "Cisco");
        m.insert("00:25:45", "Cisco");
        m.insert("00:26:CB", "Cisco");
        m.insert("00:27:0D", "Cisco");
        m.insert("04:6C:9D", "Cisco");
        m.insert("0C:27:24", "Cisco");
        m.insert("10:05:CA", "Cisco");
        m.insert("1C:DF:0F", "Cisco");
        m.insert("2C:54:2D", "Cisco");
        m.insert("34:DB:FD", "Cisco");
        m.insert("38:ED:18", "Cisco");
        m.insert("40:F4:EC", "Cisco");
        m.insert("44:AD:D9", "Cisco");
        m.insert("48:F8:B3", "Cisco");
        m.insert("4C:4E:35", "Cisco");
        m.insert("50:06:04", "Cisco");
        m.insert("54:78:1A", "Cisco");
        m.insert("58:AC:78", "Cisco");
        m.insert("5C:50:15", "Cisco");
        m.insert("64:D9:89", "Cisco");
        m.insert("68:86:A7", "Cisco");
        m.insert("6C:20:56", "Cisco");
        m.insert("70:69:5A", "Cisco");
        m.insert("74:26:AC", "Cisco");
        m.insert("78:BC:1A", "Cisco");
        m.insert("84:78:AC", "Cisco");
        m.insert("88:5A:92", "Cisco");
        m.insert("8C:60:4F", "Cisco");
        m.insert("A0:EC:F9", "Cisco");
        m.insert("AC:F2:C5", "Cisco");
        m.insert("B0:AA:77", "Cisco");
        m.insert("B4:14:89", "Cisco");
        m.insert("CC:D8:C1", "Cisco");
        m.insert("D0:C7:89", "Cisco");
        m.insert("D4:8C:B5", "Cisco");
        m.insert("E8:BA:70", "Cisco");
        m.insert("EC:E1:A9", "Cisco");
        m.insert("F0:29:29", "Cisco");
        m.insert("F4:CF:E2", "Cisco");
        m.insert("FC:FB:FB", "Cisco");

        // ── Intel (Wi-Fi / NICs) ─────────────────────────────────────────────
        m.insert("00:1B:21", "Intel");
        m.insert("00:1E:67", "Intel");
        m.insert("00:1F:3B", "Intel");
        m.insert("00:22:19", "Intel");
        m.insert("00:22:FA", "Intel");
        m.insert("00:24:D7", "Intel");
        m.insert("00:27:10", "Intel");
        m.insert("08:11:96", "Intel");
        m.insert("10:02:B5", "Intel");
        m.insert("10:7C:61", "Intel");
        m.insert("18:56:80", "Intel");
        m.insert("1C:69:7A", "Intel");
        m.insert("24:77:03", "Intel");
        m.insert("28:D2:44", "Intel");
        m.insert("2C:6E:85", "Intel");
        m.insert("30:3A:64", "Intel");
        m.insert("34:02:86", "Intel");
        m.insert("38:B1:DB", "Intel");
        m.insert("3C:97:0E", "Intel");
        m.insert("40:25:C2", "Intel");
        m.insert("48:51:B7", "Intel");
        m.insert("4C:EB:42", "Intel");
        m.insert("50:76:AF", "Intel");
        m.insert("54:35:30", "Intel");
        m.insert("58:FB:84", "Intel");
        m.insert("5C:C5:D4", "Intel");
        m.insert("60:67:20", "Intel");
        m.insert("68:05:CA", "Intel");
        m.insert("6C:88:14", "Intel");
        m.insert("70:1A:04", "Intel");
        m.insert("74:04:F1", "Intel");
        m.insert("78:92:9C", "Intel");
        m.insert("7C:7A:91", "Intel");
        m.insert("80:19:34", "Intel");
        m.insert("84:3A:4B", "Intel");
        m.insert("88:53:2E", "Intel");
        m.insert("8C:8D:28", "Intel");
        m.insert("90:E2:BA", "Intel");
        m.insert("94:65:9C", "Intel");
        m.insert("98:4F:EE", "Intel");
        m.insert("9C:B6:D0", "Intel");
        m.insert("A0:A8:CD", "Intel");
        m.insert("A4:4C:C8", "Intel");
        m.insert("A8:7E:EA", "Intel");
        m.insert("AC:72:89", "Intel");
        m.insert("B4:96:91", "Intel");
        m.insert("B8:08:CF", "Intel");
        m.insert("BC:77:37", "Intel");
        m.insert("C0:3F:D5", "Intel");
        m.insert("C4:85:08", "Intel");
        m.insert("C8:0A:A9", "Intel");
        m.insert("D0:AB:D5", "Intel");
        m.insert("D4:3D:7E", "Intel");
        m.insert("D8:FC:93", "Intel");
        m.insert("E4:70:B8", "Intel");
        m.insert("E8:6A:64", "Intel");
        m.insert("EC:9B:F3", "Intel");
        m.insert("F0:77:C3", "Intel");
        m.insert("F4:8C:50", "Intel");
        m.insert("F8:34:41", "Intel");

        // ── Dell ─────────────────────────────────────────────────────────────
        m.insert("00:06:5B", "Dell");
        m.insert("00:08:74", "Dell");
        m.insert("00:0D:56", "Dell");
        m.insert("00:0F:1F", "Dell");
        m.insert("00:11:43", "Dell");
        m.insert("00:12:3F", "Dell");
        m.insert("00:13:72", "Dell");
        m.insert("00:14:22", "Dell");
        m.insert("00:15:C5", "Dell");
        m.insert("00:16:F0", "Dell");
        m.insert("00:18:8B", "Dell");
        m.insert("00:19:B9", "Dell");
        m.insert("00:1A:A0", "Dell");
        m.insert("00:1C:23", "Dell");
        m.insert("00:1D:09", "Dell");
        m.insert("00:1E:4F", "Dell");
        m.insert("00:1F:D0", "Dell");
        m.insert("00:21:9B", "Dell");
        m.insert("00:22:19", "Dell");
        m.insert("00:23:AE", "Dell");
        m.insert("00:24:E8", "Dell");
        m.insert("00:25:64", "Dell");
        m.insert("00:26:B9", "Dell");
        m.insert("18:03:73", "Dell");
        m.insert("18:66:DA", "Dell");
        m.insert("24:B6:FD", "Dell");
        m.insert("28:F1:0E", "Dell");
        m.insert("2C:76:8A", "Dell");
        m.insert("34:17:EB", "Dell");
        m.insert("38:EA:A7", "Dell");
        m.insert("3C:2C:30", "Dell");
        m.insert("40:A8:F0", "Dell");
        m.insert("44:A8:42", "Dell");
        m.insert("48:4D:7E", "Dell");
        m.insert("4C:D9:8F", "Dell");
        m.insert("54:9F:35", "Dell");
        m.insert("5C:F9:DD", "Dell");
        m.insert("74:86:7A", "Dell");
        m.insert("78:45:C4", "Dell");
        m.insert("84:8F:69", "Dell");
        m.insert("8C:EC:4B", "Dell");
        m.insert("90:B1:1C", "Dell");
        m.insert("98:90:96", "Dell");
        m.insert("A4:1F:72", "Dell");
        m.insert("B0:83:FE", "Dell");
        m.insert("B8:AC:6F", "Dell");
        m.insert("C8:1F:66", "Dell");
        m.insert("D4:BE:D9", "Dell");
        m.insert("D8:9E:F3", "Dell");
        m.insert("E0:DB:55", "Dell");
        m.insert("E4:54:E8", "Dell");
        m.insert("EC:F4:BB", "Dell");
        m.insert("F0:1F:AF", "Dell");
        m.insert("F8:DB:88", "Dell");
        m.insert("FC:15:B4", "Dell");

        // ── Hewlett Packard / HP ─────────────────────────────────────────────
        m.insert("00:01:E6", "HP");
        m.insert("00:0E:7F", "HP");
        m.insert("00:10:83", "HP");
        m.insert("00:11:0A", "HP");
        m.insert("00:13:21", "HP");
        m.insert("00:14:38", "HP");
        m.insert("00:15:60", "HP");
        m.insert("00:16:35", "HP");
        m.insert("00:17:08", "HP");
        m.insert("00:18:FE", "HP");
        m.insert("00:1A:4B", "HP");
        m.insert("00:1B:78", "HP");
        m.insert("00:1C:C4", "HP");
        m.insert("00:1E:0B", "HP");
        m.insert("00:1F:29", "HP");
        m.insert("00:21:5A", "HP");
        m.insert("00:22:64", "HP");
        m.insert("00:23:7D", "HP");
        m.insert("00:24:81", "HP");
        m.insert("00:25:B3", "HP");
        m.insert("00:26:55", "HP");
        m.insert("2C:27:D7", "HP");
        m.insert("2C:44:FD", "HP");
        m.insert("30:8D:99", "HP");
        m.insert("3C:4A:92", "HP");
        m.insert("40:B0:34", "HP");
        m.insert("5C:B9:01", "HP");
        m.insert("70:10:6F", "HP");
        m.insert("78:E3:B5", "HP");
        m.insert("80:C1:6E", "HP");
        m.insert("84:34:97", "HP");
        m.insert("90:1B:0E", "HP");
        m.insert("9C:8E:99", "HP");
        m.insert("A0:1D:48", "HP");
        m.insert("B4:99:BA", "HP");
        m.insert("C4:34:6B", "HP");
        m.insert("D4:C9:EF", "HP");
        m.insert("E0:07:1B", "HP");
        m.insert("F0:92:1C", "HP");
        m.insert("FC:15:B4", "HP");

        // ── Lenovo ───────────────────────────────────────────────────────────
        m.insert("00:21:CC", "Lenovo");
        m.insert("00:23:18", "Lenovo");
        m.insert("00:24:BE", "Lenovo");
        m.insert("00:26:2D", "Lenovo");
        m.insert("28:D2:44", "Lenovo");
        m.insert("2C:DD:E9", "Lenovo");
        m.insert("30:10:B3", "Lenovo");
        m.insert("40:2C:F4", "Lenovo");
        m.insert("44:37:E6", "Lenovo");
        m.insert("48:F1:7F", "Lenovo");
        m.insert("4C:79:6E", "Lenovo");
        m.insert("54:EE:75", "Lenovo");
        m.insert("60:02:92", "Lenovo");
        m.insert("60:D9:25", "Lenovo");
        m.insert("6C:40:08", "Lenovo");
        m.insert("70:5A:0F", "Lenovo");
        m.insert("78:A5:04", "Lenovo");
        m.insert("80:FA:5B", "Lenovo");
        m.insert("84:2B:2B", "Lenovo");
        m.insert("88:70:8C", "Lenovo");
        m.insert("90:7F:61", "Lenovo");
        m.insert("98:FA:9B", "Lenovo");
        m.insert("A4:4E:31", "Lenovo");
        m.insert("B8:AC:6F", "Lenovo");
        m.insert("C8:DD:C9", "Lenovo");
        m.insert("D4:25:8B", "Lenovo");
        m.insert("E4:70:B8", "Lenovo");
        m.insert("F4:8E:38", "Lenovo");
        m.insert("F8:16:54", "Lenovo");

        // ── Supermicro ────────────────────────────────────────────────────────
        m.insert("00:25:90", "Supermicro");
        m.insert("00:30:48", "Supermicro");
        m.insert("0C:C4:7A", "Supermicro");
        m.insert("3C:EC:EF", "Supermicro");
        m.insert("AC:1F:6B", "Supermicro");

        // ── ASUS ─────────────────────────────────────────────────────────────
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
        m.insert("04:92:26", "ASUS");
        m.insert("10:BF:48", "ASUS");
        m.insert("14:DA:E9", "ASUS");
        m.insert("1C:87:2C", "ASUS");
        m.insert("20:CF:30", "ASUS");
        m.insert("2C:FD:A1", "ASUS");
        m.insert("30:85:A9", "ASUS");
        m.insert("38:2C:4A", "ASUS");
        m.insert("40:16:7E", "ASUS");
        m.insert("48:5B:39", "ASUS");
        m.insert("50:46:5D", "ASUS");
        m.insert("54:04:A6", "ASUS");
        m.insert("60:45:CB", "ASUS");
        m.insert("6C:62:6D", "ASUS");
        m.insert("74:D0:2B", "ASUS");
        m.insert("7C:10:C9", "ASUS");
        m.insert("80:1F:02", "ASUS");
        m.insert("88:D7:F6", "ASUS");
        m.insert("90:E6:BA", "ASUS");
        m.insert("9C:5C:8E", "ASUS");
        m.insert("AC:22:0B", "ASUS");
        m.insert("B0:6E:BF", "ASUS");
        m.insert("BC:AE:C5", "ASUS");
        m.insert("C8:60:00", "ASUS");
        m.insert("D0:17:C2", "ASUS");
        m.insert("D4:5D:64", "ASUS");
        m.insert("E0:3F:49", "ASUS");
        m.insert("E4:92:FB", "ASUS");
        m.insert("F0:2F:74", "ASUS");
        m.insert("F4:6D:04", "ASUS");
        m.insert("FC:34:97", "ASUS");

        // ── NETGEAR ──────────────────────────────────────────────────────────
        m.insert("00:14:6C", "NETGEAR");
        m.insert("00:18:4D", "NETGEAR");
        m.insert("00:1B:2F", "NETGEAR");
        m.insert("00:1E:2A", "NETGEAR");
        m.insert("00:1F:33", "NETGEAR");
        m.insert("00:22:75", "NETGEAR");
        m.insert("00:24:B2", "NETGEAR");
        m.insert("00:26:F2", "NETGEAR");
        m.insert("10:0C:6B", "NETGEAR");
        m.insert("20:4E:7F", "NETGEAR");
        m.insert("28:C6:8E", "NETGEAR");
        m.insert("2C:B0:5D", "NETGEAR");
        m.insert("30:46:9A", "NETGEAR");
        m.insert("3C:37:86", "NETGEAR");
        m.insert("44:94:FC", "NETGEAR");
        m.insert("4C:60:DE", "NETGEAR");
        m.insert("60:38:E0", "NETGEAR");
        m.insert("6C:B0:CE", "NETGEAR");
        m.insert("74:44:01", "NETGEAR");
        m.insert("84:1B:5E", "NETGEAR");
        m.insert("9C:3D:CF", "NETGEAR");
        m.insert("A0:21:B7", "NETGEAR");
        m.insert("C0:3F:0E", "NETGEAR");
        m.insert("C4:04:15", "NETGEAR");
        m.insert("C8:D7:19", "NETGEAR");
        m.insert("E0:46:9A", "NETGEAR");
        m.insert("E4:F4:C6", "NETGEAR");

        // ── D-Link ────────────────────────────────────────────────────────────
        m.insert("00:1E:58", "D-Link");
        m.insert("00:1F:3C", "D-Link");
        m.insert("00:21:91", "D-Link");
        m.insert("00:22:B0", "D-Link");
        m.insert("00:24:01", "D-Link");
        m.insert("14:D6:4D", "D-Link");
        m.insert("1C:7E:E5", "D-Link");
        m.insert("28:10:7B", "D-Link");
        m.insert("34:08:04", "D-Link");
        m.insert("5C:D9:98", "D-Link");
        m.insert("78:54:2E", "D-Link");
        m.insert("84:C9:B2", "D-Link");
        m.insert("90:94:E4", "D-Link");
        m.insert("A0:AB:1B", "D-Link");
        m.insert("C8:BE:19", "D-Link");
        m.insert("CC:B2:55", "D-Link");
        m.insert("F0:7D:68", "D-Link");

        // ── Linksys ───────────────────────────────────────────────────────────
        m.insert("00:14:BF", "Linksys");
        m.insert("00:18:39", "Linksys");
        m.insert("00:18:E7", "Linksys");
        m.insert("00:1A:70", "Linksys");
        m.insert("00:1C:10", "Linksys");
        m.insert("00:1D:7E", "Linksys");
        m.insert("00:1E:E5", "Linksys");
        m.insert("00:21:29", "Linksys");
        m.insert("00:22:6B", "Linksys");
        m.insert("00:23:69", "Linksys");
        m.insert("00:25:9C", "Linksys");
        m.insert("20:AA:4B", "Linksys");
        m.insert("48:F8:B3", "Linksys");
        m.insert("58:6D:8F", "Linksys");
        m.insert("68:7F:74", "Linksys");
        m.insert("C0:C1:C0", "Linksys");

        // ── Synology ─────────────────────────────────────────────────────────
        m.insert("00:11:32", "Synology");
        m.insert("00:1B:21", "Synology");

        // ── QNAP ─────────────────────────────────────────────────────────────
        m.insert("00:08:9B", "QNAP");
        m.insert("24:5E:BE", "QNAP");
        m.insert("D4:AE:52", "QNAP");

        // ── Raspberry Pi Foundation ──────────────────────────────────────────
        m.insert("B8:27:EB", "Raspberry Pi");
        m.insert("DC:A6:32", "Raspberry Pi");
        m.insert("E4:5F:01", "Raspberry Pi");
        m.insert("28:CD:C1", "Raspberry Pi");

        // ── Espressif (ESP8266 / ESP32) ───────────────────────────────────────
        m.insert("18:FE:34", "Espressif");
        m.insert("24:0A:C4", "Espressif");
        m.insert("2C:F4:32", "Espressif");
        m.insert("30:AE:A4", "Espressif");
        m.insert("3C:71:BF", "Espressif");
        m.insert("40:F5:20", "Espressif");
        m.insert("48:3F:DA", "Espressif");
        m.insert("4C:11:AE", "Espressif");
        m.insert("54:43:54", "Espressif");
        m.insert("60:01:94", "Espressif");
        m.insert("68:C6:3A", "Espressif");
        m.insert("70:03:9F", "Espressif");
        m.insert("7C:9E:BD", "Espressif");
        m.insert("80:7D:3A", "Espressif");
        m.insert("84:0D:8E", "Espressif");
        m.insert("84:F3:EB", "Espressif");
        m.insert("8C:AA:B5", "Espressif");
        m.insert("90:97:D5", "Espressif");
        m.insert("94:B9:7E", "Espressif");
        m.insert("A0:20:A6", "Espressif");
        m.insert("A4:CF:12", "Espressif");
        m.insert("B4:E6:2D", "Espressif");
        m.insert("BC:DD:C2", "Espressif");
        m.insert("C4:4F:33", "Espressif");
        m.insert("CC:50:E3", "Espressif");
        m.insert("D8:A0:1D", "Espressif");
        m.insert("DC:4F:22", "Espressif");
        m.insert("E8:DB:84", "Espressif");
        m.insert("EC:FA:BC", "Espressif");
        m.insert("F4:CF:A2", "Espressif");
        m.insert("FC:F5:C4", "Espressif");

        // ── Amazon / Kindle / Echo ────────────────────────────────────────────
        m.insert("00:BB:3A", "Amazon");
        m.insert("0C:47:C9", "Amazon");
        m.insert("18:74:2E", "Amazon");
        m.insert("28:EF:01", "Amazon");
        m.insert("34:D2:70", "Amazon");
        m.insert("40:B4:CD", "Amazon");
        m.insert("44:65:0D", "Amazon");
        m.insert("50:DC:E7", "Amazon");
        m.insert("68:37:E9", "Amazon");
        m.insert("74:75:48", "Amazon");
        m.insert("84:D6:D0", "Amazon");
        m.insert("A0:02:DC", "Amazon");
        m.insert("AC:63:BE", "Amazon");
        m.insert("B4:7C:9C", "Amazon");
        m.insert("F0:27:2D", "Amazon");
        m.insert("F0:4F:7C", "Amazon");
        m.insert("FC:65:DE", "Amazon");

        // ── Sony ──────────────────────────────────────────────────────────────
        m.insert("00:01:4A", "Sony");
        m.insert("00:0A:D9", "Sony");
        m.insert("00:13:A9", "Sony");
        m.insert("00:1A:80", "Sony");
        m.insert("00:1F:A7", "Sony");
        m.insert("00:24:BE", "Sony");
        m.insert("04:98:F3", "Sony");
        m.insert("10:4F:A8", "Sony");
        m.insert("18:00:2D", "Sony");
        m.insert("30:17:C8", "Sony");
        m.insert("30:F9:ED", "Sony");
        m.insert("54:42:49", "Sony");
        m.insert("70:2C:1F", "Sony");
        m.insert("A8:E0:73", "Sony");
        m.insert("BC:16:F5", "Sony");
        m.insert("D8:D4:3C", "Sony");
        m.insert("FC:0F:E6", "Sony");

        // ── Realtek ───────────────────────────────────────────────────────────
        m.insert("00:E0:4C", "Realtek");
        m.insert("00:E0:64", "Realtek");
        m.insert("10:7B:44", "Realtek");
        m.insert("23:6C:5F", "Realtek");
        m.insert("4A:56:02", "Realtek");

        // ── Aruba Networks ────────────────────────────────────────────────────
        m.insert("00:0B:86", "Aruba");
        m.insert("00:1A:1E", "Aruba");
        m.insert("00:24:6C", "Aruba");
        m.insert("04:BD:88", "Aruba");
        m.insert("18:64:72", "Aruba");
        m.insert("1C:28:AF", "Aruba");
        m.insert("20:4C:03", "Aruba");
        m.insert("24:DE:C6", "Aruba");
        m.insert("40:E3:D6", "Aruba");
        m.insert("48:5D:60", "Aruba");
        m.insert("60:B9:C0", "Aruba");
        m.insert("6C:F3:7F", "Aruba");
        m.insert("84:D4:7E", "Aruba");
        m.insert("88:5B:DD", "Aruba");
        m.insert("AC:A3:1E", "Aruba");
        m.insert("D8:C7:C8", "Aruba");

        // ── Philips Hue / Signify ─────────────────────────────────────────────
        m.insert("00:17:88", "Philips Hue");
        m.insert("EC:B5:FA", "Philips Hue");

        // ── Texas Instruments ─────────────────────────────────────────────────
        m.insert("00:12:37", "Texas Instruments");
        m.insert("00:17:E9", "Texas Instruments");
        m.insert("BC:6A:29", "Texas Instruments");
        m.insert("D8:49:2F", "Texas Instruments");
        m.insert("F4:B8:5E", "Texas Instruments");

        // ── Broadcom ─────────────────────────────────────────────────────────
        m.insert("00:10:18", "Broadcom");
        m.insert("00:90:4C", "Broadcom");
        m.insert("28:C6:3F", "Broadcom");
        m.insert("80:2A:A8", "Broadcom");

        // ── MediaTek ─────────────────────────────────────────────────────────
        m.insert("00:0C:E7", "MediaTek");
        m.insert("00:90:CC", "MediaTek");
        m.insert("14:A3:64", "MediaTek");

        // ── Qualcomm / Atheros ────────────────────────────────────────────────
        m.insert("00:03:7F", "Atheros");
        m.insert("00:0B:6B", "Atheros");
        m.insert("00:E0:22", "Atheros");
        m.insert("28:E3:1F", "Qualcomm");
        m.insert("40:CB:C0", "Qualcomm");

        // ── Juniper Networks ──────────────────────────────────────────────────
        m.insert("00:05:85", "Juniper");
        m.insert("00:10:DB", "Juniper");
        m.insert("00:12:1E", "Juniper");
        m.insert("00:17:CB", "Juniper");
        m.insert("00:19:E2", "Juniper");
        m.insert("00:1B:C0", "Juniper");
        m.insert("00:21:59", "Juniper");
        m.insert("00:23:9C", "Juniper");
        m.insert("00:24:DC", "Juniper");
        m.insert("2C:6B:F5", "Juniper");
        m.insert("40:B4:F0", "Juniper");
        m.insert("6C:9C:ED", "Juniper");
        m.insert("A0:D3:C1", "Juniper");
        m.insert("B0:A8:6E", "Juniper");

        // ── Fortinet ──────────────────────────────────────────────────────────
        m.insert("00:09:0F", "Fortinet");
        m.insert("00:0F:E0", "Fortinet");
        m.insert("08:5B:0E", "Fortinet");
        m.insert("70:4C:A5", "Fortinet");
        m.insert("90:6C:AC", "Fortinet");
        m.insert("E8:1C:BA", "Fortinet");

        // ── Palo Alto Networks ────────────────────────────────────────────────
        m.insert("00:1B:17", "Palo Alto");
        m.insert("04:6C:9D", "Palo Alto");
        m.insert("58:49:3B", "Palo Alto");
        m.insert("84:78:AC", "Palo Alto");

        // ── Nintendo ──────────────────────────────────────────────────────────
        m.insert("00:09:BF", "Nintendo");
        m.insert("00:16:56", "Nintendo");
        m.insert("00:17:AB", "Nintendo");
        m.insert("00:19:1D", "Nintendo");
        m.insert("00:1A:E9", "Nintendo");
        m.insert("00:1B:EA", "Nintendo");
        m.insert("00:1C:BE", "Nintendo");
        m.insert("00:1E:35", "Nintendo");
        m.insert("00:1F:32", "Nintendo");
        m.insert("00:21:47", "Nintendo");
        m.insert("00:22:D7", "Nintendo");
        m.insert("00:23:31", "Nintendo");
        m.insert("00:24:44", "Nintendo");
        m.insert("00:24:F3", "Nintendo");
        m.insert("00:26:59", "Nintendo");
        m.insert("2C:10:C1", "Nintendo");
        m.insert("40:D2:8A", "Nintendo");
        m.insert("58:BD:A3", "Nintendo");
        m.insert("7C:BB:8A", "Nintendo");
        m.insert("98:E8:FA", "Nintendo");
        m.insert("A4:C0:E1", "Nintendo");
        m.insert("B8:AE:6E", "Nintendo");
        m.insert("CC:FB:65", "Nintendo");
        m.insert("E0:E7:51", "Nintendo");

        // ── LG Electronics ───────────────────────────────────────────────────
        m.insert("00:1C:62", "LG");
        m.insert("00:1E:75", "LG");
        m.insert("00:22:A9", "LG");
        m.insert("00:24:83", "LG");
        m.insert("08:37:3D", "LG");
        m.insert("10:68:3F", "LG");
        m.insert("14:C1:4E", "LG");
        m.insert("18:29:4A", "LG");
        m.insert("1C:08:AA", "LG");
        m.insert("20:16:D8", "LG");
        m.insert("28:B2:BD", "LG");
        m.insert("30:D8:5A", "LG");
        m.insert("34:4D:F7", "LG");
        m.insert("38:8C:50", "LG");
        m.insert("50:55:27", "LG");
        m.insert("58:A2:B5", "LG");
        m.insert("60:E3:AC", "LG");
        m.insert("64:89:9A", "LG");
        m.insert("6C:E8:73", "LG");
        m.insert("78:5D:C8", "LG");
        m.insert("88:C9:D0", "LG");
        m.insert("A8:16:D0", "LG");
        m.insert("CC:2D:83", "LG");

        // ── ZTE ───────────────────────────────────────────────────────────────
        m.insert("00:19:C6", "ZTE");
        m.insert("00:1E:73", "ZTE");
        m.insert("00:22:93", "ZTE");
        m.insert("00:26:ED", "ZTE");
        m.insert("0C:37:DC", "ZTE");
        m.insert("14:EA:80", "ZTE");
        m.insert("1C:8B:19", "ZTE");
        m.insert("20:0D:B0", "ZTE");
        m.insert("28:5F:DB", "ZTE");
        m.insert("2C:26:17", "ZTE");
        m.insert("30:D3:2D", "ZTE");
        m.insert("34:6B:D3", "ZTE");
        m.insert("3C:DA:7E", "ZTE");
        m.insert("40:49:0F", "ZTE");
        m.insert("4C:09:B4", "ZTE");
        m.insert("50:8F:4C", "ZTE");
        m.insert("54:A5:28", "ZTE");
        m.insert("58:87:39", "ZTE");
        m.insert("64:13:6C", "ZTE");
        m.insert("68:A0:F6", "ZTE");
        m.insert("6C:8B:D3", "ZTE");

        // ── Zyxel ─────────────────────────────────────────────────────────────
        m.insert("00:13:49", "Zyxel");
        m.insert("00:19:CB", "Zyxel");
        m.insert("00:1F:A4", "Zyxel");
        m.insert("10:92:7C", "Zyxel");
        m.insert("1C:74:0D", "Zyxel");
        m.insert("20:16:B9", "Zyxel");
        m.insert("28:28:5D", "Zyxel");
        m.insert("30:91:8F", "Zyxel");
        m.insert("44:33:4C", "Zyxel");
        m.insert("58:8B:F3", "Zyxel");
        m.insert("A0:E4:CB", "Zyxel");
        m.insert("BC:62:B0", "Zyxel");
        m.insert("CC:5D:4E", "Zyxel");

        // ── Eero / Amazon eero ────────────────────────────────────────────────
        m.insert("F0:27:2D", "eero");
        m.insert("F4:F5:D8", "eero");

        m
    };
}
