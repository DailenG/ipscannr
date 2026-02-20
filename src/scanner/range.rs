use std::net::Ipv4Addr;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use ipnetwork::Ipv4Network;

/// Represents a range of IP addresses to scan
#[derive(Debug, Clone)]
pub struct IpRange {
    addresses: Vec<Ipv4Addr>,
}

impl IpRange {
    /// Parse an IP range from a string
    /// Supported formats:
    /// - Single IP: 192.168.1.1
    /// - CIDR: 192.168.1.0/24
    /// - Range: 192.168.1.1-254
    /// - Range with full IPs: 192.168.1.1-192.168.1.254
    /// - Comma separated: 192.168.1.1,192.168.1.2,192.168.1.3
    pub fn parse(input: &str) -> Result<Self> {
        let input = input.trim();

        if input.is_empty() {
            return Err(anyhow!("Empty IP range"));
        }

        // Check for comma-separated list
        if input.contains(',') {
            return Self::parse_comma_list(input);
        }

        // Check for CIDR notation
        if input.contains('/') {
            return Self::parse_cidr(input);
        }

        // Check for range notation
        if input.contains('-') {
            return Self::parse_range(input);
        }

        // Single IP
        let addr = Ipv4Addr::from_str(input)
            .map_err(|_| anyhow!("Invalid IP address: {}", input))?;

        Ok(Self {
            addresses: vec![addr],
        })
    }

    fn parse_cidr(input: &str) -> Result<Self> {
        let network: Ipv4Network = input
            .parse()
            .map_err(|_| anyhow!("Invalid CIDR notation: {}", input))?;

        let addresses: Vec<Ipv4Addr> = network.iter().collect();

        if addresses.is_empty() {
            return Err(anyhow!("CIDR range is empty"));
        }

        Ok(Self { addresses })
    }

    fn parse_range(input: &str) -> Result<Self> {
        let parts: Vec<&str> = input.split('-').collect();

        if parts.len() != 2 {
            return Err(anyhow!("Invalid range format: {}", input));
        }

        let start = Ipv4Addr::from_str(parts[0].trim())
            .map_err(|_| anyhow!("Invalid start IP: {}", parts[0]))?;

        // Check if end is just a number (last octet) or full IP
        let end = if parts[1].trim().contains('.') {
            Ipv4Addr::from_str(parts[1].trim())
                .map_err(|_| anyhow!("Invalid end IP: {}", parts[1]))?
        } else {
            let end_octet: u8 = parts[1]
                .trim()
                .parse()
                .map_err(|_| anyhow!("Invalid end octet: {}", parts[1]))?;

            let octets = start.octets();
            Ipv4Addr::new(octets[0], octets[1], octets[2], end_octet)
        };

        let start_u32 = u32::from(start);
        let end_u32 = u32::from(end);

        if start_u32 > end_u32 {
            return Err(anyhow!("Start IP is greater than end IP"));
        }

        let addresses: Vec<Ipv4Addr> = (start_u32..=end_u32)
            .map(Ipv4Addr::from)
            .collect();

        Ok(Self { addresses })
    }

    fn parse_comma_list(input: &str) -> Result<Self> {
        let mut addresses = Vec::new();

        for part in input.split(',') {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }

            // Each part could be a single IP, CIDR, or range
            let range = if part.contains('/') {
                Self::parse_cidr(part)?
            } else if part.contains('-') {
                Self::parse_range(part)?
            } else {
                let addr = Ipv4Addr::from_str(part)
                    .map_err(|_| anyhow!("Invalid IP address: {}", part))?;
                Self { addresses: vec![addr] }
            };

            addresses.extend(range.addresses);
        }

        if addresses.is_empty() {
            return Err(anyhow!("No valid IP addresses found"));
        }

        Ok(Self { addresses })
    }

    pub fn addresses(&self) -> &[Ipv4Addr] {
        &self.addresses
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.addresses.len()
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.addresses.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_ip() {
        let range = IpRange::parse("192.168.1.1").unwrap();
        assert_eq!(range.len(), 1);
        assert_eq!(range.addresses()[0], Ipv4Addr::new(192, 168, 1, 1));
    }

    #[test]
    fn test_cidr() {
        let range = IpRange::parse("192.168.1.0/30").unwrap();
        assert_eq!(range.len(), 4);
    }

    #[test]
    fn test_range_short() {
        let range = IpRange::parse("192.168.1.1-5").unwrap();
        assert_eq!(range.len(), 5);
    }

    #[test]
    fn test_range_full() {
        let range = IpRange::parse("192.168.1.1-192.168.1.5").unwrap();
        assert_eq!(range.len(), 5);
    }
}
