use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::timeout;

/// Common ports to scan by default
pub const COMMON_PORTS: &[u16] = &[
    21,    // FTP
    22,    // SSH
    23,    // Telnet
    25,    // SMTP
    53,    // DNS
    80,    // HTTP
    110,   // POP3
    111,   // RPC
    135,   // MSRPC
    139,   // NetBIOS
    143,   // IMAP
    443,   // HTTPS
    445,   // SMB
    993,   // IMAPS
    995,   // POP3S
    1433,  // MSSQL
    1521,  // Oracle
    3306,  // MySQL
    3389,  // RDP
    5432,  // PostgreSQL
    5900,  // VNC
    6379,  // Redis
    8080,  // HTTP Alt
    8443,  // HTTPS Alt
    27017, // MongoDB
];

/// Get service name for a port
pub fn get_service_name(port: u16) -> &'static str {
    lazy_static_services().get(&port).copied().unwrap_or("unknown")
}

fn lazy_static_services() -> &'static HashMap<u16, &'static str> {
    use std::sync::OnceLock;
    static SERVICES: OnceLock<HashMap<u16, &'static str>> = OnceLock::new();

    SERVICES.get_or_init(|| {
        let mut m = HashMap::new();
        m.insert(21, "ftp");
        m.insert(22, "ssh");
        m.insert(23, "telnet");
        m.insert(25, "smtp");
        m.insert(53, "dns");
        m.insert(80, "http");
        m.insert(110, "pop3");
        m.insert(111, "rpc");
        m.insert(135, "msrpc");
        m.insert(139, "netbios");
        m.insert(143, "imap");
        m.insert(443, "https");
        m.insert(445, "smb");
        m.insert(993, "imaps");
        m.insert(995, "pop3s");
        m.insert(1433, "mssql");
        m.insert(1521, "oracle");
        m.insert(3306, "mysql");
        m.insert(3389, "rdp");
        m.insert(5432, "postgres");
        m.insert(5900, "vnc");
        m.insert(6379, "redis");
        m.insert(8080, "http-alt");
        m.insert(8443, "https-alt");
        m.insert(27017, "mongodb");
        m
    })
}

/// Result of a port scan
#[derive(Debug, Clone)]
pub struct PortResult {
    pub port: u16,
    pub is_open: bool,
    pub service: &'static str,
}

/// Port scanner configuration
#[derive(Debug, Clone)]
pub struct PortScannerConfig {
    pub timeout: Duration,
    pub concurrent_limit: usize,
}

impl Default for PortScannerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(500),
            concurrent_limit: 50,
        }
    }
}

/// Port scanner
pub struct PortScanner {
    config: PortScannerConfig,
    semaphore: Arc<Semaphore>,
}

impl PortScanner {
    pub fn new(config: PortScannerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.concurrent_limit));
        Self { config, semaphore }
    }

    /// Scan a single port on a host
    pub async fn scan_port(&self, ip: Ipv4Addr, port: u16) -> PortResult {
        let permit = self.semaphore.acquire().await;
        if permit.is_err() {
            return PortResult {
                port,
                is_open: false,
                service: get_service_name(port),
            };
        }
        let _permit = permit.ok();

        let addr = SocketAddr::new(IpAddr::V4(ip), port);

        let is_open = timeout(
            self.config.timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        PortResult {
            port,
            is_open,
            service: get_service_name(port),
        }
    }

    /// Scan multiple ports on a host
    pub async fn scan_ports(&self, ip: Ipv4Addr, ports: &[u16]) -> Vec<PortResult> {
        let worker_count = self.config.concurrent_limit.max(1);
        let (job_tx, job_rx) = mpsc::channel::<u16>(worker_count.saturating_mul(2));
        let (result_tx, mut result_rx) = mpsc::channel::<PortResult>(ports.len().max(1));
        let shared_rx = Arc::new(Mutex::new(job_rx));
        let mut workers = Vec::with_capacity(worker_count);

        for _ in 0..worker_count {
            let scanner = self.clone_inner();
            let rx = Arc::clone(&shared_rx);
            let tx = result_tx.clone();
            workers.push(tokio::spawn(async move {
                loop {
                    let next_port = {
                        let mut guard = rx.lock().await;
                        guard.recv().await
                    };
                    let Some(port) = next_port else {
                        break;
                    };
                    let result = scanner.scan_port(ip, port).await;
                    if tx.send(result).await.is_err() {
                        break;
                    }
                }
            }));
        }
        drop(result_tx);

        for &port in ports {
            if job_tx.send(port).await.is_err() {
                break;
            }
        }
        drop(job_tx);

        let mut results = Vec::new();
        while let Some(result) = result_rx.recv().await {
            results.push(result);
        }

        for worker in workers {
            let _ = worker.await;
        }

        // Sort by port number
        results.sort_by_key(|r| r.port);
        results
    }

    fn clone_inner(&self) -> Self {
        Self {
            config: self.config.clone(),
            semaphore: Arc::clone(&self.semaphore),
        }
    }
}

/// Parse port specification string
/// Formats: "80", "80,443,8080", "1-1024", "80,443,1000-2000"
pub fn parse_ports(input: &str) -> Vec<u16> {
    let mut ports = Vec::new();

    for part in input.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }

        if part.contains('-') {
            let range: Vec<&str> = part.split('-').collect();
            if range.len() == 2 {
                if let (Ok(start), Ok(end)) = (range[0].parse::<u16>(), range[1].parse::<u16>()) {
                    for port in start..=end {
                        ports.push(port);
                    }
                }
            }
        } else if let Ok(port) = part.parse::<u16>() {
            ports.push(port);
        }
    }

    ports.sort();
    ports.dedup();
    ports
}
