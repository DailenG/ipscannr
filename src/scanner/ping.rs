use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::sync::Semaphore;
use tokio::time::timeout;

/// Result of a ping operation
#[derive(Debug, Clone)]
pub struct PingResult {
    pub ip: Ipv4Addr,
    pub is_alive: bool,
    pub rtt: Option<Duration>,
    pub method: PingMethod,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethod {
    Icmp,
    TcpSyn,
}

impl std::fmt::Display for PingMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingMethod::Icmp => write!(f, "ICMP"),
            PingMethod::TcpSyn => write!(f, "TCP"),
        }
    }
}

/// Pinger configuration
#[derive(Debug, Clone)]
pub struct PingerConfig {
    pub timeout: Duration,
    pub retries: u32,
    pub concurrent_limit: usize,
}

impl Default for PingerConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            retries: 1,
            concurrent_limit: 100,
        }
    }
}

/// Pinger for host discovery
pub struct Pinger {
    config: PingerConfig,
    semaphore: Arc<Semaphore>,
}

impl Pinger {
    pub fn new(config: PingerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.concurrent_limit));
        Self { config, semaphore }
    }

    /// Ping a single host using TCP connect (more reliable on Windows without admin)
    pub async fn ping(&self, ip: Ipv4Addr) -> PingResult {
        let _permit = self.semaphore.acquire().await.unwrap();

        // Try TCP connect to common ports (more reliable without raw sockets)
        let ports = [80, 443, 22, 445, 139, 135, 3389];

        for _ in 0..=self.config.retries {
            for &port in &ports {
                if let Some(rtt) = self.tcp_ping(ip, port).await {
                    return PingResult {
                        ip,
                        is_alive: true,
                        rtt: Some(rtt),
                        method: PingMethod::TcpSyn,
                    };
                }
            }
        }

        PingResult {
            ip,
            is_alive: false,
            rtt: None,
            method: PingMethod::TcpSyn,
        }
    }

    async fn tcp_ping(&self, ip: Ipv4Addr, port: u16) -> Option<Duration> {
        let start = Instant::now();
        let addr = SocketAddr::new(IpAddr::V4(ip), port);

        let result = timeout(
            self.config.timeout,
            tokio::net::TcpStream::connect(addr),
        )
        .await;

        match result {
            Ok(Ok(_)) => Some(start.elapsed()),
            Ok(Err(e)) => {
                // Connection refused means host is alive but port closed
                if e.kind() == std::io::ErrorKind::ConnectionRefused {
                    Some(start.elapsed())
                } else {
                    None
                }
            }
            Err(_) => None, // Timeout
        }
    }

}

/// Scan multiple hosts concurrently
pub async fn scan_hosts(
    addresses: Vec<Ipv4Addr>,
    config: PingerConfig,
    progress_tx: tokio::sync::mpsc::Sender<PingResult>,
) -> Result<()> {
    let pinger = Arc::new(Pinger::new(config));
    let mut handles = Vec::new();

    for ip in addresses {
        let pinger = Arc::clone(&pinger);
        let tx = progress_tx.clone();

        let handle = tokio::spawn(async move {
            let result = pinger.ping(ip).await;
            let _ = tx.send(result).await;
        });

        handles.push(handle);
    }

    for handle in handles {
        let _ = handle.await;
    }

    Ok(())
}
