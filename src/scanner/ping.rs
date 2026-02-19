use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use surge_ping::{Client, Config as PingConfig, PingIdentifier, PingSequence};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::time::timeout;

/// Result of a ping operation
#[derive(Debug, Clone)]
pub struct PingResult {
    pub ip: Ipv4Addr,
    pub is_alive: bool,
    pub rtt: Option<Duration>,
    pub method: PingMethod,
    pub status: HostStatus,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PingMethod {
    Icmp,
    Tcp,
}

impl std::fmt::Display for PingMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PingMethod::Icmp => write!(f, "ICMP"),
            PingMethod::Tcp => write!(f, "TCP"),
        }
    }
}

/// Status of the host detection
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum HostStatus {
    /// Host responded to ICMP or TCP probes
    Online,
    /// Host has open ports but doesn't respond to ICMP
    OnlineNoIcmp,
    /// Host appears offline (no response to any probe)
    Offline,
}

impl std::fmt::Display for HostStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostStatus::Online => write!(f, "Online"),
            HostStatus::OnlineNoIcmp => write!(f, "Online (no ICMP)"),
            HostStatus::Offline => write!(f, "Offline"),
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
    icmp_client: Option<Arc<Client>>,
}

impl Pinger {
    pub fn new(config: PingerConfig) -> Self {
        let semaphore = Arc::new(Semaphore::new(config.concurrent_limit));
        
        // Try to create ICMP client - may fail without admin privileges
        let icmp_client = Client::new(&PingConfig::default()).ok().map(Arc::new);
        
        Self {
            config,
            semaphore,
            icmp_client,
        }
    }

    /// Ping a single host - tries ICMP first, then TCP probes as fallback
    pub async fn ping(&self, ip: Ipv4Addr) -> PingResult {
        let permit = self.semaphore.acquire().await;
        if permit.is_err() {
            return PingResult {
                ip,
                is_alive: false,
                rtt: None,
                method: PingMethod::Icmp,
                status: HostStatus::Offline,
            };
        }
        let _permit = permit.ok();

        // Try ICMP ping first if we have a client
        if let Some(client) = &self.icmp_client {
            for attempt in 0..=self.config.retries {
                if let Some(rtt) = self.icmp_ping(client, ip, attempt as u16).await {
                    return PingResult {
                        ip,
                        is_alive: true,
                        rtt: Some(rtt),
                        method: PingMethod::Icmp,
                        status: HostStatus::Online,
                    };
                }
            }
        }

        // ICMP failed or not available - try TCP probes to common ports
        let ports = [80, 443, 22, 445, 139, 135, 3389, 21, 23, 25, 53];
        
        for _ in 0..=self.config.retries {
            for &port in &ports {
                if let Some(rtt) = self.tcp_ping(ip, port).await {
                    // Host has open port but doesn't respond to ICMP
                    let status = if self.icmp_client.is_some() {
                        HostStatus::OnlineNoIcmp
                    } else {
                        HostStatus::Online
                    };
                    
                    return PingResult {
                        ip,
                        is_alive: true,
                        rtt: Some(rtt),
                        method: PingMethod::Tcp,
                        status,
                    };
                }
            }
        }

        // No response to any probe
        PingResult {
            ip,
            is_alive: false,
            rtt: None,
            method: if self.icmp_client.is_some() {
                PingMethod::Icmp
            } else {
                PingMethod::Tcp
            },
            status: HostStatus::Offline,
        }
    }

    async fn icmp_ping(&self, client: &Client, ip: Ipv4Addr, seq: u16) -> Option<Duration> {
        let start = Instant::now();
        let payload = [0; 56]; // Standard ping payload size
        
        let mut pinger = client.pinger(IpAddr::V4(ip), PingIdentifier(rand::random())).await;
        
        let result = timeout(
            self.config.timeout,
            pinger.ping(PingSequence(seq), &payload),
        )
        .await;

        match result {
            Ok(Ok((_packet, duration))) => Some(duration),
            _ => None,
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
    let worker_count = pinger.config.concurrent_limit.max(1);
    let (job_tx, job_rx) = mpsc::channel::<Ipv4Addr>(worker_count.saturating_mul(2));
    let shared_rx = Arc::new(Mutex::new(job_rx));

    let mut workers = Vec::with_capacity(worker_count);
    for _ in 0..worker_count {
        let rx = Arc::clone(&shared_rx);
        let tx = progress_tx.clone();
        let pinger = Arc::clone(&pinger);
        workers.push(tokio::spawn(async move {
            loop {
                let next_ip = {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                };
                let Some(ip) = next_ip else {
                    break;
                };
                let result = pinger.ping(ip).await;
                if tx.send(result).await.is_err() {
                    break;
                }
            }
        }));
    }

    for ip in addresses {
        if job_tx.send(ip).await.is_err() {
            break;
        }
    }
    drop(job_tx);

    for worker in workers {
        let _ = worker.await;
    }

    Ok(())
}
