use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Arc;

use dns_lookup::lookup_addr;
use tokio::sync::{Mutex, Semaphore};

/// DNS resolver with caching
pub struct DnsResolver {
    cache: Arc<Mutex<HashMap<Ipv4Addr, Option<String>>>>,
    semaphore: Arc<Semaphore>,
}

impl DnsResolver {
    pub fn new(concurrent_limit: usize) -> Self {
        Self {
            cache: Arc::new(Mutex::new(HashMap::new())),
            semaphore: Arc::new(Semaphore::new(concurrent_limit)),
        }
    }

    /// Resolve an IP address to a hostname
    pub async fn resolve(&self, ip: Ipv4Addr) -> Option<String> {
        // Check cache first
        {
            let cache = self.cache.lock().await;
            if let Some(cached) = cache.get(&ip) {
                return cached.clone();
            }
        }

        let _permit = self.semaphore.acquire().await.unwrap();

        // Perform DNS lookup in blocking task
        let result = tokio::task::spawn_blocking(move || {
            lookup_addr(&ip.into()).ok()
        })
        .await
        .ok()
        .flatten();

        // Cache the result
        {
            let mut cache = self.cache.lock().await;
            cache.insert(ip, result.clone());
        }

        result
    }

    /// Resolve multiple IP addresses concurrently
    pub async fn resolve_batch(&self, ips: Vec<Ipv4Addr>) -> HashMap<Ipv4Addr, Option<String>> {
        let mut handles = Vec::new();

        for ip in ips {
            let resolver = Self {
                cache: Arc::clone(&self.cache),
                semaphore: Arc::clone(&self.semaphore),
            };

            let handle = tokio::spawn(async move {
                let hostname = resolver.resolve(ip).await;
                (ip, hostname)
            });

            handles.push(handle);
        }

        let mut results = HashMap::new();
        for handle in handles {
            if let Ok((ip, hostname)) = handle.await {
                results.insert(ip, hostname);
            }
        }

        results
    }

    /// Clear the cache
    pub async fn clear_cache(&self) {
        let mut cache = self.cache.lock().await;
        cache.clear();
    }
}

impl Default for DnsResolver {
    fn default() -> Self {
        Self::new(20)
    }
}
