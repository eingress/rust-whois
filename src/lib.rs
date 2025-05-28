//! # Whois Service Library
//! 
//! A high-performance, production-ready whois lookup library for Rust.
//! 
//! ## Features
//! 
//! - Dynamic TLD discovery via IANA
//! - Intelligent whois server detection
//! - Structured data parsing with calculated fields
//! - Optional caching with smart domain normalization
//! - Zero hardcoded values - fully dynamic
//! - Production-ready error handling
//! 
//! ## Quick Start
//! 
//! ```rust,no_run
//! use whois_service::WhoisClient;
//! 
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = WhoisClient::new().await?;
//!     let result = client.lookup("google.com").await?;
//!     
//!     println!("Domain: {}", result.domain);
//!     println!("Registrar: {:?}", result.parsed_data.as_ref().and_then(|p| p.registrar.as_ref()));
//!     
//!     Ok(())
//! }
//! ```

pub mod whois;
pub mod cache;
pub mod config;
pub mod errors;
pub mod metrics;

// Re-export main types for easy access
pub use whois::{WhoisService, WhoisResult};
pub use cache::CacheService;
pub use config::Config;
pub use errors::WhoisError;



use std::sync::Arc;

/// Parsed whois data structure with calculated fields
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ParsedWhoisData {
    pub registrar: Option<String>,
    pub creation_date: Option<String>,
    pub expiration_date: Option<String>,
    pub updated_date: Option<String>,
    pub name_servers: Vec<String>,
    pub status: Vec<String>,
    pub registrant_name: Option<String>,
    pub registrant_email: Option<String>,
    pub admin_email: Option<String>,
    pub tech_email: Option<String>,
    pub created_ago: Option<i64>,  // Days since creation
    pub updated_ago: Option<i64>,  // Days since last update
    pub expires_in: Option<i64>,   // Days until expiration (negative if expired)
}

/// High-level whois client with optional caching
#[derive(Clone)]
pub struct WhoisClient {
    service: Arc<WhoisService>,
    cache: Option<Arc<CacheService>>,
}

impl WhoisClient {
    /// Create a new whois client with default configuration
    pub async fn new() -> Result<Self, WhoisError> {
        let config = Arc::new(Config::load().map_err(|e| WhoisError::ConfigError(e))?);
        Self::new_with_config(config).await
    }

    /// Create a new whois client with custom configuration
    pub async fn new_with_config(config: Arc<Config>) -> Result<Self, WhoisError> {
        let service = Arc::new(WhoisService::new(config.clone()).await?);
        let cache = Some(Arc::new(
            CacheService::new(config)
                .map_err(|e| WhoisError::CacheError(format!("Failed to initialize cache: {}", e)))?
        ));
        
        Ok(Self { service, cache })
    }

    /// Create a new whois client without caching
    pub async fn new_without_cache() -> Result<Self, WhoisError> {
        let config = Arc::new(Config::load().map_err(|e| WhoisError::ConfigError(e))?);
        let service = Arc::new(WhoisService::new(config).await?);
        
        Ok(Self { service, cache: None })
    }

    /// Perform a whois lookup for the given domain
    /// 
    /// This method will use cache if available, unless `fresh` is true.
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResponse, WhoisError> {
        self.lookup_with_options(domain, false).await
    }

    /// Perform a fresh whois lookup, bypassing cache
    pub async fn lookup_fresh(&self, domain: &str) -> Result<WhoisResponse, WhoisError> {
        self.lookup_with_options(domain, true).await
    }

    /// Perform a whois lookup with caching options
    pub async fn lookup_with_options(&self, domain: &str, fresh: bool) -> Result<WhoisResponse, WhoisError> {
        let start_time = std::time::Instant::now();
        let normalized_domain = domain.trim().to_lowercase();
        
        // Basic domain validation
        if normalized_domain.is_empty() {
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }
        
        if !normalized_domain.contains('.') {
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }

        // Check cache first (if available and not requesting fresh)
        if !fresh {
            if let Some(cache) = &self.cache {
                match cache.get(&normalized_domain).await {
                    Ok(Some(cached_result)) => {
                        return Ok(cached_result);
                    }
                    Ok(None) => {
                        // Cache miss, continue to fresh lookup
                    }
                    Err(e) => {
                        tracing::warn!("Cache read error for {}: {}", normalized_domain, e);
                        // Continue to fresh lookup on cache error
                    }
                }
            }
        }

        // Perform fresh lookup
        let result = self.service.lookup(&normalized_domain).await?;
        let query_time = start_time.elapsed().as_millis() as u64;
        
        let response = WhoisResponse {
            domain: normalized_domain.clone(),
            whois_server: result.server,
            raw_data: result.raw_data,
            parsed_data: result.parsed_data,
            cached: false,
            query_time_ms: query_time,
            parsing_analysis: None, // No debug info in library mode
        };

        // Cache the result if cache is available
        if let Some(cache) = &self.cache {
            if let Err(e) = cache.set(&normalized_domain, &response).await {
                tracing::warn!("Failed to cache result for {}: {}", normalized_domain, e);
                // Don't fail the request for cache write errors
            }
        }

        Ok(response)
    }

    /// Get cache statistics if caching is enabled
    pub fn cache_enabled(&self) -> bool {
        self.cache.is_some()
    }
}

/// Response structure for whois lookups
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct WhoisResponse {
    pub domain: String,
    pub whois_server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub cached: bool,
    pub query_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parsing_analysis: Option<Vec<String>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_whois_client_creation() {
        let client = WhoisClient::new_without_cache().await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_domain_validation() {
        let client = WhoisClient::new_without_cache().await.unwrap();
        
        // Test empty domain
        let result = client.lookup("").await;
        assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
        
        // Test invalid domain
        let result = client.lookup("invalid").await;
        assert!(matches!(result, Err(WhoisError::InvalidDomain(_))));
    }
} 