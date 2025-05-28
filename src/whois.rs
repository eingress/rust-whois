use crate::{config::Config, errors::WhoisError, ParsedWhoisData};
use chrono::{DateTime, Utc, NaiveDateTime};
use once_cell::sync::Lazy;
use publicsuffix::{List, Psl};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::Semaphore,
    time::timeout,
};
use tracing::{debug, info, warn};

// Global PSL instance - shared across all service instances
static PSL: Lazy<List> = Lazy::new(|| List::new());

// Buffer pool type
type BufferPool = Arc<tokio::sync::Mutex<Vec<Vec<u8>>>>;

// RAII Buffer Pool - automatically returns buffer to pool on drop
pub struct PooledBuffer {
    buffer: Vec<u8>,
    pool: BufferPool,
    buffer_size: usize,
    max_pool_size: usize,
}

impl PooledBuffer {
    pub fn new(pool: BufferPool, buffer_size: usize, max_pool_size: usize) -> Self {
        let buffer = match pool.try_lock() {
            Ok(mut p) => {
                if let Some(mut buf) = p.pop() {
                    // Ensure buffer is the right size
                    if buf.len() != buffer_size {
                        buf.resize(buffer_size, 0);
                    } else {
                        buf.clear();
                        buf.resize(buffer_size, 0);
                    }
                    debug!("Buffer retrieved from pool (remaining: {})", p.len());
                    buf
                } else {
                    debug!("Buffer pool empty, creating new buffer");
                    vec![0; buffer_size]
                }
            },
            Err(_) => {
                debug!("Buffer pool locked, creating new buffer to avoid deadlock");
                vec![0; buffer_size]
            }
        };
        
        Self { 
            buffer, 
            pool, 
            buffer_size,
            max_pool_size,
        }
    }
    
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buffer
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        match self.pool.try_lock() {
            Ok(mut pool) => {
                if pool.len() < self.max_pool_size {
                    // Reset buffer to correct size and clear it
                    self.buffer.clear();
                    self.buffer.resize(self.buffer_size, 0);
                    pool.push(std::mem::take(&mut self.buffer));
                    debug!("Buffer returned to pool (size: {})", pool.len());
                } else {
                    debug!("Buffer pool full, dropping buffer");
                }
            },
            Err(_) => {
                debug!("Buffer pool locked, dropping buffer to avoid deadlock");
            }
        }
    }
}

pub struct WhoisService {
    config: Arc<Config>,
    tld_servers: Arc<tokio::sync::RwLock<HashMap<String, String>>>,
    domain_query_semaphore: Arc<Semaphore>,  // For actual domain lookups
    discovery_semaphore: Arc<Semaphore>,     // For TLD discovery (higher limit)
    buffer_pool: BufferPool,  // Reusable buffers for network I/O
}

pub struct WhoisResult {
    pub server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub parsing_analysis: Vec<String>,
}

impl WhoisService {
    pub async fn new(config: Arc<Config>) -> Result<Self, WhoisError> {
        let service = Self {
            config: config.clone(),
            tld_servers: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
            domain_query_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries)),
            discovery_semaphore: Arc::new(Semaphore::new(config.concurrent_whois_queries * 2)),
            buffer_pool: Arc::new(tokio::sync::Mutex::new(Vec::with_capacity(config.buffer_pool_size))),
        };

        info!("WhoisService initialized with dynamic TLD discovery");
        info!("Buffer pool: {} buffers of {} bytes each", config.buffer_pool_size, config.buffer_size);
        
        Ok(service)
    }

    /// Perform whois lookup for a domain
    /// Assumes domain is already validated and properly formatted (e.g., "example.com")
    pub async fn lookup(&self, domain: &str) -> Result<WhoisResult, WhoisError> {
        let domain = domain.trim().to_lowercase();
        
        // Basic validation - assume domain is pre-parsed and valid
        if domain.is_empty() || !domain.contains('.') {
            return Err(WhoisError::InvalidDomain(domain));
        }
        
        // Extract TLD from the domain using global PSL
        let tld = self.extract_tld(&domain)?;
        
        // Find appropriate whois server (with dynamic discovery)
        let whois_server = self.find_whois_server(&tld).await?;
        
        // Perform whois query
        let raw_data = self.raw_whois_query(&whois_server, &domain).await?;
        
        // Check for referrals and follow them
        let (final_server, final_data) = self.follow_referrals(&whois_server, &raw_data, &domain).await?;
        
        // Parse the whois data with detailed analysis
        let (parsed_data, parsing_analysis) = self.parse_whois_data_with_analysis(&final_data);
        
        Ok(WhoisResult {
            server: final_server,
            raw_data: final_data,
            parsed_data,
            parsing_analysis,
        })
    }

    /// Extract TLD from domain using global PSL for accurate parsing
    fn extract_tld(&self, domain: &str) -> Result<String, WhoisError> {
        // Parse the domain using the global public suffix list
        match PSL.domain(domain.as_bytes()) {
            Some(parsed_domain) => {
                // Get the public suffix (effective TLD)
                let suffix = parsed_domain.suffix();
                match std::str::from_utf8(suffix.as_bytes()) {
                    Ok(tld) => Ok(tld.to_string()),
                    Err(_) => Err(WhoisError::InvalidDomain(format!("Invalid UTF-8 in TLD for domain: {}", domain)))
                }
            },
            None => {
                // Fallback to simple extraction if PSL parsing fails
                warn!("Public suffix parsing failed for {}, using fallback", domain);
                let parts: Vec<&str> = domain.split('.').collect();
                if parts.is_empty() {
                    Err(WhoisError::InvalidDomain(format!("No TLD found in domain: {}", domain)))
                } else {
                    Ok(parts[parts.len() - 1].to_string())
                }
            }
        }
    }

    async fn find_whois_server(&self, tld: &str) -> Result<String, WhoisError> {
        // Check cache first
        {
            let servers = self.tld_servers.read().await;
            if let Some(server) = servers.get(tld) {
                return Ok(server.clone());
            }
        }

        // Dynamic discovery
        if let Some(server) = self.discover_whois_server_dynamic(tld).await {
            // Cache the discovered server
            {
                let mut servers = self.tld_servers.write().await;
                servers.insert(tld.to_string(), server.clone());
            }
            return Ok(server);
        }

        Err(WhoisError::UnsupportedTld(tld.to_string()))
    }

    async fn discover_whois_server_dynamic(&self, tld: &str) -> Option<String> {
        debug!("Dynamically discovering whois server for TLD: {}", tld);

        // Strategy 1: Query root whois servers for referrals (most reliable and fast)
        if let Some(server) = self.query_root_servers_for_tld(tld).await {
            debug!("Found whois server from root query: {}", server);
            // Just test connectivity, don't validate with fake domains
            if self.test_whois_server(&server).await {
                info!("Discovered whois server via root query for {}: {}", tld, server);
                return Some(server);
            }
        }

        // Strategy 2: Try common patterns with connectivity testing only
        let patterns = self.generate_whois_patterns(tld);
        for pattern in patterns {
            debug!("Testing pattern server: {}", pattern);
            if self.test_whois_server(&pattern).await {
                info!("Discovered whois server via pattern for {}: {}", tld, pattern);
                return Some(pattern);
            }
        }

        warn!("Could not discover whois server for TLD: {}", tld);
        None
    }

    fn generate_whois_patterns(&self, tld: &str) -> Vec<String> {
        // Intelligent pattern generation based on TLD characteristics
        let mut patterns = Vec::new();
        
        // Most reliable patterns first
        patterns.push(format!("whois.nic.{}", tld));
        
        // Country-specific patterns (for ccTLDs)
        if tld.len() == 2 {
            patterns.push(format!("whois.{}", tld));
            patterns.push(format!("whois.domain.{}", tld));
            patterns.push(format!("whois.registry.{}", tld));
            patterns.push(format!("whois.dns.{}", tld));
        } else {
            // gTLD patterns
            patterns.push(format!("whois.{}", tld));
            patterns.push(format!("whois.registry.{}", tld));
        }
        
        patterns
    }

    async fn query_root_servers_for_tld(&self, tld: &str) -> Option<String> {
        let root_servers = self.get_root_servers();

        for root_server in &root_servers {
            debug!("Querying root server {} for TLD: {}", root_server, tld);
            
            match self.discovery_whois_query(root_server, tld).await {
                Ok(response) => {
                    debug!("Root server {} response length: {} bytes", root_server, response.len());
                    
                    // Parse the response line by line to find referral
                    for line in response.lines() {
                        let line = line.trim();
                        
                        // Look for "whois:" lines (IANA format)
                        if line.to_lowercase().starts_with("whois:") {
                            if let Some(server) = line.split(':').nth(1) {
                                let server = server.trim().to_string();
                                debug!("Found whois server: {}", server);
                                return Some(server);
                            }
                        }
                        
                        // Look for "refer:" lines (alternative format)
                        if line.to_lowercase().starts_with("refer:") {
                            if let Some(server) = line.split(':').nth(1) {
                                let server = server.trim().to_string();
                                debug!("Found refer server: {}", server);
                                return Some(server);
                            }
                        }
                        
                        // Look for "whois server:" lines (alternative format)
                        if line.to_lowercase().contains("whois server:") {
                            if let Some(server) = line.split(':').nth(1) {
                                let server = server.trim().to_string();
                                debug!("Found whois server: {}", server);
                                return Some(server);
                            }
                        }
                    }
                    
                    // Fallback: try the regex approach
                    if let Some(server) = self.extract_whois_server(&response) {
                        debug!("Found referral server via regex: {}", server);
                        return Some(server);
                    }
                    
                    debug!("No referral found in response from {}", root_server);
                }
                Err(e) => {
                    debug!("Failed to query root server {}: {}", root_server, e);
                }
            }
        }

        None
    }

    fn get_root_servers(&self) -> Vec<String> {
        // Root whois servers - IANA is the authoritative source
        vec![
            "whois.iana.org".to_string(),
        ]
    }

    async fn test_whois_server(&self, server: &str) -> bool {
        match timeout(
            Duration::from_secs(self.config.discovery_timeout_seconds.min(10)), 
            TcpStream::connect((server, 43))
        ).await {
            Ok(Ok(_)) => {
                debug!("Successfully connected to whois server: {}", server);
                true
            },
            Ok(Err(e)) => {
                debug!("Failed to connect to whois server {}: {}", server, e);
                false
            },
            Err(_) => {
                debug!("Timeout connecting to whois server: {}", server);
                false
            }
        }
    }

    async fn raw_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        // Acquire semaphore permit to limit concurrent queries
        let _permit = self.domain_query_semaphore.acquire().await.map_err(|_| WhoisError::Internal("Semaphore error".to_string()))?;
        
        self.execute_whois_query(server, query).await
    }

    async fn discovery_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        // Use separate semaphore for discovery queries (higher limit)
        let _permit = self.discovery_semaphore.acquire().await.map_err(|_| WhoisError::Internal("Discovery semaphore error".to_string()))?;
        
        self.execute_whois_query(server, query).await
    }

    async fn execute_whois_query(&self, server: &str, query: &str) -> Result<String, WhoisError> {
        let mut stream = timeout(
            Duration::from_secs(self.config.whois_timeout_seconds),
            TcpStream::connect((server, 43))
        ).await??;

        // Optimize TCP performance
        if let Err(e) = stream.set_nodelay(true) {
            debug!("Failed to set TCP_NODELAY: {}", e);
        }

        // Send query
        let query_line = format!("{}\r\n", query);
        stream.write_all(query_line.as_bytes()).await?;

        // Get RAII buffer from pool - automatically returns on drop
        let mut pooled_buffer = PooledBuffer::new(
            self.buffer_pool.clone(), 
            self.config.buffer_size, 
            self.config.buffer_pool_size
        );
        let buffer = pooled_buffer.as_mut();

        // Read response
        let mut response = Vec::new();
        
        loop {
            match timeout(
                Duration::from_secs(self.config.whois_timeout_seconds),
                stream.read(buffer)
            ).await? {
                Ok(0) => break, // EOF
                Ok(n) => {
                    response.extend_from_slice(&buffer[..n]);
                    if response.len() > self.config.max_response_size {
                        return Err(WhoisError::ResponseTooLarge);
                    }
                }
                Err(e) => {
                    return Err(WhoisError::IoError(e));
                }
            }
        }

        // Buffer automatically returns to pool when pooled_buffer goes out of scope
        String::from_utf8(response).map_err(|_| WhoisError::InvalidUtf8)
    }

    async fn follow_referrals(&self, initial_server: &str, initial_data: &str, domain: &str) -> Result<(String, String), WhoisError> {
        let mut current_server = initial_server.to_string();
        let mut current_data = initial_data.to_string();
        let mut referral_count = 0;
        let max_referrals = self.config.max_referrals;

        while referral_count < max_referrals {
            if let Some(referral_server) = self.extract_whois_server(&current_data) {
                if referral_server != current_server {
                    debug!("Following referral from {} to {}", current_server, referral_server);
                    
                    match self.raw_whois_query(&referral_server, domain).await {
                        Ok(new_data) => {
                            current_server = referral_server;
                            current_data = new_data;
                            referral_count += 1;
                            continue;
                        }
                        Err(e) => {
                            warn!("Failed to query referral server {}: {}", referral_server, e);
                            break;
                        }
                    }
                }
            }
            break;
        }

        Ok((current_server, current_data))
    }

    fn extract_whois_server(&self, data: &str) -> Option<String> {
        for line in data.lines() {
            let line = line.trim();
            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                
                if (key.contains("whois") && key.contains("server")) || key == "refer" {
                    return Some(value.to_string());
                }
            }
        }
        None
    }

    fn parse_whois_data(&self, data: &str) -> Option<ParsedWhoisData> {
        let mut parsed = ParsedWhoisData {
            registrar: None,
            creation_date: None,
            expiration_date: None,
            updated_date: None,
            name_servers: Vec::new(),
            status: Vec::new(),
            registrant_name: None,
            registrant_email: None,
            admin_email: None,
            tech_email: None,
            created_ago: None,
            updated_ago: None,
            expires_in: None,
        };

        for line in data.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('%') || line.starts_with('#') || line.starts_with(">>>") {
                continue;
            }

            if let Some((key, value)) = line.split_once(':') {
                let key = key.trim().to_lowercase();
                let value = value.trim();
                
                if value.is_empty() {
                    continue;
                }

                // Match field patterns more intelligently (order matters - most specific first)
                match key.as_str() {
                    // Expiration date patterns (check first to catch "Registrar Registration Expiration Date")
                    k if k.contains("expir") || k.contains("expires") => {
                        if parsed.expiration_date.is_none() {
                            parsed.expiration_date = Some(value.to_string());
                        }
                    },
                    
                    // Creation date patterns
                    k if k.contains("creation") || k.contains("created") || k == "registered" => {
                        if parsed.creation_date.is_none() {
                            parsed.creation_date = Some(value.to_string());
                        }
                    },
                    
                    // Updated date patterns
                    k if k.contains("updated") || k.contains("modified") || k.contains("last updated") => {
                        if parsed.updated_date.is_none() {
                            parsed.updated_date = Some(value.to_string());
                        }
                    },
                    
                    // Registrar patterns (after date patterns to avoid conflicts)
                    k if k.contains("registrar") && !k.contains("whois") && !k.contains("url") && !k.contains("abuse") && !k.contains("expir") && !k.contains("registration") => {
                        if parsed.registrar.is_none() {
                            parsed.registrar = Some(value.to_string());
                        }
                    },
                    
                    // Name server patterns
                    k if k.contains("name server") || k == "nserver" || k == "ns" => {
                        // Extract just the hostname, ignore IP addresses
                        let server = value.split_whitespace().next().unwrap_or(value);
                        if !parsed.name_servers.contains(&server.to_string()) {
                            parsed.name_servers.push(server.to_string());
                        }
                    },
                    
                    // Status patterns
                    k if k.contains("status") || k.contains("state") => {
                        if !parsed.status.contains(&value.to_string()) {
                            parsed.status.push(value.to_string());
                        }
                    },
                    
                    // Registrant name patterns
                    k if k.starts_with("registrant") && (k.contains("name") || k.contains("organization") || k.contains("org") || k == "registrant") => {
                        if parsed.registrant_name.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.registrant_name = Some(value.to_string());
                        }
                    },
                    
                    // Email patterns
                    k if k.contains("registrant") && k.contains("email") => {
                        if parsed.registrant_email.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.registrant_email = Some(value.to_string());
                        }
                    },
                    k if k.contains("admin") && k.contains("email") => {
                        if parsed.admin_email.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.admin_email = Some(value.to_string());
                        }
                    },
                    k if k.contains("tech") && k.contains("email") => {
                        if parsed.tech_email.is_none() && !value.to_lowercase().contains("select request") {
                            parsed.tech_email = Some(value.to_string());
                        }
                    },
                    
                    _ => {} // Ignore unrecognized fields
                }
            }
        }

        // Calculate date-based fields
        let now = Utc::now();
        
        // Calculate created_ago (days since creation)
        if let Some(ref creation_date) = parsed.creation_date {
            if let Some(created_dt) = self.parse_date(creation_date) {
                let days_ago = (now - created_dt).num_days();
                parsed.created_ago = Some(days_ago);
            }
        }
        
        // Calculate updated_ago (days since last update)
        if let Some(ref updated_date) = parsed.updated_date {
            if let Some(updated_dt) = self.parse_date(updated_date) {
                let days_ago = (now - updated_dt).num_days();
                parsed.updated_ago = Some(days_ago);
            }
        }
        
        // Calculate expires_in (days until expiration, negative if expired)
        if let Some(ref expiration_date) = parsed.expiration_date {
            if let Some(expires_dt) = self.parse_date(expiration_date) {
                let days_until = (expires_dt - now).num_days();
                parsed.expires_in = Some(days_until);
            }
        }

        Some(parsed)
    }

    /// Parse various date formats commonly found in whois data
    fn parse_date(&self, date_str: &str) -> Option<DateTime<Utc>> {
        let date_str = date_str.trim();
        
        // Common whois date formats to try
        let formats = [
            "%Y-%m-%dT%H:%M:%S%.fZ",           // 2025-05-18T13:36:06.0Z
            "%Y-%m-%dT%H:%M:%S%z",             // 2025-05-18T13:36:06+0000
            "%Y-%m-%d %H:%M:%S",               // 2025-05-18 13:36:06
            "%Y-%m-%d",                        // 2025-05-18
            "%d-%b-%Y",                        // 18-May-2025
            "%d %b %Y",                        // 18 May 2025
            "%Y/%m/%d",                        // 2025/05/18
            "%m/%d/%Y",                        // 05/18/2025
            "%d.%m.%Y",                        // 18.05.2025
        ];

        // Try parsing with timezone first
        for format in &formats {
            if let Ok(dt) = DateTime::parse_from_str(date_str, format) {
                return Some(dt.with_timezone(&Utc));
            }
        }

        // Try parsing as naive datetime and assume UTC
        for format in &formats {
            if let Ok(naive_dt) = NaiveDateTime::parse_from_str(date_str, format) {
                return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
            }
        }

        // Try parsing just the date part and assume midnight UTC
        let date_only_formats = [
            "%Y-%m-%d",
            "%d-%b-%Y", 
            "%d %b %Y",
            "%Y/%m/%d",
            "%m/%d/%Y",
            "%d.%m.%Y",
        ];

        for format in &date_only_formats {
            if let Ok(naive_date) = chrono::NaiveDate::parse_from_str(date_str, format) {
                if let Some(naive_dt) = naive_date.and_hms_opt(0, 0, 0) {
                    return Some(DateTime::from_naive_utc_and_offset(naive_dt, Utc));
                }
            }
        }

        debug!("Failed to parse date: {}", date_str);
        None
    }

    fn parse_whois_data_with_analysis(&self, data: &str) -> (Option<ParsedWhoisData>, Vec<String>) {
        let mut analysis = Vec::new();
        
        // Parse the data
        let parsed_data = self.parse_whois_data(data);
        
        // Analyze what was found
        analysis.push("=== PARSING ANALYSIS ===".to_string());
        
        if let Some(ref parsed) = parsed_data {
            analysis.push(format!("✓ Registrar: {}", parsed.registrar.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Creation Date: {}", parsed.creation_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Expiration Date: {}", parsed.expiration_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Updated Date: {}", parsed.updated_date.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Registrant Name: {}", parsed.registrant_name.as_ref().unwrap_or(&"NOT FOUND".to_string())));
            analysis.push(format!("✓ Name Servers: {} found", parsed.name_servers.len()));
            analysis.push(format!("✓ Status: {} found", parsed.status.len()));
        }
        
        // Show lines that might contain registrant info
        analysis.push("\n=== LINES CONTAINING 'REGISTRANT' ===".to_string());
        for (i, line) in data.lines().enumerate() {
            if line.to_lowercase().contains("registrant") {
                analysis.push(format!("Line {}: {}", i + 1, line.trim()));
            }
        }
        
        // Show lines that might contain expiry info
        analysis.push("\n=== LINES CONTAINING 'EXPIR' ===".to_string());
        for (i, line) in data.lines().enumerate() {
            if line.to_lowercase().contains("expir") {
                analysis.push(format!("Line {}: {}", i + 1, line.trim()));
            }
        }
        
        (parsed_data, analysis)
    }
} 