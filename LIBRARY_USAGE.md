# Library Usage Guide

This guide provides comprehensive examples for using the whois service as a Rust library in your applications.

## 📦 Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
whois-service = "0.1.0"
tokio = { version = "1.0", features = ["full"] }
```

## 🚀 Basic Usage

### Simple Domain Lookup

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let result = client.lookup("google.com").await?;
    
    println!("Server: {}", result.server);
    println!("Cached: {}", result.cached);
    
    if let Some(data) = result.parsed_data {
        println!("Registrar: {:?}", data.registrar);
        println!("Created: {:?}", data.created);
        println!("Expires: {:?}", data.expires);
        println!("Domain age: {} days", data.created_ago.unwrap_or(0));
        println!("Expires in: {} days", data.expires_in.unwrap_or(0));
    }
    
    Ok(())
}
```

### Error Handling

```rust
use whois_service::{WhoisClient, WhoisError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    match client.lookup("invalid-domain").await {
        Ok(result) => {
            println!("Success: {}", result.server);
        }
        Err(WhoisError::InvalidDomain(domain)) => {
            println!("Invalid domain: {}", domain);
        }
        Err(WhoisError::UnsupportedTld(tld)) => {
            println!("Unsupported TLD: {}", tld);
        }
        Err(WhoisError::NetworkTimeout) => {
            println!("Network timeout - try again later");
        }
        Err(e) => {
            println!("Other error: {}", e);
        }
    }
    
    Ok(())
}
```

## 🔧 Configuration Options

### Custom Configuration

```rust
use whois_service::{WhoisClient, Config};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = Config {
        whois_timeout_seconds: 15,
        cache_ttl_seconds: 1800,
        cache_max_entries: 5000,
        concurrent_whois_queries: 4,
        ..Default::default()
    };
    
    let client = WhoisClient::new_with_config(config).await?;
    let result = client.lookup("example.com").await?;
    
    println!("Result: {:?}", result.parsed_data);
    Ok(())
}
```

### Without Caching

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create client without caching for memory-constrained environments
    let client = WhoisClient::new_without_cache().await?;
    
    let result = client.lookup("github.com").await?;
    println!("Server: {}", result.server);
    // result.cached will always be false
    
    Ok(())
}
```

## 🔄 Batch Processing

### Sequential Processing

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let domains = vec!["google.com", "github.com", "rust-lang.org"];
    
    for domain in domains {
        match client.lookup(domain).await {
            Ok(result) => {
                println!("✅ {}: {} (cached: {})", 
                    domain, result.server, result.cached);
            }
            Err(e) => {
                println!("❌ {}: {}", domain, e);
            }
        }
    }
    
    Ok(())
}
```

### Concurrent Processing

```rust
use whois_service::WhoisClient;
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let domains = vec![
        "google.com", "github.com", "rust-lang.org", 
        "stackoverflow.com", "reddit.com"
    ];
    
    let mut join_set = JoinSet::new();
    
    for domain in domains {
        let client_clone = client.clone();
        let domain_owned = domain.to_string();
        
        join_set.spawn(async move {
            let result = client_clone.lookup(&domain_owned).await;
            (domain_owned, result)
        });
    }
    
    while let Some(result) = join_set.join_next().await {
        match result? {
            (domain, Ok(whois_result)) => {
                println!("✅ {}: {} ({}ms)", 
                    domain, 
                    whois_result.server,
                    whois_result.query_time_ms
                );
            }
            (domain, Err(e)) => {
                println!("❌ {}: {}", domain, e);
            }
        }
    }
    
    Ok(())
}
```

## 📊 Performance Monitoring

### Timing and Metrics

```rust
use whois_service::WhoisClient;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let start = Instant::now();
    let result = client.lookup("example.com").await?;
    let duration = start.elapsed();
    
    println!("Query completed in: {:?}", duration);
    println!("Server response time: {}ms", result.query_time_ms);
    println!("Cache hit: {}", result.cached);
    
    if let Some(data) = result.parsed_data {
        println!("Parsed {} fields", data.name_servers.len());
    }
    
    Ok(())
}
```

### Cache Performance Testing

```rust
use whois_service::WhoisClient;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    let domain = "google.com";
    
    // First lookup (cache miss)
    let start = Instant::now();
    let result1 = client.lookup(domain).await?;
    let fresh_time = start.elapsed();
    
    // Second lookup (cache hit)
    let start = Instant::now();
    let result2 = client.lookup(domain).await?;
    let cached_time = start.elapsed();
    
    println!("Fresh lookup: {:?} (cached: {})", fresh_time, result1.cached);
    println!("Cached lookup: {:?} (cached: {})", cached_time, result2.cached);
    println!("Cache speedup: {:.1}x", 
        fresh_time.as_nanos() as f64 / cached_time.as_nanos() as f64);
    
    Ok(())
}
```

## 🌐 Advanced Use Cases

### Domain Validation Service

```rust
use whois_service::WhoisClient;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct DomainInfo {
    domain: String,
    is_registered: bool,
    registrar: Option<String>,
    expires_in_days: Option<i64>,
    risk_level: String,
}

async fn validate_domain(client: &WhoisClient, domain: &str) -> DomainInfo {
    match client.lookup(domain).await {
        Ok(result) => {
            let parsed = result.parsed_data.as_ref();
            let expires_in = parsed.and_then(|p| p.expires_in);
            
            let risk_level = match expires_in {
                Some(days) if days < 30 => "HIGH".to_string(),
                Some(days) if days < 90 => "MEDIUM".to_string(),
                Some(_) => "LOW".to_string(),
                None => "UNKNOWN".to_string(),
            };
            
            DomainInfo {
                domain: domain.to_string(),
                is_registered: true,
                registrar: parsed.and_then(|p| p.registrar.clone()),
                expires_in_days: expires_in,
                risk_level,
            }
        }
        Err(_) => DomainInfo {
            domain: domain.to_string(),
            is_registered: false,
            registrar: None,
            expires_in_days: None,
            risk_level: "UNREGISTERED".to_string(),
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let domains = vec!["google.com", "github.com", "nonexistent-domain-12345.com"];
    
    for domain in domains {
        let info = validate_domain(&client, domain).await;
        println!("{}: {} (Risk: {})", 
            info.domain, 
            if info.is_registered { "Registered" } else { "Available" },
            info.risk_level
        );
    }
    
    Ok(())
}
```

### Monitoring Service

```rust
use whois_service::WhoisClient;
use tokio::time::{interval, Duration};

struct DomainMonitor {
    client: WhoisClient,
    domains: Vec<String>,
}

impl DomainMonitor {
    async fn new(domains: Vec<String>) -> Result<Self, Box<dyn std::error::Error>> {
        let client = WhoisClient::new().await?;
        Ok(Self { client, domains })
    }
    
    async fn check_expiration(&self, domain: &str) -> Option<i64> {
        match self.client.lookup(domain).await {
            Ok(result) => {
                result.parsed_data
                    .and_then(|data| data.expires_in)
            }
            Err(e) => {
                eprintln!("Error checking {}: {}", domain, e);
                None
            }
        }
    }
    
    async fn monitor(&self) {
        let mut interval = interval(Duration::from_secs(3600)); // Check hourly
        
        loop {
            interval.tick().await;
            
            println!("🔍 Checking domain expirations...");
            
            for domain in &self.domains {
                if let Some(days) = self.check_expiration(domain).await {
                    if days < 30 {
                        println!("⚠️  {} expires in {} days!", domain, days);
                    } else {
                        println!("✅ {} expires in {} days", domain, days);
                    }
                }
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let domains = vec![
        "google.com".to_string(),
        "github.com".to_string(),
        "rust-lang.org".to_string(),
    ];
    
    let monitor = DomainMonitor::new(domains).await?;
    monitor.monitor().await;
    
    Ok(())
}
```

## 🔧 Integration Patterns

### With Web Frameworks (Axum)

```rust
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::Json,
    routing::get,
    Router,
};
use serde_json::{json, Value};
use whois_service::WhoisClient;

type AppState = WhoisClient;

async fn lookup_domain(
    State(client): State<AppState>,
    Path(domain): Path<String>,
) -> Result<Json<Value>, StatusCode> {
    match client.lookup(&domain).await {
        Ok(result) => Ok(Json(json!({
            "domain": domain,
            "server": result.server,
            "cached": result.cached,
            "data": result.parsed_data
        }))),
        Err(_) => Err(StatusCode::NOT_FOUND),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let app = Router::new()
        .route("/whois/:domain", get(lookup_domain))
        .with_state(client);
    
    println!("Server running on http://localhost:3000");
    
    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await?;
    axum::serve(listener, app).await?;
    
    Ok(())
}
```

### With Databases (SQLx)

```rust
use whois_service::WhoisClient;
use sqlx::{PgPool, Row};
use chrono::{DateTime, Utc};

struct DomainRecord {
    domain: String,
    registrar: Option<String>,
    created: Option<DateTime<Utc>>,
    expires: Option<DateTime<Utc>>,
    last_checked: DateTime<Utc>,
}

async fn update_domain_info(
    pool: &PgPool,
    client: &WhoisClient,
    domain: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let result = client.lookup(domain).await?;
    
    let record = DomainRecord {
        domain: domain.to_string(),
        registrar: result.parsed_data.as_ref()
            .and_then(|d| d.registrar.clone()),
        created: result.parsed_data.as_ref()
            .and_then(|d| d.created),
        expires: result.parsed_data.as_ref()
            .and_then(|d| d.expires),
        last_checked: Utc::now(),
    };
    
    sqlx::query!(
        r#"
        INSERT INTO domains (domain, registrar, created, expires, last_checked)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (domain) DO UPDATE SET
            registrar = EXCLUDED.registrar,
            created = EXCLUDED.created,
            expires = EXCLUDED.expires,
            last_checked = EXCLUDED.last_checked
        "#,
        record.domain,
        record.registrar,
        record.created,
        record.expires,
        record.last_checked
    )
    .execute(pool)
    .await?;
    
    Ok(())
}
```

## 🚨 Error Handling Best Practices

### Comprehensive Error Handling

```rust
use whois_service::{WhoisClient, WhoisError};
use std::time::Duration;
use tokio::time::timeout;

async fn robust_lookup(
    client: &WhoisClient, 
    domain: &str
) -> Result<String, String> {
    // Add timeout wrapper
    let lookup_future = client.lookup(domain);
    let result = timeout(Duration::from_secs(60), lookup_future).await;
    
    match result {
        Ok(Ok(whois_result)) => {
            Ok(format!("Success: {} via {}", domain, whois_result.server))
        }
        Ok(Err(WhoisError::InvalidDomain(_))) => {
            Err(format!("Invalid domain format: {}", domain))
        }
        Ok(Err(WhoisError::UnsupportedTld(tld))) => {
            Err(format!("TLD '{}' not supported", tld))
        }
        Ok(Err(WhoisError::NetworkTimeout)) => {
            Err(format!("Network timeout for {}", domain))
        }
        Ok(Err(WhoisError::IoError(e))) => {
            Err(format!("Network error for {}: {}", domain, e))
        }
        Ok(Err(e)) => {
            Err(format!("Whois error for {}: {}", domain, e))
        }
        Err(_) => {
            Err(format!("Operation timeout for {}", domain))
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    
    let test_domains = vec![
        "google.com",           // Should work
        "invalid..domain",      // Invalid format
        "test.invalidtld",      // Unsupported TLD
        "slow-server.ly",       // Might timeout
    ];
    
    for domain in test_domains {
        match robust_lookup(&client, domain).await {
            Ok(msg) => println!("✅ {}", msg),
            Err(msg) => println!("❌ {}", msg),
        }
    }
    
    Ok(())
}
```

## 📈 Performance Tips

1. **Reuse the client**: Create one `WhoisClient` and clone it for concurrent use
2. **Enable caching**: Use `WhoisClient::new()` instead of `new_without_cache()`
3. **Batch processing**: Use concurrent lookups for multiple domains
4. **Error handling**: Implement proper timeouts and retry logic
5. **Memory management**: The client handles buffer pooling automatically

## 🔗 Related Examples

- [Simple Lookup](examples/simple_lookup.rs)
- [Integration Example](examples/integration_example.rs)
- [Batch Processing](examples/batch_processing.rs)
- [Performance Testing](examples/performance_test.rs)

For more examples and advanced usage patterns, check the [examples directory](examples/) in the repository. 