# Whois Service

A high-performance, production-ready whois lookup service and library for Rust.

## Features

- 🚀 **High Performance**: Built with Rust + Tokio for maximum throughput (870+ lookups/minute)
- 🌐 **Dynamic TLD Discovery**: No hardcoded values - discovers whois servers via IANA
- 🧠 **Intelligent Parsing**: Structured data extraction with calculated fields
- 💾 **Smart Caching**: Optional caching with domain normalization
- 🔧 **Zero Configuration**: Works out of the box with sensible defaults
- 📊 **Production Ready**: Comprehensive error handling, metrics, and logging
- 📚 **Library + Service**: Use as a Rust library or standalone web service

## Quick Start

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
whois-service = { version = "0.1", default-features = false }
```

Basic usage:

```rust
use whois_service::WhoisClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?;
    let result = client.lookup("google.com").await?;
    
    println!("Domain: {}", result.domain);
    println!("Registrar: {:?}", result.parsed_data.as_ref()
        .and_then(|p| p.registrar.as_ref()));
    
    Ok(())
}
```

### As a Web Service

```bash
# Run the web service
cargo run --release

# Query via HTTP
curl "http://localhost:3000/whois/google.com" | jq .
```

## Library API

### WhoisClient

The main client for performing whois lookups:

```rust
// Create with default configuration (includes caching)
let client = WhoisClient::new().await?;

// Create without caching
let client = WhoisClient::new_without_cache().await?;

// Create with custom configuration
let config = Arc::new(Config::load()?);
let client = WhoisClient::new_with_config(config).await?;
```

### Lookup Methods

```rust
// Standard lookup (uses cache if available)
let result = client.lookup("example.com").await?;

// Fresh lookup (bypasses cache)
let result = client.lookup_fresh("example.com").await?;

// Lookup with options
let result = client.lookup_with_options("example.com", true).await?; // true = fresh
```

### Response Structure

```rust
pub struct WhoisResponse {
    pub domain: String,
    pub whois_server: String,
    pub raw_data: String,
    pub parsed_data: Option<ParsedWhoisData>,
    pub cached: bool,
    pub query_time_ms: u64,
    pub parsing_analysis: Option<Vec<String>>, // Only in debug mode
}

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
    pub created_ago: Option<i64>,    // Days since creation
    pub updated_ago: Option<i64>,    // Days since last update  
    pub expires_in: Option<i64>,     // Days until expiration (negative if expired)
}
```

## Web Service API

### Endpoints

- `GET /whois?domain=example.com` - Basic whois lookup
- `GET /whois/example.com` - Path-based lookup
- `POST /whois` - JSON body: `{"domain": "example.com", "fresh": false}`
- `GET /whois/debug?domain=example.com` - Debug lookup with parsing analysis
- `GET /whois/debug/example.com` - Path-based debug lookup
- `GET /health` - Health check
- `GET /metrics` - Prometheus metrics

### Query Parameters

- `domain` (required): Domain name to lookup
- `fresh` (optional): Skip cache if true

### Example Responses

Basic lookup:
```json
{
  "domain": "google.com",
  "whois_server": "whois.verisign-grs.com",
  "cached": false,
  "query_time_ms": 665,
  "parsed_data": {
    "registrar": "MarkMonitor Inc.",
    "creation_date": "1997-09-15T04:00:00Z",
    "expiration_date": "2028-09-14T04:00:00Z",
    "updated_date": "2019-09-09T15:39:04Z",
    "created_ago": 10024,
    "updated_ago": 1906,
    "expires_in": 1387,
    "name_servers": ["ns1.google.com", "ns2.google.com", "ns3.google.com", "ns4.google.com"],
    "status": ["clientDeleteProhibited", "clientTransferProhibited", "clientUpdateProhibited"]
  }
}
```

Debug lookup (includes parsing analysis):
```json
{
  "domain": "google.com",
  "whois_server": "whois.verisign-grs.com",
  "cached": false,
  "query_time_ms": 665,
  "parsed_data": { /* ... same as above ... */ },
  "parsing_analysis": [
    "Found registrar: MarkMonitor Inc.",
    "Found creation date: 1997-09-15T04:00:00Z",
    "Found expiration date: 2028-09-14T04:00:00Z",
    "Found 4 name servers",
    "Found 3 status codes"
  ]
}
```

## Configuration

Configuration via environment variables:

```bash
# Server settings
PORT=3000
ENVIRONMENT=production

# Performance tuning
CONCURRENT_WHOIS_QUERIES=50
WHOIS_TIMEOUT_SECONDS=30
DISCOVERY_TIMEOUT_SECONDS=10

# Caching
CACHE_MAX_ENTRIES=10000
CACHE_TTL_SECONDS=3600

# Buffer management
BUFFER_POOL_SIZE=100
BUFFER_SIZE=16384
```

## Examples

Run the included examples:

```bash
# Simple library usage
cargo run --example simple_lookup

# Integration example with error handling and batch processing
cargo run --example integration_example
```

## Performance

- **Throughput**: 870+ fresh lookups per minute
- **Cached Performance**: Sub-microsecond response times (11µs typical)
- **Fresh Lookup Latency**: ~250-750ms per lookup (network dependent)
- **Memory**: Efficient buffer pooling and caching
- **Concurrency**: Configurable semaphore-based limiting

### Performance Comparison

| Operation Type | Response Time | Improvement |
|---------------|---------------|-------------|
| Fresh Lookup | 341ms | Baseline |
| Cached Lookup | 14µs | 24,357x faster |

## Architecture

### Core Components

1. **WhoisService**: Core lookup engine with dynamic TLD discovery
2. **CacheService**: Smart caching with domain normalization  
3. **Config**: System-adaptive configuration
4. **Metrics**: Prometheus metrics collection
5. **Errors**: Comprehensive error handling

### Key Features

- **RAII Buffer Pool**: Automatic memory management with `Drop` trait
- **Global PSL**: Mozilla Public Suffix List for accurate TLD extraction
- **Async/Await**: Full async support with Tokio
- **Zero Hardcoding**: All servers discovered dynamically via IANA
- **Production Ready**: Graceful shutdown, error tracking, metrics
- **Smart Domain Normalization**: Handles case, whitespace, trailing dots
- **Intelligent Referral Following**: Follows whois server redirects automatically

## Error Handling

The library provides detailed error types:

```rust
pub enum WhoisError {
    InvalidDomain(String),
    UnsupportedTld(String),
    Timeout,
    IoError(tokio::io::Error),
    HttpError(reqwest::Error),
    RegexError(regex::Error),
    ResponseTooLarge,
    InvalidUtf8,
    ConfigError(config::ConfigError),
    CacheError(String),
    Internal(String),
}
```

All errors implement proper error handling with graceful degradation:
- Cache errors don't fail requests
- Network timeouts are handled gracefully
- Invalid domains are validated early
- Comprehensive logging for debugging

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Ensure all tests pass: `cargo test`
5. Submit a pull request

## License

Licensed under either of:

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT License ([LICENSE-MIT](LICENSE-MIT))

at your option.

## Changelog

### v0.1.0
- Initial release
- Dynamic TLD discovery via IANA
- Smart caching with domain normalization
- Production-ready web service
- Comprehensive library API
- RAII buffer pool management
- Mozilla Public Suffix List integration
- Calculated date fields (created_ago, updated_ago, expires_in)
- Graceful error handling and degradation 