use axum::{
    extract::{Query, State, FromRequestParts},
    response::Json,
    routing::{get, post},
    Router,
    http::request::Parts,
};
use serde::{Deserialize, Serialize};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpListener;
use tower::ServiceBuilder;
use tower_http::{
    cors::CorsLayer,
    trace::TraceLayer,
    compression::CompressionLayer,
};
use tracing::info;

mod whois;
mod cache;
mod config;
mod metrics;
mod errors;

use whois::WhoisService;
use cache::CacheService;
use config::Config;
use errors::WhoisError;

#[derive(Clone)]
pub struct AppState {
    whois_service: Arc<WhoisService>,
    cache_service: Arc<CacheService>,
    config: Arc<Config>,
}

// Domain validation extractor
#[derive(Debug, Clone)]
pub struct ValidatedDomain(pub String);

#[axum::async_trait]
impl<S> FromRequestParts<S> for ValidatedDomain
where
    S: Send + Sync,
{
    type Rejection = WhoisError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        // Extract domain from path parameters
        let path = parts.uri.path();
        
        // Handle /whois/debug/:domain
        if let Some(domain_part) = path.strip_prefix("/whois/debug/") {
            let domain = domain_part.split('/').next().unwrap_or("").to_string();
            if !domain.is_empty() {
                return Self::validate_domain(domain);
            }
        }
        
        // Handle /whois/:domain
        if let Some(domain_part) = path.strip_prefix("/whois/") {
            let domain = domain_part.split('/').next().unwrap_or("").to_string();
            if !domain.is_empty() {
                return Self::validate_domain(domain);
            }
        }
        
        Err(WhoisError::InvalidDomain("Domain not found in path".to_string()))
    }
}

impl ValidatedDomain {
    pub fn validate_domain(domain: String) -> Result<Self, WhoisError> {
        let domain = domain.trim().to_lowercase();
        
        if domain.is_empty() {
            metrics::increment_errors("invalid_domain");
            return Err(WhoisError::InvalidDomain("Empty domain".to_string()));
        }
        
        if domain.len() > 253 {
            metrics::increment_errors("domain_too_long");
            return Err(WhoisError::InvalidDomain("Domain name too long".to_string()));
        }
        
        if !domain.contains('.') {
            metrics::increment_errors("invalid_domain_format");
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }
        
        // Add more sophisticated validation
        if domain.contains("..") || domain.starts_with('.') || domain.ends_with('.') {
            metrics::increment_errors("invalid_domain_format");
            return Err(WhoisError::InvalidDomain("Invalid domain format".to_string()));
        }
        
        Ok(ValidatedDomain(domain))
    }
    
    pub(crate) fn from_query_params(params: &WhoisQuery) -> Result<Self, WhoisError> {
        Self::validate_domain(params.domain.clone())
    }
}

#[derive(Deserialize)]
struct WhoisQuery {
    /// Domain name to lookup (e.g., "example.com")
    /// Must be a valid, pre-parsed domain name
    domain: String,
    #[serde(default)]
    /// Skip cache if true
    fresh: bool,
}

// Consolidated response structure
#[derive(Serialize, Clone)]
struct WhoisResponse {
    domain: String,
    whois_server: String,
    raw_data: String,
    parsed_data: Option<ParsedWhoisData>,
    cached: bool,
    query_time_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    parsing_analysis: Option<Vec<String>>, // Only include in debug mode
}

#[derive(Serialize, Clone)]
struct ParsedWhoisData {
    registrar: Option<String>,
    creation_date: Option<String>,
    expiration_date: Option<String>,
    updated_date: Option<String>,
    name_servers: Vec<String>,
    status: Vec<String>,
    registrant_name: Option<String>,
    registrant_email: Option<String>,
    admin_email: Option<String>,
    tech_email: Option<String>,
    created_ago: Option<i64>,  // Days since creation
    updated_ago: Option<i64>,  // Days since last update
    expires_in: Option<i64>,   // Days until expiration (negative if expired)
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    version: String,
    uptime_seconds: u64,
}



#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "whois_service=info,tower_http=debug".into()),
        )
        .init();

    // Load configuration
    let config = Arc::new(Config::load()?);
    info!("Configuration loaded successfully");

    // Initialize services
    let whois_service = Arc::new(WhoisService::new(config.clone()).await?);
    let cache_service = Arc::new(CacheService::new(config.clone())?);  // Handle cache initialization error

    // Initialize metrics
    metrics::init_metrics();

    let app_state = AppState {
        whois_service,
        cache_service,
        config: config.clone(),
    };

    // Build the application
    let app = Router::new()
        .route("/whois", get(whois_lookup))
        .route("/whois", post(whois_lookup_post))
        .route("/whois/:domain", get(whois_lookup_path))  // Path-based route for easier testing
        .route("/whois/debug", get(whois_debug))
        .route("/whois/debug/:domain", get(whois_debug_path))  // Path-based debug route
        .route("/health", get(health_check))
        .route("/metrics", get(metrics::metrics_handler))
        .layer(
            ServiceBuilder::new()
                .layer(TraceLayer::new_for_http())
                .layer(CompressionLayer::new())
                .layer(CorsLayer::permissive())
                .into_inner(),
        )
        .with_state(app_state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;
    
    info!("Whois service listening on {}", addr);
    info!("Health check: http://{}/health", addr);
    info!("Metrics: http://{}/metrics", addr);
    info!("API expects pre-parsed domain names (e.g., 'example.com')");

    // Graceful shutdown handling
    let shutdown_signal = async {
        tokio::signal::ctrl_c()
            .await
            .expect("Failed to install CTRL+C signal handler");
        info!("Received shutdown signal, gracefully shutting down...");
    };

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal)
        .await?;

    Ok(())
}

async fn whois_lookup(
    Query(params): Query<WhoisQuery>,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let start_time = std::time::Instant::now();
    
    // Validate domain using centralized validation
    let validated_domain = ValidatedDomain::from_query_params(&params)?;
    let domain = validated_domain.0;
    
    // Increment request counter
    metrics::increment_requests(&domain);

    // Check cache first (unless fresh is requested)
    if !params.fresh {
        match state.cache_service.get(&domain).await {
            Ok(Some(cached_result)) => {
                metrics::increment_cache_hits();
                return Ok(Json(cached_result));
            }
            Ok(None) => {
                // Cache miss, continue to fresh lookup
            }
            Err(e) => {
                tracing::warn!("Cache read error for {}: {}", domain, e);
                metrics::increment_errors("cache_read_error");
                // Continue to fresh lookup on cache error
            }
        }
    }

    // Perform whois lookup with error tracking
    let result = match state.whois_service.lookup(&domain).await {
        Ok(result) => result,
        Err(e) => {
            // Track specific error types
            match &e {
                WhoisError::Timeout => metrics::increment_errors("timeout"),
                WhoisError::UnsupportedTld(_) => metrics::increment_errors("unsupported_tld"),
                WhoisError::ResponseTooLarge => metrics::increment_errors("response_too_large"),
                WhoisError::IoError(_) => metrics::increment_errors("io_error"),
                WhoisError::InvalidUtf8 => metrics::increment_errors("invalid_utf8"),
                _ => metrics::increment_errors("other"),
            }
            return Err(e);
        }
    };
    
    let query_time = start_time.elapsed().as_millis() as u64;
    
    let response = WhoisResponse {
        domain: domain.clone(),
        whois_server: result.server,
        raw_data: result.raw_data,
        parsed_data: result.parsed_data,
        cached: false,
        query_time_ms: query_time,
        parsing_analysis: None, // No debug info for regular lookup
    };

    // Cache the result (with error handling)
    match tokio::time::timeout(
        std::time::Duration::from_secs(5),
        state.cache_service.set(&domain, &response)
    ).await {
        Ok(Ok(())) => {
            // Cache write successful
        }
        Ok(Err(e)) => {
            tracing::warn!("Failed to cache result for {}: {}", domain, e);
            metrics::increment_errors("cache_write_error");
        }
        Err(_) => {
            tracing::warn!("Cache write timeout for {}", domain);
            metrics::increment_errors("cache_write_timeout");
        }
    }
    
    metrics::record_query_time(query_time);
    metrics::increment_cache_misses();

    Ok(Json(response))
}

async fn whois_lookup_post(
    State(state): State<AppState>,
    Json(payload): Json<WhoisQuery>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    whois_lookup(Query(payload), State(state)).await
}

async fn whois_debug(
    Query(params): Query<WhoisQuery>,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let start_time = std::time::Instant::now();
    
    // Validate domain using centralized validation
    let validated_domain = ValidatedDomain::from_query_params(&params)?;
    let domain = validated_domain.0;
    
    // Increment request counter
    metrics::increment_requests(&domain);

    // Always perform fresh lookup for debug (no cache)
    let result = state.whois_service.lookup(&domain).await?;
    
    let query_time = start_time.elapsed().as_millis() as u64;
    
    let response = WhoisResponse {
        domain: domain.clone(),
        whois_server: result.server,
        raw_data: result.raw_data,
        parsed_data: result.parsed_data,
        cached: false,
        query_time_ms: query_time,
        parsing_analysis: Some(result.parsing_analysis), // Include debug info
    };

    metrics::record_query_time(query_time);

    Ok(Json(response))
}

// Path-based whois lookup for easier testing
async fn whois_lookup_path(
    validated_domain: ValidatedDomain,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let query = WhoisQuery { domain: validated_domain.0, fresh: false };
    whois_lookup(Query(query), State(state)).await
}

// Path-based debug lookup for easier testing
async fn whois_debug_path(
    validated_domain: ValidatedDomain,
    State(state): State<AppState>,
) -> Result<Json<WhoisResponse>, WhoisError> {
    let query = WhoisQuery { domain: validated_domain.0, fresh: false };
    whois_debug(Query(query), State(state)).await
}

async fn health_check(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        uptime_seconds: state.config.start_time.elapsed().as_secs(),
    })
} 