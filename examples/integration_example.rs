//! Integration example showing how to use whois-service in your application
//! 
//! This example demonstrates:
//! - Error handling
//! - Batch processing
//! - Custom configuration
//! - Caching benefits

use whois_service::{WhoisClient, WhoisError, Config};
use std::sync::Arc;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter("whois_service=info")
        .init();

    println!("🚀 Whois Service Integration Example");
    println!("====================================");

    // Example 1: Basic usage with error handling
    println!("\n1️⃣ Basic Usage with Error Handling");
    basic_usage_example().await?;

    // Example 2: Batch processing
    println!("\n2️⃣ Batch Processing");
    batch_processing_example().await?;

    // Example 3: Caching demonstration
    println!("\n3️⃣ Caching Benefits");
    caching_example().await?;

    // Example 4: Custom configuration
    println!("\n4️⃣ Custom Configuration");
    custom_config_example().await?;

    println!("\n✅ All examples completed successfully!");
    Ok(())
}

async fn basic_usage_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new_without_cache().await?;
    
    let test_cases = vec![
        ("google.com", true),      // Valid domain
        ("invalid", false),        // Invalid domain
        ("nonexistent.invalidtld", false), // Unsupported TLD
    ];

    for (domain, should_succeed) in test_cases {
        print!("   Testing {}: ", domain);
        
        match client.lookup(domain).await {
            Ok(result) => {
                if should_succeed {
                    println!("✅ Success - Registrar: {}", 
                        result.parsed_data.as_ref()
                            .and_then(|p| p.registrar.as_ref())
                            .unwrap_or(&"Unknown".to_string()));
                } else {
                    println!("❌ Unexpected success");
                }
            }
            Err(WhoisError::InvalidDomain(_)) => {
                if !should_succeed {
                    println!("✅ Expected error - Invalid domain");
                } else {
                    println!("❌ Unexpected error");
                }
            }
            Err(WhoisError::UnsupportedTld(_)) => {
                if !should_succeed {
                    println!("✅ Expected error - Unsupported TLD");
                } else {
                    println!("❌ Unexpected error");
                }
            }
            Err(e) => {
                println!("❌ Error: {}", e);
            }
        }
    }
    
    Ok(())
}

async fn batch_processing_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new_without_cache().await?;
    
    let domains = vec![
        "github.com",
        "stackoverflow.com", 
        "rust-lang.org",
    ];

    println!("   Processing {} domains...", domains.len());
    let start = Instant::now();
    
    // Process domains concurrently
    let mut handles = Vec::new();
    
    for domain in domains {
        let client_clone = client.clone(); // WhoisClient is cheaply cloneable
        let domain = domain.to_string();
        
        let handle = tokio::spawn(async move {
            match client_clone.lookup(&domain).await {
                Ok(result) => {
                    let registrar = result.parsed_data.as_ref()
                        .and_then(|p| p.registrar.as_ref())
                        .map(|s| s.clone())
                        .unwrap_or_else(|| "Unknown".to_string());
                    (domain, Ok(registrar))
                }
                Err(e) => (domain, Err(e.to_string()))
            }
        });
        
        handles.push(handle);
    }
    
    // Collect results
    let mut successful = 0;
    let mut failed = 0;
    
    for handle in handles {
        match handle.await? {
            (domain, Ok(registrar)) => {
                println!("   ✅ {}: {}", domain, registrar);
                successful += 1;
            }
            (domain, Err(error)) => {
                println!("   ❌ {}: {}", domain, error);
                failed += 1;
            }
        }
    }
    
    let elapsed = start.elapsed();
    println!("   📊 Results: {} successful, {} failed in {:?}", 
        successful, failed, elapsed);
    
    Ok(())
}

async fn caching_example() -> Result<(), Box<dyn std::error::Error>> {
    let client = WhoisClient::new().await?; // With caching enabled
    let domain = "example.com";
    
    // First lookup (cache miss)
    println!("   First lookup (cache miss):");
    let start = Instant::now();
    let result1 = client.lookup(domain).await?;
    let first_time = start.elapsed();
    println!("     Time: {:?}, Cached: {}", first_time, result1.cached);
    
    // Second lookup (cache hit)
    println!("   Second lookup (cache hit):");
    let start = Instant::now();
    let result2 = client.lookup(domain).await?;
    let second_time = start.elapsed();
    println!("     Time: {:?}, Cached: {}", second_time, result2.cached);
    
    // Show performance improvement
    if second_time < first_time {
        let improvement = ((first_time.as_millis() as f64 - second_time.as_millis() as f64) 
            / first_time.as_millis() as f64) * 100.0;
        println!("   🚀 Cache improved performance by {:.1}%", improvement);
    }
    
    Ok(())
}

async fn custom_config_example() -> Result<(), Box<dyn std::error::Error>> {
    // Load default config and modify it
    let mut config = Config::load()?;
    
    // Customize settings for this application
    config.whois_timeout_seconds = 15;  // Shorter timeout
    config.cache_ttl_seconds = 1800;    // 30 minute cache
    config.concurrent_whois_queries = 25; // Lower concurrency
    
    let client = WhoisClient::new_with_config(Arc::new(config)).await?;
    
    println!("   Using custom configuration:");
    println!("     - Timeout: 15 seconds");
    println!("     - Cache TTL: 30 minutes");
    println!("     - Max concurrent queries: 25");
    
    let result = client.lookup("rust-lang.org").await?;
    println!("   ✅ Lookup successful with custom config");
    println!("     Server: {}", result.whois_server);
    
    Ok(())
}

 