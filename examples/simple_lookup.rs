//! Simple example of using the whois-service library
//! 
//! Run with: cargo run --example simple_lookup --no-default-features

use whois_service::{WhoisClient, WhoisError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing for better debugging
    tracing_subscriber::fmt()
        .with_env_filter("whois_service=info")
        .init();

    println!("🔍 Whois Service Library Example");
    println!("================================");

    // Create a whois client without caching for this example
    let client = WhoisClient::new_without_cache().await?;
    
    // Test domains
    let test_domains = vec![
        "google.com",
        "github.com", 
        "rust-lang.org",
    ];

    for domain in test_domains {
        println!("\n📋 Looking up: {}", domain);
        println!("{}", "─".repeat(50));
        
        match client.lookup(domain).await {
            Ok(result) => {
                println!("✅ Success!");
                println!("   Server: {}", result.whois_server);
                println!("   Cached: {}", result.cached);
                
                if let Some(parsed) = &result.parsed_data {
                    println!("   Registrar: {}", parsed.registrar.as_deref().unwrap_or("Unknown"));
                    println!("   Created: {}", parsed.creation_date.as_deref().unwrap_or("Unknown"));
                    println!("   Expires: {}", parsed.expiration_date.as_deref().unwrap_or("Unknown"));
                    
                    if let Some(days_ago) = parsed.created_ago {
                        println!("   Age: {} days", days_ago);
                    }
                    
                    if let Some(expires_in) = parsed.expires_in {
                        if expires_in > 0 {
                            println!("   Expires in: {} days", expires_in);
                        } else {
                            println!("   ⚠️  EXPIRED {} days ago", expires_in.abs());
                        }
                    }
                    
                    if !parsed.name_servers.is_empty() {
                        println!("   Name servers: {}", parsed.name_servers.len());
                        for (i, ns) in parsed.name_servers.iter().take(3).enumerate() {
                            println!("     {}. {}", i + 1, ns);
                        }
                        if parsed.name_servers.len() > 3 {
                            println!("     ... and {} more", parsed.name_servers.len() - 3);
                        }
                    }
                } else {
                    println!("   ⚠️  No parsed data available");
                }
            }
            Err(WhoisError::UnsupportedTld(tld)) => {
                println!("❌ Unsupported TLD: {}", tld);
            }
            Err(WhoisError::InvalidDomain(msg)) => {
                println!("❌ Invalid domain: {}", msg);
            }
            Err(WhoisError::Timeout) => {
                println!("❌ Timeout - server took too long to respond");
            }
            Err(e) => {
                println!("❌ Error: {}", e);
            }
        }
    }

    println!("\n🎉 Example completed!");
    Ok(())
} 