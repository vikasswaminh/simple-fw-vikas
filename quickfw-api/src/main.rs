use quickfw_api::logger::LogWriter;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;

use std::path::Path;

use axum::http::{header, HeaderValue};
use tracing::{error, info};

/// Security headers middleware — sets CSP, X-Frame-Options, etc. on every response.
async fn security_headers_middleware(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();

    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: ws:; font-src 'self'"
        ),
    );
    headers.insert(
        header::X_FRAME_OPTIONS,
        HeaderValue::from_static("DENY"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    headers.insert(
        "Permissions-Policy",
        HeaderValue::from_static("camera=(), microphone=(), geolocation=()"),
    );
    headers.insert(
        header::STRICT_TRANSPORT_SECURITY,
        HeaderValue::from_static("max-age=63072000; includeSubDomains"),
    );
    // No caching for API responses (credentials in flight)
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );

    response
}

async fn create_router() -> Router {
    // No CORS layer — the web UI is served from the same origin,
    // so cross-origin requests are not needed and should be blocked.

    quickfw_api::file::create_router()
        .await
        .merge(quickfw_api::system::create_router().await)
        .merge(quickfw_api::firewall_api::create_router().await)
        .merge(quickfw_api::nat_api::create_router().await)
        .merge(quickfw_api::routing_api::create_router().await)
        .merge(quickfw_api::auth::create_auth_router())
        .merge(quickfw_api::audit::create_router())
        .merge(quickfw_api::tools::create_router())
        .layer(DefaultBodyLimit::max(1_048_576)) // 1MB global body limit
        .layer(middleware::from_fn(quickfw_api::audit::audit_middleware)) // inside auth (sees AuthUser)
        .layer(middleware::from_fn(quickfw_api::auth::basic_auth_middleware))
        .layer(middleware::from_fn(security_headers_middleware)) // outside auth so headers appear on 401/403 too
}

#[derive(Parser, Debug)]
#[command(version, about = "QuickFW API Server", long_about = None)]
struct Cli {
    #[clap(short, long, default_value_t=tracing::Level::INFO)]
    log_level: tracing::Level,
}

/// Generate a self-signed TLS certificate if none exists.
fn ensure_tls_cert() -> Result<(String, String), String> {
    let cert_path = "/etc/quickfw/tls.crt";
    let key_path = "/etc/quickfw/tls.key";

    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        info!("TLS certificate found at {}", cert_path);
        return Ok((cert_path.to_string(), key_path.to_string()));
    }

    info!("Generating self-signed TLS certificate...");
    if let Err(e) = std::fs::create_dir_all("/etc/quickfw") {
        error!("Failed to create /etc/quickfw directory: {}", e);
        return Err(format!("Failed to create /etc/quickfw: {}", e));
    }
    let output = std::process::Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:prime256v1",
            "-nodes",
            "-keyout",
            key_path,
            "-out",
            cert_path,
            "-days",
            "3650",
            "-subj",
            "/CN=quickfw",
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            // Set restrictive permissions on key file
            if let Err(e) = std::process::Command::new("chmod").args(["600", key_path]).output() {
                error!("Failed to chmod key file: {}", e);
                return Err(format!("Failed to chmod key file: {}", e));
            }
            if let Err(e) = std::process::Command::new("chmod").args(["644", cert_path]).output() {
                error!("Failed to chmod cert file: {}", e);
                return Err(format!("Failed to chmod cert file: {}", e));
            }
            info!("Self-signed TLS certificate generated successfully");
        }
        Ok(o) => {
            error!(
                "Failed to generate TLS certificate: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            return Err(format!("Failed to generate TLS certificate: {}", String::from_utf8_lossy(&o.stderr)));
        }
        Err(e) => {
            error!("Failed to run openssl: {}", e);
            return Err(format!("Failed to run openssl: {}", e));
        }
    }

    if Path::new(cert_path).exists() && Path::new(key_path).exists() {
        Ok((cert_path.to_string(), key_path.to_string()))
    } else {
        Err("TLS certificate or key file missing after generation attempt".to_string())
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let app = create_router().await;

    let log_writer = LogWriter::new(100);

    // log
    tracing_subscriber::FmtSubscriber::builder()
        .with_max_level(cli.log_level)
        .with_writer(log_writer)
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .with_ansi(false)
        .init();

    // ctrl c
    let signal = async move {
        tokio::signal::ctrl_c().await.unwrap();
        info!("Received ctrl_c, shutting down...");
        println!("Shutting down...");
    };

    // Try HTTPS first, fall back to HTTP if TLS cert generation fails
    match ensure_tls_cert() {
        Ok((cert_path, key_path)) => {
            // --- HTTPS on 443 + HTTP redirect on 3000 ---
            let https_addr = SocketAddr::from(([0, 0, 0, 0], 443));
            let http_addr = SocketAddr::from(([0, 0, 0, 0], 3000));

            // HTTP redirect server on port 3000
            let redirect_app = axum::Router::new().fallback(|req: axum::extract::Request| async move {
                let host = req
                    .headers()
                    .get(header::HOST)
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or("localhost");
                // Strip port from host if present
                let hostname = host.split(':').next().unwrap_or(host);
                let path = req.uri().path();
                let query = req.uri().query().map(|q| format!("?{}", q)).unwrap_or_default();
                let redirect_url = format!("https://{}{}{}", hostname, path, query);
                // Use 301 Moved Permanently (not 308) for broadest client compatibility
                axum::response::Response::builder()
                    .status(axum::http::StatusCode::MOVED_PERMANENTLY)
                    .header(header::LOCATION, redirect_url)
                    .body(axum::body::Body::empty())
                    .unwrap()
            });

            // Spawn HTTP redirect server
            tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(http_addr).await.unwrap();
                info!("HTTP redirect server listening on {} -> HTTPS", http_addr);
                axum::serve(listener, redirect_app).await.unwrap();
            });

            // Start HTTPS server
            // ...existing code...
        }
        Err(e) => {
            error!("TLS setup failed: {}. Starting HTTP only on port 3000", e);
            let http_addr = SocketAddr::from(([0, 0, 0, 0], 3000));
            axum::Server::bind(&http_addr)
                .serve(app.into_make_service())
                .await
                .unwrap();
            return;
        }
    }
        println!("QuickFW API listening on https://{}", https_addr);
        println!("HTTP redirect on http://{}", http_addr);
        info!("QuickFW HTTPS server listening on {}", https_addr);

        let tls_config = axum_server::tls_rustls::RustlsConfig::from_pem_file(&cert_path, &key_path)
            .await
            .expect("Failed to load TLS certificate");

        let handle = axum_server::Handle::new();
        let shutdown_handle = handle.clone();
        tokio::spawn(async move {
            signal.await;
            shutdown_handle.graceful_shutdown(Some(Duration::from_secs(5)));
        });

        axum_server::bind_rustls(https_addr, tls_config)
            .handle(handle)
            .serve(app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .unwrap();
    } else {
        // Fallback: plain HTTP (should only happen if openssl is missing)
        let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
        println!("WARNING: TLS certificate not available, falling back to HTTP on {}", addr);
        info!("Listening on {} (HTTP fallback - TLS cert not available)", addr);
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();

        axum::serve(listener, app)
            .with_graceful_shutdown(signal)
            .await
            .unwrap();
    }
}
