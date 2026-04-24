use quickfw_api::logger::LogWriter;
use axum::extract::DefaultBodyLimit;
use axum::middleware;
use axum::Router;
use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;

use std::path::Path;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

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
            // script-src is strict (no 'unsafe-inline'): any XSS reflected
            // into the SPA can't execute. style-src keeps 'unsafe-inline'
            // because index.html has a critical-CSS <style> block. Tightened
            // with object-src 'none', base-uri 'self', form-action 'self',
            // frame-ancestors 'none' to block plugin/base/clickjacking abuse.
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' wss: ws:; font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
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
        .merge(quickfw_api::users_api::create_router())
        .merge(quickfw_api::logs_api::create_router())
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
/// Uses temp files and atomic move to avoid leaving partially-created files with wrong permissions.
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

    // Use temp files to avoid leaving partially-created files
    let temp_cert = "/etc/quickfw/tls.crt.tmp";
    let temp_key = "/etc/quickfw/tls.key.tmp";

    // Clean up any stale temp files
    let _ = std::fs::remove_file(temp_cert);
    let _ = std::fs::remove_file(temp_key);

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
            temp_key,
            "-out",
            temp_cert,
            "-days",
            "3650",
            "-subj",
            "/CN=quickfw",
        ])
        .output();

    match output {
        Ok(o) if o.status.success() => {
            // Set restrictive permissions on key file BEFORE moving to final location
            if let Err(e) = std::fs::set_permissions(temp_key, std::fs::Permissions::from_mode(0o600)) {
                let _ = std::fs::remove_file(temp_key);
                let _ = std::fs::remove_file(temp_cert);
                error!("Failed to set key file permissions: {}", e);
                return Err(format!("Failed to set key file permissions: {}", e));
            }
            if let Err(e) = std::fs::set_permissions(temp_cert, std::fs::Permissions::from_mode(0o644)) {
                let _ = std::fs::remove_file(temp_key);
                let _ = std::fs::remove_file(temp_cert);
                error!("Failed to set cert file permissions: {}", e);
                return Err(format!("Failed to set cert file permissions: {}", e));
            }

            // Atomic move to final location
            if let Err(e) = std::fs::rename(temp_key, key_path) {
                let _ = std::fs::remove_file(temp_key);
                let _ = std::fs::remove_file(temp_cert);
                error!("Failed to move key file: {}", e);
                return Err(format!("Failed to move key file: {}", e));
            }
            if let Err(e) = std::fs::rename(temp_cert, cert_path) {
                // Try to rollback key file
                let _ = std::fs::remove_file(key_path);
                let _ = std::fs::remove_file(temp_cert);
                error!("Failed to move cert file: {}", e);
                return Err(format!("Failed to move cert file: {}", e));
            }

            info!("Self-signed TLS certificate generated successfully");
        }
        Ok(o) => {
            let _ = std::fs::remove_file(temp_key);
            let _ = std::fs::remove_file(temp_cert);
            error!(
                "Failed to generate TLS certificate: {}",
                String::from_utf8_lossy(&o.stderr)
            );
            return Err(format!("Failed to generate TLS certificate: {}", String::from_utf8_lossy(&o.stderr)));
        }
        Err(e) => {
            let _ = std::fs::remove_file(temp_key);
            let _ = std::fs::remove_file(temp_cert);
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
        tokio::signal::ctrl_c().await.expect("Failed to listen for ctrl_c signal");
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
                    .unwrap_or_else(|_| {
                        axum::response::Response::builder()
                            .status(axum::http::StatusCode::INTERNAL_SERVER_ERROR)
                            .body(axum::body::Body::from("Internal Server Error"))
                            .unwrap()
                    })
            });

            // Spawn HTTP redirect server
            tokio::spawn(async move {
                let listener = tokio::net::TcpListener::bind(http_addr).await
                    .expect("Failed to bind HTTP redirect server");
                info!("HTTP redirect server listening on {} -> HTTPS", http_addr);
                axum::serve(listener, redirect_app).await
                    .expect("HTTP redirect server failed");
            });

            // Start HTTPS server
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
                .expect("HTTPS server failed");
        }
        Err(e) => {
            error!("TLS setup failed: {}. Falling back to HTTP on port 3000", e);
            let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
            println!("WARNING: TLS setup failed, falling back to HTTP on {}", addr);
            info!("Listening on {} (HTTP fallback)", addr);
            let listener = tokio::net::TcpListener::bind(addr).await
                .expect("Failed to bind HTTP server");

            axum::serve(listener, app)
                .with_graceful_shutdown(signal)
                .await
                .expect("HTTP server failed");
        }
    }
}
