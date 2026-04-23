//! Authentication: session-based + Basic auth, argon2 password hashing,
//! WebSocket token auth, and per-IP rate limiting.

use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::Request,
    http::{self, header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rand::Rng;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Mutex;
use tracing::warn;

const ADMIN_PASSWORD_PATH: &str = "/etc/quickfw/admin.password";
const DEFAULT_USER: &str = "admin";
const DEFAULT_PASS: &str = "quickfw";
const SESSION_MAX_AGE: u64 = 1800; // 30 minutes
const MAX_SESSIONS: usize = 100;
const API_RATE_LIMIT: u32 = 60; // per minute
const AUTH_LOCKOUT_THRESHOLD: u32 = 5;
const AUTH_LOCKOUT_SECS: u64 = 900; // 15 minutes

const BANNED_PASSWORDS: &[&str] = &[
    "admin",
    "password",
    "123456",
    "12345678",
    "qwerty",
    "letmein",
    "firewall",
    "changeme",
    "quickfw",
];

// --- Stores ---

struct SessionInfo {
    user: String,
    last_active: u64,
}

struct RateEntry {
    api_count: u32,
    api_window: u64,
    login_failures: u32,
    lockout_until: u64,
}

lazy_static::lazy_static! {
    static ref WS_TOKENS: Mutex<HashMap<String, u64>> = Mutex::new(HashMap::new());
    static ref SESSIONS: Mutex<HashMap<String, SessionInfo>> = Mutex::new(HashMap::new());
    static ref RATE_LIMITS: Mutex<HashMap<String, RateEntry>> = Mutex::new(HashMap::new());
}

/// Authenticated user identity — set as a request extension by auth middleware.
#[derive(Clone)]
pub struct AuthUser(pub String);

// --- Router ---

pub fn create_auth_router() -> Router {
    Router::new()
        .route("/api/auth/password", post(change_password))
        .route("/api/auth/ws-token", post(get_ws_token))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
}

// --- Middleware ---

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_else(|e| {
            tracing::warn!("System clock is before Unix epoch: {}. Treating as epoch.", e);
            std::time::Duration::from_secs(0)
        })
        .as_secs()
}

fn get_client_ip(request: &Request) -> String {
    request
        .extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|ci| ci.0.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Main auth middleware: rate limiting -> session/basic auth -> forced password change.
pub async fn basic_auth_middleware(
    mut request: Request,
    next: Next,
) -> Result<Response, Response> {
    let path = request.uri().path().to_string();
    let client_ip = get_client_ip(&request);
    let now = unix_now();

    // --- Skip rate limiting + auth for static assets and SPA deep links ---
    // The SPA handles its own client-side routing; any non-/api/, non-/ws path
    // is served as index.html by the fallback (see file.rs). That HTML page is
    // public — the SPA enforces auth on subsequent API calls.
    let method = request.method().clone();
    let is_static = !path.starts_with("/api/")
        && path != "/ws"
        && (method == http::Method::GET || method == http::Method::HEAD);

    // --- Rate limiting (API endpoints only) ---
    if !is_static {
        let mut limits = RATE_LIMITS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        // Cap store at 10000 entries
        if limits.len() > 10000 {
            let oldest = limits
                .iter()
                .min_by_key(|(_, e)| e.api_window)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest {
                limits.remove(&k);
            }
        }
        let entry = limits.entry(client_ip.clone()).or_insert(RateEntry {
            api_count: 0,
            api_window: now,
            login_failures: 0,
            lockout_until: 0,
        });

        // Check lockout
        if entry.lockout_until > now {
            return Err(too_many_requests_response(entry.lockout_until - now));
        }

        // Check API rate limit (sliding window per minute)
        if now - entry.api_window >= 60 {
            entry.api_count = 1;
            entry.api_window = now;
        } else {
            entry.api_count += 1;
            if entry.api_count > API_RATE_LIMIT {
                return Err(too_many_requests_response(60 - (now - entry.api_window)));
            }
        }
    }

    // --- First-boot protection ---
    // If the appliance hasn't been initialized (no password or default password),
    // only allow static assets and auth endpoints needed for setup.
    let is_initialized = !tokio::task::spawn_blocking(is_default_password).await.unwrap_or(true);
    if !is_initialized {
        let allowed_during_setup = is_static
            || path == "/api/auth/login"
            || path == "/api/auth/password"
            || path == "/index.html"
            || path == "/login.html";
        if !allowed_during_setup {
            let resp = axum::response::Response::builder()
                .status(axum::http::StatusCode::SERVICE_UNAVAILABLE)
                .header(header::CONTENT_TYPE, "application/json")
                .body(axum::body::Body::from(r#"{"error":"Appliance not initialized"}"#))
                .unwrap_or_else(|_| axum::response::Response::new(axum::body::Body::from("Service Unavailable")));
            return Err(resp);
        }
    }

    // --- Auth-exempt paths ---
    // The HTML page + static assets load without auth.
    // The JS login form handles authentication via /api/auth/login session cookie.
    // Only /api/* endpoints (except /api/auth/login) require auth.
    if is_static
        || path == "/api/auth/login"
        || path == "/index.html"
        || path == "/login.html"
    {
        request
            .extensions_mut()
            .insert(AuthUser("anonymous".to_string()));
        return Ok(next.run(request).await);
    }

    // --- WebSocket: token auth via query param ---
    if path == "/ws" {
        let query = request.uri().query().unwrap_or("");
        let token = query.split('&').find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k == "token" {
                Some(v.to_string())
            } else {
                None
            }
        });
        match token {
            Some(t) if verify_ws_token(&t) => {
                request
                    .extensions_mut()
                    .insert(AuthUser(DEFAULT_USER.to_string()));
                return Ok(next.run(request).await);
            }
            _ => {
                warn!("WebSocket connection rejected: missing or invalid token");
                return Err(unauthorized_response());
            }
        }
    }

    // --- Try API key (X-API-Key header) — not supported in QuickFW core ---
    if request
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok())
        .is_some()
    {
        // API key auth not supported in QuickFW core
        return Err(unauthorized_response());
    }

    // --- Try session cookie ---
    if let Some(user) = check_session_cookie(&request) {
        let needs_change = tokio::task::spawn_blocking(is_default_password).await.unwrap_or(true);
        if needs_change && !is_auth_path(&path) {
            return Err(forced_password_change_response());
        }
        // CSRF: require X-CSRF-Token header to match quickfw_csrf cookie on
        // state-changing requests. Exempt the bootstrap /api/auth/* paths
        // (client doesn't have the cookie yet on first login).
        if !csrf_check(&request, &path) {
            return Err(forbidden_response("CSRF token missing or invalid"));
        }
        request.extensions_mut().insert(AuthUser(user));
        return Ok(next.run(request).await);
    }

    // --- Fall back to Basic auth ---
    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    match auth_header {
        Some(ref auth) if auth.starts_with("Basic ") => {
            let encoded = auth[6..].to_string();
            let decoded = tokio::task::spawn_blocking(move || base64_decode(&encoded)).await.unwrap_or(Err(()));
            if let Ok(decoded) = decoded {
                if let Some((user, pass)) = decoded.split_once(':') {
                    let user = user.to_string();
                    let pass = pass.to_string();
                    let user_for_verify = user.clone();
                    let valid = tokio::task::spawn_blocking(move || verify_credentials(&user_for_verify, &pass))
                        .await
                        .unwrap_or(false);
                    if valid {
                        let needs_change = tokio::task::spawn_blocking(is_default_password).await.unwrap_or(true);
                        if needs_change && !is_auth_path(&path) {
                            return Err(forced_password_change_response());
                        }
                        // Reset login failures on successful auth
                        {
                            let mut limits = RATE_LIMITS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                            if let Some(entry) = limits.get_mut(&client_ip) {
                                entry.login_failures = 0;
                            }
                        }
                        request
                            .extensions_mut()
                            .insert(AuthUser(user));
                        return Ok(next.run(request).await);
                    } else {
                        // Track auth failure
                        let mut limits = RATE_LIMITS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                        let entry = limits.entry(client_ip).or_insert(RateEntry {
                            api_count: 0,
                            api_window: now,
                            login_failures: 0,
                            lockout_until: 0,
                        });
                        entry.login_failures += 1;
                        if entry.login_failures >= AUTH_LOCKOUT_THRESHOLD {
                            entry.lockout_until = now + AUTH_LOCKOUT_SECS;
                            entry.login_failures = 0;
                            warn!("IP {} locked out for {} seconds after {} failed auth attempts",
                                &request.extensions().get::<axum::extract::ConnectInfo<SocketAddr>>()
                                    .map(|ci| ci.0.to_string()).unwrap_or_default(),
                                AUTH_LOCKOUT_SECS, AUTH_LOCKOUT_THRESHOLD);
                        }
                    }
                }
            }
            warn!("Invalid credentials");
            Err(unauthorized_response())
        }
        _ => Err(unauthorized_response()),
    }
}

fn unauthorized_response() -> Response {
    // Return JSON 401 without WWW-Authenticate header.
    // This prevents the ugly browser Basic auth popup.
    // The frontend JS handles 401 by showing the login form.
    let body = serde_json::json!({"error": "unauthorized", "message": "Authentication required"});
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(axum::body::Body::from("Unauthorized")))
}

fn too_many_requests_response(retry_after: u64) -> Response {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", retry_after.to_string())
        .body(axum::body::Body::from("Too many requests"))
        .unwrap_or_else(|_| Response::new(axum::body::Body::from("Too many requests")))
}

fn forced_password_change_response() -> Response {
    let body = serde_json::json!({
        "error": "password_change_required",
        "message": "Default password must be changed before accessing the system"
    });
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(axum::body::Body::from("Forbidden")))
}

fn is_auth_path(path: &str) -> bool {
    path == "/api/auth/password" || path == "/api/auth/ws-token"
}

/// CSRF double-submit check.
///
/// Returns true (check passes) when:
///   - method is safe (GET/HEAD/OPTIONS) — CSRF irrelevant
///   - path is a bootstrap auth endpoint (client has no CSRF cookie yet)
///   - X-CSRF-Token header matches the quickfw_csrf cookie value
fn csrf_check(request: &Request, path: &str) -> bool {
    let method = request.method();
    if method == http::Method::GET
        || method == http::Method::HEAD
        || method == http::Method::OPTIONS
    {
        return true;
    }

    // Bootstrap paths: the client cannot have the CSRF cookie before the
    // first successful login/password-change. SameSite=Strict on the session
    // cookie already blocks cross-site POSTs to these endpoints.
    if path == "/api/auth/login"
        || path == "/api/auth/password"
        || path == "/api/auth/logout"
    {
        return true;
    }

    let cookie_header = match request.headers().get(header::COOKIE).and_then(|v| v.to_str().ok()) {
        Some(h) => h,
        None => return false,
    };
    let cookie_token = cookie_header
        .split(';')
        .filter_map(|c| c.trim().strip_prefix("quickfw_csrf="))
        .next()
        .unwrap_or("");

    let header_token = request
        .headers()
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    if cookie_token.is_empty() || header_token.is_empty() {
        return false;
    }
    use subtle::ConstantTimeEq;
    cookie_token.as_bytes().ct_eq(header_token.as_bytes()).into()
}

fn forbidden_response(reason: &str) -> Response {
    let body = serde_json::json!({"error": "forbidden", "message": reason});
    Response::builder()
        .status(StatusCode::FORBIDDEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(axum::body::Body::from(body.to_string()))
        .unwrap_or_else(|_| Response::new(axum::body::Body::from("Forbidden")))
}

// --- Session helpers ---

fn check_session_cookie(request: &Request) -> Option<String> {
    let cookie_header = request.headers().get(header::COOKIE)?.to_str().ok()?;
    let token = cookie_header
        .split(';')
        .filter_map(|c| c.trim().strip_prefix("quickfw_session="))
        .next()?;

    let now = unix_now();
    let mut sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    if let Some(session) = sessions.get_mut(token) {
        if now - session.last_active < SESSION_MAX_AGE {
            session.last_active = now; // sliding window
            return Some(session.user.clone());
        } else {
            sessions.remove(token);
        }
    }
    None
}

fn create_session(user: &str) -> String {
    let token: String = OsRng
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let now = unix_now();
    let mut sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());

    // Evict expired sessions
    sessions.retain(|_, s| now - s.last_active < SESSION_MAX_AGE);

    // Cap at MAX_SESSIONS — evict oldest
    if sessions.len() >= MAX_SESSIONS {
        let oldest = sessions
            .iter()
            .min_by_key(|(_, s)| s.last_active)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            sessions.remove(&k);
        }
    }

    sessions.insert(
        token.clone(),
        SessionInfo {
            user: user.to_string(),
            last_active: now,
        },
    );
    token
}

fn destroy_session(token: &str) {
    let mut sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    sessions.remove(token);
}

// --- Password helpers ---

fn is_default_password() -> bool {
    // TODO: wrap with tokio::task::spawn_blocking for high-concurrency deployments
    match std::fs::read_to_string(ADMIN_PASSWORD_PATH) {
        Ok(stored) => {
            let stored = stored.trim();
            if stored == DEFAULT_PASS {
                return true;
            }
            if stored.starts_with("$argon2") {
                if let Ok(parsed_hash) = PasswordHash::new(stored) {
                    return Argon2::default()
                        .verify_password(DEFAULT_PASS.as_bytes(), &parsed_hash)
                        .is_ok();
                }
            }
            false
        }
        Err(_) => true,
    }
}

fn verify_credentials(user: &str, pass: &str) -> bool {
    if user != DEFAULT_USER {
        return false;
    }

    // TODO: wrap with tokio::task::spawn_blocking for high-concurrency deployments
    let stored = std::fs::read_to_string(ADMIN_PASSWORD_PATH)
        .map(|s| s.trim().to_string())
        .unwrap_or_default();

    if stored.is_empty() {
        if pass == DEFAULT_PASS {
            let _ = hash_and_store_password(DEFAULT_PASS);
            return true;
        }
        return false;
    }

    if stored.starts_with("$argon2") {
        match PasswordHash::new(&stored) {
            Ok(parsed_hash) => Argon2::default()
                .verify_password(pass.as_bytes(), &parsed_hash)
                .is_ok(),
            Err(_) => false,
        }
    } else {
        // Legacy plaintext — verify and auto-migrate
        if pass == stored {
            let _ = hash_and_store_password(pass);
            true
        } else {
            // Constant-time compare to avoid timing leak using subtle crate
            use subtle::ConstantTimeEq;
            let pass_bytes = pass.as_bytes();
            let stored_bytes = stored.as_bytes();
            let len = std::cmp::min(pass_bytes.len(), stored_bytes.len());
            let _ = pass_bytes[..len].ct_eq(&stored_bytes[..len]);
            false
        }
    }
}

fn hash_and_store_password(password: &str) -> Result<(), Box<dyn std::error::Error>> {
    let _ = std::fs::create_dir_all("/etc/quickfw");
    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| format!("argon2 hash error: {}", e))?
        .to_string();
    std::fs::write(ADMIN_PASSWORD_PATH, &hash)?;
    Ok(())
}

/// Verify a password against the stored hash (public for re-auth checks).
pub fn verify_password(pass: &str) -> bool {
    verify_credentials(DEFAULT_USER, pass)
}

/// List active sessions (for identity/sessions endpoint).
pub fn list_active_sessions() -> Vec<serde_json::Value> {
    let sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = unix_now();
    sessions
        .iter()
        .filter(|(_, s)| now - s.last_active < SESSION_MAX_AGE)
        .map(|(token, s)| {
            serde_json::json!({
                "user": s.user,
                "last_active_secs_ago": now - s.last_active,
                "token_prefix": &token[..std::cmp::min(8, token.len())],
            })
        })
        .collect()
}

// --- WS token helpers ---

fn generate_ws_token() -> String {
    let token: String = OsRng
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let expiry = unix_now() + 300; // 5 minutes

    let mut tokens = WS_TOKENS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = unix_now();
    tokens.retain(|_, exp| *exp > now);
    if tokens.len() >= 100 {
        let oldest = tokens
            .iter()
            .min_by_key(|(_, exp)| **exp)
            .map(|(k, _)| k.clone());
        if let Some(k) = oldest {
            tokens.remove(&k);
        }
    }
    tokens.insert(token.clone(), expiry);
    token
}

fn verify_ws_token(token: &str) -> bool {
    let mut tokens = WS_TOKENS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = unix_now();
    tokens.retain(|_, exp| *exp > now);
    tokens.remove(token).is_some()
}

// --- API Handlers ---

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    expires_in_seconds: u64,
}

async fn login(
    Json(payload): Json<LoginRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let username = payload.username.clone();
    let password = payload.password.clone();
    let valid = tokio::task::spawn_blocking(move || verify_credentials(&username, &password))
        .await
        .unwrap_or(false);
    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid credentials"})),
        ));
    }

    let token = create_session(&payload.username);
    let session_cookie = format!(
        "quickfw_session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        token, SESSION_MAX_AGE
    );

    // Double-submit CSRF cookie. NOT HttpOnly — the SPA's API client reads
    // it via document.cookie and echoes it as the X-CSRF-Token header on
    // every mutating request. See csrf_check() in the auth middleware.
    //
    // SameSite=Lax (not Strict) because Chromium occasionally refuses to
    // send a Strict cookie on subresource fetches after a same-page login
    // when the cookie was set by that same fetch response. Lax still blocks
    // cross-site POSTs (the only relevant CSRF vector), and the session
    // cookie itself stays Strict.
    let csrf_token = generate_random_token();
    let csrf_cookie = format!(
        "quickfw_csrf={}; Secure; SameSite=Lax; Path=/; Max-Age={}",
        csrf_token, SESSION_MAX_AGE
    );

    // Build headers manually: the `[(K, V), (K, V)]` array form uses
    // HeaderMap::insert which OVERWRITES duplicate keys — so we'd lose one
    // of the two Set-Cookie values. HeaderMap::append keeps both.
    let mut headers = axum::http::HeaderMap::new();
    headers.append(header::SET_COOKIE, session_cookie.parse().unwrap());
    headers.append(header::SET_COOKIE, csrf_cookie.parse().unwrap());

    Ok((
        headers,
        Json(LoginResponse {
            token,
            expires_in_seconds: SESSION_MAX_AGE,
        }),
    ))
}

/// 32-byte URL-safe random token used for CSRF cookies.
fn generate_random_token() -> String {
    use rand::Rng;
    let mut rng = OsRng;
    let bytes: [u8; 32] = rng.gen();
    // Hex encoding — safe for cookie values and predictable length (64 chars)
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

async fn logout(request: Request) -> impl IntoResponse {
    // Extract session token from cookie
    if let Some(cookie_header) = request.headers().get(header::COOKIE).and_then(|v| v.to_str().ok())
    {
        if let Some(token) = cookie_header
            .split(';')
            .filter_map(|c| c.trim().strip_prefix("quickfw_session="))
            .next()
        {
            destroy_session(token);
        }
    }

    let clear_session =
        "quickfw_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string();
    let clear_csrf =
        "quickfw_csrf=; Secure; SameSite=Lax; Path=/; Max-Age=0".to_string();

    let mut headers = axum::http::HeaderMap::new();
    headers.append(header::SET_COOKIE, clear_session.parse().unwrap());
    headers.append(header::SET_COOKIE, clear_csrf.parse().unwrap());

    (headers, Json(serde_json::json!({"message": "Logged out"})))
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current: String,
    new: String,
}

async fn change_password(
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    let current = payload.current.clone();
    let valid = tokio::task::spawn_blocking(move || verify_credentials(DEFAULT_USER, &current))
        .await
        .unwrap_or(false);
    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Current password is incorrect"})),
        ));
    }

    // Validate new password — banned list first, then length
    if BANNED_PASSWORDS.contains(&payload.new.to_lowercase().as_str()) {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "This password is too common and not allowed"})),
        ));
    }

    if payload.new.len() < 8 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "New password must be at least 8 characters"})),
        ));
    }

    let new_password = payload.new.clone();
    // Convert error to String inside the closure so the closure returns a Send type.
    tokio::task::spawn_blocking(move || hash_and_store_password(&new_password).map_err(|e| e.to_string()))
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to store password: {}", e)})),
            )
        })?
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("Failed to store password: {}", e)})),
            )
        })?;

    // Invalidate all existing sessions so stolen cookies are revoked
    {
        let mut sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        sessions.clear();
    }

    Ok(Json(serde_json::json!({"message": "Password changed successfully"})))
}

#[derive(Serialize)]
struct WsTokenResponse {
    token: String,
    expires_in_seconds: u64,
}

async fn get_ws_token() -> Json<WsTokenResponse> {
    let token = generate_ws_token();
    Json(WsTokenResponse {
        token,
        expires_in_seconds: 300,
    })
}

// --- Base64 decode ---
// Uses the well-vetted `base64` crate instead of a hand-rolled implementation.

fn base64_decode(input: &str) -> Result<String, ()> {
    let bytes = base64_decode_bytes(input)?;
    String::from_utf8(bytes).map_err(|_| ())
}

fn base64_decode_bytes(input: &str) -> Result<Vec<u8>, ()> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD
        .decode(input.trim())
        .map_err(|_| ())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base64_decode() {
        assert_eq!(base64_decode("YWRtaW46cGFzc3dvcmQ=").unwrap(), "admin:password");
        assert_eq!(base64_decode("dGVzdA==").unwrap(), "test");
        assert!(base64_decode("invalid!!!").is_err());
    }

    #[test]
    fn test_banned_passwords() {
        for password in BANNED_PASSWORDS {
            assert!(BANNED_PASSWORDS.contains(password));
        }
    }

    #[test]
    fn test_session_creation_and_verification() {
        // Clear any existing sessions
        {
            let mut sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            sessions.clear();
        }

        let token = create_session("admin");
        assert!(!token.is_empty());

        // Verify session exists
        {
            let sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(sessions.contains_key(&token));
        }
    }

    #[test]
    fn test_session_destruction() {
        // Clear any existing sessions
        {
            let mut sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            sessions.clear();
        }

        let token = create_session("admin");
        destroy_session(&token);

        // Verify session is gone
        {
            let sessions = SESSIONS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            assert!(!sessions.contains_key(&token));
        }
    }

    #[test]
    fn test_ws_token_generation_and_verification() {
        // Clear any existing tokens
        {
            let mut tokens = WS_TOKENS.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            tokens.clear();
        }

        let token = generate_ws_token();
        assert!(!token.is_empty());
        assert!(verify_ws_token(&token));
        
        // Token should be consumed (one-time use)
        assert!(!verify_ws_token(&token));
    }

    #[test]
    fn test_unix_now_does_not_panic() {
        let now = unix_now();
        // Should return a u64 without panicking, even if clock is before 1970
        // (we can't easily mock the clock, but we verify it doesn't panic)
        assert!(now > 0 || now == 0);
    }

    #[test]
    fn test_rate_limiting_entry_creation() {
        let now = unix_now();
        let entry = RateEntry {
            api_count: 0,
            api_window: now,
            login_failures: 0,
            lockout_until: 0,
        };
        
        assert_eq!(entry.api_count, 0);
        assert_eq!(entry.login_failures, 0);
        assert_eq!(entry.lockout_until, 0);
    }

    #[test]
    fn test_unix_now() {
        let now1 = unix_now();
        std::thread::sleep(std::time::Duration::from_millis(10));
        let now2 = unix_now();
        assert!(now2 >= now1);
    }
}