//! Authentication: session-based + Basic auth, argon2 password hashing,
//! WebSocket token auth, and per-IP rate limiting.

use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::Request,
    http::{header, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use rand::Rng;
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
        .unwrap()
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

    // --- Skip rate limiting for static assets ---
    let is_static = path.ends_with(".js")
        || path.ends_with(".css")
        || path.ends_with(".html")
        || path.ends_with(".woff2")
        || path.ends_with(".svg")
        || path.ends_with(".ico")
        || path.starts_with("/fonts/")
        || path == "/";

    // --- Rate limiting (API endpoints only) ---
    if !is_static {
        let mut limits = RATE_LIMITS.lock().unwrap();
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
        if is_default_password() && !is_auth_path(&path) {
            return Err(forced_password_change_response());
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
            let encoded = &auth[6..];
            if let Ok(decoded) = base64_decode(encoded) {
                if let Some((user, pass)) = decoded.split_once(':') {
                    if verify_credentials(user, pass) {
                        if is_default_password() && !is_auth_path(&path) {
                            return Err(forced_password_change_response());
                        }
                        // Reset login failures on successful auth
                        {
                            let mut limits = RATE_LIMITS.lock().unwrap();
                            if let Some(entry) = limits.get_mut(&client_ip) {
                                entry.login_failures = 0;
                            }
                        }
                        request
                            .extensions_mut()
                            .insert(AuthUser(user.to_string()));
                        return Ok(next.run(request).await);
                    } else {
                        // Track auth failure
                        let mut limits = RATE_LIMITS.lock().unwrap();
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
        .unwrap()
}

fn too_many_requests_response(retry_after: u64) -> Response {
    Response::builder()
        .status(StatusCode::TOO_MANY_REQUESTS)
        .header("Retry-After", retry_after.to_string())
        .body(axum::body::Body::from("Too many requests"))
        .unwrap()
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
        .unwrap()
}

fn is_auth_path(path: &str) -> bool {
    path == "/api/auth/password" || path == "/api/auth/ws-token"
}

// --- Session helpers ---

fn check_session_cookie(request: &Request) -> Option<String> {
    let cookie_header = request.headers().get(header::COOKIE)?.to_str().ok()?;
    let token = cookie_header
        .split(';')
        .filter_map(|c| c.trim().strip_prefix("quickfw_session="))
        .next()?;

    let now = unix_now();
    let mut sessions = SESSIONS.lock().unwrap();

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
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let now = unix_now();
    let mut sessions = SESSIONS.lock().unwrap();

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
    let mut sessions = SESSIONS.lock().unwrap();
    sessions.remove(token);
}

// --- Password helpers ---

fn is_default_password() -> bool {
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
            // Constant-time compare to avoid timing leak
            let _ = Argon2::default().verify_password(
                pass.as_bytes(),
                &PasswordHash::new("$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap(),
            );
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
    let sessions = SESSIONS.lock().unwrap();
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
    let token: String = rand::thread_rng()
        .sample_iter(&rand::distributions::Alphanumeric)
        .take(64)
        .map(char::from)
        .collect();

    let expiry = unix_now() + 300; // 5 minutes

    let mut tokens = WS_TOKENS.lock().unwrap();
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
    let mut tokens = WS_TOKENS.lock().unwrap();
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
    if !verify_credentials(&payload.username, &payload.password) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid credentials"})),
        ));
    }

    let token = create_session(&payload.username);
    let cookie = format!(
        "quickfw_session={}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age={}",
        token, SESSION_MAX_AGE
    );

    Ok((
        [(header::SET_COOKIE, cookie)],
        Json(LoginResponse {
            token,
            expires_in_seconds: SESSION_MAX_AGE,
        }),
    ))
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

    let clear_cookie =
        "quickfw_session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0".to_string();

    (
        [(header::SET_COOKIE, clear_cookie)],
        Json(serde_json::json!({"message": "Logged out"})),
    )
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current: String,
    new: String,
}

async fn change_password(
    Json(payload): Json<ChangePasswordRequest>,
) -> Result<impl IntoResponse, (StatusCode, Json<serde_json::Value>)> {
    if !verify_credentials(DEFAULT_USER, &payload.current) {
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

    hash_and_store_password(&payload.new).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("Failed to store password: {}", e)})),
        )
    })?;

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

fn base64_decode(input: &str) -> Result<String, ()> {
    let bytes = base64_decode_bytes(input)?;
    String::from_utf8(bytes).map_err(|_| ())
}

fn base64_decode_bytes(input: &str) -> Result<Vec<u8>, ()> {
    const TABLE: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let input = input.trim_end_matches('=');
    let mut output = Vec::with_capacity(input.len() * 3 / 4);

    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &byte in input.as_bytes() {
        let val = TABLE.iter().position(|&c| c == byte).ok_or(())? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            output.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }

    Ok(output)
}
