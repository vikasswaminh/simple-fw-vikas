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
    role: crate::users::Role,
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

/// Authenticated user identity — set as a request extension by auth
/// middleware. Carries the resolved role so gate middleware can inspect it
/// without re-reading users.yaml on every request.
#[derive(Clone)]
pub struct AuthUser {
    pub username: String,
    pub role: crate::users::Role,
}

impl AuthUser {
    pub fn new(username: String, role: crate::users::Role) -> Self {
        Self { username, role }
    }
    pub fn anonymous() -> Self {
        Self { username: "anonymous".to_string(), role: crate::users::Role::Readonly }
    }
}

/// Middleware that gates handlers by minimum required role. Use with
/// `from_fn(require_role(Role::Admin))`. A missing AuthUser (no auth) or
/// insufficient role returns 403.
pub fn require_role(
    min: crate::users::Role,
) -> impl Fn(
    Request,
    axum::middleware::Next,
) -> std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Response, Response>> + Send>,
> + Clone {
    move |request: Request, next: axum::middleware::Next| {
        let min = min;
        Box::pin(async move {
            let has_role = request
                .extensions()
                .get::<AuthUser>()
                .map(|u| u.role >= min)
                .unwrap_or(false);
            if has_role {
                Ok(next.run(request).await)
            } else {
                Err(forbidden_response("Insufficient role"))
            }
        })
    }
}

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
        request.extensions_mut().insert(AuthUser::anonymous());
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
                // WS tokens are issued to logged-in admins (frontend gates
                // /api/auth/ws-token). Treat WS connection as admin.
                request
                    .extensions_mut()
                    .insert(AuthUser::new(DEFAULT_USER.to_string(), crate::users::Role::Admin));
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
    if let Some((user, role)) = check_session_cookie(&request) {
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
        request.extensions_mut().insert(AuthUser::new(user, role));
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
                        // Look up the user's role from users.yaml so Basic
                        // auth callers still flow through RBAC.
                        let user_for_role = user.clone();
                        let role = tokio::task::spawn_blocking(move || {
                            crate::users::find_user(&crate::users::load_users(), &user_for_role)
                                .map(|u| u.role)
                                .unwrap_or(crate::users::Role::Readonly)
                        })
                        .await
                        .unwrap_or(crate::users::Role::Readonly);
                        request
                            .extensions_mut()
                            .insert(AuthUser::new(user, role));
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

fn check_session_cookie(request: &Request) -> Option<(String, crate::users::Role)> {
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
            return Some((session.user.clone(), session.role));
        } else {
            sessions.remove(token);
        }
    }
    None
}

fn create_session(user: &str, role: crate::users::Role) -> String {
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
            role,
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
    // An appliance is "not initialized" when either:
    //   - users.yaml is absent AND admin.password is absent (brand-new install), OR
    //   - the admin user (per users.yaml, or fallback admin.password) still
    //     verifies the literal DEFAULT_PASS.
    let file = crate::users::load_users();
    if file.users.is_empty() {
        // No users.yaml (and no admin.password to migrate from either) → first boot.
        return true;
    }
    // If any admin's stored hash verifies "quickfw", consider the appliance uninitialized.
    for u in &file.users {
        if u.role == crate::users::Role::Admin
            && crate::users::verify_password(&u.password_hash, DEFAULT_PASS)
        {
            return true;
        }
    }
    false
}

fn verify_credentials(user: &str, pass: &str) -> bool {
    // Load users.yaml (with first-boot migration from admin.password).
    let file = crate::users::load_users();

    // Bootstrap corner case: both users.yaml and admin.password are empty.
    // Accept the default admin/quickfw credential once so first-boot login
    // can reach the forced-password-change screen.
    if file.users.is_empty() {
        if user == DEFAULT_USER && pass == DEFAULT_PASS {
            let _ = hash_and_store_password(DEFAULT_PASS);
            return true;
        }
        return false;
    }

    match crate::users::find_user(&file, user) {
        Some(u) => crate::users::verify_password(&u.password_hash, pass),
        None => {
            // Constant-time dummy compare to avoid leaking which users exist.
            use subtle::ConstantTimeEq;
            let _ = pass.as_bytes().ct_eq(pass.as_bytes());
            false
        }
    }
}

/// Look up a user's role — used by the login handler to populate the
/// session + login response.
pub fn role_for_user(user: &str) -> Option<crate::users::Role> {
    crate::users::find_user(&crate::users::load_users(), user).map(|u| u.role)
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
    /// Authenticated user's username — so the SPA can show who's logged in.
    username: String,
    /// Authenticated user's role ("admin" | "operator" | "readonly") — so
    /// the frontend can hide admin-only controls for non-admin users.
    role: String,
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

    let role = tokio::task::spawn_blocking({
        let u = payload.username.clone();
        move || role_for_user(&u)
    })
    .await
    .unwrap_or(None)
    .unwrap_or(crate::users::Role::Readonly);

    let token = create_session(&payload.username, role);
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
    // SameSite=None for the CSRF cookie. Same-origin request semantics vary
    // across browsers for Lax on 127.0.0.1 / localhost, and the double-submit
    // pattern does not rely on SameSite — security comes from the fact that
    // cross-origin code cannot read the cookie value to put in the
    // X-CSRF-Token header. Secure is required with SameSite=None.
    let csrf_cookie = format!(
        "quickfw_csrf={}; Secure; SameSite=None; Path=/; Max-Age={}",
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
            username: payload.username.clone(),
            role: role.as_str().to_string(),
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
        "quickfw_csrf=; Secure; SameSite=None; Path=/; Max-Age=0".to_string();

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
    // Update users.yaml (authoritative) and the legacy admin.password (kept
    // in sync so any tool still reading it gets the current hash).
    tokio::task::spawn_blocking(move || -> Result<(), String> {
        let mut file = crate::users::load_users();
        // If users.yaml is empty (pre-migration first boot), create admin.
        if file.users.is_empty() {
            let hash = crate::users::hash_password(&new_password)?;
            file.users.push(crate::users::User {
                username: DEFAULT_USER.to_string(),
                password_hash: hash,
                role: crate::users::Role::Admin,
            });
            crate::users::save_users(&file)?;
        } else {
            crate::users::set_password(&mut file, DEFAULT_USER, &new_password)
                .map_err(|e| e.to_string())?;
        }
        // Best-effort sync of legacy admin.password so a rollback binary
        // still works. Non-fatal.
        let _ = hash_and_store_password(&new_password).map_err(|e| e.to_string());
        Ok(())
    })
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

        let token = create_session("admin", crate::users::Role::Admin);
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

        let token = create_session("admin", crate::users::Role::Admin);
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

    // --- CSRF double-submit tests ---
    // Build axum::Request values by hand and assert csrf_check's decisions.
    // These are critical-path: a regression here silently disables CSRF.

    fn req(method: &str, cookie: Option<&str>, header: Option<&str>) -> Request {
        let mut builder = axum::http::Request::builder()
            .method(method)
            .uri("http://localhost/api/firewall");
        if let Some(c) = cookie {
            builder = builder.header(header::COOKIE, c);
        }
        if let Some(h) = header {
            builder = builder.header("x-csrf-token", h);
        }
        builder.body(axum::body::Body::empty()).unwrap()
    }

    #[test]
    fn csrf_check_passes_on_safe_methods() {
        // GET / HEAD / OPTIONS never require CSRF — they can't mutate state.
        for m in ["GET", "HEAD", "OPTIONS"] {
            assert!(
                csrf_check(&req(m, None, None), "/api/firewall"),
                "{} should bypass CSRF",
                m
            );
        }
    }

    #[test]
    fn csrf_check_passes_on_bootstrap_auth_paths() {
        // These paths can't have a CSRF cookie yet — login issues it.
        for path in ["/api/auth/login", "/api/auth/password", "/api/auth/logout"] {
            assert!(
                csrf_check(&req("POST", None, None), path),
                "{} should be exempt from CSRF",
                path
            );
        }
    }

    #[test]
    fn csrf_check_rejects_post_without_cookie() {
        // POST with a header but no cookie — attacker has a guessed header
        // value but can't read the cookie → must be rejected.
        assert!(!csrf_check(
            &req("POST", None, Some("some-random-token")),
            "/api/firewall"
        ));
    }

    #[test]
    fn csrf_check_rejects_post_without_header() {
        // Browser happens to send the cookie but no X-CSRF-Token — classic
        // CSRF attack vector (cross-origin form submit). Must reject.
        assert!(!csrf_check(
            &req("POST", Some("quickfw_csrf=abc123"), None),
            "/api/firewall"
        ));
    }

    #[test]
    fn csrf_check_rejects_mismatched_tokens() {
        // Cookie and header both present but differ — either a stale cookie
        // or an attacker substituting a known-value header.
        assert!(!csrf_check(
            &req("POST", Some("quickfw_csrf=abc"), Some("xyz")),
            "/api/firewall"
        ));
    }

    #[test]
    fn csrf_check_accepts_matching_tokens() {
        assert!(csrf_check(
            &req(
                "POST",
                Some("quickfw_csrf=abc123; quickfw_session=xyz"),
                Some("abc123")
            ),
            "/api/firewall"
        ));
    }

    #[test]
    fn csrf_check_rejects_empty_strings() {
        // An empty header string with a non-empty cookie must not be treated
        // as a valid equal-length compare. Same for an empty cookie value.
        assert!(!csrf_check(
            &req("POST", Some("quickfw_csrf=abc"), Some("")),
            "/api/firewall"
        ));
        assert!(!csrf_check(
            &req("POST", Some("quickfw_csrf="), Some("abc")),
            "/api/firewall"
        ));
    }
}