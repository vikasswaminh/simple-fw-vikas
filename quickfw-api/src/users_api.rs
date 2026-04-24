//! /api/users CRUD handlers (Phase G).
//!
//! All routes here are gated by `require_role(Role::Admin)` at router
//! construction time — only admins can list, create, delete, or change
//! another user's role/password.

use axum::{
    extract::Path,
    http::StatusCode,
    middleware,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tracing::info;

use crate::{
    auth::{require_role, AuthUser},
    state,
    users::{self, Role, UserOpError},
};

pub fn create_router() -> Router {
    Router::new()
        .route("/api/users", get(list_users))
        .route("/api/users", post(create_user))
        .route("/api/users/:username", delete(delete_user))
        .route("/api/users/:username/role", post(set_role))
        .route("/api/users/:username/password", post(set_password))
        // Admin-only gate.
        .layer(middleware::from_fn(require_role(Role::Admin)))
}

#[derive(Serialize)]
struct UserDto {
    username: String,
    role: String,
}

async fn list_users(axum::Extension(caller): axum::Extension<AuthUser>) -> Json<Vec<UserDto>> {
    let _ = caller; // presence already enforced by the gate
    let file = users::load_users();
    Json(
        file.users
            .iter()
            .map(|u| UserDto {
                username: u.username.clone(),
                role: u.role.as_str().to_string(),
            })
            .collect(),
    )
}

#[derive(Deserialize)]
struct CreateUserRequest {
    username: String,
    password: String,
    role: String,
}

async fn create_user(
    Json(req): Json<CreateUserRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    if req.username.is_empty() || req.username.len() > 32 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "invalid username"})),
        ));
    }
    if !req
        .username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "username may only contain [A-Za-z0-9._-]"})),
        ));
    }
    let role = Role::parse(&req.role).ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "role must be admin|operator|readonly"})),
    ))?;

    let mut file = users::load_users();
    match users::create_user(&mut file, &req.username, &req.password, role) {
        Ok(()) => {
            info!("user created: {} ({})", req.username, role.as_str());
            Ok(Json(serde_json::json!({"message": "User created"})))
        }
        Err(e) => Err(map_err(e)),
    }
}

async fn delete_user(
    axum::Extension(caller): axum::Extension<AuthUser>,
    Path(username): Path<String>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    if caller.username == username {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "cannot delete the user you are logged in as"})),
        ));
    }
    let mut file = users::load_users();
    match users::delete_user(&mut file, &username) {
        Ok(()) => {
            info!("user deleted: {}", username);
            Ok(Json(serde_json::json!({"message": "User deleted"})))
        }
        Err(e) => Err(map_err(e)),
    }
}

#[derive(Deserialize)]
struct SetRoleRequest {
    role: String,
}

async fn set_role(
    Path(username): Path<String>,
    Json(req): Json<SetRoleRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    let role = Role::parse(&req.role).ok_or((
        StatusCode::BAD_REQUEST,
        Json(serde_json::json!({"error": "role must be admin|operator|readonly"})),
    ))?;
    let mut file = users::load_users();
    match users::set_role(&mut file, &username, role) {
        Ok(()) => {
            info!("user {} role -> {}", username, role.as_str());
            Ok(Json(serde_json::json!({"message": "Role updated"})))
        }
        Err(e) => Err(map_err(e)),
    }
}

#[derive(Deserialize)]
struct SetPasswordRequest {
    password: String,
}

async fn set_password(
    Path(username): Path<String>,
    Json(req): Json<SetPasswordRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<serde_json::Value>)> {
    let _guard = state::config_lock().lock().await;
    let mut file = users::load_users();
    match users::set_password(&mut file, &username, &req.password) {
        Ok(()) => {
            info!("password reset for {}", username);
            Ok(Json(serde_json::json!({"message": "Password updated"})))
        }
        Err(e) => Err(map_err(e)),
    }
}

fn map_err(e: UserOpError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match e {
        UserOpError::NotFound => StatusCode::NOT_FOUND,
        UserOpError::AlreadyExists | UserOpError::LastAdmin | UserOpError::InvalidRole
        | UserOpError::WeakPassword => StatusCode::BAD_REQUEST,
        UserOpError::Hash(_) | UserOpError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, Json(serde_json::json!({"error": e.to_string()})))
}
