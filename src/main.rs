// ============================================================
// Google Auth Middleware Crate
// lib.rs - Complete and Ready to Compile
// ============================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

// ============================================================
// Error Types
// ============================================================

#[derive(Debug, Clone)]
pub enum AuthError {
    InvalidToken,
    UserNotFound,
    FileError(String),
    ParseError(String),
    NetworkError(String),
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthError::InvalidToken => write!(f, "Invalid Google token"),
            AuthError::UserNotFound => write!(f, "User not authorized"),
            AuthError::FileError(msg) => write!(f, "File error: {}", msg),
            AuthError::ParseError(msg) => write!(f, "Parse error: {}", msg),
            AuthError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for AuthError {}

// ============================================================
// Data Structures
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleUser {
    pub google_id: String,
    pub email: String,
    pub name: Option<String>,
    pub picture: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedUsers {
    pub users: Vec<GoogleUser>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GoogleTokenInfo {
    pub sub: String,           // Google ID
    pub email: String,
    pub email_verified: bool,
    pub name: Option<String>,
    pub picture: Option<String>,
}

// ============================================================
// Auth Config
// ============================================================

pub struct GoogleAuthConfig {
    pub users_file_path: String,
    pub google_client_id: String,
}

impl GoogleAuthConfig {
    pub fn new(users_file_path: String, google_client_id: String) -> Self {
        Self {
            users_file_path,
            google_client_id,
        }
    }
}

// ============================================================
// Core Auth Functions
// ============================================================

/// Load authorized users from JSON file
pub fn load_authorized_users(path: &str) -> Result<AuthorizedUsers, AuthError> {
    let file_path = Path::new(path);
    
    if !file_path.exists() {
        return Err(AuthError::FileError(format!("File not found: {}", path)));
    }

    let content = fs::read_to_string(file_path)
        .map_err(|e| AuthError::FileError(e.to_string()))?;

    let users: AuthorizedUsers = serde_json::from_str(&content)
        .map_err(|e| AuthError::ParseError(e.to_string()))?;

    Ok(users)
}

/// Check if user is authorized
pub fn is_user_authorized(
    google_id: &str,
    email: &str,
    authorized_users: &AuthorizedUsers
) -> bool {
    authorized_users.users.iter().any(|user| {
        user.google_id == google_id || user.email == email
    })
}

/// Verify Google ID token and get user info
pub async fn verify_google_token(
    id_token: &str,
    _client_id: &str,
) -> Result<GoogleTokenInfo, AuthError> {
    let url = format!(
        "https://oauth2.googleapis.com/tokeninfo?id_token={}",
        id_token
    );

    let response = reqwest::get(&url)
        .await
        .map_err(|e| AuthError::NetworkError(e.to_string()))?;

    if !response.status().is_success() {
        return Err(AuthError::InvalidToken);
    }

    let token_info: GoogleTokenInfo = response
        .json()
        .await
        .map_err(|e| AuthError::ParseError(e.to_string()))?;

    Ok(token_info)
}

/// Main authentication function
pub async fn authenticate_user(
    id_token: &str,
    config: &GoogleAuthConfig,
) -> Result<GoogleUser, AuthError> {
    // 1. Verify token with Google
    let token_info = verify_google_token(id_token, &config.google_client_id).await?;

    // 2. Load authorized users
    let authorized_users = load_authorized_users(&config.users_file_path)?;

    // 3. Check if user is authorized
    if !is_user_authorized(&token_info.sub, &token_info.email, &authorized_users) {
        return Err(AuthError::UserNotFound);
    }

    // 4. Return authorized user info
    Ok(GoogleUser {
        google_id: token_info.sub,
        email: token_info.email,
        name: token_info.name,
        picture: token_info.picture,
    })
}

// ============================================================
// Session Management
// ============================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user: GoogleUser,
    pub created_at: SystemTime,
    pub expires_at: SystemTime,
    pub last_accessed: SystemTime,
}

impl Session {
    pub fn new(session_id: String, user: GoogleUser, ttl_seconds: u64) -> Self {
        let now = SystemTime::now();
        Self {
            session_id,
            user,
            created_at: now,
            expires_at: now + Duration::from_secs(ttl_seconds),
            last_accessed: now,
        }
    }

    pub fn is_expired(&self) -> bool {
        SystemTime::now() > self.expires_at
    }

    pub fn refresh(&mut self, ttl_seconds: u64) {
        let now = SystemTime::now();
        self.last_accessed = now;
        self.expires_at = now + Duration::from_secs(ttl_seconds);
    }
}

pub struct SessionStore {
    sessions: RwLock<HashMap<String, Session>>,
    ttl_seconds: u64,
}

impl SessionStore {
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
            ttl_seconds,
        }
    }

    /// Generate a unique session ID
    pub fn generate_session_id() -> String {
        use std::time::UNIX_EPOCH;
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!("{:x}", timestamp)
    }

    /// Create a new session
    pub fn create_session(&self, user: GoogleUser) -> Result<Session, AuthError> {
        let session_id = Self::generate_session_id();
        let session = Session::new(session_id.clone(), user, self.ttl_seconds);

        let mut sessions = self.sessions.write()
            .map_err(|_| AuthError::ParseError("Failed to acquire write lock".to_string()))?;
        
        sessions.insert(session_id.clone(), session.clone());
        
        Ok(session)
    }

    /// Get session by ID
    pub fn get_session(&self, session_id: &str) -> Result<Session, AuthError> {
        let sessions = self.sessions.read()
            .map_err(|_| AuthError::ParseError("Failed to acquire read lock".to_string()))?;

        let session = sessions.get(session_id)
            .ok_or(AuthError::InvalidToken)?;

        if session.is_expired() {
            drop(sessions);
            self.remove_session(session_id)?;
            return Err(AuthError::InvalidToken);
        }

        Ok(session.clone())
    }

    /// Refresh session (extend expiration)
    pub fn refresh_session(&self, session_id: &str) -> Result<Session, AuthError> {
        let mut sessions = self.sessions.write()
            .map_err(|_| AuthError::ParseError("Failed to acquire write lock".to_string()))?;

        let session = sessions.get_mut(session_id)
            .ok_or(AuthError::InvalidToken)?;

        if session.is_expired() {
            return Err(AuthError::InvalidToken);
        }

        session.refresh(self.ttl_seconds);
        Ok(session.clone())
    }

    /// Remove session (logout)
    pub fn remove_session(&self, session_id: &str) -> Result<(), AuthError> {
        let mut sessions = self.sessions.write()
            .map_err(|_| AuthError::ParseError("Failed to acquire write lock".to_string()))?;

        sessions.remove(session_id);
        Ok(())
    }

    /// Clean up expired sessions
    pub fn cleanup_expired(&self) -> Result<usize, AuthError> {
        let mut sessions = self.sessions.write()
            .map_err(|_| AuthError::ParseError("Failed to acquire write lock".to_string()))?;

        let before_count = sessions.len();
        sessions.retain(|_, session| !session.is_expired());
        let removed = before_count - sessions.len();

        Ok(removed)
    }

    /// Get all active sessions for a user
    pub fn get_user_sessions(&self, google_id: &str) -> Result<Vec<Session>, AuthError> {
        let sessions = self.sessions.read()
            .map_err(|_| AuthError::ParseError("Failed to acquire read lock".to_string()))?;

        let user_sessions: Vec<Session> = sessions.values()
            .filter(|s| s.user.google_id == google_id && !s.is_expired())
            .cloned()
            .collect();

        Ok(user_sessions)
    }

    /// Get session count
    pub fn session_count(&self) -> usize {
        self.sessions.read()
            .map(|s| s.len())
            .unwrap_or(0)
    }
}

// ============================================================
// Axum Middleware (Optional)
// ============================================================

#[cfg(feature = "axum")]
pub mod axum_middleware {
    use super::*;
    use axum::{
        extract::{Request, State},
        http::StatusCode,
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct AuthState {
        pub config: Arc<GoogleAuthConfig>,
    }

    pub async fn google_auth_middleware(
        State(auth_state): State<AuthState>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, AuthResponse> {
        // Extract token from Authorization header
        let auth_header = request
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .ok_or(AuthResponse::Unauthorized("Missing Authorization header".into()))?;

        let token = auth_header
            .strip_prefix("Bearer ")
            .ok_or(AuthResponse::Unauthorized("Invalid Authorization format".into()))?;

        // Authenticate user
        match authenticate_user(token, &auth_state.config).await {
            Ok(user) => {
                // Add user info to request extensions
                request.extensions_mut().insert(user);
                Ok(next.run(request).await)
            }
            Err(e) => Err(AuthResponse::Unauthorized(e.to_string())),
        }
    }

    pub enum AuthResponse {
        Unauthorized(String),
    }

    impl IntoResponse for AuthResponse {
        fn into_response(self) -> Response {
            match self {
                AuthResponse::Unauthorized(msg) => {
                    (StatusCode::UNAUTHORIZED, msg).into_response()
                }
            }
        }
    }
}

// ============================================================
// Axum Session Middleware
// ============================================================

#[cfg(feature = "axum")]
pub mod session_middleware {
    use super::*;
    use axum::{
        extract::{Request, State},
        http::{header, StatusCode},
        middleware::Next,
        response::{IntoResponse, Response},
    };
    use std::sync::Arc;

    #[derive(Clone)]
    pub struct SessionState {
        pub store: Arc<SessionStore>,
        pub config: Arc<GoogleAuthConfig>,
    }

    /// Middleware that checks for valid session cookie
    pub async fn session_auth_middleware(
        State(session_state): State<SessionState>,
        mut request: Request,
        next: Next,
    ) -> Result<Response, SessionAuthResponse> {
        // Try to get session ID from cookie
        let session_id = request
            .headers()
            .get(header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';')
                    .find_map(|cookie| {
                        let parts: Vec<&str> = cookie.trim().splitn(2, '=').collect();
                        if parts.len() == 2 && parts[0] == "session_id" {
                            Some(parts[1].to_string())
                        } else {
                            None
                        }
                    })
            })
            .ok_or(SessionAuthResponse::Unauthorized("No session cookie".into()))?;

        // Get and refresh session
        match session_state.store.refresh_session(&session_id) {
            Ok(session) => {
                // Add user and session to request extensions
                request.extensions_mut().insert(session.user.clone());
                request.extensions_mut().insert(session);
                Ok(next.run(request).await)
            }
            Err(_) => Err(SessionAuthResponse::Unauthorized("Invalid or expired session".into())),
        }
    }

    pub enum SessionAuthResponse {
        Unauthorized(String),
    }

    impl IntoResponse for SessionAuthResponse {
        fn into_response(self) -> Response {
            match self {
                SessionAuthResponse::Unauthorized(msg) => {
                    (StatusCode::UNAUTHORIZED, msg).into_response()
                }
            }
        }
    }
}

// ============================================================
// Helper Functions
// ============================================================

/// Create a sample users.json file
pub fn create_sample_users_file(path: &str) -> Result<(), AuthError> {
    let sample = AuthorizedUsers {
        users: vec![
            GoogleUser {
                google_id: "123456789012345678901".to_string(),
                email: "user@example.com".to_string(),
                name: Some("Sample User".to_string()),
                picture: None,
            },
        ],
    };

    let json = serde_json::to_string_pretty(&sample)
        .map_err(|e| AuthError::ParseError(e.to_string()))?;

    fs::write(path, json)
        .map_err(|e| AuthError::FileError(e.to_string()))?;

    Ok(())
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_load_authorized_users() {
        // Create test file
        let test_path = "test_users.json";
        create_sample_users_file(test_path).unwrap();

        // Load users
        let users = load_authorized_users(test_path).unwrap();
        assert_eq!(users.users.len(), 1);
        assert_eq!(users.users[0].email, "user@example.com");

        // Cleanup
        let _ = fs::remove_file(test_path);
    }

    #[test]
    fn test_is_user_authorized() {
        let users = AuthorizedUsers {
            users: vec![
                GoogleUser {
                    google_id: "123".to_string(),
                    email: "test@example.com".to_string(),
                    name: None,
                    picture: None,
                },
            ],
        };

        assert!(is_user_authorized("123", "test@example.com", &users));
        assert!(!is_user_authorized("999", "other@example.com", &users));
    }

    #[test]
    fn test_session_lifecycle() {
        let store = SessionStore::new(60);
        
        let user = GoogleUser {
            google_id: "123".to_string(),
            email: "test@example.com".to_string(),
            name: None,
            picture: None,
        };

        // Create session
        let session = store.create_session(user).unwrap();
        assert!(!session.is_expired());

        // Get session
        let retrieved = store.get_session(&session.session_id).unwrap();
        assert_eq!(retrieved.user.email, "test@example.com");

        // Remove session
        store.remove_session(&session.session_id).unwrap();
        assert!(store.get_session(&session.session_id).is_err());
    }
}