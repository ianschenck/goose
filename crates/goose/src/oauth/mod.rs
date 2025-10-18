use axum::extract::{Query, State};
use axum::response::Html;
use axum::routing::get;
use axum::Router;
use minijinja::render;
use rmcp::transport::auth::{OAuthState, OAuthTokenResponse, TokenUpdateCallback};
use rmcp::transport::AuthorizationManager;
use serde::Deserialize;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::{oneshot, Mutex};
use tracing::{info, warn};

use crate::oauth::persist::{clear_credentials, load_cached_state, save_credentials};

mod persist;

/// Callback that persists OAuth credentials when they're updated
struct CredentialPersister {
    name: String,
    mcp_server_url: String,
}

impl TokenUpdateCallback for CredentialPersister {
    fn on_token_updated(&self, client_id: &str, token_response: &OAuthTokenResponse) {
        info!("OAuth token updated for {}, persisting to keyring", self.name);

        let name = self.name.clone();
        let mcp_server_url = self.mcp_server_url.clone();
        let client_id = client_id.to_string();
        let token_response = token_response.clone();

        // Spawn async task to save credentials
        tokio::spawn(async move {
            match OAuthState::new(&mcp_server_url, None).await {
                Ok(mut oauth_state) => {
                    if let Err(e) = oauth_state.set_credentials(&client_id, token_response).await {
                        warn!("Failed to set credentials for persistence: {}", e);
                        return;
                    }

                    if let Err(e) = save_credentials(&name, &oauth_state).await {
                        warn!("Failed to persist refreshed OAuth credentials: {}", e);
                    } else {
                        info!("Successfully persisted OAuth credentials for {}", name);
                    }
                }
                Err(e) => {
                    warn!("Failed to create OAuth state for persistence: {}", e);
                }
            }
        });
    }
}

const CALLBACK_TEMPLATE: &str = include_str!("oauth_callback.html");

#[derive(Clone)]
struct AppState {
    code_receiver: Arc<Mutex<Option<oneshot::Sender<CallbackParams>>>>,
}

#[derive(Debug, Deserialize)]
struct CallbackParams {
    code: String,
    state: String,
}

pub async fn oauth_flow(
    mcp_server_url: &String,
    name: &String,
) -> Result<AuthorizationManager, anyhow::Error> {
    // Create callback for automatic credential persistence
    let callback = Arc::new(CredentialPersister {
        name: name.clone(),
        mcp_server_url: mcp_server_url.clone(),
    });

    // Try to use cached credentials
    if let Ok(oauth_state) = load_cached_state(mcp_server_url, name).await {
        if let Some(mut authorization_manager) = oauth_state.into_authorization_manager() {
            // Install callback so future refreshes are persisted automatically
            authorization_manager.set_token_update_callback(Some(callback.clone()));

            // Try to refresh the token
            if authorization_manager.refresh_token().await.is_ok() {
                // Token refreshed successfully, callback will persist it automatically
                return Ok(authorization_manager);
            }
        }

        // Cached credentials are bad, clear them
        if let Err(e) = clear_credentials(name) {
            warn!("error clearing bad credentials: {}", e);
        }
    }

    let (code_sender, code_receiver) = oneshot::channel::<CallbackParams>();
    let app_state = AppState {
        code_receiver: Arc::new(Mutex::new(Some(code_sender))),
    };

    let rendered = render!(CALLBACK_TEMPLATE, name => name);
    let handler = move |Query(params): Query<CallbackParams>, State(state): State<AppState>| {
        let rendered = rendered.clone();
        async move {
            if let Some(sender) = state.code_receiver.lock().await.take() {
                let _ = sender.send(params);
            }
            Html(rendered)
        }
    };
    let app = Router::new()
        .route("/oauth_callback", get(handler))
        .with_state(app_state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 0));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let used_addr = listener.local_addr()?;
    tokio::spawn(async move {
        let result = axum::serve(listener, app).await;
        if let Err(e) = result {
            eprintln!("Callback server error: {}", e);
        }
    });

    // Start new OAuth flow with callback
    let mut oauth_state = OAuthState::new_with_callback(mcp_server_url, None, Some(callback)).await?;
    let redirect_uri = format!("http://localhost:{}/oauth_callback", used_addr.port());
    oauth_state
        .start_authorization(&["offline_access"], redirect_uri.as_str(), Some("goose"))
        .await?;

    let authorization_url = oauth_state.get_authorization_url().await?;
    if webbrowser::open(authorization_url.as_str()).is_err() {
        eprintln!("Open the following URL to authorize {}:", name);
        eprintln!("  {}", authorization_url);
    }

    let CallbackParams {
        code: auth_code,
        state: csrf_token,
    } = code_receiver.await?;
    oauth_state.handle_callback(&auth_code, &csrf_token).await?;

    // Initial credentials are saved via callback during handle_callback
    // Manual save as backup in case callback hasn't completed yet
    if let Err(e) = save_credentials(name, &oauth_state).await {
        warn!("Failed to save credentials: {}", e);
    }

    let auth_manager = oauth_state
        .into_authorization_manager()
        .ok_or_else(|| anyhow::anyhow!("Failed to get authorization manager"))?;

    Ok(auth_manager)
}
