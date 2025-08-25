use axum::{
   extract::Query,
   http::{HeaderMap, StatusCode},
   response::Json,
   routing::get,
   Router,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio;
use tower_http::cors::CorsLayer;

#[derive(Serialize)]
struct ApiResponse {
    message: String,
    user: String,
    timestamp: u64,
    query_params: HashMap<String, String>,
}

#[derive(Deserialize)]
struct TestQuery {
    name: Option<String>,
    count: Option<u32>,
}

async fn test_endpoint(
    headers: HeaderMap,
    Query(params): Query<TestQuery>,
) -> Result<Json<ApiResponse>, StatusCode> {
    let auth_header = headers.get("authorization")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("No auth header");

    if !auth_header.starts_with("Bearer ") {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let user = auth_header.strip_prefix("Bearer ").unwrap_or("unknown");

    let mut query_params = HashMap::new();
    if let Some(name) = params.name {
        query_params.insert("name".to_string(), name);
    }
    if let Some(count) = params.count {
        query_params.insert("count".to_string(), count.to_string());
    }

    Ok(Json(ApiResponse {
        message: "type shiiii".to_string(),
        user: user.to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        query_params,
    }))
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/hello", get(test_endpoint))
        .layer(CorsLayer::permissive());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:3002")
        .await
        .unwrap();

    println!("Server running on http://127.0.0.1:3002");
    axum::serve(listener, app).await.unwrap();
}