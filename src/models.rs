use serde::Serialize;

#[derive(sqlx::FromRow)]
pub struct SessionToken {
    pub id: i64,
    pub user_id: i64,
    pub session_token: String,
}

#[derive(sqlx::FromRow)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub password: String,
}

#[derive(sqlx::FromRow, Serialize)]
pub struct ChatMessage {
    pub id: i64,
    pub sender_id: i64,
    pub recipient_id: i64,
    pub sender_name: String,
    pub content: String,
    pub timestamp: String,
}
