use actix_web::{web, HttpRequest, HttpResponse, Error};
use actix_ws::{handle, Message, MessageStream, Session};
use futures_util::StreamExt;
use crate::models::{SessionToken, ChatMessage};
use crate::AppState;

pub async fn websocket_route(
    req: HttpRequest,
    stream: web::Payload,
    app_state: web::Data<AppState>,
) -> Result<HttpResponse, Error> {
    let db = &app_state.db_pool;

    if let Some(cookie) = req.cookie("session_token") {
        let session = sqlx::query_as::<_, SessionToken>(
            "SELECT * FROM sessions WHERE session_token = ?",
        )
        .bind(cookie.value())
        .fetch_optional(db)
        .await;

        if let Some(session) = session.unwrap_or(None) {
            let user_id = session.user_id;

            // Fetch username for the session
            let username_result = sqlx::query_scalar!(
                "SELECT username FROM users WHERE id = ?",
                user_id
            )
            .fetch_one(db)
            .await;

            // If we cannot fetch the username, return an error response
            let username = match username_result {
                Ok(name) => name,
                Err(err) => {
                    eprintln!("Failed to fetch username: {:?}", err);
                    return Ok(HttpResponse::InternalServerError().body("Failed to fetch username"));
                }
            };

            // Check if the username already exists in the database
            let username_exists = sqlx::query_scalar!(
                "SELECT COUNT(*) FROM users WHERE username = ?",
                username
            )
            .fetch_one(db)
            .await
            .unwrap_or(0);

            if username_exists > 1 {
                // Return error response if username already exists
                return Ok(HttpResponse::BadRequest().body("Username already exists"));
            }

            // Retrieve message history
            let messages = sqlx::query_as::<_, ChatMessage>(
                "SELECT
                    messages.id AS id,
                    messages.sender_id AS sender_id,
                    users.username AS sender_name,
                    messages.content AS content,
                    messages.timestamp AS timestamp
                FROM
                    messages
                JOIN
                    users
                ON
                    messages.sender_id = users.id
                ORDER BY
                    messages.timestamp ASC;"
            )
            .fetch_all(db)
            .await
            .unwrap_or_else(|_| vec![]);

            // Create WebSocket connection
            let (response, mut session, msg_stream) = handle(&req, stream)?;

            // Send message history
            for message in messages {
                let formatted_message = format!(
                    "{}: {}      [{}]",
                    message.sender_name, message.content, message.timestamp
                );
                if let Err(err) = session.text(formatted_message).await {
                    eprintln!("Failed to send message history: {:?}", err);
                }
            }

            // Launch the WebSocket message handler
            actix_web::rt::spawn(websocket_handler(
                session,
                msg_stream,
                app_state.clone(),
                user_id,
            ));
            return Ok(response);
        }
    }

    Ok(HttpResponse::Unauthorized().body("Unauthorized"))
}


async fn websocket_handler(
    mut session: Session,
    mut msg_stream: MessageStream,
    app_state: web::Data<AppState>,
    sender_id: i64,
) -> Result<(), Error> {
    let db = &app_state.db_pool;
    let mut rx = app_state.tx.subscribe();

    loop {
        tokio::select! {
            Some(Ok(msg)) = msg_stream.next() => {
                if let Message::Text(text) = msg {
                    // Парсимо отримане повідомлення
                    let data: serde_json::Value = serde_json::from_str(&text).unwrap_or_default();
                    let message_content = data["message"].as_str().unwrap_or("").to_string();
                    let recipient_id = data["recipient_id"].as_i64().unwrap_or(0);

                    if recipient_id == 0 {
                        eprintln!("Invalid recipient_id");
                        continue;
                    }

                    // Отримуємо поточний таймстемп
                    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();

                    // Збереження повідомлення у базу
                    sqlx::query!(
                        "INSERT INTO messages (sender_id, recipient_id, content, timestamp) VALUES (?, ?, ?, ?)",
                        sender_id,
                        recipient_id,
                        message_content,
                        timestamp
                    )
                    .execute(db)
                    .await
                    .ok();

                    // Отримуємо ім'я відправника
                    let sender_name = sqlx::query_scalar!(
                        "SELECT username FROM users WHERE id = ?",
                        sender_id
                    )
                    .fetch_one(db)
                    .await
                    .unwrap_or_else(|_| "Анонім".to_string());

                    // Підготовка повідомлення
                    let message_json = serde_json::json!({
                        "sender_id": sender_id,
                        "recipient_id": recipient_id,
                        "sender_name": sender_name,
                        "content": message_content,
                        "timestamp": timestamp,
                    });

                    // Надсилання повідомлення через канал
                    let _ = app_state.tx.send(message_json.to_string());
                }
            }
            Ok(message) = rx.recv() => {
                // Парсимо отримане повідомлення
                let data: serde_json::Value = serde_json::from_str(&message).unwrap_or_default();
                let recipient_id = data["recipient_id"].as_i64().unwrap_or(0);
                let sender_id_in_message = data["sender_id"].as_i64().unwrap_or(0);

                // Відправляємо повідомлення, якщо клієнт є відправником або одержувачем
                if recipient_id == sender_id || sender_id_in_message == sender_id {
                    if let Err(err) = session.text(message).await {
                        eprintln!("Failed to send message to client: {:?}", err);
                    }
                }
            }
            else => {
                break;
            }
        }
    }

    Ok(())
}
