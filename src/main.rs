mod models;
mod websocket;
mod routes;

use actix_web::{web, App, HttpServer, middleware::Logger};
use sqlx::SqlitePool;
use tokio::sync::broadcast;

struct AppState {
    db_pool: SqlitePool,
    tx: broadcast::Sender<String>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init(); // Ініціалізація логера

    let db_pool = SqlitePool::connect("sqlite://chat.db").await.unwrap();
    let (tx, _rx) = broadcast::channel::<String>(100);

    let app_state = web::Data::new(AppState {
        db_pool: db_pool.clone(),
        tx,
    });

    HttpServer::new(move || {
        App::new()
            .wrap(Logger::default())
            .app_data(app_state.clone())
            .service(routes::register_form)
            .service(routes::login_form)
            .service(routes::register)
            .service(routes::login)
            .service(routes::index)
            .service(routes::logout)
            .service(routes::get_users) // Додано
            .service(routes::get_messages) // Додано
            .service(web::resource("/ws/").route(web::get().to(websocket::websocket_route)))
    })
        .bind("127.0.0.1:8080")?
        .run()
        .await
}
