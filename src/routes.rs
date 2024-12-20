use std::collections::HashMap;
use actix_web::{web, HttpResponse, Responder, get, post, cookie, http::header, HttpRequest};
use bcrypt::{hash, verify};
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use crate::AppState;
use crate::models::{ChatMessage, SessionToken, User};

#[derive(Deserialize)]
pub struct RegisterData {
    pub username: String,
    pub password: String,
}

#[derive(Deserialize)]
pub struct LoginData {
    pub username: String,
    pub password: String,
}

#[derive(Serialize)]
pub struct ApiUser {
    pub id: i64,
    pub username: String,
}

// Форма реєстрації
#[get("/register")]
async fn register_form() -> HttpResponse {
    let html = include_str!("../static/register.html");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// Форма входу
#[get("/login")]
async fn login_form() -> HttpResponse {
    let html = include_str!("../static/login.html");
    HttpResponse::Ok()
        .content_type("text/html; charset=utf-8")
        .body(html)
}

// Обробка реєстрації нового користувача
#[post("/register")]
async fn register(
    data: web::Form<RegisterData>,       // Вхідні дані, передані з форми реєстрації
    app_state: web::Data<AppState>,     // Загальний стан програми, що включає пул з'єднань з БД
) -> HttpResponse {
    // Отримуємо пул з'єднань з базою даних
    let db = &app_state.db_pool;

    // Хешуємо пароль користувача для безпечного збереження в базі даних
    let hashed_password = hash(&data.password, 4).unwrap();

    // Формуємо SQL-запит для вставки нового користувача в таблицю `users`
    let result = sqlx::query!(
        "INSERT INTO users (username, password) VALUES (?, ?)", // Запит на додавання нового користувача
        data.username,         // Ім'я користувача з форми реєстрації
        hashed_password        // Захешований пароль
    )
    .execute(db)               // Виконуємо запит до бази даних
    .await;

    // Обробляємо результат виконання запиту
    match result {
        // Якщо запит виконано успішно
        Ok(_) => HttpResponse::Found()
            .insert_header((
                header::LOCATION,                // Заголовок перенаправлення
                "/login?message=Реєстрація успішна&success=true", // Повідомлення про успіх
            ))
            .finish(),                           // Завершуємо відповідь
        // Якщо сталася помилка (наприклад, ім'я користувача вже зайняте)
        Err(_) => HttpResponse::Found()
            .insert_header((
                header::LOCATION,                // Заголовок перенаправлення
                "/register?message=Ім'я користувача вже зайнято&success=false", // Повідомлення про помилку
            ))
            .finish(),                           // Завершуємо відповідь
    }
}



// Обробка входу
// Обробка входу користувача
#[post("/login")]
async fn login(
    data: web::Form<LoginData>,       // Вхідні дані з форми входу
    app_state: web::Data<AppState>,  // Спільний стан програми (зокрема пул з'єднань з БД)
) -> HttpResponse {
    let db = &app_state.db_pool;      // Отримуємо пул з'єднань з базою даних

    // Виконуємо запит до бази даних для отримання користувача за його ім'ям
    let user = sqlx::query_as::<_, User>(   // Повертає об'єкт типу `User`
        "SELECT * FROM users WHERE username = ?" // SQL-запит для пошуку користувача за ім'ям
    )
    .bind(&data.username)               // Підставляємо значення імені користувача
    .fetch_optional(db)                 // Повертає `Option<User>` або `None`, якщо не знайдено
    .await;

    // Перевіряємо, чи був знайдений користувач і чи немає помилок у запиті
    if let Ok(Some(user)) = user {
        // Перевіряємо, чи співпадає пароль
        if verify(&data.password, &user.password).unwrap() {
            // Генеруємо унікальний токен для сесії
            let session_token = Uuid::new_v4().to_string();

            // Вставляємо токен сесії в таблицю `sessions` у базі даних
            sqlx::query!(
                "INSERT INTO sessions (user_id, session_token) VALUES (?, ?)", // SQL-запит
                user.id,                    // ID користувача
                session_token               // Сформований токен сесії
            )
            .execute(db)                   // Виконуємо запит до БД
            .await
            .unwrap();                     // Обробка помилок (unwrap тут припускає, що помилки не буде)

            // Якщо все успішно, створюємо cookie з токеном сесії та перенаправляємо на головну сторінку
            return HttpResponse::Found()
                .cookie(
                    cookie::Cookie::build("session_token", session_token) // Встановлюємо cookie з токеном
                        .finish(),
                )
                .insert_header((header::LOCATION, "/")) // Перенаправлення на головну сторінку
                .finish();
        }
    }

    // Якщо дані невірні (користувач не знайдений або пароль не співпадає),
    // перенаправляємо назад на сторінку входу з повідомленням про помилку
    HttpResponse::Found()
        .insert_header((
            header::LOCATION,                          // Заголовок перенаправлення
            "/login?message=Невірні дані&success=false", // Повідомлення про помилку
        ))
        .finish()
}

// Обробка запиту на головну сторінку
#[get("/")]
async fn index(req: HttpRequest, app_state: web::Data<AppState>) -> HttpResponse {
    let db = &app_state.db_pool; // Отримуємо пул з'єднань з базою даних

    // Перевіряємо, чи є cookie з токеном сесії
    if let Some(cookie) = req.cookie("session_token") {
        // Шукаємо сесію в базі даних за токеном
        let session = sqlx::query_as::<_, SessionToken>(
            "SELECT * FROM sessions WHERE session_token = ?" // SQL-запит для перевірки токена
        )
        .bind(cookie.value()) // Підставляємо значення токена з cookie
        .fetch_optional(db)  // Отримуємо результат як Option<SessionToken>
        .await
        .unwrap();           // Виконуємо запит і розпаковуємо результат (unwrap припускає, що помилки не буде)

        // Якщо сесія існує, відображаємо головну сторінку
        if session.is_some() {
            let html = include_str!("../static/index.html"); // Завантажуємо HTML-файл
            return HttpResponse::Ok() // Відправляємо відповідь зі статусом 200
                .content_type("text/html; charset=utf-8") // Встановлюємо тип контенту
                .body(html); // Додаємо HTML в тіло відповіді
        }
    }

    // Якщо сесія не знайдена, перенаправляємо на сторінку входу з повідомленням
    HttpResponse::Found()
        .insert_header(( // Встановлюємо заголовок для перенаправлення
            header::LOCATION, 
            "/login?message=Будь ласка, увійдіть у систему&success=false" // Повідомлення про необхідність входу
        ))
        .finish()
}


// Обробка запиту на вихід з системи
#[post("/logout")]
async fn logout() -> impl Responder {
    HttpResponse::Found() // Відправляємо відповідь з кодом 302 (перенаправлення)
        .insert_header((
            header::LOCATION, 
            "/login?message=Вихід успішний&success=true" // Повідомлення про успішний вихід
        ))
        .cookie( // Видаляємо cookie з токеном сесії
            cookie::Cookie::build("session_token", "") // Створюємо пустий cookie з тим самим іменем
                .path("/") // Встановлюємо шлях, для якого діє cookie
                .max_age(cookie::time::Duration::seconds(0)) // Встановлюємо максимальний вік cookie як 0 (видалення)
                .finish()
        )
        .finish()
}


// API для отримання списку користувачів (виключаючи поточного користувача)
#[get("/api/users")]
async fn get_users(app_state: web::Data<AppState>, req: HttpRequest) -> HttpResponse {
    let db = &app_state.db_pool; // Отримуємо пул з'єднань з базою даних

    // Отримуємо токен сесії з cookie
    if let Some(cookie) = req.cookie("session_token") {
        // Перевіряємо сесію за токеном
        let session = sqlx::query_as::<_, SessionToken>(
            "SELECT * FROM sessions WHERE session_token = ?", // SQL-запит для пошуку сесії
        )
        .bind(cookie.value()) // Підставляємо значення токена з cookie
        .fetch_optional(db)  // Отримуємо результат як Option<SessionToken>
        .await
        .unwrap();           // Обробка помилки виконання запиту (unwrap припускає, що помилки немає)

        // Якщо сесія існує
        if let Some(session) = session {
            let user_id = session.user_id; // Отримуємо ID поточного користувача з сесії

            // Отримуємо список усіх користувачів, виключаючи поточного
            let users = sqlx::query!(
                "SELECT id, username FROM users WHERE id != ?", // SQL-запит для отримання користувачів
                user_id                                        // Підставляємо ID поточного користувача
            )
            .fetch_all(db)                                     // Виконуємо запит для отримання всіх записів
            .await
            .unwrap_or_default();                              // Якщо запит не вдався, повертаємо пустий список

            // Перетворюємо результати запиту в список структур `ApiUser`
            let users: Vec<ApiUser> = users.into_iter()
                .map(|record| ApiUser { // Кожен запис перетворюємо в структуру `ApiUser`
                    id: record.id,
                    username: record.username,
                })
                .collect();

            // Повертаємо список користувачів у форматі JSON
            return HttpResponse::Ok().json(users);
        }
    }

    // Якщо токен відсутній або недійсний, повертаємо статус 401 (Unauthorized)
    HttpResponse::Unauthorized().body("Unauthorized")
}


// API для отримання повідомлень між поточним користувачем і обраним одержувачем
#[get("/api/messages")]
async fn get_messages(
    app_state: web::Data<AppState>,               // Спільний стан програми (зокрема, пул з'єднань з БД)
    req: HttpRequest,                             // HTTP-запит, що містить cookie
    query: web::Query<HashMap<String, String>>,   // Параметри запиту, включаючи `recipient_id`
) -> HttpResponse {
    let db = &app_state.db_pool; // Отримуємо пул з'єднань з базою даних

    // Отримуємо токен сесії з cookie
    if let Some(cookie) = req.cookie("session_token") {
        // Перевіряємо сесію за токеном
        let session = sqlx::query_as::<_, SessionToken>(
            "SELECT * FROM sessions WHERE session_token = ?", // SQL-запит для пошуку сесії
        )
        .bind(cookie.value()) // Підставляємо значення токена з cookie
        .fetch_optional(db)  // Отримуємо результат як Option<SessionToken>
        .await
        .unwrap();           // Розпаковуємо результат (припускається, що помилки немає)

        // Якщо сесія знайдена
        if let Some(session) = session {
            let user_id = session.user_id; // Отримуємо ID поточного користувача

            // Перевіряємо, чи передано `recipient_id` у параметрах запиту
            if let Some(recipient_id_str) = query.get("recipient_id") {
                if let Ok(recipient_id) = recipient_id_str.parse::<i64>() {
                    // Отримуємо повідомлення між поточним користувачем і обраним одержувачем
                    let messages = sqlx::query!(
                        "SELECT
                            messages.id,
                            messages.sender_id,
                            messages.recipient_id,
                            users.username AS sender_name,
                            messages.content,
                            messages.timestamp
                        FROM
                            messages
                        JOIN
                            users ON messages.sender_id = users.id
                        WHERE
                            (messages.sender_id = ? AND messages.recipient_id = ?)
                            OR
                            (messages.sender_id = ? AND messages.recipient_id = ?)
                        ORDER BY
                            messages.timestamp ASC;",
                        user_id,          // Поточний користувач як відправник
                        recipient_id,     // Обраний одержувач
                        recipient_id,     // Обраний одержувач як відправник
                        user_id           // Поточний користувач як одержувач
                    )
                    .fetch_all(db)       // Отримуємо всі результати запиту
                    .await
                    .unwrap_or_default(); // Якщо запит не вдався, повертаємо пустий список

                    // Перетворюємо записи в список структур `ChatMessage`
                    let messages: Vec<ChatMessage> = messages.into_iter()
                        .filter_map(|record| {
                            Some(ChatMessage {
                                id: record.id, // ID повідомлення
                                sender_id: record.sender_id, // ID відправника
                                recipient_id: record.recipient_id.expect("REASON"), // ID одержувача
                                sender_name: record.sender_name, // Ім'я відправника
                                content: record.content, // Текст повідомлення
                                timestamp: record.timestamp.unwrap_or_else(|| "Unknown".to_string()), // Час повідомлення
                            })
                        })
                        .collect();

                    // Повертаємо список повідомлень у форматі JSON
                    return HttpResponse::Ok().json(messages);
                }
            }
        }
    }

    // Якщо токен недійсний або параметри запиту некоректні, повертаємо статус 401 (Unauthorized)
    HttpResponse::Unauthorized().body("Unauthorized")
}
