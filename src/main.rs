mod middleware;

use jsonwebtoken::{self, EncodingKey};
// use middleware::JwtMiddleware;
use salvo::affix_state;
use salvo::http::header::{self, HeaderValue};
use salvo::http::response::ResBody;
use salvo::jwt_auth::{ConstDecoder, HeaderFinder, JwtAuth, JwtAuthState};
use salvo::oapi::extract::JsonBody;
use salvo::prelude::*;
use salvo::size_limiter;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, LazyLock};
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;
use utoipa::openapi::security::SecurityScheme;
use utoipa::{Modify, OpenApi, ToSchema};
use utoipa_swagger_ui::Config;

static STORE: LazyLock<Db> = LazyLock::new(new_store);
pub type Db = Mutex<Vec<Todo>>;

pub fn new_store() -> Db {
    Mutex::new(Vec::new())
}

const SECRET_KEY: &str = "YOUR_SECRET_KEY";

#[derive(Debug, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "username": "user123",
    "exp": 1735689600
}))]
pub struct JwtClaims {
    #[schema(example = "user123")]
    username: String,
    #[schema(example = 1735689600)]
    exp: i64,
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct LoginRequest {
    #[schema(example = "root")]
    username: String,
    #[schema(example = "pwd")]
    password: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, ToSchema)]
pub struct Todo {
    #[schema(example = 1)]
    pub id: u64,
    #[schema(example = "Buy coffee")]
    pub text: String,
    pub completed: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub enum TodoError {
    #[schema(example = "Todo with id=1 already exists")]
    Config(String),
    #[schema(example = "Todo with id=1 not found")]
    NotFound(String),
}

#[derive(OpenApi)]
#[openapi(
    paths(
        list_todos,
        create_todo,
        delete_todo,
        update_todo,
        login
    ),
    components(
        schemas(Todo, TodoError, JwtClaims, LoginRequest)
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "todo", description = "Todo items management endpoints."),
        (name = "auth", description = "Authentication endpoints.")
    )
)]
struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.as_mut().unwrap();

        components.add_security_scheme(
            "bearer_auth",
            SecurityScheme::Http(utoipa::openapi::security::Http::new(
                utoipa::openapi::security::HttpAuthScheme::Bearer,
            )),
        );
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().init();

    let auth_handler: JwtAuth<JwtClaims, _> =
        JwtAuth::new(ConstDecoder::from_secret(SECRET_KEY.as_bytes()))
            .finders(vec![Box::new(HeaderFinder::new())])
            .force_passed(true);

    // let jwt_middleware = JwtMiddleware::new("YOUR_SECRET_KEY".to_string());

    let config = Arc::new(Config::from("/api-doc/openapi.json"));
    let router = Router::new()
        .get(hello)
        .push(
            Router::with_path("api")
                .push(
                    Router::with_path("todos")
                        .hoop(auth_handler)
                        .hoop(size_limiter::max_size(1024 * 16))
                        .get(list_todos)
                        .post(create_todo)
                        .push(
                            Router::with_path("{id}")
                                .put(update_todo)
                                .delete(delete_todo),
                        ),
                )
                .push(Router::new().path("login").post(login)),
        )
        .push(Router::with_path("/api-doc/openapi.json").get(openapi_json))
        .push(
            Router::with_path("/swagger-ui/{**}")
                .hoop(affix_state::inject(config))
                .get(serve_swagger),
        );

    let acceptor = TcpListener::new("0.0.0.0:5800").bind().await;
    Server::new(acceptor).serve(router).await;
}

#[handler]
async fn hello(res: &mut Response) {
    res.render("Hello");
}

#[handler]
pub async fn openapi_json(res: &mut Response) {
    res.render(Json(ApiDoc::openapi()))
}

#[handler]
pub async fn serve_swagger(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let config = depot.obtain::<Arc<Config>>().unwrap();
    let path = req.uri().path();

    let tail = match path.strip_prefix("/swagger-ui/") {
        Some(tail) => tail,
        None => {
            res.status_code(StatusCode::NOT_FOUND);
            return;
        }
    };

    match utoipa_swagger_ui::serve(tail, config.clone()) {
        Ok(swagger_file) => {
            if let Some(file) = swagger_file {
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(&file.content_type).unwrap(),
                );
                res.body(ResBody::Once(file.bytes.to_vec().into()));
            } else {
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
        Err(_error) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = String),
        (status = 401, description = "Unauthorized")
    ),
    tag = "auth"
)]
#[handler]
pub async fn login(req: JsonBody<LoginRequest>, res: &mut Response) {
    let login_request = req.into_inner();

    if login_request.username == "root" && login_request.password == "pwd" {
        let exp = OffsetDateTime::now_utc() + Duration::days(14);
        let claim = JwtClaims {
            username: login_request.username,
            exp: exp.unix_timestamp(),
        };
        let token = jsonwebtoken::encode(
            &jsonwebtoken::Header::default(),
            &claim,
            &EncodingKey::from_secret(SECRET_KEY.as_bytes()),
        )
        .unwrap();

        res.render(Json(token));
    } else {
        res.status_code(StatusCode::UNAUTHORIZED);
    }
}

#[utoipa::path(
    get,
    path = "/api/todos",
    responses(
        (status = 200, description = "List all todos successfully", body = [Todo])
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[handler]
pub async fn list_todos(depot: &mut Depot, res: &mut Response) {
    match depot.jwt_auth_state() {
        JwtAuthState::Authorized => {
            let todos = STORE.lock().await;
            let todos: Vec<Todo> = todos.clone();
            res.render(Json(todos));
        }
        JwtAuthState::Unauthorized => {
            res.status_code(StatusCode::UNAUTHORIZED);
        }
        JwtAuthState::Forbidden => {
            res.status_code(StatusCode::FORBIDDEN);
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/todos",
    request_body = Todo,
    responses(
        (status = 201, description = "Todo created successfully", body = Todo),
        (status = 409, description = "Todo already exists", body = TodoError)
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[handler]
pub async fn create_todo(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    match depot.jwt_auth_state() {
        JwtAuthState::Authorized => {
            let new_todo = req.parse_body::<Todo>().await.unwrap();
            tracing::debug!(todo = ?new_todo, "create todo");

            let mut todos = STORE.lock().await;

            if todos.iter().any(|todo| todo.id == new_todo.id) {
                tracing::debug!(id = ?new_todo.id, "todo already exists");
                res.status_code(StatusCode::CONFLICT);
                res.render(Text::Plain("Todo already exists"));
                return;
            }

            todos.push(new_todo.clone());
            res.status_code(StatusCode::CREATED);
            res.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            res.render(Json(new_todo));
        }
        JwtAuthState::Unauthorized => {
            res.status_code(StatusCode::UNAUTHORIZED);
        }
        JwtAuthState::Forbidden => {
            res.status_code(StatusCode::FORBIDDEN);
        }
    }
}

#[utoipa::path(
    put,
    path = "/api/todos/{id}",
    responses(
        (status = 200, description = "Todo modified successfully"),
        (status = 404, description = "Todo not found", body = TodoError)
    ),
    params(
        ("id" = u64, Path, description = "Id of todo item to modify")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[handler]
pub async fn update_todo(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    match depot.jwt_auth_state() {
        JwtAuthState::Authorized => {
            let id = req.param::<u64>("id").unwrap();
            let updated_todo = req.parse_body::<Todo>().await.unwrap();
            tracing::debug!(todo = ?updated_todo, id = ?id, "update todo");

            let mut todos = STORE.lock().await;
            tracing::debug!("Current todos: {:?}", todos);

            if let Some(todo) = todos.iter_mut().find(|t| t.id == id) {
                *todo = updated_todo;
                res.status_code(StatusCode::OK);
                res.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_static("application/json"),
                );
                res.render(Json(todo.clone())); // Kirim kembali todo yang diupdate
            } else {
                tracing::debug!(id = ?id, "todo not found");
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
        JwtAuthState::Unauthorized => {
            res.status_code(StatusCode::UNAUTHORIZED);
        }
        JwtAuthState::Forbidden => {
            res.status_code(StatusCode::FORBIDDEN);
        }
    }
}

#[utoipa::path(
    delete,
    path = "/api/todos/{id}",
    responses(
        (status = 200, description = "Todo deleted successfully"),
        (status = 401, description = "Unauthorized to delete Todo"),
        (status = 404, description = "Todo not found", body = TodoError)
    ),
    params(
        ("id" = u64, Path, description = "Id of todo item to delete")
    ),
    security(
        ("bearer_auth" = [])
    )
)]
#[handler]
pub async fn delete_todo(depot: &mut Depot, req: &mut Request, res: &mut Response) {
    match depot.jwt_auth_state() {
        JwtAuthState::Authorized => {
            let id = req.param::<u64>("id").unwrap();
            tracing::debug!(id = ?id, "delete todo");

            let mut todos = STORE.lock().await;
            let initial_len = todos.len();
            todos.retain(|todo| todo.id != id);

            if todos.len() != initial_len {
                res.status_code(StatusCode::NO_CONTENT);
            } else {
                tracing::debug!(id = ?id, "todo not found");
                res.status_code(StatusCode::NOT_FOUND);
            }
        }
        JwtAuthState::Unauthorized => {
            res.status_code(StatusCode::UNAUTHORIZED);
        }
        JwtAuthState::Forbidden => {
            res.status_code(StatusCode::FORBIDDEN);
        }
    }
}
