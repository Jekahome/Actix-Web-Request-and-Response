use actix_web::{web, guard::{self,Guard}, App, HttpResponse, 
HttpRequest, HttpServer, Responder, Either, 
http::{self,header::{self,ContentType}} };

use actix_web::{get, post};// макросы роутинга
use actix_files::NamedFile;
use futures::StreamExt;

use std::sync::RwLock;
use serde::Serialize;
use serde::Deserialize;

// Файл изменений версии
// https://github.com/actix/actix-web/blob/master/actix-web/CHANGES.md



/// Response:
///
/// Response `actix_web::HttpResponse`
/// Response `Trait actix_web::Responder`
/// Response `Trait actix_web::Responder` Json
/// Response `web::Json`
/// Response `web::Form`
/// Response `Either`
/// Response custom `impl Responder`
/// Response `CustomizeResponder`
/// Response `actix_web::HttpResponse` Streaming
///
/// FromRequest:
///
/// Request `web::Json`
/// Request `web::Path`
/// Request String
/// Request `web::Data`
/// Request `Either`
/// Request `web::Form` 
/// Request `web::Query` 
/// Request `web::Payload`
/// Request `web::Bytes`
/// Request `custom Impl FromRequest`
///
///
/// Error:
///
/// custom Error 

/*
impl Responder:

    &'static [u8]
    &'static str
    &String
    (R, StatusCode)
    ByteString
    Cow<'_, str>
    Option<R>
    ResponseBuilder
    Result<R, E>
    String
    Vec<u8>

    HttpResponse and HttpResponseBuilder
    Option<R> where R: Responder
    Result<R, E> where R: Responder and E: ResponseError
    (R, StatusCode) where R: Responder
    Bytes, BytesMut
    Json<T> and Form<T> where T: Serialize
    Either<L, R> where L: Serialize and R: Serialize
    CustomizeResponder<R>
    actix_files::NamedFile


FromRequest Extractor:

    Header	None
    Path	PathConfig
    Json	JsonConfig
    Form	FormConfig
    Query	QueryConfig
    Bytes	PayloadConfig
    String	PayloadConfig
    Payload	PayloadConfig
 
*/

/*
Response `actix_web::HttpResponse`

`curl http://127.0.0.1:8080/http-response`

Response:
    content-length: 12
    content-type: text/plain; charset=utf-8
    x-hdr: sample
    date: Fri, 01 Mar 2024 22:01:45 GMT
*/
#[get("/http-response")]
async fn hello_http_response() -> HttpResponse {
    // HttpResponse::Ok().body("Hello world!\n")
    // or
    HttpResponse::Ok()
    .content_type(ContentType::plaintext())
    .insert_header(("X-Hdr", "sample"))
    .body("Hello world!")// or .json(impl Serialize) or .finish()
}

/* 
Response `Trait actix_web::Responder`
Request String

`curl -d 'Hi' -X POST http://127.0.0.1:8080/example/echo`

*/
#[post("/echo")]
async fn echo_impl_responder(req_body: String) -> impl Responder {
    HttpResponse::Ok().body(req_body)
}

/*
`curl http://127.0.0.1:8080/app/hey`
`curl http://127.0.0.1:8080/example/hi`
*/
async fn manual_hello() -> impl Responder {
    HttpResponse::Ok().body("Hey there!")
}

/*
Response impl Responder: String
Request `web::Data`

`curl http://127.0.0.1:8080/example/state`

Hello  counter=1!
Hello  counter=2!
Hello  counter=3!
*/  
#[get("/state")]
async fn state_example(data: web::Data<RwLock<AppState>>) -> String {
    let mut data = data.write().unwrap();
    data.counter += 1;
    let app_name = &data.app_name; // <- get app_name

    format!("Hello {} counter={}!", app_name, data.counter) // <- response with app_name
}

/* 
Response `Trait actix_web::Responder` Json
Request `web::Path`

`curl http://127.0.0.1:8080/a/Karl`

content-length: 15
content-type: application/json

{"name":"Karl"}
*/
#[derive(Serialize, Deserialize)]
struct MyObj {
    name: String,
}
#[get("/a/{name}")]
async fn response_json(name: web::Path<String>) -> actix_web::Result<impl Responder> {
    let obj = MyObj {
        name: name.to_string(),
    };
    // Ok(web::Json(obj)) 
    // or
    Ok(HttpResponse::Ok()
    .append_header(header::ContentType(mime::APPLICATION_JSON))
    .append_header(("X-TEST", "value1"))
    .append_header(("X-TEST", "value2"))
    .json(obj))
}

/*
Response Json
Request `web::Json`

`curl -d '{"name":"Karlovich"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:8080/c/Karl`
*/
#[post("/c/{name}")]
async fn response_json2(req: HttpRequest, obj: web::Json<MyObj>) -> web::Json<MyObj> {
    web::Json(MyObj {
        name: format!("{} {}", req.match_info().get("name").unwrap().to_owned(), obj.name),
    })
}

/*
Response Form

`curl http://127.0.0.1:8080/response_form`

content-length: 10
content-type: application/x-www-form-urlencoded
body: name=actix
*/
#[get("/response_form")]
async fn response_form() -> web::Form<MyObj> {
    web::Form(MyObj {
        name: "actix".to_owned(),
    })
}

/*
Response `Either` 
Request `Either`

`curl -d '{"name":"Karlovich"}' -H "Content-Type: application/json" -X POST http://127.0.0.1:8080/response_either`

*/
#[post("/response_either")]
async fn response_either(form: Either<web::Json<MyObj>, web::Form<MyObj>>) -> Either<&'static str, Result<HttpResponse, actix_web::Error>> {
    let name: String = match form {
        Either::Left(json) => json.name.to_owned(),
        Either::Right(form) => form.name.to_owned(),
    };

    if 1 == 2 {
        // respond with Left variant
        Either::Left("Bad data")
    } else {
        // respond with Right variant
        Either::Right(
            Ok(HttpResponse::Ok()
                .content_type(mime::TEXT_HTML)
                .body(format!("<p>Hello {}!</p>",name)))
        )
    }
}

/*
Response custom `impl Responder`

`curl http://127.0.0.1:8080/response_custom`
*/
// Responder
impl Responder for MyObj {
    type Body = actix_web::body::BoxBody;

    fn respond_to(self, _req: &HttpRequest) -> HttpResponse<Self::Body> {
        let body = serde_json::to_string(&self).unwrap();

        // Create response and set content type
        HttpResponse::Ok()
            .content_type(ContentType::json())
            .body(body)
    }
}
#[get("/response_custom")]
async fn response_custom() -> impl Responder {
    MyObj { name: "user".into() }
}

/*
Response CustomizeResponder

`curl http://127.0.0.1:8080/b/Karl` 
*/
#[get("/b/{name}")]
async fn output_test_impl_responder(name: web::Path<String>) -> impl Responder {
    let obj = MyObj {
        name: name.to_string(),
    };
    let obj_str:String = serde_json::to_string(&obj).unwrap(); 
    let responder = obj_str
    .customize()
    .with_status(http::StatusCode::BAD_REQUEST)
    .insert_header(("x-hello", "world"));
    responder 
}

/*
Request `web::Path`  

Данные URL формате /{key1}/{key2} => /value1/value2

`curl http://127.0.0.1:8080/app/input-path/Jeka/8`

extract path info from "/{username}/{count}" url

*/
async fn input_test_path( path: web::Path<(String, u32)>) -> Result<String, actix_web::Error> {
    let (username, count) = path.into_inner();
    Ok(format!("Welcome {}! {}",  username, count))
}


/*
Response NamedFile

`curl -O http://127.0.0.1:8080/response_file`
*/
#[get("/response_file")]
async fn response_file() -> impl Responder {
    /*
     let mut file = File::create("foo.txt")?;
     file.write_all(b"Hello, world!")?;
     let named_file = NamedFile::from_file(file, "bar.txt")?;
    */
    NamedFile::open_async("Cargo.toml").await
}

/*
Response NamedFile

`curl -O http://127.0.0.1:8080/response_file2/file_data`
*/
#[get("/response_file2/{filename:.*}")]
async fn response_file2(req: HttpRequest) -> Result<actix_files::NamedFile, actix_web::Error> {
    let path: std::path::PathBuf = req.match_info().query("filename").parse().unwrap();
    //let file = actix_files::NamedFile::open(format!("./static_files/{}.txt",path.display()))?;
    let file = NamedFile::open_async(format!("./static_files/{}.txt",path.display())).await?;
    Ok(file
        .use_last_modified(true)
        .set_content_disposition(header::ContentDisposition {
            disposition: header::DispositionType::Attachment,
            parameters: vec![],
        }))
}

/*
Response `actix_web::HttpResponse` Streaming

Streaming response body  

    Все что реализует Stream<Item=Bytes, Error=Error>
    HttpResponse implementation Stream<Item=Bytes, Error=Error>

`curl 127.0.0.1:8080/app/output-impl-stream`
*/
#[get("/output-impl-stream")]
async fn output_test_impl_stream() -> HttpResponse {
    let body = futures::stream::once(futures::future::ok::<_, actix_web::Error>(web::Bytes::from_static(b"test")));

    HttpResponse::Ok()
        .content_type("application/json")
        .streaming(body)
}

/*
Request `web::Form`  
  
`curl -d "username=Jeka" -H "Content-Type: application/x-www-form-urlencoded" -X POST  127.0.0.1:8080/app/input_test_form`
*/
#[derive(Deserialize)]
struct FormData {
    username: String,
}

#[post("/input_test_form")]
async fn input_test_form(form: web::Form<FormData>) -> HttpResponse {
    HttpResponse::Ok().body(format!("username: {}", form.username))
}

/*
Request `web::Query` 

Данные URL формате ?key=value&key=value

`curl http://127.0.0.1:8080/app/input_test_query?username=Jeka`
*/
#[derive(Deserialize)]
struct Info {
    username: String,
}
#[get("/input_test_query")]
async fn input_test_query(web::Query(info): web::Query<Info>,req: HttpRequest) -> Result<String, actix_web::Error> {
    println!("{}",req.query_string());// username=Jeka
    Ok(format!("Welcome {}!", info.username))
}

/*
Request `web::Payload`

`curl -d '{"command":4,"chank":2,"all_chanks":111,"sound":[1,2,3,4]}' -H "Content-Type: application/json" -X POST 127.0.0.1:8080/app/input_test_payload`

*/
const MAX_SIZE: usize = 262_144; // max payload size is 256k
#[derive(Debug, Serialize, Deserialize, Default)]
struct MyInputData{
    command:u8,
    chank:u32,
    all_chanks:u32,
    sound:Vec<u32>
}
#[post("/input_test_payload")]
async fn input_test_payload(mut payload: web::Payload) -> Result<HttpResponse, actix_web::Error> {
    // payload is a stream of Bytes objects
    let mut body = web::BytesMut::new();
    while let Some(chunk) = payload.next().await {
        let chunk = chunk?;
        // limit max size of in-memory payload
        if (body.len() + chunk.len()) > MAX_SIZE {
            return Err(actix_web::error::ErrorBadRequest("overflow"));
        }
        body.extend_from_slice(&chunk);
    }

    // body is loaded, now we can deserialize serde-json
    let obj = serde_json::from_slice::<MyInputData>(&body)?;
    Ok(HttpResponse::Ok().json(obj)) // <- send response
}

/*
Request `web::Bytes`

`curl -d '{"command":4,"chank":2,"all_chanks":111,"sound":[1,2,3,4]}' -H "Content-Type: application/json" -X POST 127.0.0.1:8080/app/input_test_bytes`
*/
#[post("/input_test_bytes")]
async fn input_test_bytes(bytes: actix_web::web::Bytes) -> Result<HttpResponse, actix_web::Error>  {
    //println!("{:?}", bytes);// b"{\"command\":4,\"chank\":2,\"all_chanks\":111,\"sound\":[1,2,3,4]}"
    let res =  std::str::from_utf8(&bytes)?;
    let deserialized: MyInputData = serde_json::from_str(res)?;
    // MyInputData { command: 4, chank: 2, all_chanks: 111, sound: [1, 2, 3, 4] }
    println!("{:?}", deserialized);
    Ok(HttpResponse::Ok().finish())
}

/*
Request `custom Impl FromRequest`
*/
use futures_util::future::{ok, err, Ready};
impl actix_web::FromRequest for MyInputData {
    type Error = actix_web::Error;
    type Future = Ready<Result<MyInputData, actix_web::Error>>;
    
    fn from_request(req: &HttpRequest, payload: &mut actix_web::dev::Payload) -> Self::Future {      
        futures_util::future::ok(MyInputData::default())
        // futures_util::future::err(ErrorBadRequest("no luck"))        
    }
}
/// extract `MyInputData` from request
/// `curl -d '{"command":4,"chank":2,"all_chanks":111,"sound":[1,2,3,4]}' -H "Content-Type: application/json" -X POST 127.0.0.1:8080/app/input-custom-from-request`
#[post("/input-custom-from-request")]
async fn input_test_custom_from_request(input: Result<MyInputData, actix_web::Error>) -> Result<HttpResponse, actix_web::Error> {
     // Got thing: MyInputData { command: 0, chank: 0, all_chanks: 0, sound: [] }
    match input {
        Ok(thing) => {
            println!("Got thing: {:?}", thing);
            Ok(HttpResponse::Ok().content_type(mime::TEXT_PLAIN_UTF_8).body("Ok"))
        },
        Err(e) =>  {
            println!("Error extracting thing: {}", e);
            Ok(HttpResponse::Ok().content_type(mime::TEXT_PLAIN_UTF_8).body("Error extracting"))
        }
    }
}


/*
custom Error 

actix_web::error::ResponseError implementation std::error::Error 
т.е. возврат std::error::Error преобразуется в ResponseError с кодом 500 по умолчанию

Рекомендация
Возможно, было бы полезно подумать о разделении ошибок, создаваемых приложением, 
на две широкие группы: те, которые предназначены для пользователя, и те, 
которые не предназначены для разработчика.
*/
use derive_more::{Display, Error};
#[derive(Debug, Display, Error)]
enum MyError {
    #[display(fmt = "internal error")]
    InternalError,

    #[display(fmt = "bad request")]
    BadClientData,

    #[display(fmt = "timeout")]
    Timeout,
}

impl actix_web::error::ResponseError for MyError {
    fn error_response(&self) -> HttpResponse {
        HttpResponse::build(self.status_code())
            .insert_header(ContentType::html())
            .body(self.to_string())
    }

    fn status_code(&self) -> actix_web::http::StatusCode {
        match *self {
            MyError::InternalError => actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
            MyError::BadClientData => actix_web::http::StatusCode::BAD_REQUEST,
            MyError::Timeout => actix_web::http::StatusCode::GATEWAY_TIMEOUT,
        }
    }
}

/*
`curl 127.0.0.1:8080/app/output-error`
*/
#[get("/output-error")]
async fn output_test_error() -> Result<&'static str, MyError> {
    Err(MyError::BadClientData)
}

/* 
Конвертация std::result::Err в actix_web::Error  

`curl 127.0.0.1:8080/app/output-error-not-impl`
*/
#[derive(Debug)]
struct MyErrorNotImpl {
    name: &'static str,
}
#[get("/output-error-not-impl")]
async fn output_test_error_not_impl() -> std::result::Result<&'static str, actix_web::Error>{
    let result: std::result::Result<&'static str, MyErrorNotImpl> = Err(MyErrorNotImpl { name: "test error" });
    log::info!("{:?}", result);
    Ok(result.map_err(|e|  actix_web::error::ErrorBadRequest(e.name))?)
}

//==============================================================================================================================
// Модульная конфигурация
fn scoped_config(cfg: &mut web::ServiceConfig) {
    cfg.service(echo_impl_responder)
    .service(state_example)
    .route("/hi", web::get().to(manual_hello)) ;
}
fn config(cfg: &mut web::ServiceConfig) {
    cfg.service( web::scope("/example").configure(scoped_config));
}

// Регистрация роута постоенного через макрос #[post или get] с помощью App::service
// Регистрация роута постоенного вручную с помощью App::route 
// Пространство имен web::scope задает префикс роута 
// Конфигация с помощью метода configure есть у App и web::Scope
#[actix_web::main]
async fn main() -> std::io::Result<()> {
    std::env::set_var("RUST_LOG", "info");
    std::env::set_var("RUST_BACKTRACE", "1");
    env_logger::init();

    let data = web::Data::new(RwLock::new(AppState::default()));

    HttpServer::new(move || {
        let logger = actix_web::middleware::Logger::default();

        let json_config = web::JsonConfig::default()
            .limit(4096)
            .error_handler(|err, _req| {
                // create custom error response
                actix_web::error::InternalError::from_response(err, HttpResponse::Conflict().finish()).into()
            });

        let form_config = web::FormConfig::default()
            .limit(4097)
            .error_handler(|err, _req| {
                // create custom error response
                actix_web::error::InternalError::from_response(err, HttpResponse::Conflict().finish()).into()
            });

        App::new()
            .wrap(logger)
            .app_data(data.clone())
            .service(response_json)
            .service(response_json2).app_data(json_config)
            .service(hello_http_response)
            .service(response_form)
            .service(response_either)
            .service(response_file)
            .service(response_file2)
            .service(response_custom)
            .service( 
                web::scope("/app")
                        .guard(guard::Header("Host", "127.0.0.1:8080"))
                        .guard(MyGuard{filter:"127.0.0.1:8080".to_owned()})
                        .route("/hey", web::get().to(manual_hello)) 
                        .route("/bla", web::to( || async { HttpResponse::Ok().body("blablabla")}))
                        .service(output_test_impl_stream)
                        .service(input_test_payload)
                        .service(input_test_form).app_data(form_config)
                        .service(input_test_query)
                        .service(input_test_bytes)    
                        .route("/input-path/{username}/{count}", web::get().to(input_test_path))   
                        .service(input_test_custom_from_request)
                        .service(output_test_error)
                        .service(output_test_error_not_impl)
            ).service(
                // use http://127.0.0.1:8080/static
                actix_files::Files::new("/static", "./static_files")
                    .show_files_listing()
                    .use_last_modified(true)
                    .prefer_utf8(true),
            )
            .configure(config)
            /*.service( 
                web::scope("/example")
                            .service(echo)
                            .service(state_example)
                            .route("/hi", web::get().to(manual_hello)) 
                ) 
            */
             
    })
    .workers(4) //  по-умолчанию количество HTTP-воркеров равно количеству логических процессоров в системе
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
 

// Носитель данных состояния между запросами 
#[derive(Default)]
struct AppState {
    counter: usize,
    app_name: String,
}

// actix_web::guard::Guard trait
// Фильтрует запросы с помощью actix_web::dev::RequestHead и входных параметров инициализации
struct MyGuard{
    filter:String
}
impl Guard for MyGuard{
    fn check(&self, ctx: &actix_web::guard::GuardContext<'_> ) -> bool {
        
        let head = ctx.head();

        if let Some(val) = head.headers.get("Host") {
            return val == &self.filter;
        }
        false
    }
}
