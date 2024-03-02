#![allow(unused_must_use)]

use awc::{Client,ClientBuilder, error::SendRequestError};
use actix_http::header::{self, HeaderMap, HeaderValue};
use std::time::{Duration, Instant};

// Client GET
async fn client_get_easy() -> Result<(), SendRequestError>{
    /* 
        let mut client = Client::default();
    
        // Create request builder and send request
        let response = client.get("http://127.0.0.1:8080/a/Karl")
        .insert_header(("User-Agent", "actix-web/3.0"))
        .send()     // <- Send request
        .await;     // <- Wait for response
    
        println!("Response: {:#?}", response);
    */

    // or ClientBuilder -----------------------------

    let mut client:Client = ClientBuilder::new()
        .timeout(Duration::new(5, 0))
        .initial_connection_window_size(65535)
        .finish();
    let headers = client.headers().unwrap();
    headers.insert(header::USER_AGENT, HeaderValue::from_static("actix-web/3.0"));


   let request: awc::ClientRequest = client.get("http://127.0.0.1:8080/a/Karl");

    let send_client: awc::SendClientRequest = request.send();
    let response = send_client.await; 
    println!("Response: {:#?}", &response);
    let bodydata = response.unwrap().body().await;
    //let bodydata = response.json::<Obj>().await.unwrap();
    println!("Response: {:#?}", bodydata); 
 
    Ok(())
}

// Client POST
async fn client_post() -> Result<(), SendRequestError>{

    let content = "Hello";

    let client:Client = ClientBuilder::new()
        //.timeout(Duration::new(5, 0))
        //.header("User-Agent", "actix-web/3.0")
        //.initial_connection_window_size(65535)
        .finish();
    
    let request: awc::ClientRequest = client.post("http://127.0.0.1:8080/example/echo")
                                      .insert_header((header::ACCESS_CONTROL_ALLOW_ORIGIN,"*"))
                                      //.insert_header((header::CONTENT_TYPE, "multipart/form-data"))
                                      .insert_header((header::CONTENT_TYPE, "application/octet-stream"))
                                      //.insert_header((header::CONTENT_DISPOSITION, "attachment; filename=\"test.txt\""))
                                      .insert_header((header::CONTENT_LENGTH, format!("{}",content.len())));
    /*
    let body = stream::once( 
        async move {
         Ok::<_, Error>( Bytes::from_iter(buff) )
        }
    );

    let send_client = request.send_stream(Box::pin(body));
    */ 
    let send_client:awc::SendClientRequest = request.send_body(content);
    
    let response = send_client.await; 
    println!("Response: {:#?}", &response);
    let bodydata = response.unwrap().body().await;
    //let bodydata = response.json::<Obj>().await.unwrap();
    println!("Response: {:#?}", bodydata);

    /*response.and_then(|response| { 
        println!("Response: {:#?}", response);
        Ok(())
    });*/
    Ok(())
 }
 
#[actix_web::main]
async fn main() {
    client_get_easy().await;

    client_post().await;
}