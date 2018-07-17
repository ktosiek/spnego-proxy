extern crate base64;
extern crate futures;
extern crate gssapi_sys;
extern crate hyper;
extern crate rand;
extern crate tokio;

use std::collections::HashMap;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};

mod gssapi;
mod gssapi_worker;
use futures::prelude::*;
use gssapi_worker::GSSWorker;

use hyper::service::Service;
use hyper::{Body, Method, Request, Response, Server, StatusCode};

use rand::Rng;

struct ClientSession {
    id: u64,
    gss_worker: GSSWorker,
}

fn new_session<'a>() -> ClientSession {
    ClientSession {
        id: rand::thread_rng().gen_range(0, 1 << 64 - 1),
        gss_worker: GSSWorker::new(),
    }
}

impl Service for ClientSession {
    // this is the body gives you
    type ReqBody = hyper::Body;
    // you could change this to a custom `Payload` impl if you wanted
    type ResBody = hyper::Body;
    // can be any `E: std::error::Error`
    type Error = String;
    // doesn't have to Box<Future>, it's just easier if you return different
    // future types depending on conditions
    type Future = Box<Future<Item = Response<Self::ResBody>, Error = Self::Error> + Send>;

    fn call(&mut self, req: Request<Self::ReqBody>) -> Self::Future {
        handle_request(self, req)
    }
}

fn handle_request(
    session: &mut ClientSession,
    req: Request<Body>,
) -> Box<Future<Item = Response<Body>, Error = String> + Send> {
    let authenticate = req
        .headers()
        .get("Authorization")
        .and_then(|h| parse_authorization_header(h.to_str().unwrap()));
    println!("Authorization: {:?}", authenticate);
    if authenticate.is_none() {
        let mut res = Response::builder();
        res.header("WWW-Authenticate", "Negotiate")
            .status(StatusCode::UNAUTHORIZED);
        let response = res
            .body(Body::from("No Authorization"))
            .map_err(|e| format!("{:?}", e));
        return Box::new(futures::done(response));
    }
    let result = authenticate
        .clone()
        .map(|a| session.gss_worker.accept_sec_context(a));
    Box::new(futures::done(Ok(Response::new(Body::from(format!(
        "Session {}\nAuthenticate: {:?}\nResult: {:?}",
        session.id, authenticate, result
    ))))))
}

fn parse_authorization_header(raw: &str) -> Option<Vec<u8>> {
    if !raw.starts_with("Negotiate ") {
        return None;
    }
    return base64::decode(&raw[10..]).ok();
}

fn main() {
    let addr = ([10, 0, 0, 2], 3000).into();

    let new_service = || Ok::<_, String>(new_session());
    let server = Server::bind(&addr).serve(new_service);

    println!("Listening on http://{}", addr);
    hyper::rt::run(server.map_err(|err| eprintln!("server error: {}", err)));
}
