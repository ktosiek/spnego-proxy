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
    state: AuthState,
}

enum AuthState {
    InProgress(GSSWorker),
    Ok(String),
}

enum Either<L, R> {
    Left(L),
    Right(R),
}

fn new_session<'a>() -> ClientSession {
    ClientSession {
        id: rand::thread_rng().gen_range(0, 1 << 64 - 1),
        state: AuthState::InProgress(GSSWorker::new()),
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
    match (authenticate, &session.state) {
        (Some(token), state) => {
            let gss_worker = match state {
                AuthState::InProgress(gss_worker) => gss_worker,
                _ => None,
            };
            match continue_authentication(gss_worker, token, req, session) {
                Either::Left(user) => {
                    session.state = AuthState::Ok(user);
                    proxy_request(req, session, &user)
                }
                Either::Right(response) => response,
            }
        }
        (None, AuthState::Ok(user)) => proxy_request(req, session, &user),
        (None, AuthState::InProgress(_)) => Box::new(futures::done(request_new_negotiation())),
    }
}

fn request_new_negotiation() -> Result<Response<Body>, String> {
    let mut res = Response::builder();
    res.header("WWW-Authenticate", "Negotiate")
        .status(StatusCode::UNAUTHORIZED);
    let response = res
        .body(Body::from("No Authorization"))
        .map_err(|e| format!("{:?}", e));
    response
}

fn continue_authentication(
    gss_worker: &GSSWorker,
    token: Vec<u8>,
    req: Request<Body>,
    session: &ClientSession,
) -> Either<String, Box<Future<Item = Response<Body>, Error = String> + Send>> {
    match gss_worker.accept_sec_context(token) {
        gssapi_worker::AcceptResult::Accepted(user) => Either::Left(user),
        gssapi_worker::AcceptResult::ContinueNeeded(output) => {
            Either::Right(Box::new(futures::done(
                Response::builder()
                    .header(
                        "WWW-Authenticate",
                        format!("Negotiate {}", base64::encode(&output)).as_bytes(),
                    )
                    .status(StatusCode::UNAUTHORIZED)
                    .body(Body::from("No Authorization"))
                    .map_err(|e| format!("{:?}", e)),
            )))
        }
        gssapi_worker::AcceptResult::Failed(err) => Either::Right(Box::new(futures::done(
            Response::builder()
                .header("WWW-Authenticate", "Negotiate")
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from(format!("Authorization failed: {}", err)))
                .map_err(|e| format!("{:?}", e)),
        ))),
    }
}

fn proxy_request(
    req: Request<Body>,
    session: &ClientSession,
    user: &String,
) -> Box<Future<Item = Response<Body>, Error = String> + Send> {
    // TODO: Proxy
    Box::new(futures::done(Ok(Response::new(Body::from(format!(
        "Session {}\nUser: {}\n",
        session.id, user
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
