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
    let (state, response) = match (&authenticate, &session.state) {
        (Some(token), AuthState::InProgress(gss_worker)) => {
            match continue_authentication(gss_worker, token) {
                Either::Left((output, user)) => {
                    let response = proxy_request(req, session, &user, &output);
                    (Some(AuthState::Ok(user)), response)
                }
                Either::Right(response) => (None, response),
            }
        }
        (Some(token), AuthState::Ok(_)) => {
            println!("Got Authorization header on an authorized connection");
            let gss_worker = GSSWorker::new();
            match continue_authentication(&gss_worker, token) {
                Either::Left((output, user)) => {
                    let response = proxy_request(req, session, &user, &output);
                    (Some(AuthState::Ok(user)), response)
                }
                Either::Right(response) => (Some(AuthState::InProgress(gss_worker)), response),
            }
        }
        (None, AuthState::Ok(user)) => (None, proxy_request(req, session, &user, &vec![])),
        (None, AuthState::InProgress(_)) => (
            None,
            Box::new(futures::done(authorization_request(&vec![])))
                as Box<Future<Item = Response<Body>, Error = String> + Send>,
        ),
    };
    match state {
        Some(s) => {
            session.state = s;
        }
        _ => {}
    }
    response
}

fn authorization_request(token: &Vec<u8>) -> Result<Response<Body>, String> {
    let authenticate = if token.is_empty() {
        String::from("Negotiate")
    } else {
        format!("Negotiate {}", base64::encode(token))
    };
    Response::builder()
        .header("WWW-Authenticate", authenticate.as_bytes())
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::from("No Authorization"))
        .map_err(|e| format!("{:?}", e))
}

fn continue_authentication(
    gss_worker: &GSSWorker,
    token: &Vec<u8>,
) -> Either<(Vec<u8>, String), Box<Future<Item = Response<Body>, Error = String> + Send>> {
    match gss_worker.accept_sec_context(token.clone()) {
        gssapi_worker::AcceptResult::Accepted(output, user) => Either::Left((output, user)),
        gssapi_worker::AcceptResult::ContinueNeeded(output) => {
            Either::Right(Box::new(futures::done(authorization_request(&output))))
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
    authenticate: &Vec<u8>,
) -> Box<Future<Item = Response<Body>, Error = String> + Send> {
    // TODO: Proxy
    let mut response = Response::builder();
    if !authenticate.is_empty() {
        response.header(
            "WWW-Authenticate",
            format!("Negotiate {}", base64::encode(authenticate)).as_bytes(),
        );
    }
    Box::new(futures::done(
        response
            .body(Body::from(format!(
                "Session {}\nUser: {}\n",
                session.id, user
            )))
            .map_err(|e| format!("{:?}", e)),
    ))
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
