extern crate futures;
extern crate hyper;
extern crate rand;
extern crate tokio;

use futures::prelude::*;


use hyper::{Body, Method, Request, Response, Server, StatusCode};
use hyper::service::Service;

use rand::Rng;

struct ClientSession {
    id: u64,
}

fn new_session() -> ClientSession {
    ClientSession {
        id: rand::thread_rng().gen_range(0, 2 ^ 64 - 1),
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
    session: &ClientSession,
    req: Request<Body>,
) -> Box<Future<Item = Response<Body>, Error = String> + Send> {
    Box::new(futures::done(Ok(
        Response::new(Body::from(format!("Session {}", session.id))),
    )))
}

fn main() {
    let addr = ([10, 0, 0, 2], 3000).into();

    let new_service = || Ok::<_, String>(new_session());
    let server = Server::bind(&addr).serve(new_service);

    println!("Listening on http://{}", addr);
    hyper::rt::run(server.map_err(|err| eprintln!("server error: {}", err)));
}
