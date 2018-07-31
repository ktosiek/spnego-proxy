#![feature(rust_2018_preview)]
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate structopt;

use std::sync::{Arc, Mutex};

mod configuration;
mod gssapi;
mod gssapi_worker;
use self::configuration::Configuration;
use self::gssapi_worker::GSSWorker;
use futures::prelude::*;
use structopt::StructOpt;

use hyper::client::{Client, HttpConnector};
use hyper::service::Service;
use hyper::{Body, Request, Response, Server, StatusCode};

#[derive(Debug)]
struct ClientSession {
    state: AuthState,
}

struct ClientService(Arc<Mutex<ClientSession>>);

#[derive(Debug)]
enum AuthState {
    InProgress(GSSWorker),
    Ok(String),
}

enum Either<L, R> {
    Left(L),
    Right(R),
}

type BoxFuture<I> = Box<Future<Item = I, Error = String> + Send>;
type ResponseFuture = Future<Item = Response<Body>, Error = String> + Send;

lazy_static! {
    static ref http_client: Arc<Mutex<Client<HttpConnector>>> = Arc::new(Mutex::new(Client::new()));
    static ref current_config: Configuration = Configuration::from_args();
}

fn new_session() -> ClientService {
    let worker = GSSWorker::new();
    ClientService(Arc::new(Mutex::new(ClientSession {
        state: AuthState::InProgress(worker),
    })))
}

impl Service for ClientService {
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
        handle_request(self.0.clone(), req)
    }
}

fn handle_request(session_m: Arc<Mutex<ClientSession>>, req: Request<Body>) -> Box<ResponseFuture> {
    let authenticate = req
        .headers()
        .get("Authorization")
        .and_then(|h| parse_authorization_header(h.to_str().unwrap()));
    trace!("Authorization: {:?}", authenticate);

    Box::new(
        {
            let session_mm = session_m.clone();
            let session = session_mm.lock().unwrap();
            match (&authenticate, &session.state) {
                (Some(token), AuthState::InProgress(gss_worker)) => Box::new(
                    continue_authentication(gss_worker, token).and_then(|r| match r {
                        Either::Left((output, user)) => {
                            let client = http_client.lock().unwrap();
                            Box::new(
                                proxy_request(req, &client, &user, &output)
                                    .map(|response| (Some(AuthState::Ok(user)), response)),
                            )
                                as Box<dyn Future<Item = _, Error = _> + Send>
                        }
                        Either::Right(response) => Box::new(futures::done(Ok((None, response))))
                            as Box<dyn Future<Item = _, Error = _> + Send>,
                    }),
                ),
                (None, AuthState::InProgress(_)) => {
                    Box::new(futures::done(Ok((None, authorization_request(&[])))))
                        as Box<dyn Future<Item = _, Error = _> + Send>
                }
                (_, AuthState::Ok(user)) => {
                    let client = http_client.lock().unwrap();
                    Box::new(
                        proxy_request(req, &client, &user, &[]).map(|response| (None, response)),
                    ) as Box<dyn Future<Item = _, Error = _> + Send>
                }
            }
        }.and_then(move |(state, response)| {
            let mut sess = session_m.lock().unwrap();
            debug!("Setting state {:?}", state);
            if let Some(s) = state {
                sess.state = s;
            }
            Ok(response)
        }),
    )
}

fn authorization_request(token: &[u8]) -> Response<Body> {
    let authenticate = if token.is_empty() {
        String::from("Negotiate")
    } else {
        format!("Negotiate {}", base64::encode(token))
    };
    Response::builder()
        .header("WWW-Authenticate", authenticate.as_bytes())
        .status(StatusCode::UNAUTHORIZED)
        .body(Body::from("No Authorization"))
        .unwrap()
}

fn continue_authentication(
    gss_worker: &GSSWorker,
    token: &[u8],
) -> BoxFuture<Either<(Vec<u8>, String), Response<Body>>> {
    Box::new(gss_worker.accept_sec_context(token).and_then(|r| match r {
        gssapi_worker::AcceptResult::Accepted(output, user) => Ok(Either::Left((output, user))),
        gssapi_worker::AcceptResult::ContinueNeeded(output) => {
            Ok(Either::Right(authorization_request(&output)))
        }
        gssapi_worker::AcceptResult::Failed(err) => {
            info!("Authentication failed: {}", err);
            Response::builder()
                .header("WWW-Authenticate", "Negotiate")
                .status(StatusCode::UNAUTHORIZED)
                .body(Body::from("Authentication failed"))
                .map_err(|e| format!("{:?}", e))
                .map(Either::Right)
        }
    }))
}

fn proxy_request(
    req: Request<Body>,
    client: &Client<HttpConnector>,
    _user: &str,
    authenticate: &[u8],
) -> Box<ResponseFuture> {
    let backend_uri = format!("{}{}", current_config.backend, req.uri());
    info!("Requesting {}", backend_uri);
    let new_request = builder_from_request(&req)
        .version(http::Version::HTTP_11)
        .uri(backend_uri)
        .body(req.into_body())
        .unwrap();

    let auth_header = if !authenticate.is_empty() {
        Some(
            http::header::HeaderValue::from_str(
                format!("Negotiate {}", base64::encode(authenticate)).as_str(),
            ).unwrap(),
        )
    } else {
        None
    };

    Box::new(
        client
            .request(new_request)
            .or_else(|e| futures::done(Ok(error_response(&e))))
            .map(|mut response| {
                if let Some(val) = auth_header {
                    response.headers_mut().insert("WWW-Authenticate", val);
                }
                *response.version_mut() = http::Version::HTTP_11;

                response
            }),
    )
}

fn builder_from_request(req: &Request<Body>) -> ::http::request::Builder {
    let mut r = Request::builder();
    r.method(req.method().as_str()).uri(req.uri());

    for (key, value) in req.headers().iter() {
        r.header(key.as_str(), value.as_bytes());
    }
    r
}

fn error_response<E: ::std::error::Error>(err: &E) -> Response<Body> {
    error!("Error when requesting {}", err);
    Response::builder()
        .status(500)
        .body(Body::from("Internal server error"))
        .unwrap()
}

fn parse_authorization_header(raw: &str) -> Option<Vec<u8>> {
    if raw.starts_with("Negotiate ") {
        base64::decode(&raw[10..]).ok()
    } else {
        None
    }
}

fn main() {
    stderrlog::new()
        .module(module_path!())
        .verbosity(current_config.verbosity)
        .timestamp(
            current_config
                .log_timestamp
                .unwrap_or(stderrlog::Timestamp::Off),
        )
        .init()
        .unwrap();

    let addr = current_config.bind.parse().unwrap();

    let new_service = || Ok::<_, String>(new_session());
    let server = Server::bind(&addr).serve(new_service);

    info!("Listening on http://{}", addr);
    hyper::rt::run(server.map_err(|err| error!("server error: {}", err)));
}
