use super::gssapi;
use super::gssapi::GSSError;
use futures::sink::Sink;
use futures::stream::Stream;
use futures::sync::mpsc;
use futures::sync::mpsc::{Receiver, Sender};
use futures::sync::oneshot;
use futures::Future;
use std::str;

#[derive(Debug)]
pub enum Cmd {
    Accept(Vec<u8>),
}

#[derive(Debug)]
pub enum Msg {
    ContinueNeeded(Vec<u8>),
    Accepted(Vec<u8>, String),
    Failed(GSSError),
}

#[derive(Debug)]
pub enum AcceptResult {
    ContinueNeeded(Vec<u8>),
    Accepted(Vec<u8>, String),
    Failed(GSSError),
}

impl Msg {
    fn from(r: Result<gssapi::AcceptResult, gssapi::GSSError>) -> Msg {
        match r {
            Ok(gssapi::AcceptResult::Complete(buf, name)) => {
                let str_name =
                    String::from(str::from_utf8(name.display_name().unwrap().as_bytes()).unwrap());
                Msg::Accepted(Vec::from(buf.as_bytes()), str_name.clone())
            }
            Ok(gssapi::AcceptResult::ContinueNeeded(buf)) => {
                Msg::ContinueNeeded(Vec::from(buf.as_bytes()))
            }
            Err(e) => Msg::Failed(e),
        }
    }
}

#[derive(Debug)]
pub struct GSSWorker {
    cmd_channel: Sender<(Cmd, oneshot::Sender<Msg>)>,
}

impl GSSWorker {
    pub fn new() -> GSSWorker {
        let (cmd_tx, cmd_rx) = mpsc::channel(0);
        ::std::thread::spawn(move || worker_thread(cmd_rx));
        GSSWorker {
            cmd_channel: cmd_tx,
        }
    }

    pub fn accept_sec_context(
        &self,
        input_token: &[u8],
    ) -> Box<dyn Future<Item = AcceptResult, Error = String> + Send> {
        let (msg_tx, msg_rx) = oneshot::channel();
        Box::new(
            self.cmd_channel
                .clone()
                .send((Cmd::Accept(Vec::from(input_token)), msg_tx))
                .map_err(|_e| String::from("Worker thread died"))
                .and_then(|_| {
                    msg_rx
                        .map(|r| match r {
                            Msg::Accepted(v, s) => AcceptResult::Accepted(v, s),
                            Msg::ContinueNeeded(v) => AcceptResult::ContinueNeeded(v),
                            Msg::Failed(e) => AcceptResult::Failed(e),
                        })
                        .map_err(|_e| String::from("Worker thread died"))
                }),
        )
    }
}

fn worker_thread(inbox: Receiver<(Cmd, oneshot::Sender<Msg>)>) {
    let mut context = gssapi::GSSContext::new();
    let mut inbox_iter = inbox.wait().into_iter();

    while let Some(Ok((cmd, output))) = inbox_iter.next() {
        let response = match cmd {
            Cmd::Accept(bytes) => Msg::from(gssapi::accept_sec_context(
                &mut context,
                &gssapi::AppBuffer::from(&bytes),
            )),
        };
        output.send(response).unwrap();
    }
    debug!("Stopping thread");
}
