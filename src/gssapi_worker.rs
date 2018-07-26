use super::gssapi;
use super::gssapi::GSSError;
use futures::sync::oneshot;
use futures::Future;
use std::str;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};

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

pub struct GSSWorker {
    cmd_channel: Sender<(Cmd, oneshot::Sender<Msg>)>,
}

impl GSSWorker {
    pub fn new() -> GSSWorker {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        ::std::thread::spawn(move || worker_thread(cmd_rx));
        GSSWorker {
            cmd_channel: cmd_tx,
        }
    }

    // TODO: a future
    pub fn accept_sec_context(&self, input_token: &[u8]) -> AcceptResult {
        let (msg_tx, msg_rx) = oneshot::channel();
        self.cmd_channel
            .send((Cmd::Accept(Vec::from(input_token)), msg_tx))
            .unwrap();
        msg_rx
            .map(|r| match r {
                Msg::Accepted(v, s) => AcceptResult::Accepted(v, s),
                Msg::ContinueNeeded(v) => AcceptResult::ContinueNeeded(v),
                Msg::Failed(e) => AcceptResult::Failed(e),
            })
            .wait()
            .unwrap()
    }
}

fn worker_thread(inbox: Receiver<(Cmd, oneshot::Sender<Msg>)>) {
    let mut context = gssapi::GSSContext::new();

    for (cmd, output) in inbox {
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
