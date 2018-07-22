use gssapi;
use gssapi::GSSError;
use std::str;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};

pub enum Cmd {
    Accept(Vec<u8>),
}

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
    cmd_channel: Sender<Cmd>,
    msg_channel: Receiver<Msg>,
}

impl GSSWorker {
    pub fn new() -> GSSWorker {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (msg_tx, msg_rx) = mpsc::channel();
        ::std::thread::spawn(move || worker_thread(cmd_rx, msg_tx));
        GSSWorker {
            cmd_channel: cmd_tx,
            msg_channel: msg_rx,
        }
    }

    // TODO: a future
    pub fn accept_sec_context(&self, input_token: Vec<u8>) -> AcceptResult {
        self.cmd_channel.send(Cmd::Accept(input_token)).unwrap();
        match self.msg_channel.recv().unwrap() {
            Msg::Accepted(v, s) => AcceptResult::Accepted(v, s),
            Msg::ContinueNeeded(v) => AcceptResult::ContinueNeeded(v),
            Msg::Failed(e) => AcceptResult::Failed(e),
        }
    }
}

fn worker_thread(inbox: Receiver<Cmd>, outbox: Sender<Msg>) {
    let mut context = gssapi::GSSContext::new();

    loop {
        let msg = inbox.recv();
        let response = match msg {
            Ok(Cmd::Accept(bytes)) => Msg::from(gssapi::accept_sec_context(
                &mut context,
                &gssapi::AppBuffer::from(&bytes),
            )),
            Err(_) => {
                println!("Stopping thread");
                return;
            }
        };
        outbox.send(response).unwrap();
    }
}
