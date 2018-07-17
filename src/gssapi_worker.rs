use gssapi;
use gssapi::GSSError;
use std::collections::HashMap;
use std::str;
use std::sync::mpsc;
use std::sync::mpsc::{Receiver, Sender};

pub struct GSSCtxId {
    id: u32,
}

pub enum Cmd {
    NewContext(),
    Accept(GSSCtxId, Vec<u8>),
    DropContext(GSSCtxId),
}

pub enum Msg {
    NewContext(GSSCtxId),
    ContinueNeeded(GSSCtxId, Vec<u8>),
    Accepted(GSSCtxId, String),
    Failed(GSSCtxId, GSSError),
    DroppedContext(GSSCtxId),
}

impl Msg {
    fn from(id: GSSCtxId, r: Result<gssapi::AcceptResult, gssapi::GSSError>) -> Msg {
        match r {
            Ok(gssapi::AcceptResult::Complete(name)) => {
                let str_name =
                    String::from(str::from_utf8(name.display_name().unwrap().as_bytes()).unwrap());
                Msg::Accepted(id, str_name.clone())
            }
            Ok(gssapi::AcceptResult::ContinueNeeded(buf)) => {
                Msg::ContinueNeeded(id, Vec::from(buf.as_bytes()))
            }
            Err(e) => Msg::Failed(id, e),
        }
    }
}

pub struct GSSWorker {
    cmd_channel: Sender<Cmd>,
    msg_channel: Receiver<Msg>,
    worker: ::std::thread::JoinHandle<()>,
}

impl GSSWorker {
    pub fn new() -> GSSWorker {
        let (cmd_tx, cmd_rx) = mpsc::channel();
        let (msg_tx, msg_rx) = mpsc::channel();
        GSSWorker {
            cmd_channel: cmd_tx,
            msg_channel: msg_rx,
            worker: ::std::thread::spawn(move || worker_thread(cmd_rx, msg_tx)),
        }
    }
}

fn worker_thread(inbox: Receiver<Cmd>, outbox: Sender<Msg>) {
    let mut contexts = HashMap::new();
    let mut next_id = 0;

    loop {
        let msg = inbox.recv().unwrap();
        let response = match msg {
            Cmd::NewContext() => {
                next_id += 1;
                contexts.insert(next_id, gssapi::GSSContext::new());
                Msg::NewContext(GSSCtxId { id: next_id })
            }
            Cmd::Accept(id, bytes) => {
                let mut ctx = contexts.get_mut(&id.id).unwrap();
                Msg::from(
                    id,
                    gssapi::accept_sec_context(&mut ctx, &gssapi::AppBuffer::from(&bytes)),
                )
            }
            Cmd::DropContext(id) => {
                contexts.remove(&id.id).unwrap();
                Msg::DroppedContext(id)
            }
        };
        outbox.send(response).unwrap();
    }
}
