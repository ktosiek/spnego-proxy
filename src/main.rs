#![feature(trace_macros)]
#[macro_use]
extern crate futures;
#[macro_use]
extern crate nom;
extern crate tokio;

use futures::prelude::*;

use tokio::io;
use tokio::net::TcpListener;
use tokio::prelude::*;

mod http_parser;
/*

struct RequestReader<'a, T> {
    inner: T,
    headers: [Header<'a>; 256], // Maximum number of headers
    buf: [u8; 1024 * 16],       // Maximum size of all headers
    position: usize,
}

struct ReadRequest<'a> {}

fn hreader<'a, T>(stream: T) -> RequestReader<'a, T> {
    RequestReader {
        inner: stream,
        headers: Box::new([]),
        buf: [0; 4096],
        position: 0,
    }
}

impl<'a, T: AsyncRead> Future for RequestReader<'a, T> {
    type Item = RequestReader<'a, T>;
    type Error = io::Error;

    fn poll(&mut self) -> Result<Async<Self::Item>, Self::Error> {
        let read = try_ready!(self.inner.poll_read(&mut self.buf[self.position..]));
        self.position += read;
        // TODO: header size limit
        // TODO: error handling
        match parse_headers(&self.buf[0..self.position], &mut self.headers).unwrap() {
            httparse::Status::Complete(_) => Ok(Async::Ready(self)),
            httparse::Status::Partial => Ok(Async::NotReady),
        }
    }
}

fn main() {
    // Bind the server's socket
    let addr = "10.0.0.2:3000".parse().unwrap();
    let tcp = TcpListener::bind(&addr).unwrap();

    // Iterate incoming connections
    let server = tcp.incoming()
        .for_each(|tcp| {
            // Split up the read and write halves
            let (reader, writer) = tcp.split();

            // Copy the data back to the client
            let conn = io::copy(reader, writer)
            // print what happened
            .map(|(n, _, _)| {
                println!("wrote {} bytes", n)
            })
            // Handle any errors
            .map_err(|err| {
                println!("IO error {:?}", err)
            });

            // Spawn the future as a concurrent task
            tokio::spawn(conn);

            Ok(())
        })
        .map_err(|err| {
            println!("server error {:?}", err);
        });

    // Start the runtime and spin up the server
    tokio::run(server);
}
*/

fn main() {}
