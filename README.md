SPNEGO Proxy
============

WIP: A small reverse HTTP proxy for authenticating clients with SPNEGO.

TODO:
[ ] Mutual auth
[ ] Less .unwrap()
[x] Always check major/minor GSS codes
[ ] Logging (and hiding some errors from the client)
[ ] Move to raw tokio (hyper hides the peer info), or even raw sockets/splice
[ ] Web workers bound to threads? GSS-API is not Send/Sync
[ ] Authorization
[x] Actual proxying
[ ] HTTPS support for server and client

Hacking
-------

Running:

    KRB5_KTNAME=$PWD/tk-laptop.keytab KRB5_TRACE=/dev/stderr RUST_BACKTRACE=full cargo run -- --bind 0.0.0.0:3000 --backend http://127.0.0.1:3001

Testing:

    KRB5_TRACE=/dev/stderr curl --max-redirs 2 -v http://tk-laptop.local:3000 --negotiate -u :
