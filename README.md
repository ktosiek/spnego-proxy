SPNEGO Proxy
============

WIP: A small reverse HTTP proxy for authenticating clients with SPNEGO.

TODO:
[ ] Mutual auth
[ ] Less .unwrap()
[ ] Logging
[ ] Move to raw tokio (hyper hides the peer info), or even raw sockets/splice (any good select() lib?)
[ ] Workers bound to threads? GSS-API is not Send/Sync
[ ] Authorization
[ ] Actual proxying
[ ] Configuration file

Hacking
-------

Running:

    KRB5_KTNAME=$PWD/tk-laptop.keytab KRB5_TRACE=/dev/stderr RUST_BACKTRACE=full cargo run

Testing:

    KRB5_TRACE=/dev/stderr curl --max-redirs 2 -v http://tk-laptop.local:3000 --negotiate -u :
