#[derive(Debug, StructOpt)]
#[structopt(
    name = "spnego-proxy",
    about = "GSS-API based authentication proxy."
)]
pub struct Configuration {
    #[structopt(
        help = "Address to listen on",
        default_value = "0.0.0.0:80",
        long = "bind"
    )]
    pub bind: String,
    #[structopt(help = "Backend behind the proxy", long = "backend")]
    pub backend: String,
}
