use stderrlog;

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

    #[structopt(
        help = "Accept an invalid certificate from the backend",
        long = "insecure",
    )]
    pub tls_insecure: bool,

    // Logging {
    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    pub verbosity: usize,
    /// Timestamp (sec, ms, ns, none)
    #[structopt(long = "log-timestamp")]
    pub log_timestamp: Option<stderrlog::Timestamp>,
    // }
}
