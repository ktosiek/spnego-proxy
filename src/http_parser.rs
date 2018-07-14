use nom;
use std::str;

pub struct ParsingState<'buf>(State<'buf>);

#[derive(Debug, PartialEq)]
pub struct Request<'buf> {
    method: &'buf str,
    protocol: &'buf str,
    path: &'buf [u8],
    headers: Vec<Header<'buf>>,
}

#[derive(Debug, PartialEq)]
pub struct Header<'buf> {
    name: &'buf str,
    value: &'buf [u8],
}

struct RequestLine<'buf> {
    method: &'buf str,
    protocol: &'buf str,
    path: &'buf [u8],
}

enum State<'buf> {
    Initial(),
    HasRequestLine(RequestLine<'buf>, Vec<Header<'buf>>),
    Finished(Request<'buf>),
}

pub fn new_parsing_state<'buf>() -> ParsingState<'buf> {
    ParsingState(State::Initial())
}

pub fn parse<'buf>(
    buf: &'buf [u8],
    parsing_state: ParsingState<'buf>
) -> nom::IResult<&'buf [u8], &'buf ParsingState<'buf>> {
    match parsing_state.0 {
        State::Initial() => {
            let (buf2, rl) = try_parse!(buf, parse_request_line);
            let next_state = State::HasRequestLine(rl, Vec::new());
            parse(buf2, ParsingState(next_state))
        },
        State::HasRequestLine(rl, headers) => {
            let (buf2, next_header) = try_parse!(buf, parse_next_header);
            match next_header {
                Some(header) => {
                    headers.push(header);
                    parse(buf2, parsing_state)
                }
                None => {
                    parse(buf2, ParsingState(State::Finished(Request {
                        method: rl.method,
                        protocol: rl.protocol,
                        path: rl.path,
                        headers: headers,
                    })))
                }
            }
        }
        State::Finished(_) =>
            Ok((buf, parsing_state))
    }
}

named!(parse_request_line<&[u8], RequestLine>, 
    do_parse!(
        method: http_method     >>
        tag!(" ")               >>
        path: http_uri          >>
        tag!(" ")               >>
        protocol: http_protocol >>
        newline                 >>

        (RequestLine { method, protocol, path })
    )
);

named!(parse_next_header<&[u8], Option<Header> >,
    alt!(
        map!(end_of_headers, const_none)
        | map!(parse_header_line, Option::Some)
    )
);

fn const_none<T, O>(x: T) -> Option<O> { Option::None }

named!(end_of_headers<&[u8], ()>,
    do_parse!(
        newline >> newline >> (())
    )
);

named!(parse_header_line<&[u8], Header>,
    do_parse!(
        name: map_res!(take_while!(is_header_name_char), str::from_utf8) >>
        tag!(" ") >>
        value: take_while!(is_header_value_char) >>

        (Header { name, value })
    )
);

named!(http_method<&[u8], &str>, map_res!(take_while!(is_uri_char), str::from_utf8));
named!(http_uri<&[u8], &[u8]>, take_while!(is_uri_char));
named!(http_protocol<&[u8], &str>, map_res!(take_while!(is_uri_char), str::from_utf8));

named!(newline, tag!("\r\n"));

fn is_uri_char(i: u8) -> bool {
    i > 32 && i < 127
}

fn is_header_name_char(i: u8) -> bool {
    i >= 32 && i < 127
}

fn is_header_value_char(i: u8) -> bool {
    i == 9 || (i >= 32 && i <= 126) || i >= 160
}
