use std::{
    io::{BufReader, prelude::*},
    net::{TcpListener, TcpStream},
};
use http::{Request, Response, StatusCode};

fn main() {
    let listener = TcpListener::bind("localhost:7878").unwrap();

    for stream in listener.incoming() {
	let stream = stream.unwrap();

	handle_connection(stream);
    }
}

fn handle_connection(stream: TcpStream) {
    let buf_reader = BufReader::new(&stream);
    let http_request: Vec<_> = buf_reader
	.lines()
	.map(|result| result.unwrap())
	.take_while(|line| !line.is_empty())
	.collect();
    let request: Request<Vec<_>> = http_request.into();

    let mut response: Response<_> = respond_to(request);

    stream.write_all(response.as_bytes()).unwrap();
}

fn respond_to(req: Request<()>) -> http::Result<Response<()>> {
    let mut builder = Response::builder()
	.header("Location","eu-west-1")
	.status(StatusCode::OK);

    builder.body(())
}
