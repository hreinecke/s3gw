use std::{
    io::{BufReader, prelude::*},
    net::{TcpListener, TcpStream},
};
use httparse::{Request, Status};
use http::{Response, StatusCode};

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

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = Request::new(&mut headers);
    let buf:String = http_request.into_iter()
	.map(String::from)
	.collect();

    match req.parse(buf.as_bytes()) {
	Ok(Status::Complete(offset)) => {
	    println!("Request parsed successfully, offset {:?}", offset);
	}
	Ok(Status::Partial) => {
	    println!("Request parsed partially");
	}
	Err(e) => {
	    println!("Request error {:?}!", e);
	}
    }
	   
    let mut response: http::Response<_> = not_found().unwrap();
    let mapped_response: http::Response<&[u8]> = response.map(|b| {
	assert_eq!(b, "some string");
	b.as_bytes()
    });

    stream.write_all(mapped_response.as_bytes()).unwrap();
}

fn not_found() -> http::Result<Response<()>> {
    Response::builder()
	.header("Location","eu-west-1")
	.status(StatusCode::OK)
	.body(())
}
