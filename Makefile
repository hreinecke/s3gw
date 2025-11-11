PRG := s3gw
OBJS := tls_server.o http_parser.o
LIBS := -lssl -lcrypto
CFLAGS = -Wall -g
CERT := server.pem

all: $(PRG)

s3gw: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tls_server.o: tls_server.c http_parser.h

server-cert.pem:
	openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
