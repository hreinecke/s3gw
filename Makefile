PRG := s3gw
OBJS := tls.o http_parser.o
LIBS := -lssl -lcrypto
CFLAGS = -Wall -g
CERT := server-cert.pem

all: $(PRG) $(CERT)

s3gw: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tls.o: tls.c http_parser.h

server-cert.pem:
	openssl req -x509 -newkey rsa:4096 -keyout server-key.pem -out server-cert.pem -sha256 -days 365 -nodes -subj "/CN=localhost"
