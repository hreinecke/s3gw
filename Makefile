PRG := s3gw
OBJS := server.o tls.o tcp.o request.o parser.o format.o bucket.o http_parser.o
LIBS := -lssl -lcrypto -luuid
CFLAGS = -Wall -g
CERT := server-cert.pem
KEY := server-key.pem

all: $(PRG) $(CERT) $(KEY)

clean:
	rm -f $(PRG) $(CERT) $(OBJS)

$(PRG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

$(CERT):
	openssl req -x509 -newkey rsa:4096 -keyout $(KEY) -out $(CERT) -sha256 -days 365 -nodes -subj "/CN=localhost"

server.o: server.c s3gw.h
tls.o: tls.c s3gw.h
tcp.o: tcp.c s3gw.h
request.o: request.c s3gw.h
parser.o: parser.c s3gw.h s3_api.h http_parser.h
format.o: format.c s3gw.h s3_api.h
bucket.o: bucket.c s3gw.h s3_api.h utils.h
