PRG := s3gw
OBJS := tls.o request.o parser.o format.o http_parser.o
LIBS := -lssl -lcrypto -luuid
CFLAGS = -Wall -g
CERT := server-cert.pem
KEY := server-key.pem

all: $(PRG) $(CERT) $(KEY)

clean:
	rm -f $(PRG) $(CERT) $(OBJS)

$(PRG): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tls.o: tls.c http_parser.h

$(CERT):
	openssl req -x509 -newkey rsa:4096 -keyout $(KEY) -out $(CERT) -sha256 -days 365 -nodes -subj "/CN=localhost"
