PRG := s3gw
OBJS := tls_server.o http_parser.o
LIBS := -lssl -lcrypto
CFLAGS = -Wall -g

all: $(PRG)

s3gw: $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LIBS)

tls_server.o: tls_server.c http_parser.h
