/*
 *  Copyright 2024-2025 The OpenSSL Project Authors. All Rights Reserved.
 *
 *  Licensed under the Apache License 2.0 (the "License").  You may not use
 *  this file except in compliance with the License.  You can obtain a copy
 *  in the file LICENSE in the source distribution or at
 *  https://www.openssl.org/source/license.html
 */

/*
 * NB: Changes to this file should also be reflected in
 * doc/man7/ossl-guide-tls-server-block.pod
 */

#include <string.h>

#include <err.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "http_parser.h"

static const char cache_id[] = "Simple S3 Gateway";

static int parse_xml(http_parser *http, const char *body, size_t len)
{
	printf("data: %s\n", body);
	return 0;
}

static size_t handle_request(SSL *ssl, http_parser *http)
{
	unsigned char buf[8192];
	http_parser_settings settings;
	size_t nread;
	size_t nwritten;
	size_t total = 0;
	char location[] = "eu-west-1";
	char bucket[] = "arn:2e28574b-3276-44a1-8e00-b3de937c07c0";

	memset(&settings, 0, sizeof(settings));
	settings.on_body = parse_xml;

	while (SSL_read_ex(ssl, buf, sizeof(buf), &nread) > 0) {
		int ret;

		ret = http_parser_execute(http, &settings,
					  (const char *)buf, nread);
		if (ret == 0 || http->http_errno) {
			fprintf(stderr, "failed to parse HTTP, errno %d\n",
				http->http_errno);
			break;
		}
		sprintf("HTTP/1.1 200\r\nLocation: %s\r\nx-amz-bucket-arn: %s\r\n",
			location, bucket);
		nread = strlen((const char *)buf);
		if (SSL_write_ex(ssl, buf, nread, &nwritten) > 0 &&
		    nwritten == nread) {
			total += nwritten;
			continue;
		}
		fprintf(stderr, "Error writing response\n");
		break;
	}
	return total;
}

/* Minimal TLS echo server. */
int main(int argc, char *argv[])
{
	long opts;
	const char *hostport;
	SSL_CTX *ctx = NULL;
	BIO *acceptor_bio;
	http_parser *http;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [host:]port", argv[0]);
		exit(1);
	}
	hostport = argv[1];

	http = malloc(sizeof(*http));
	if (!http) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	memset(http, 0, sizeof(*http));
	http_parser_init(http, HTTP_REQUEST);

	ctx = SSL_CTX_new(TLS_server_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Failed to create server SSL_CTX");
		exit(1);
	}

	if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
		SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Failed to set TLS 1.3");
		exit(1);
	}

	/*
	 * Tolerate clients hanging up without a TLS "shutdown".
	 * Appropriate in all application protocols which perform
	 * their own message "framing", and don't rely on TLS to
	 * defend against "truncation" attacks.
	 */
	opts = SSL_OP_IGNORE_UNEXPECTED_EOF;

	/*
	 * Block potential CPU-exhaustion attacks by clients that
	 * request frequent renegotiation.  This is of course only
	 * effective if there are existing limits on initial full TLS
	 * handshake or connection rates.
	 */
	opts |= SSL_OP_NO_RENEGOTIATION;
#if 0
	/*
	 * Most servers elect to use their own cipher or group preference
	 * rather than that of the client.
	 */
	opts |= SSL_OP_SERVER_PREFERENCE;
#endif
	/* Apply the selection options */
	SSL_CTX_set_options(ctx, opts);

	/*
	 * Servers that want to enable session resumption must specify a
	 cache id byte array, that identifies the server application, and
	 reduces the chance of inappropriate cache sharing.
	*/
	SSL_CTX_set_session_id_context(ctx, (void *)cache_id, sizeof(cache_id));
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_SERVER);

	/*
	 * Sessions older than this are considered a cache miss even if
	 * still in the cache.  The default is two hours.  Busy servers
	 * whose clients make many connections in a short burst may want
	 * a shorter timeout, on lightly loaded servers with sporadic
	 * connections from any given client, a longer time may be appropriate.
	 */
	SSL_CTX_set_timeout(ctx, 3600);

	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

	/*
	 * Create a listener socket wrapped in a BIO.
	 * The first call to BIO_do_accept() initialises the socket
	 */
	acceptor_bio = BIO_new_accept(hostport);
	if (acceptor_bio == NULL) {
		SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error creating acceptor bio");
		exit(1);
	}

	BIO_set_bind_mode(acceptor_bio, BIO_BIND_REUSEADDR);
	if (BIO_do_accept(acceptor_bio) <= 0) {
		SSL_CTX_free(ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error setting up acceptor socket");
		exit(1);
	}

	/* Wait for incoming connection */
	for (;;) {
		BIO *client_bio;
		SSL *ssl;
		size_t total;

		/* Pristine error stack for each new connection */
		ERR_clear_error();

		/* Wait for the next client to connect */
		if (BIO_do_accept(acceptor_bio) <= 0) {
			/* Client went away before we accepted the connection */
			continue;
		}

		/* Pop the client connection from the BIO chain */
		client_bio = BIO_pop(acceptor_bio);
		fprintf(stderr, "New client connection accepted\n");

		/* Associate a new SSL handle with the new connection */
		if ((ssl = SSL_new(ctx)) == NULL) {
			ERR_print_errors_fp(stderr);
			warnx("Error creating SSL handle for new connection");
			BIO_free(client_bio);
			continue;
		}
		SSL_set_bio(ssl, client_bio, client_bio);

		/* Attempt an SSL handshake with the client */
		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
			warnx("Error performing SSL handshake with client");
			SSL_free(ssl);
			continue;
		}
		total = handle_request(ssl, http);
		fprintf(stderr, "Client connection closed, %zu bytes sent\n",
			total);
		SSL_free(ssl);
	}

	/*
	 * Unreachable placeholder cleanup code, the above loop runs forever.
	 */
	SSL_CTX_free(ctx);
	free(http);
	return 0;
}
