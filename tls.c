/*
 *  Copyright 2025 Hannes Reinecke, SUSE
 */

#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uuid/uuid.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static const char cache_id[] = "Simple S3 Gateway";

void tls_setup(struct s3gw_ctx *ctx)
{
	long opts;

	ctx->ssl_ctx = SSL_CTX_new(TLS_server_method());
	if (ctx->ssl_ctx == NULL) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Failed to create server SSL_CTX\n");
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

	/* Apply the selection options */
	SSL_CTX_set_options(ctx->ssl_ctx, opts);

	if (SSL_CTX_use_certificate_chain_file(ctx->ssl_ctx, ctx->cert) <= 0) {
		SSL_CTX_free(ctx->ssl_ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Failed to load the server certificate %s\n",
			ctx->cert);
		exit(1);
	}

	if (SSL_CTX_use_PrivateKey_file(ctx->ssl_ctx, ctx->key,
					SSL_FILETYPE_PEM) <= 0) {
		SSL_CTX_free(ctx->ssl_ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error loading the server private key %s, "
			"possible key/cert mismatch\n", ctx->key);
		exit(1);
	}

	/*
	 * Servers that want to enable session resumption must specify a
	 cache id byte array, that identifies the server application, and
	 reduces the chance of inappropriate cache sharing.
	*/
	SSL_CTX_set_session_id_context(ctx->ssl_ctx,
				       (void *)cache_id, sizeof(cache_id));
	SSL_CTX_set_session_cache_mode(ctx->ssl_ctx, SSL_SESS_CACHE_SERVER);

	/*
	 * Sessions older than this are considered a cache miss even if
	 * still in the cache.  The default is two hours.  Busy servers
	 * whose clients make many connections in a short burst may want
	 * a shorter timeout, on lightly loaded servers with sporadic
	 * connections from any given client, a longer time may be appropriate.
	 */
	SSL_CTX_set_timeout(ctx->ssl_ctx, 3600);

	SSL_CTX_set_verify(ctx->ssl_ctx, SSL_VERIFY_NONE, NULL);
}

static void tls_listen(struct s3gw_ctx *ctx)
{
	/*
	 * Create a listener socket wrapped in a BIO.
	 * The first call to BIO_do_accept() initialises the socket
	 */
	ctx->accept_bio = BIO_new_accept(ctx->hostport);
	if (ctx->accept_bio == NULL) {
		SSL_CTX_free(ctx->ssl_ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error creating accept bio\n");
		exit(1);
	}

	BIO_set_bind_mode(ctx->accept_bio, BIO_BIND_REUSEADDR);
	if (BIO_do_accept(ctx->accept_bio) <= 0) {
		SSL_CTX_free(ctx->ssl_ctx);
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error setting up accept socket\n");
		exit(1);
	}
}

static int tls_wait_for_connection(struct s3gw_ctx *ctx)
{
	/* Pristine error stack for each new connection */
	ERR_clear_error();

	/* Wait for the next client to connect */
	return BIO_do_accept(ctx->accept_bio);
}

static int tls_accept(struct s3gw_ctx *ctx, struct s3gw_request *req)
{
	BIO *client_bio;
	int ret;

	/* Pop the client connection from the BIO chain */
	client_bio = BIO_pop(ctx->accept_bio);
	fprintf(stderr, "New client connection accepted\n");

	/* Associate a new SSL handle with the new connection */
	if ((req->ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr,
			"Error creating SSL handle for new connection\n");
		BIO_free(client_bio);
		return -ENOMEM;
	}
	SSL_set_bio(req->ssl, client_bio, client_bio);

	/* Attempt an SSL handshake with the client */
	ret = SSL_accept(req->ssl);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error performing SSL handshake with client\n");
		SSL_free(req->ssl);
		req->ssl = NULL;
	}
	return ret;
}

static void tls_close(struct s3gw_request *req)
{
	SSL_shutdown(req->ssl);
	SSL_free(req->ssl);
	req->ssl = NULL;
}

static void tls_free(struct s3gw_ctx *ctx)
{
	SSL_CTX_free(ctx->ssl_ctx);
	free(ctx);
}

void tls_loop(struct s3gw_ctx *ctx)
{
	tls_setup(ctx);

	tls_listen(ctx);

	/* Wait for incoming connection */
	for (;;) {
		struct s3gw_request req;
		size_t total;

		if (tls_wait_for_connection(ctx) <= 0) {
			/* Client went away before we accepted the connection */
			continue;
		}

		memset(&req, 0, sizeof(req));
		req.op = API_OPS_UNKNOWN;
		http_parser_init(&req.http, HTTP_REQUEST);
		req.http.data = &req;

		if (tls_accept(ctx, &req) <= 0)
			continue;

		total = handle_request(&req);

		fprintf(stderr, "Client connection closed, %zu bytes sent\n",
			total);
		tls_close(&req);
	}

	tls_free(ctx);
}
