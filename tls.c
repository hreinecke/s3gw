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

struct s3gw_ctx {
	const char *hostport;
	const char *cert;
	const char *key;
	SSL_CTX *ssl_ctx;
	BIO *accept_bio;
};

struct s3gw_request {
	enum s3_api_ops op;
	char *host;
	char *token;
	void *next_hdr;
};

static const char cache_id[] = "Simple S3 Gateway";
static const char s3gw_token[] = "76a46a30-357b-4362-acfb-4d3d2ac6ee2b";

static int parse_xml(http_parser *http, const char *body, size_t len)
{
	printf("data: %s\n", body);
	return 0;
}

static int parse_header(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	char buf[1024];

	if (!strncmp(at, "Host", len)) {
		req->next_hdr = req->host;
	} else if (!strncmp(at, "x-aws-ec2-metadata-token", len)) {
		req->next_hdr = req->token;
	} else {
		req->next_hdr = NULL;
		memset(buf, 0, sizeof(buf));
		strncpy(buf, at, len);
		printf("header: %s\n", buf);
	}
	return 0;
}

static int parse_header_value(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	char buf[1024];

	if (req->next_hdr == req->host) {
		asprintf(&req->host, at);
		req->host[len] = '\0';
	} else if (req->next_hdr == req->token) {
		asprintf(&req->token, at);
		req->token[len] = '\0';
	} else {
		memset(buf, 0, sizeof(buf));
		strncpy(buf, at, len);
		printf("value: %s\n", buf);
	}
	req->next_hdr = NULL;
	return 0;
}

static int parse_url(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	char buf[2048];
	const char *method = http_method_str(http->method);

	memset(buf, 0, sizeof(buf));
	strncpy(buf, at, len);
	switch (http->method) {
	case HTTP_PUT:
		if (!strncmp(at, "/latest/api/token", len)) {
			req->op = IMDS_GET_METADATA_VERSIONS;
		}
		break;
	case HTTP_GET:
		if (!strncmp(at, "/latest/meta-data/iam/security-credentials/",
			     len)) {
			req->op = IMDS_GET_CREDENTIALS;
		}
		break;
	default:
		break;
	}
			
	printf("urn: %s %s\n", method, buf);
	return 0;
}

static int bucket_ok(char *buf, const char *loc, const char *arn)
{
	enum http_status s = 200;
	size_t off = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;
	ret = sprintf(buf + off, "Location: %s\r\n", loc);
	if (ret < 0)
		return -errno;
	off += ret;
	ret = sprintf(buf + off, "x-amz-bucket-arn: %s\r\n", arn);
	if (ret < 0)
		return -errno;
	off += ret;
	return off;
}

static int put_ok(char *buf, const char *data)
{
	enum http_status s = HTTP_STATUS_OK;
	size_t off = 0, len = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;

	if (data)
		len = strlen(data);
	ret = sprintf(buf + off, "Content-Length: %ld\r\n\r\n", len);
	if (ret < 0)
		return -errno;
	off += ret;
	if (data) {
		ret = sprintf(buf + off, "%s\r\n\r\n", data);
		if (ret < 0)
			return -errno;
		off += ret;
	}
	return off;
}

static int format_response(struct s3gw_request *req, char *buf)
{
	char location[] = "eu-west-1";
	char bucket[] = "arn:2e28574b-3276-44a1-8e00-b3de937c07c0";
	int ret;
	char data[4096], tstamp[256];
	time_t cur_time = time(NULL);
	struct tm *cur_tm = gmtime(&cur_time);

	switch (req->op) {
	case IMDS_GET_METADATA_VERSIONS:
		ret = put_ok(buf, s3gw_token);
		break;
	case IMDS_GET_CREDENTIALS:
		strftime(tstamp, 256, "%Y-%m-%dT%TZ", cur_tm);
		sprintf(data,"{\n");
		sprintf(data, "\"Code\" : \"Success\"\n");
		sprintf(data, "\"LastUpdated\" : \"%s\"\n", tstamp);
		sprintf(data, "\"Type\" : \"AWS-HMAC\"\n");
		sprintf(data, "\"AccessKeyId\" : \"ASIAIOSFODNN7EXAMPLE\"\n");
		sprintf(data, "\"SecretAccessKey\" : \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n");
		sprintf(data, "\"Token\" : \"%s\"\n", s3gw_token);
		cur_time += 3600;
		cur_tm = gmtime(&cur_time);
		strftime(tstamp, 256, "%Y-%m-%dT%TZ", cur_tm);
		sprintf(data, "\"Expiration\" : \"%s\"\n}\n", tstamp);
		ret = put_ok(buf, data);
		break;
	default:
		ret = bucket_ok(buf, location, bucket);
		break;
	}
	return ret;
}

static size_t handle_request(SSL *ssl, http_parser *http)
{
	struct s3gw_request req;
	char buf[8192];
	http_parser_settings settings;
	size_t nread;
	size_t nwritten;
	size_t total = 0;

	memset(&req, 0, sizeof(req));
	req.op = API_OPS_UNKNOWN;

	http->data = &req;
	memset(&settings, 0, sizeof(settings));
	settings.on_body = parse_xml;
	settings.on_header_field = parse_header;
	settings.on_header_value = parse_header_value;
	settings.on_url = parse_url;

	while (SSL_read_ex(ssl, buf, sizeof(buf), &nread) > 0) {
		int ret;

		ret = http_parser_execute(http, &settings,
					  (const char *)buf, nread);
		if (ret == 0 || http->http_errno) {
			fprintf(stderr, "failed to parse HTTP, errno %d\n",
				http->http_errno);
			break;
		}

		ret = format_response(&req, buf);
		if (ret < 0) {
			fprintf(stderr, "Error formatting response\n");
			break;
		}
		printf("Response:\n%s\n", buf);
		nread = ret;
		if (SSL_write_ex(ssl, buf, nread, &nwritten) > 0 &&
		    nwritten == nread) {
			total += nwritten;
			break;
		}
		fprintf(stderr, "Error writing response\n");
		break;
	}
	return total;
}

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

static SSL *tls_accept(struct s3gw_ctx *ctx)
{
	BIO *client_bio;
	SSL *ssl;
	int ret;

	/* Pop the client connection from the BIO chain */
	client_bio = BIO_pop(ctx->accept_bio);
	fprintf(stderr, "New client connection accepted\n");

	/* Associate a new SSL handle with the new connection */
	if ((ssl = SSL_new(ctx->ssl_ctx)) == NULL) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr,
			"Error creating SSL handle for new connection\n");
		BIO_free(client_bio);
		return NULL;
	}
	SSL_set_bio(ssl, client_bio, client_bio);

	/* Attempt an SSL handshake with the client */
	ret = SSL_accept(ssl);
	if (ret <= 0) {
		ERR_print_errors_fp(stderr);
		fprintf(stderr, "Error performing SSL handshake with client\n");
		SSL_free(ssl);
		return NULL;
	}
	return ssl;
}

int main(int argc, char *argv[])
{
	char *default_cert = "server-cert.pem";
	char *default_key = "server-key.pem";
	struct s3gw_ctx *ctx = NULL;
	http_parser *http;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	ctx->cert = default_cert;
	ctx->key = default_key;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [host:]port\n", argv[0]);
		free(ctx);
		exit(1);
	}
	ctx->hostport = argv[1];

	http = malloc(sizeof(*http));
	if (!http) {
		fprintf(stderr, "Out of memory\n");
		free(ctx);
		exit(1);
	}
	memset(http, 0, sizeof(*http));

	tls_setup(ctx);

	tls_listen(ctx);

	/* Wait for incoming connection */
	for (;;) {
		SSL *ssl;
		size_t total;

		if (tls_wait_for_connection(ctx) <= 0) {
			/* Client went away before we accepted the connection */
			continue;
		}

		ssl = tls_accept(ctx);
		if (!ssl)
			continue;

		http_parser_init(http, HTTP_REQUEST);
		total = handle_request(ssl, http);
		SSL_shutdown(ssl);
		fprintf(stderr, "Client connection closed, %zu bytes sent\n",
			total);
		SSL_free(ssl);
	}

	/*
	 * Unreachable placeholder cleanup code, the above loop runs forever.
	 */
	SSL_CTX_free(ctx->ssl_ctx);
	free(ctx);
	return 0;
}
