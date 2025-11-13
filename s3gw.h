#ifndef _S3GW_H
#define _S3GW_H

struct s3gw_ctx {
	const char *hostport;
	const char *cert;
	const char *key;
	int fd;
	SSL_CTX *ssl_ctx;
	BIO *accept_bio;
};

struct s3gw_request {
	int fd;
	SSL *ssl;
	http_parser http;
	enum s3_api_ops op;
	char *host;
	char *token;
	void *next_hdr;
};

void setup_parser(http_parser_settings *settings);
size_t handle_request(struct s3gw_request *req);
int format_response(struct s3gw_request *req, char *buf);

void tls_loop(struct s3gw_ctx *ctx);
void tcp_loop(struct s3gw_ctx *ctx);

#endif /* _S3GW_H */

