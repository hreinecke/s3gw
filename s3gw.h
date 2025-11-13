#ifndef _S3GW_H
#define _S3GW_H

struct s3gw_ctx {
	const char *hostport;
	const char *cert;
	const char *key;
	SSL_CTX *ssl_ctx;
	BIO *accept_bio;
};

struct s3gw_request {
	SSL *ssl;
	enum s3_api_ops op;
	char *host;
	char *token;
	void *next_hdr;
};

void setup_parser(http_parser_settings *settings);
size_t handle_request(struct s3gw_request *req, http_parser *http);
int format_response(struct s3gw_request *req, char *buf);

#endif /* _S3GW_H */

