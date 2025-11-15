#ifndef _S3GW_H
#define _S3GW_H

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "utils.h"

struct s3gw_owner {
	const char *id;
	const char *key;
	const char *secret;
};

struct s3gw_ctx {
	const char *hostport;
	const char *cert;
	const char *key;
	const char *base_dir;
	const char *owner;
	const char *region;
	int fd;
	SSL_CTX *ssl_ctx;
	BIO *accept_bio;
};

struct s3gw_bucket {
	struct linked_list list;
	struct linked_list objects;
	char *name;
	char *arn;
	char *region;
	time_t ctime;
};

struct s3gw_object {
	struct linked_list list;
	struct s3gw_bucket *bucket;
	char *key;
	size_t size;
	unsigned char *etag;
	size_t etag_len;
	time_t mtime;
};

struct s3gw_request {
	struct s3gw_ctx *ctx;
	int fd;
	SSL *ssl;
	http_parser http;
	enum s3_api_ops op;
	char *host;
	void *next_hdr;
	char *region;
	char *bucket;
	char *object;
	char *prefix;
};

void setup_parser(http_parser_settings *settings);

/* request.c */
void init_request(struct s3gw_ctx *ctx, struct s3gw_request *req);
void reset_request(struct s3gw_request *req);
size_t handle_request(struct s3gw_request *req);

/* dir.c */
int create_owner(struct s3gw_ctx *ctx, char *owner_id,
		 char *key, char *secret);
int find_buckets(struct s3gw_request *req, struct linked_list *head);
int find_objects(struct s3gw_request *req, struct linked_list *head);
void clear_object(struct s3gw_object *obj);

/* bucket.c */
char *list_buckets(struct s3gw_request *req, int *outlen);
char *check_bucket(struct s3gw_request *req, int *outlen);

/* object.c */
char *list_objects(struct s3gw_request *req, int *outlen);
char *check_object(struct s3gw_request *req, int *outlen);

/* format.c */
char *format_response(struct s3gw_request *req, int *outlen);

void tls_loop(struct s3gw_ctx *ctx);
void tcp_loop(struct s3gw_ctx *ctx);

/* md5sum.c */
unsigned char *md5sum(char *input, int input_len, int *out_len);

#endif /* _S3GW_H */

