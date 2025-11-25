#ifndef _S3GW_H
#define _S3GW_H

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <libxml/tree.h>

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
	void *map;
	size_t size;
	unsigned char *etag;
	size_t etag_len;
	time_t mtime;
	int error;
};

struct s3gw_header {
	struct linked_list list;
	char *key;
	char *value;
};

struct s3gw_request {
	struct s3gw_ctx *ctx;
	int fd;
	SSL *ssl;
	http_parser http;
	xmlDoc *xml;
	unsigned char *payload;
	size_t payload_len;
	size_t expected_len;
	enum s3_api_ops op;
	struct linked_list hdr_list;
	struct linked_list auth_list;
	struct linked_list query_list;
	void *next_hdr;
	char *owner;
	char *region;
	char *tstamp;
	char *url;
	char *query;
	char *bucket;
	char *key;
};

struct s3gw_response {
	struct s3gw_request *req;
	enum http_status status;
	struct linked_list resp_hdr_list;
	struct s3gw_object *obj;
	unsigned char *payload;
	size_t payload_len;
};

void setup_parser(http_parser_settings *settings);

/* request.c */
void init_request(struct s3gw_ctx *ctx, struct s3gw_request *req);
void reset_request(struct s3gw_request *req);
void reset_response(struct s3gw_response *resp);
size_t handle_request(struct s3gw_request *req, struct s3gw_response *resp);
char *fetch_request_header(struct s3gw_request *req, const char *key, int *len);
const char *fetch_request_query(struct s3gw_request *req,
				const char *key, int *len);

/* dir.c */
int create_owner_secret(struct s3gw_ctx *ctx, char *owner_id, char *secret);
char *get_owner_secret(struct s3gw_ctx *ctx, char *owner_id, int *out_len);
int dir_create_bucket(struct s3gw_request *req, const char *bucket);
int dir_delete_bucket(struct s3gw_request *req, const char *bucket);
int dir_find_buckets(struct s3gw_request *req, const char *prefix,
		     struct linked_list *head);
int dir_create_object(struct s3gw_request *req, struct s3gw_object *obj,
		      const char *object);
int dir_fetch_object(struct s3gw_request *req, struct s3gw_object *obj,
		     const char *object);
int dir_delete_object(struct s3gw_request *req, const char *bucket,
		      const char *object);
int dir_find_objects(struct s3gw_request *req, struct linked_list *head,
		     char *prefix, char *delim, char *marker);
int dir_find_prefix(struct s3gw_request *req, struct linked_list *head,
		    char *prefix, char *delim, char *marker);
int dir_splice_objects(struct s3gw_request *req,
		       char *s_bucket, char *s_obj,
		       char *d_bucket, char *d_obj);

/* bucket.c */
xmlNode *find_node(xmlNode *top, const xmlChar *key);
void create_bucket(struct s3gw_request *req, struct s3gw_response *resp);
void delete_bucket(struct s3gw_request *req,  struct s3gw_response *resp);
void list_buckets(struct s3gw_request *req,  struct s3gw_response *resp);
void check_bucket(struct s3gw_request *req,  struct s3gw_response *resp);
void bucket_versioning(struct s3gw_request *req,  struct s3gw_response *resp);
void bucket_policy_status(struct s3gw_request *req, struct s3gw_response *resp);

/* object.c */
void create_object(struct s3gw_request *req, struct s3gw_response *resp);
void delete_object(struct s3gw_request *req,  struct s3gw_response *resp);
void list_objects(struct s3gw_request *req,  struct s3gw_response *resp);
void get_object(struct s3gw_request *req,  struct s3gw_response *resp);
void copy_object(struct s3gw_request *req,  struct s3gw_response *resp,
		 const char *source);
void delete_objects(struct s3gw_request *req,  struct s3gw_response *resp);
void clear_object(struct s3gw_object *obj);

/* format.c */
int put_response_header(struct s3gw_response *resp, const char *key,
			char *value);
char *gen_response_header(struct s3gw_response *resp, int *outlen);
char *format_response(struct s3gw_request *req, struct s3gw_response *resp,
		      int *outlen);

void tls_loop(struct s3gw_ctx *ctx);
void tcp_loop(struct s3gw_ctx *ctx);

/* auth.c */
char *bin2hex(unsigned char *input, int input_len, size_t *out_len);
unsigned char *hex2bin(char *input, size_t *out_len);
char *uri_encode(const char *value, bool encode_slash);
char *uri_decode(const char *value, size_t len);
unsigned char *hmac_sha256(const void *key, int keylen,
			   const unsigned char *data, int datalen,
			   unsigned char *result, unsigned int *resultlen);
unsigned char *md5sum(char *input, int input_len, int *out_len);
char *auth_string_to_sign(struct s3gw_request *req, int *out_len);
char *auth_sign_str(struct s3gw_request *req, char *str_to_sign, int *out_len);
int check_authorization(struct s3gw_request *req);

#endif /* _S3GW_H */

