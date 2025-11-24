#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include <libxml/parser.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static int parse_body(http_parser *http, const char *body, size_t len)
{
	struct s3gw_request *req = http->data;
	unsigned char *out;
	int out_len;

	if (!len)
		return 0;
	req->xml = xmlParseMemory(body, len);
	if (!req->xml) {
		fprintf(stderr, "failed to parse xml body\n");
		return 0;
	}
	xmlDocDumpMemory(req->xml, &out, &out_len);
	printf("body:\n%s", out);
	free(out);
	return 0;
}

static int parse_header(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	struct s3gw_header *hdr;

	hdr = malloc(sizeof(*hdr));
	if (!hdr)
		return -ENOMEM;
	hdr->key = malloc(len + 1);
	if (!hdr->key) {
		free(hdr);
		return -ENOMEM;
	}
	memset(hdr->key, 0, len + 1);
	strncpy(hdr->key, at, len);
	list_add(&hdr->list, &req->hdr_list);
	req->next_hdr = hdr;
	return 0;
}

static int parse_header_value(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	struct s3gw_header *hdr = req->next_hdr;

	if (!req->next_hdr)
		return -EINVAL;
	hdr->value = malloc(len + 1);
	if (!hdr->value)
		return -ENOMEM;
	memset(hdr->value, 0, len + 1);
	strncpy(hdr->value, at, len);
	req->next_hdr = NULL;
	return 0;
}

static int parse_query(struct s3gw_request *req)
{
	char *query, *q, *p, *save;
	struct s3gw_header *hdr, *prev, *tmp;

	query = strdup(req->query);
	if (!query)
		return -ENOMEM;

	q = strtok_r(query, "&", &save);
	while (q) {
		hdr = malloc(sizeof(*hdr));
		if (!hdr)
			return -ENOMEM;
		p = strchr(q, '=');
		if (p) {
			*p = '\0';
			p++;
		}
		hdr->key = strdup(q);
		hdr->value = NULL;
		if (p)
			hdr->value = strdup(p);
		/* Sort the list alphabetically */
		prev = NULL;
		list_for_each_entry(tmp, &req->query_list, list) {
			if (strcmp(tmp->key, hdr->key) < 0)
				prev = tmp;
		}
		if (prev)
			list_add(&hdr->list, &prev->list);
		else
			list_add(&hdr->list, &req->query_list);
		q = strtok_r(NULL, "&", &save);
	}
	free(query);
	list_for_each_entry(hdr, &req->query_list, list)
		printf("query: %s = %s\n", hdr->key,
		       hdr->value ? hdr->value : "");
	return 0;
}

static int parse_url(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	const char *method = http_method_str(http->method);

	req->url = malloc(len + 1);
	if (!req->url)
		return 0;
	memset(req->url, 0, len + 1);
	memcpy(req->url, at, len); 
	req->query = strchr(req->url, '?');
	if (req->query) {
		*req->query = '\0';
		req->query++;
		if (strlen(req->query))
			parse_query(req);
	}
	printf("urn: %s %s %s\n", method, req->url,
	       req->query ? req->query : "");
	if (strlen(req->url) > 1) {
		req->key = strdup(req->url + 1);
		if (!req->key)
			return 0;
	}

	switch (http->method) {
	case HTTP_GET:
		req->op = S3_OP_GetObject;
		break;
	case HTTP_HEAD:
		req->op = S3_OP_HeadObject;
		break;
	case HTTP_PUT:
		req->op = S3_OP_PutObject;
		break;
	case HTTP_POST:
		req->op = S3_OP_DeleteObjects;
		break;
	case HTTP_DELETE:
		req->op = S3_OP_DeleteObject;
		break;
	}
	return 0;
}

struct s3_op_desc {
	enum s3_api_ops op;
	char *desc;
};

#define OP_STR(o) \
	{ .op = o, .desc = #o }

struct s3_op_desc s3_ops[] = {
	OP_STR(S3_OP_Unknown),
	OP_STR(S3_OP_CreateBucket),
	OP_STR(S3_OP_HeadBucket),
	OP_STR(S3_OP_ListBuckets),
	OP_STR(S3_OP_ListObjects),
	OP_STR(S3_OP_ListObjectsV2),
	OP_STR(S3_OP_ListMultipartUploads),
	OP_STR(S3_OP_DeleteBucket),
	OP_STR(S3_OP_PutBucketPolicy),
	OP_STR(S3_OP_GetBucketPolicy),
	OP_STR(S3_OP_DeleteBucketPolicy),
	OP_STR(S3_OP_GetBucketPolicyStatus),
	OP_STR(S3_OP_GetBucketVersioning),
	OP_STR(S3_OP_PutObject),
	OP_STR(S3_OP_CopyObject),
	OP_STR(S3_OP_RestoreObject),
	OP_STR(S3_OP_GetObject),
	OP_STR(S3_OP_HeadObject),
	OP_STR(S3_OP_DeleteObject),
	OP_STR(S3_OP_DeleteObjects),
	OP_STR(S3_OP_CreateMultipartUpload), /* NI */
	OP_STR(S3_OP_CompleteMultipartUpload), /* NI */
	OP_STR(S3_OP_AbortMultipartUpload), /* NI */
	OP_STR(S3_OP_UploadPart), /* NI */
	OP_STR(S3_OP_UploadPartCopy), /* NI */
	OP_STR(S3_OP_ListParts), /* NI */
};

const char *s3_op_str(enum s3_api_ops op)
{
	int i;

	for (i = 0; i < ARRAY_SIZE(s3_ops); i++) {
		if (s3_ops[i].op == op)
			return s3_ops[i].desc;
	}
	return NULL;
}

int parse_header_complete(http_parser *http)
{
	struct s3gw_request *req = http->data;
	char *p, *host;
	int ret;

	p = fetch_request_header(req, "Content-Length", &ret);
	if (ret) {
		char *eptr;

		ret = strtoul(p, &eptr, 10);
		if (eptr != p)
			req->payload_len = ret;
	}
	host = fetch_request_header(req, "Host", &ret);
	if (ret) {
		printf("Host: %s\n", host);
		p = strchr(host, '.');
		if (p && !strcmp(p + 1, req->ctx->hostport)) {
			req->bucket = strdup(host);
			p = strchr(req->bucket, '.');
			*p = '\0';
			printf("Bucket: %s\n", req->bucket);
		}
	}
	switch (req->op) {
	case S3_OP_GetObject:
		if (!req->key) {
			if (fetch_request_query(req, "versioning", &ret))
				req->op = S3_OP_GetBucketVersioning;
			else if (fetch_request_query(req, "policyStatus", &ret))
				req->op = S3_OP_GetBucketPolicyStatus;
			else if (fetch_request_query(req, "delimiter", &ret))
				req->op = S3_OP_ListObjects;
			else
				req->op = S3_OP_ListBuckets;
		}
		break;
	case S3_OP_HeadObject:
		if (!req->key)
			req->op = S3_OP_HeadBucket;
		break;
	case S3_OP_PutObject:
		if (!req->key)
			req->op = S3_OP_CreateBucket;
		break;
	case S3_OP_DeleteObject:
		if (!req->key)
			req->op = S3_OP_DeleteBucket;
		break;
	default:
		break;
	}
	printf("Op: %s\n", s3_op_str(req->op));
	return 0;
}

void setup_parser(http_parser_settings *settings)
{
  	memset(settings, 0, sizeof(*settings));
	settings->on_body = parse_body;
	settings->on_header_field = parse_header;
	settings->on_header_value = parse_header_value;
	settings->on_headers_complete = parse_header_complete;
	settings->on_url = parse_url;
}
