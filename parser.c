#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static int parse_xml(http_parser *http, const char *body, size_t len)
{
	printf("data: %s\n", body);
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
	printf("header: %s\n", hdr->key);
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

struct url_options {
	enum s3_api_ops op;
	char *str;
};

static struct url_options s3_url_options[] = {
	{ S3_OP_ListObjects, "prefix=" },
	{ S3_OP_ListObjects, "max-keys=" },
	{ S3_OP_ListObjects, "marker=" },
};

static int parse_url(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	char buf[2048], *opt = NULL, *p;
	char *bucket, *object = NULL;
	const char *method = http_method_str(http->method);

	memset(buf, 0, sizeof(buf));
	strncpy(buf, at, len);
	printf("urn: %s %s\n", method, buf);
	switch (http->method) {
	case HTTP_HEAD:
		if (strlen(buf) < 2) {
			break;
		}
		bucket = buf + 1;
		p = strchr(bucket, '/');
		if (p) {
			*p = '\0';
			p++;
			object = p;
		} else
			p = bucket;

		opt = strchr(p, '?');
		if (opt) {
			*opt = '\0';
			opt++;
		}
		if (object) {
			req->op = S3_OP_HeadObject;
			req->bucket = strdup(bucket);
			req->object = strdup(object);
			printf("using object %s/%s\n",
			       req->bucket, req->object);
		} else {
			req->op = S3_OP_HeadBucket;
			req->bucket = strdup(bucket);
			printf("using bucket '%s'\n", req->bucket);
		}
		break;
	case HTTP_PUT:
		break;
	case HTTP_GET:
		if (!strncmp(buf, "/", len)) {
			req->op = S3_OP_ListBuckets;
			break;
		}
		p = strchr(buf, '?');
		if (p) {
			*p = '\0';
			req->bucket = strdup(buf + 1);
			req->op = S3_OP_ListObjects;
			p++;
			opt = p;
			printf("using bucket '%s' (opt '%s')\n",
			       req->bucket, opt);
		}
		break;
	default:
		break;
	}

	while (opt) {
		int i;
		char *val = NULL;

		p = strchr(opt, '&');
		if (p) {
			*p = '\0';
			p++;
		}
		val = strchr(opt, '=');
		if (val)
			val++;
		printf("parsing '%s' val '%s' (next '%s')\n",
		       opt, val, p);
		for (i = 0; i < ARRAY_SIZE(s3_url_options); i++) {
			struct url_options *opts;

			opts = &s3_url_options[i];
			if (opts->op != req->op)
				continue;
			if (!strncmp(opt, opts->str,
				     strlen(opts->str))) {
				printf("using option '%s' value '%s'\n",
				       opts->str, val);
			}
		}
		opt = p;
	}

	return 0;
}

int parse_header_complete(http_parser *http)
{
	struct s3gw_request *req = http->data;
	struct s3gw_header *hdr;
	char *host;

	list_for_each_entry(hdr, &req->hdr_list, list) {
		if (!strcmp(hdr->key, "Host")) {
			host = hdr->value;
			break;
		}
	}
	if (http->method == HTTP_GET) {
		printf("GET from %s\n", host);
		return 1;
	}
	return 0;
}

void setup_parser(http_parser_settings *settings)
{
  	memset(settings, 0, sizeof(*settings));
	settings->on_body = parse_xml;
	settings->on_header_field = parse_header;
	settings->on_header_value = parse_header_value;
	settings->on_headers_complete = parse_header_complete;
	settings->on_url = parse_url;
}
