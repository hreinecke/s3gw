#include <stdio.h>
#include <stdbool.h>
#include <string.h>

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
	char buf[1024];

	memset(buf, 0, sizeof(buf));
	strncpy(buf, at, len);
	printf("header: %s\n", buf);
	if (!strncmp(at, "Host", len)) {
		req->next_hdr = req->host;
	} else {
		req->next_hdr = NULL;
	}
	return 0;
}

static int parse_header_value(http_parser *http, const char *at, size_t len)
{
	struct s3gw_request *req = http->data;
	char *buf;

	buf = strdup(at);
	buf[len] = '\0';
	printf("value: %s\n", buf);
	if (req->next_hdr == req->host) {
		req->host = buf;
	} else {
		free(buf);
	}
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
	const char *method = http_method_str(http->method);

	memset(buf, 0, sizeof(buf));
	strncpy(buf, at, len);
	printf("urn: %s %s\n", method, buf);
	switch (http->method) {
	case HTTP_HEAD:
		if (strlen(buf) < 2) {
			break;
		}
		req->bucket = strdup(buf + 1);
		p = strchr(buf + 1, '/');
		if (p) {
			*p = '\0';
			p++;
			req->op = S3_OP_HeadObject;
			req->object = strdup(p);
			printf("using object %s/%s\n",
			       req->bucket, req->object);
		} else {
			req->op = S3_OP_HeadBucket;
			p = strdup(buf + 1);
			printf("using bucket '%s'\n", req->bucket);
		}
		opt = strchr(p, '?');
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
			req->bucket = strdup(p + 1);
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

	if (http->method == HTTP_GET) {
		printf("GET from %s\n", req->host);
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
