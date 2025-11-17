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
	}
	printf("urn: %s %s %s\n", method, req->url, req->query);
	if (strlen(req->url) > 1) {
		char *p;

		req->bucket = strdup(req->url + 1);
		if (!req->bucket)
			return 0;
		p = strchr(req->bucket, '/');
		if (p) {
			*p = '\0';
			p++;
			req->object = p;
		}
	}
	
	return 0;
}

int parse_header_complete(http_parser *http)
{
	struct s3gw_request *req = http->data;
	struct s3gw_header *hdr;
	char *host;

	list_for_each_entry(hdr, &req->hdr_list, list) {
		printf("header '%s': %s\n", hdr->key, hdr->value);
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
