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

static void print_xml(xmlNode *node)
{
	xmlNode *cur = NULL;

	for (cur = node; cur; cur = cur->next) {
		if (cur->type == XML_ELEMENT_NODE)
			printf("xml node '%s'\n",
			       cur->name);
		else if (cur->type == XML_TEXT_NODE)
			printf("xml text '%s': '%s'\n",
			       cur->name, cur->content);
		print_xml(cur->children);
	}
}

static int parse_xml(http_parser *http, const char *body, size_t len)
{
	struct s3gw_request *req = http->data;
	xmlNode *root;
	unsigned char *out;
	int out_len;

	if (!len)
		return 0;
	if (req->op == S3_OP_PutObject) {
		req->payload = malloc(len + 1);
		memset(req->payload, 0, len + 1);
		memcpy(req->payload, body, len);
		printf("body:\n%s\n", req->payload);
		return 0;
	}
	req->xml = xmlParseMemory(body, len);
	if (!req->xml) {
		fprintf(stderr, "failed to parse body\n");
		return 0;
	}
	root = xmlDocGetRootElement(req->xml);
	print_xml(root);
	xmlDocDumpMemory(req->xml, &out, &out_len);
	printf("%s", out);
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
		printf("query: %s = %s\n", hdr->key, hdr->value);
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

	switch (http->method) {
	case HTTP_GET:
		if (!req->bucket)
			req->op = S3_OP_ListBuckets;
		else if (!req->object)
			req->op = S3_OP_ListObjects;
		else
			req->op = S3_OP_GetObject;
		break;
	case HTTP_HEAD:
		if (req->object)
			req->op = S3_OP_HeadObject;
		else if (req->bucket)
			req->op = S3_OP_HeadBucket;
		break;
	case HTTP_PUT:
		if (req->object)
			req->op = S3_OP_PutObject;
		else if (req->bucket)
			req->op = S3_OP_CreateBucket;
		break;
	case HTTP_POST:
		if (req->bucket)
			req->op = S3_OP_DeleteObjects;
		break;
	case HTTP_DELETE:
		if (req->object)
			req->op = S3_OP_DeleteObject;
		else if (req->bucket)
			req->op = S3_OP_DeleteBucket;
		break;
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
		if (!strcmp(hdr->key, "Content-Length")) {
			int ret;
			char *eptr;

			ret = strtoul(hdr->value, &eptr, 10);
			if (eptr != hdr->value) {
				if (req->payload_len)
					printf("overriding payload length\n");
				req->payload_len = ret;
			}
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
