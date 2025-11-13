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
	char cred_url[] = "/latest/meta-data/iam/security-credentials/";
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
		if (!strncmp(at, cred_url, strlen(cred_url))) {
			if (len > strlen(cred_url))
				req->op = IMDS_GET_ROLE_CREDENTIALS;
			else
				req->op = IMDS_GET_CREDENTIALS;
		}
		break;
	default:
		break;
	}
			
	printf("urn: %s %s\n", method, buf);
	return 0;
}

void setup_parser(http_parser_settings *settings)
{
  	memset(settings, 0, sizeof(*settings));
	settings->on_body = parse_xml;
	settings->on_header_field = parse_header;
	settings->on_header_value = parse_header_value;
	settings->on_url = parse_url;
}
