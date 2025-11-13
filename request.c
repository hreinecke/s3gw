/*
 *  Copyright 2025 Hannes Reinecke, SUSE
 */

#include <string.h>
#include <stdbool.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static int read_request(struct s3gw_request *req, char *buf, size_t len,
			size_t *outlen)
{
	return SSL_read_ex(req->ssl, buf, len, outlen);
}

static int write_request(struct s3gw_request *req, char *buf, size_t len,
			 size_t *outlen)
{
	return SSL_write_ex(req->ssl, buf, len, outlen);
}

size_t handle_request(struct s3gw_request *req)
{
	char buf[8192];
	http_parser *http = &req->http;
	http_parser_settings settings;
	size_t nread;
	size_t nwritten;
	size_t total = 0;

	setup_parser(&settings);

	while (read_request(req, buf, sizeof(buf), &nread) > 0) {
		int ret;

		ret = http_parser_execute(http, &settings,
					  (const char *)buf, nread);
		if (ret == 0 || http->http_errno) {
			fprintf(stderr, "failed to parse HTTP, errno %d\n",
				http->http_errno);
			break;
		}

		ret = format_response(req, buf);
		if (ret < 0) {
			fprintf(stderr, "Error formatting response\n");
			break;
		}
		printf("Response:\n%s\n", buf);
		nread = ret;
		if (write_request(req, buf, nread, &nwritten) > 0 &&
		    nwritten == nread) {
			total += nwritten;
			break;
		}
		fprintf(stderr, "Error writing response\n");
		break;
	}
	return total;
}
