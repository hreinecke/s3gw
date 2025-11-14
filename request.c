/*
 *  Copyright 2025 Hannes Reinecke, SUSE
 */

#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

void reset_request(struct s3gw_request *req)
{
	if (req->bucket) {
		free(req->bucket);
		req->bucket = NULL;
	}
	if (req->object) {
		free(req->object);
		req->object = NULL;
	}
	if (req->host) {
		free(req->host);
		req->host = NULL;
	}
	req->next_hdr = NULL;
	req->op = S3_OP_Unknown;
}

static int read_request(struct s3gw_request *req, char *buf, size_t len,
			size_t *outlen)
{
	struct msghdr msg;
	struct iovec iov;

	if (req->fd) {
		int ret;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		ret = recvmsg(req->fd, &msg, 0);
		if (ret > 0)
			*outlen = ret;
		return ret;
	}
	return SSL_read_ex(req->ssl, buf, len, outlen);
}

static int write_request(struct s3gw_request *req, char *buf, size_t len,
			 size_t *outlen)
{
	struct msghdr msg;
	struct iovec iov;

	if (req->fd) {
		int ret;

		memset(&msg, 0, sizeof(msg));
		iov.iov_base = buf;
		iov.iov_len = len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		ret = sendmsg(req->fd, &msg, 0);
		if (ret > 0)
			*outlen = ret;
		return ret;
	}
	return SSL_write_ex(req->ssl, buf, len, outlen);
}

size_t handle_request(struct s3gw_request *req)
{
	char *resp, buf[8192];
	http_parser *http = &req->http;
	http_parser_settings settings;
	size_t nread;
	size_t nwritten = 0;
	size_t total = 0;
	int ret, resp_len;

	setup_parser(&settings);

	ret = read_request(req, buf, sizeof(buf), &nread);
	if (ret <= 0) {
		fprintf(stderr, "Error %d reading request\n", errno);
		return 0;
	}

	ret = http_parser_execute(http, &settings,
				  (const char *)buf, nread);
	if (ret == 0 || http->http_errno) {
		fprintf(stderr, "failed to parse HTTP, errno %d\n",
			http->http_errno);
		return 0;
	}
	if (ret < nread)
		printf("%ld trailing bytes on input\n", nread - ret);

	resp = format_response(req, &resp_len);
	if (!resp) {
		fprintf(stderr, "Error formatting response\n");
		return 0;
	}
	printf("Response (len %d):\n%s\n", resp_len, resp);
	while (total < resp_len) {
		ret = write_request(req, resp + total, resp_len - total,
				    &nwritten);
		if (ret <= 0) {
			fprintf(stderr, "Error writing response\n");
			break;
		}
		total += nwritten;
	}
	free(resp);

	return total;
}
