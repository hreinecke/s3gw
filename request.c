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

		iov.iov_base = buf;
		iov.iov_len = len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		ret = recvmsg(req->fd, &msg, 0);
		if (ret < 0)
			fprintf(stderr, "error %d reading message\n", errno);
		else {
			*outlen = ret;
			printf("read %d bytes\n", ret);
		}
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

#if 0
		iov.iov_base = buf;
		iov.iov_len = len;
		msg.msg_iov = &iov;
		msg.msg_iovlen = 1;
		ret = sendmsg(req->fd, &msg, 0);
#else
		ret = write(req->fd, buf, len);
#endif
		if (ret < 0)
			fprintf(stderr, "error %d writing message\n", errno);
		else {
			*outlen = ret;
			printf("wrote %d bytes\n", ret);
		}
		return ret;
	}
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
		printf("Response (len %d):\n%s\n", ret, buf);
		nread = ret;
		if (write_request(req, buf, nread, &nwritten) > 0 &&
		    nwritten == nread) {
			total += nwritten;
			break;
		}
		fprintf(stderr, "Error writing response\n");
		break;
	}
	reset_request(req);

	return total;
}
