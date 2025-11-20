/*
 *  Copyright 2025 Hannes Reinecke, SUSE
 */

#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <errno.h>
#include <unistd.h>

#include "s3_api.h"
#include "s3gw.h"

void init_request(struct s3gw_ctx *ctx, struct s3gw_request *req)
{
	memset(req, 0, sizeof(*req));
	INIT_LINKED_LIST(&req->hdr_list);
	INIT_LINKED_LIST(&req->auth_list);
	INIT_LINKED_LIST(&req->query_list);
	req->op = S3_OP_Unknown;
	http_parser_init(&req->http, HTTP_REQUEST);
	req->http.data = req;
	req->ctx = ctx;
}

void reset_request(struct s3gw_request *req)
{
	struct s3gw_header *hdr, *tmp;

	if (req->bucket) {
		free(req->bucket);
		req->bucket = NULL;
	}
	req->object = NULL;

	list_for_each_entry_safe(hdr, tmp, &req->hdr_list, list) {
		list_del_init(&hdr->list);
		if (hdr->value)
			free(hdr->value);
		if (hdr->key)
			free(hdr->key);
		free(hdr);
	}
	list_for_each_entry_safe(hdr, tmp, &req->auth_list, list) {
		list_del_init(&hdr->list);
		if (hdr->value) {
			free(hdr->value);
			hdr->value = NULL;
		}
		if (hdr->key) {
			free(hdr->key);
			hdr->key = NULL;
		}
		free(hdr);
	}
	list_for_each_entry_safe(hdr, tmp, &req->query_list, list) {
		list_del_init(&hdr->list);
		if (hdr->value) {
			free(hdr->value);
			hdr->value = NULL;
		}
		if (hdr->key) {
			free(hdr->key);
			hdr->key = NULL;
		}
		free(hdr);
	}
	if (req->owner) {
		free(req->owner);
		req->owner = NULL;
		req->tstamp = NULL;
		req->region = NULL;
	}
	if (req->payload) {
		free(req->payload);
		req->payload = NULL;
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

next:
	ret = read_request(req, buf, sizeof(buf), &nread);
	if (ret < 0) {
		fprintf(stderr, "Error %d reading request\n", errno);
		return 0;
	}
	if (ret == 0) {
		fprintf(stderr,
			"Connection closed after reading %ld bytes\n",
			nread);
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

	if (req->payload_len && !req->payload && !req->xml) {
		size_t plen;
		printf("reading %ld bytes of payload\n",
		       req->payload_len);
		req->payload = malloc(req->payload_len);
		ret = read_request(req, (char *)req->payload,
				   req->payload_len, &plen);
	}
	resp = format_response(req, &resp_len);
	if (!resp) {
		fprintf(stderr, "Error formatting response\n");
		return 0;
	}
	printf("Response (len %d + %lu):\n%s\n",
	       resp_len, req->obj ? req->obj->size : 0, resp);
	while (total < resp_len) {
		ret = write_request(req, resp + total, resp_len - total,
				    &nwritten);
		if (ret < 0) {
			fprintf(stderr, "Error %d writing response\n", errno);
			break;
		}
		if (ret == 0) {
			fprintf(stderr,
				"Connection closed after writing %ld bytes\n",
				total);
			break;
		}
		total += nwritten;
	}
	if (req->obj) {
		size_t off = 0;

		while (off < req->obj->size) {
			ret = write_request(req, req->obj->map + off,
					    req->obj->size - off, &nwritten);
			if (ret > 0) {
				off += nwritten;
				total += nwritten;
			}
		}
	}
	free(resp);

	if (req->status == HTTP_STATUS_CONTINUE)
		goto next;
	return total;
}

char *fetch_request_header(struct s3gw_request *req, const char *key, int *len)
{
	struct s3gw_header *hdr;

	list_for_each_entry(hdr, &req->hdr_list, list) {
		if (!strcmp(hdr->key, key)) {
			*len = hdr->value ? strlen(hdr->value) : 0;
			return hdr->value;
		}
	}
	*len = 0;
	return NULL;
}

const char *fetch_request_query(struct s3gw_request *req,
				const char *key, int *len)
{
	struct s3gw_header *hdr;

	list_for_each_entry(hdr, &req->query_list, list) {
		if (!strcmp(hdr->key, key)) {
			const char *value = hdr->value ?
				(const char *)hdr->value : "";
			*len = strlen(value);
			return value;
		}
	}
	*len = 0;
	return NULL;
}
