#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

int put_response_header(struct s3gw_response *resp, const char *key,
			char *value)
{
	struct s3gw_header *hdr;

	hdr = malloc(sizeof(*hdr));
	if (!hdr)
		return -ENOMEM;
	memset(hdr, 0, sizeof(*hdr));
	hdr->key = strdup(key);
	if (value)
		hdr->value = strdup(value);
	list_add(&hdr->list, &resp->resp_hdr_list);
	return 0;
}

char *gen_response_header(struct s3gw_response *resp, int *outlen)
{
	struct s3gw_header *hdr;
	char *header;
	size_t len, off;
	int ret;

	len = strlen(http_status_str(resp->status)) + 20;
	list_for_each_entry(hdr, &resp->resp_hdr_list, list) {
		len += strlen(hdr->key);
		if (hdr->value) {
			len += strlen(hdr->value) + 2;
		}
		len += 2;
	}
	header = malloc(len + 1);
	if (!header)
		return NULL;

	memset(header, 0, len + 1);
	ret = sprintf(header, "HTTP/1.1 %d %s\r\n",
		     resp->status, http_status_str(resp->status));
	if (ret < 0) {
		free(header);
		return NULL;
	}
	off = ret;
	list_for_each_entry(hdr, &resp->resp_hdr_list, list) {
		if (hdr->value)
			ret = sprintf(header + off,
				       "%s: %s\r\n",
				       hdr->key, hdr->value);
		else
			ret = sprintf(header + off, "%s\r\n",
				       hdr->key);
		if (ret < 0) {
			free(header);
			return NULL;
		}
		off += ret;
	}
	*outlen = off;
	return header;
}

static char *put_status(enum http_status s, const char *data, int *outlen)
{
	char *buf;
	int ret;

	if (!data) {
		ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n", s,
			       http_status_str(s));
	} else {
		ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
			       "Content-Length: %ld\r\n\r\n%s",
			       s, http_status_str(s), strlen(data),
			       data);
	}
	if (ret > 0)
		*outlen = ret;
	else
		buf = NULL;
	return buf;
}

struct s3gw_op_handler {
	enum s3_api_ops op;
	char *(*func)(struct s3gw_request *req, struct s3gw_response *resp,
			 int *outlen);
};

static struct s3gw_op_handler op_handler_list[] = {
	{ S3_OP_CreateBucket, create_bucket },
	{ S3_OP_DeleteBucket, delete_bucket },
	{ S3_OP_ListBuckets, list_buckets },
	{ S3_OP_HeadBucket, check_bucket },
	{ S3_OP_GetBucketVersioning, bucket_versioning },
	{ S3_OP_PutObject, create_object },
	{ S3_OP_DeleteObject, delete_object },
	{ S3_OP_DeleteObjects, delete_objects },
	{ S3_OP_ListObjects, list_objects },
	{ S3_OP_GetObject, get_object },
	{ S3_OP_HeadObject, get_object },
	{ S3_OP_Unknown, NULL },
};

char *format_response(struct s3gw_request *req, struct s3gw_response *resp,
		      int *outlen)
{
	char *buf = NULL, *source = NULL;
	int len;

	if (check_authorization(req) < 0) {
		buf = put_status(HTTP_STATUS_FORBIDDEN, NULL, outlen);
		return buf;
	}

	if (req->op == S3_OP_PutObject) {
		source = fetch_request_header(req, "x-amz-copy-source", &len);
		if (source && len) {
			req->op = S3_OP_CopyObject;
		}
	}
	if (req->op == S3_OP_ListObjects) {
		const char *query;

		query = fetch_request_query(req, "versioning", &len);
		if (query) {
			req->op = S3_OP_GetBucketVersioning;
		}
	}

	if (req->op == S3_OP_CopyObject) {
		buf = copy_object(req, resp, source, outlen);
	} else {
		struct s3gw_op_handler *op_handler = NULL;
		int i;

		for (i = 0; i < ARRAY_SIZE(op_handler_list); i++) {
			if (op_handler_list[i].op == req->op) {
				op_handler = &op_handler_list[i];
				break;
			}
		}
		if (op_handler && op_handler->func) {
			buf = op_handler->func(req, resp, outlen);
		} else {
			fprintf(stderr, "Invalid op %d\n", req->op);
			resp->status = HTTP_STATUS_NOT_IMPLEMENTED;
		}
	}
	if (!buf)
		buf = put_status(resp->status, NULL, outlen);
	return buf;
}
