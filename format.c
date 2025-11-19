#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

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

char *format_response(struct s3gw_request *req, int *outlen)
{
	char *buf = NULL;

	if (check_authorization(req) < 0) {
		buf = put_status(HTTP_STATUS_FORBIDDEN, NULL, outlen);
		return buf;
	}

	switch (req->op) {
	case S3_OP_CreateBucket:
		buf = create_bucket(req, outlen);
		break;
	case S3_OP_DeleteBucket:
		buf = delete_bucket(req, outlen);
		break;
	case S3_OP_ListBuckets:
		buf = list_buckets(req, outlen);
		break;
	case S3_OP_HeadBucket:
		buf = check_bucket(req, outlen);
		break;
	case S3_OP_PutObject:
		buf = create_object(req, outlen);
		break;
	case S3_OP_DeleteObject:
		buf = delete_object(req, outlen);
		break;
	case S3_OP_DeleteObjects:
		buf = delete_objects(req, outlen);
		break;
	case S3_OP_ListObjects:
		buf = list_objects(req, outlen);
		break;
	case S3_OP_GetObject:
		buf = get_object(req, outlen);
		break;
	case S3_OP_HeadObject:
		buf = get_object(req, outlen);
		break;
	default:
		fprintf(stderr, "Invalid op %d\n", req->op);
		req->status = HTTP_STATUS_NOT_IMPLEMENTED;
		break;
	}
	if (!buf)
		buf = put_status(req->status, NULL, outlen);
	return buf;
}
