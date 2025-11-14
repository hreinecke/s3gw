#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static char head_object[]=
	"Last-Modified: 2025-11-13T10:21:41+00:00\r\n"
	"Content-Length: 1805\r\n"
	"ETag: \"4b5ce72db65198d0560a7bbb84298133\"\r\n"
	"Content-Type: application/binary\r\n"
	"Connection: close\r\n"
	"Server: s3gw\r\n";

static char *object_ok(int *outlen)
{
	enum http_status s = HTTP_STATUS_OK;
	char *buf;
	int ret;

	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n%s",
		       s, http_status_str(s), head_object);
	if (ret < 0) {
		*outlen = -errno;
		return NULL;
	}
	*outlen = ret;
	return buf;
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

static char list_all_objects[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	"<ListBucketResult>\r\n"
	"  <Name>s3gw-demo-bucket</Name>\r\n"
	"  <Prefix/>\r\n"
	"  <Marker/>\r\n"
	"  <MaxKeys>100</MaxKeys>\r\n"
	"  <IsTruncated>false</IsTruncated>\r\n"
	"  <Contents>\r\n"
	"    <Key>server-cert.pem</Key>\r\n"
	"    <LastModified>2025-11-13T10:21:41+00:00</LastModified>\r\n"
	"    <ETag>\"4b5ce72db65198d0560a7bbb84298133\"</ETag>\r\n"
	"    <Size>1805</Size>\r\n"
	"    <StorageClass>STANDARD</StorageClass>\r\n"
	"    <Owner>\r\n"
	"      <DisplayName>Account+Name</DisplayName>\r\n"
	"      <ID>AIDACKEVSQ6C2EXAMPLE</ID>\r\n"
	"    </Owner>\r\n"
	"  </Contents>\r\n"
	"</ListBucketResult>\r\n";

char *format_response(struct s3gw_request *req, int *outlen)
{
	char *buf;

	switch (req->op) {
	case S3_OP_ListBuckets:
		buf = list_buckets(req, outlen);
		break;
	case S3_OP_HeadBucket:
		buf = check_bucket(req, outlen);
		break;
	case S3_OP_ListObjects:
		buf = put_status(HTTP_STATUS_OK, list_all_objects, outlen);
		break;
	case S3_OP_HeadObject:
		buf = object_ok(outlen);
		break;
	default:
		buf = put_status(HTTP_STATUS_NOT_FOUND, NULL, outlen);
		break;
	}
	return buf;
}
