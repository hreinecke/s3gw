#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static int bucket_ok(char *buf, const char *region)
{
	enum http_status s = HTTP_STATUS_OK;
	size_t off = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;
	ret = sprintf(buf + off, "x-amz-bucket-region: %s\r\n", region);
	if (ret < 0)
		return -errno;
	off += ret;
	return off;
}

static char head_object[]=
	"Last-Modified: 2025-11-13T10:21:41+00:00\r\n"
	"Content-Length: 1805\r\n"
	"ETag: \"4b5ce72db65198d0560a7bbb84298133\"\r\n"
	"Content-Type: application/binary\r\n"
	"Connection: close\r\n"
	"Server: s3gw\r\n";

static int object_ok(char *buf)
{
	enum http_status s = HTTP_STATUS_OK;
	size_t off = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;
	ret = sprintf(buf + off, "%s", head_object);
	if (ret < 0)
		return -errno;
	off += ret;
	return off;
}

static int put_status(char *buf, enum http_status s, const char *data)
{
	size_t off = 0, len = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;
	if (!data)
		return off;

	len = strlen(data);
	ret = sprintf(buf + off, "Content-Length: %ld\r\n\r\n", len);
	if (ret < 0)
		return -errno;
	off += ret;
	if (data) {
		ret = sprintf(buf + off, "%s", data);
		if (ret < 0)
			return -errno;
		off += ret;
	}
	return off;
}

static char list_all_buckets[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	"<ListAllMyBucketsResult>\r\n"
	"  <Buckets>\r\n"
	"    <Bucket>\r\n"
	"      <CreationDate>2025-11-13T10:21:41+00:00</CreationDate>\r\n"
	"      <Name>s3gw-demo-bucket</Name>\r\n"
	"    </Bucket>\r\n"
	"  </Buckets>\r\n"
	"  <Owner>\r\n"
	"    <DisplayName>Account+Name</DisplayName>\r\n"
	"    <ID>AIDACKEVSQ6C2EXAMPLE</ID>\r\n"
	"  </Owner>\r\n"
	"</ListAllMyBucketsResult>\r\n";

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

int format_response(struct s3gw_request *req, char *buf)
{
	int ret;

	switch (req->op) {
	case S3_OP_ListBuckets:
		ret = put_status(buf, HTTP_STATUS_OK, list_all_buckets);
		break;
	case S3_OP_HeadBucket:
		ret = bucket_ok(buf, "eu-west-2");
		break;
	case S3_OP_ListObjects:
		ret = put_status(buf, HTTP_STATUS_OK, list_all_objects);
		break;
	case S3_OP_HeadObject:
		ret = object_ok(buf);
		break;
	default:
		ret = put_status(buf, HTTP_STATUS_NOT_FOUND, NULL);
		break;
	}
	return ret;
}
