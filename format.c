#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static const char s3gw_token[] = "76a46a30-357b-4362-acfb-4d3d2ac6ee2b";

static int bucket_ok(char *buf, const char *loc, const char *arn)
{
	enum http_status s = 200;
	size_t off = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;
	ret = sprintf(buf + off, "Location: %s\r\n", loc);
	if (ret < 0)
		return -errno;
	off += ret;
	ret = sprintf(buf + off, "x-amz-bucket-arn: %s\r\n", arn);
	if (ret < 0)
		return -errno;
	off += ret;
	return off;
}

static int put_ok(char *buf, const char *data)
{
	enum http_status s = HTTP_STATUS_OK;
	size_t off = 0, len = 0;
	int ret;

	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n", s, http_status_str(s));
	if (ret < 0)
		return -errno;
	off += ret;
#if 0
	if (data)
		len = strlen(data);
	ret = sprintf(buf + off, "Content-Length: %ld\r\n\r\n", len);
	if (ret < 0)
		return -errno;
	off += ret;
#endif
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
	"    <Bucket>\r\r"
	"      <BucketArn>arn:2e28574b-3276-44a1-8e00-b3de937c07c0</BucketArn>\r\n"
	"      <BucketRegion>eu-west-2</BucketRegion>\r\n"
	"      <CreationDate>20251113T102141Z</CreationDate>\r\n"
	"      <Name>DefaultBucket</Name>\r\n"
	"    </Bucket>\r\n"
	"  </Buckets>\r\n"
	"  <Owner>\r\n"
	"    <DisplayName>DefaultUser</DisplayName>\r\n"
	"    <ID>aaa</ID>\r\n"
	"  </Owner>\r\n"
	"</ListAllMyBucketsResult>\r\n";

int format_response(struct s3gw_request *req, char *buf)
{
	char location[] = "eu-west-1";
	char bucket[] = "arn:2e28574b-3276-44a1-8e00-b3de937c07c0";
	int ret;

	switch (req->op) {
	case S3_LIST_BUCKETS:
		ret = put_ok(buf, list_all_buckets);
		break;
	case IMDS_GET_METADATA_VERSIONS:
		ret = put_ok(buf, s3gw_token);
		break;
	case IMDS_GET_CREDENTIALS:
		ret = put_ok(buf, "s3gw\r\n");
		break;
	default:
		ret = bucket_ok(buf, location, bucket);
		break;
	}
	return ret;
}
