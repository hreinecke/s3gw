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

static const char default_secret_key[] =
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY";

static const char default_access_key[] =
	"AKIAIOSFODNN7EXAMPLE";

static const char default_token[] =
	"AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW"
	"LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd"
	"QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU"
	"9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz"
	"+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==";

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

	if (data)
		len = strlen(data);
	ret = sprintf(buf + off, "Content-Length: %ld\r\n\r\n", len);
	if (ret < 0)
		return -errno;
	off += ret;
	if (data) {
		ret = sprintf(buf + off, "%s\r\n\r\n", data);
		if (ret < 0)
			return -errno;
		off += ret;
	}
	return off;
}

int format_response(struct s3gw_request *req, char *buf)
{
	char location[] = "eu-west-1";
	char bucket[] = "arn:2e28574b-3276-44a1-8e00-b3de937c07c0";
	int ret;
	size_t off = 0;
	char data[4096], tstamp[256];
	time_t cur_time = time(NULL);
	struct tm *cur_tm = gmtime(&cur_time);

	switch (req->op) {
	case IMDS_GET_METADATA_VERSIONS:
		ret = put_ok(buf, s3gw_token);
		break;
	case IMDS_GET_CREDENTIALS:
		ret = put_ok(buf, "s3gw\r\n");
		break;
	case IMDS_GET_ROLE_CREDENTIALS:
		strftime(tstamp, 256, "%Y-%m-%dT%TZ", cur_tm);
		ret = sprintf(data,"{\n");
		off += ret;
		ret = sprintf(data + off, "\"Code\" : \"Success\"\n");
		off += ret;
		ret = sprintf(data + off, "\"LastUpdated\" : \"%s\"\n", tstamp);
		off += ret;
		ret = sprintf(data + off, "\"Type\" : \"AWS-HMAC\"\n");
		off += ret;
		ret = sprintf(data + off,
			      "\"AccessKeyId\" : \"%s\"\n",
			      default_access_key);
		off += ret;
		ret = sprintf(data + off,
			      "\"SecretAccessKey\" : \"%s\"\n",
			      default_secret_key);
		off += ret;
		ret = sprintf(data + off,
			      "\"Token\" : \"%s\"\n",
			      default_token);
		off += ret;
		cur_time += 3600;
		cur_tm = gmtime(&cur_time);
		strftime(tstamp, 256, "%Y-%m-%dT%TZ", cur_tm);
		ret = sprintf(data + off,
			      "\"Expiration\" : \"%s\"\n}\n", tstamp);
		off += ret;
		ret = put_ok(buf, data);
		break;
	default:
		ret = bucket_ok(buf, location, bucket);
		break;
	}
	return ret;
}
