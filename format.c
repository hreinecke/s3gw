#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <errno.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static int check_authorization(struct s3gw_request *req)
{
	struct s3gw_header *hdr;
	const char auth_str[] = "AWS4-HMAC-SHA256";
	char *auth, *p, *save;
	struct s3gw_header *auth_hdr;

	list_for_each_entry(hdr, &req->hdr_list, list) {
		if (!strcmp("Authorization", hdr->key)) {
			auth = strdup(hdr->value);
			break;
		}
	}
	if (!auth)
		return -EPERM;
	p = strtok_r(auth, " ", &save);
	if (!p)
		return -EINVAL;
	if (strcmp(p, auth_str)) {
		fprintf(stderr, "Unhandled authentication method '%s'\n", p);
		return -EINVAL;
	}
	while ((p = strtok_r(NULL, ", ", &save)) != NULL) {
		char *key, *value = NULL;

		auth_hdr = malloc(sizeof(*auth_hdr));
		if (!auth_hdr) {
			free(auth);
			return -ENOMEM;
		}
		memset(auth_hdr, 0, sizeof(*auth_hdr));
		key = p;
		value = strchr(key, '=');
		if (value) {
			*value = '\0';
			value++;
		}
		auth_hdr->key = strdup(key);
		if (!auth_hdr->key) {
			free(auth);
			return -ENOMEM;
		}
		auth_hdr->value = strdup(value);
		if (!auth_hdr->value) {
			free(auth_hdr->key);
			free(auth);
			return -ENOMEM;
		}
		printf("adding auth '%s': %s\n",
		       auth_hdr->key, auth_hdr->value);
		list_add(&auth_hdr->list, &req->auth_list);
	}
	free(auth);
	return 0;
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

char *format_response(struct s3gw_request *req, int *outlen)
{
	char *buf;

	if (check_authorization(req) < 0) {
		buf = put_status(HTTP_STATUS_FORBIDDEN, NULL, outlen);
		return buf;
	}

	switch (req->op) {
	case S3_OP_ListBuckets:
		buf = list_buckets(req, outlen);
		break;
	case S3_OP_HeadBucket:
		buf = check_bucket(req, outlen);
		break;
	case S3_OP_ListObjects:
		buf = list_objects(req, outlen);
		break;
	case S3_OP_HeadObject:
		buf = check_object(req, outlen);
		break;
	default:
		buf = put_status(HTTP_STATUS_NOT_FOUND, NULL, outlen);
		break;
	}
	return buf;
}
