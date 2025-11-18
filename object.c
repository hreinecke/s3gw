#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "s3_api.h"
#include "s3gw.h"

static char list_objects_preamble[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	"<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\r\n"
	"<Name>%s</Name>\r\n"
	"%s%s%s\r\n"
	"<Marker/>\r\n"
	"<MaxKeys>%lu</MaxKeys>\r\n"
	"<IsTruncated>%s</IsTruncated>\r\n";
static char list_objects_template[] =
	"<Contents>\r\n"
	"<Key>%s</Key>\r\n"
	"<LastModified>%s</LastModified>\r\n"
	"<ETag>\"%02x%02x%02x%02x%02x%02x%02x"
	"%02x%02x%02x%02x%02x%02x%02x%02x%02x\"</ETag>\r\n"
	"<Size>%lu</Size>\r\n"
	"<StorageClass>STANDARD</StorageClass>\r\n"
	"<Owner>\r\n<ID>%s</ID>\r\n</Owner>\r\n"
	"</Contents>\r\n";
static char list_objects_postamble[] =
	"<KeyCount>%d</KeyCount>\r\n"
	"</ListBucketResult>\r\n";

char *list_objects(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	struct s3gw_object *o, *t;
	struct s3gw_header *hdr;
	char *buf, *prefix = NULL;
	size_t off = 0, total = 4096, hlen;
	enum http_status s = HTTP_STATUS_OK;
	int ret, num;
	unsigned long max_keys = 200;

	list_for_each_entry(hdr, &req->query_list, list) {
		if (!strcmp(hdr->key, "max-keys")) {
			max_keys = strtoul(hdr->value, NULL, 10);
		}
		if (!strcmp(hdr->key, "prefix"))
			prefix = hdr->value;
	}
	buf = malloc(total);
	if (!buf)
		return NULL;
	ret = snprintf(buf, total, "HTTP/1.1 %d %s\r\n"
		       "Content-Length:     \r\n\r\n",
		       s, http_status_str(s));
	if (ret < 0) {
		free(buf);
		return NULL;
	}
	off += ret;
	/* Save the header length */
	hlen = off;

	INIT_LINKED_LIST(&top);
	num = find_objects(req, &top, prefix);
	if (num < 0) {
		if (num != -EPERM) {
			ret = num;
			s = HTTP_STATUS_NOT_FOUND;
			goto out_error;
		}
		num = 0;
		ret = 0;
	}
	printf("found %d objects\n", num);
	ret = snprintf(buf + off, total - off, list_objects_preamble,
		       req->bucket, prefix ? "<Prefix>" : "",
		       prefix ? prefix : "<Prefix/>",
		       prefix ? "</Prefix>" : "",
		       max_keys, "false");
	if (ret < 0) {
		s = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto out_error;
	}
	off += ret;
	list_for_each_entry_safe(o, t, &top, list) {
		char time_str[64];
		struct tm *tm;

		list_del(&o->list);
		if (off >= total) {
			fprintf(stderr, "skip object '%s'\n",
				o->key);
			clear_object(o);
			free(o);
			continue;
		}
		tm = localtime(&o->mtime);
		strftime(time_str, 64, "%FT%T%z", tm);
		ret = snprintf(buf + off, total - off,
			       list_objects_template,
			       o->key, time_str,
			       o->etag[0], o->etag[1], o->etag[2], o->etag[3],
			       o->etag[4], o->etag[5], o->etag[6], o->etag[7],
			       o->etag[8], o->etag[9], o->etag[10], o->etag[11],
			       o->etag[12], o->etag[13], o->etag[14],
			       o->etag[15], o->size, req->owner);
		if (ret < 0)
			fprintf(stderr, "failed to format time\n");
		else
			off += ret;
		clear_object(o);
		free(o);
	}
	if (off >= total) {
		s = HTTP_STATUS_PAYLOAD_TOO_LARGE;
		goto out_error;
	}
	ret = snprintf(buf + off, total - off,
		       list_objects_postamble, num);
	if (ret < 0) {
		s = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto out_error;
	}
	off += ret;
	/* Fixup content length */
	ret = snprintf(buf + hlen - 8, 5, "%4lu", off - hlen);
	buf[hlen - 8 + ret] = '\r';
	*outlen = off;
	return buf;

out_error:
	memset(buf, 0, off);
	ret = sprintf(buf, "HTTP/1.1 %d %s\r\n",
		      s, http_status_str(s));
	*outlen = strlen(buf);
	return buf;
}

static char object_template[]=
	"HTTP/1.1 %d %s\r\n"
	"Last-Modified: %s\r\n"
	"Content-Length: %lu\r\n"
	"ETag: %02x%02x%02x%02x%02x%02x%02x"
	"%02x%02x%02x%02x%02x%02x%02x%02x%02x\r\n"
	"Content-Type: application/binary\r\n"
	"Connection: close\r\n"
	"Server: s3gw\r\n";

char *check_object(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	struct s3gw_object *o, *t;
	enum http_status s = HTTP_STATUS_OK;
	char time_str[64];
	struct tm *tm;
	char *buf;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = find_objects(req, &top, NULL);
	if (ret < 0) {
		if (ret == -EPERM)
			s = HTTP_STATUS_FORBIDDEN;
		else
			s = HTTP_STATUS_NOT_FOUND;
		goto out_error;
	}
	list_for_each_entry_safe(o, t, &top, list) {
		list_del(&o->list);
		tm = localtime(&o->mtime);
		strftime(time_str, 64, "%FT%T%z", tm);
		ret = asprintf(&buf, object_template,
			       s, http_status_str(s),
			       time_str, o->size,
			       o->etag[0], o->etag[1], o->etag[2], o->etag[3],
			       o->etag[4], o->etag[5], o->etag[6], o->etag[7],
			       o->etag[8], o->etag[9], o->etag[10], o->etag[11],
			       o->etag[12], o->etag[13], o->etag[14],
			       o->etag[15]);
		if (ret < 0) {
			s = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			goto out_error;
		}
		*outlen = ret;
		break;
	}
	return buf;

out_error:
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n",
		       s, http_status_str(s));
	if (ret > 0)
		*outlen = ret;
	else
		buf = NULL;
	return buf;
}
