#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>

#include "s3_api.h"
#include "s3gw.h"

static int check_bucket(char *dirname, char *name, struct linked_list *head)
{
	struct s3gw_bucket *b;
	char *pathname;
	struct stat st;
	int ret;

	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return -errno;

	ret = lstat(pathname, &st);
	if (ret < 0) {
		fprintf(stderr, "%s: bucket %s error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out;
	}
	b = malloc(sizeof(*b));
	if (!b) {
		ret = -ENOMEM;
		goto out;
	}
	b->name = strdup(name);
	b->ctime = st.st_ctime;
	list_add(&b->list, head);
	printf("Found bucket '%s'\n", b->name);
out:		
	free(pathname);
	return ret;
}

static int find_buckets(struct s3gw_request *req, struct linked_list *head)
{
	char *dirname;
	int ret, num = 0;
	struct dirent *se;
	DIR *sd;

	ret = asprintf(&dirname, "%s/%s",
		       req->ctx->base_dir,
		       req->ctx->owner);
	if (ret < 0)
		return -ENOMEM;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return 0;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		printf("checking %s type %d\n",
		       se->d_name, se->d_type);
		if (se->d_type == DT_DIR) {
			ret = check_bucket(dirname, se->d_name, head);
			if (ret < 0)
				break;
			num++;
		}
	}	
	closedir(sd);
	free(dirname);

	return num;
}

static char list_buckets_preamble[] =
	"<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
	"<ListAllMyBucketsResult>\r\n"
	"<Buckets>\r\n";
static char list_buckets_template[] =
	"<Bucket>\r\n"
	"<CreationDate>%s</CreationDate>\r\n"
	"<Name>%s</Name>\r\n"
	"</Bucket>\r\n";
static char list_buckets_postamble[] =
	"</Buckets>\r\n"
	"<Owner>\r\n<ID>%s</ID>\r\n</Owner>\r\n"
	"</ListAllMyBucketsResult>\r\n";

char *list_buckets(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	struct s3gw_bucket *b, *t;
	char *buf;
	size_t off = 0, total = 4096, hlen;
	enum http_status s = HTTP_STATUS_OK;
	int ret;

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
	ret = find_buckets(req, &top);
	if (ret < 0) {
		s = HTTP_STATUS_NOT_FOUND;
		goto out_error;
	}
	printf("found %d buckets\n", ret);
	ret = snprintf(buf + off, total - off, "%s", list_buckets_preamble);
	if (ret < 0) {
		s = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto out_error;
	}
	off += ret;
	list_for_each_entry_safe(b, t, &top, list) {
		char time_str[64];
		struct tm *tm;

		list_del(&b->list);
		if (off >= total) {
			fprintf(stderr, "skip bucket '%s'\n",
				b->name);
			free(b->name);
			free(b);
			continue;
		}
		tm = localtime(&b->ctime);
		strftime(time_str, 64, "%FT%T%z", tm);
		ret = snprintf(buf + off, total - off,
			       list_buckets_template,
			       time_str, b->name);
		if (ret < 0)
			fprintf(stderr, "failed to format time\n");
		else
			off += ret;
		free(b->name);
		free(b);
	}
	if (off >= total) {
		s = HTTP_STATUS_PAYLOAD_TOO_LARGE;
		goto out_error;
	}
	ret = snprintf(buf + off, total - off,
		       list_buckets_postamble, req->ctx->owner);
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
