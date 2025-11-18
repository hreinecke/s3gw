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

char *create_bucket(struct s3gw_request *req, int *outlen)
{
	enum http_status s = HTTP_STATUS_OK;
	char *buf;
	int ret;

	/* XXX: Need to check location constraint here */
	ret = dir_create_bucket(req);
	if (ret < 0) {
		s = HTTP_STATUS_BAD_REQUEST;
		if (ret == -EEXIST) {
			s = HTTP_STATUS_CONFLICT;
		}
		goto out_error;
	}
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "x-amz-bucket-region: %s\r\n"
		       "Location: /%s\r\n"
		       "Content-Length: 0\r\n"
		       "Connection: close\r\n",
		       s, http_status_str(s),
		       req->region, req->bucket);
	if (ret < 0)
		buf = NULL;
	else
		*outlen = ret;
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

char *delete_bucket(struct s3gw_request *req, int *outlen)
{
	enum http_status s = HTTP_STATUS_NO_CONTENT;
	char *buf;
	time_t now = time(NULL);
	struct tm *tm;
	char time_str[64];
	int ret;

	ret = dir_delete_bucket(req);
	if (ret < 0) {
		switch (ret) {
		case -EEXIST:
			s = HTTP_STATUS_CONFLICT;
			break;
		case -ENOENT:
			s = HTTP_STATUS_NOT_FOUND;
			break;
		default:
			s = HTTP_STATUS_BAD_REQUEST;
			break;
		}
		goto out_error;
	}
	tm = localtime(&now);
	strftime(time_str, 64, "%c", tm);
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "Date: %s\r\n"
		       "Connection: close\r\n",
		       s, http_status_str(s), time_str);
	if (ret < 0)
		buf = NULL;
	else
		*outlen = ret;
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

char *list_buckets(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	struct s3gw_bucket *b, *t;
	xmlDoc *doc;
	xmlNode *root_node, *buckets_node, *b_node, *owner_node;
	unsigned char *xml;
	int xml_len;
	char *hdr, *buf;
	size_t len;
	enum http_status s = HTTP_STATUS_OK;
	char time_str[64];
	struct tm *tm;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = dir_find_buckets(req, &top);
	if (ret < 0 && ret != -EPERM) {
		s = HTTP_STATUS_NOT_FOUND;
		goto out_error;
	}
	printf("found %d buckets\n", ret);

	/*
	 * Response format:
	 * <?xml version="1.0"?>
	 * <ListAllMyBucketsResult>
	 * <Buckets>
	 * <Bucket>
	 * <CreationDate>date</CreationDate>
	 * <Name>name</Name>
	 * </Bucket>
	 * ...
	 * </Buckets>
	 * <Owner><ID>owner</ID></Owner>
	 * </ListAllMyBucketsResult>
	 */
	doc = xmlNewDoc((const xmlChar *)"1.0");
	root_node = xmlNewDocNode(doc, NULL,
				  (const xmlChar *)"ListAllMyBucketsResult",
				  NULL);
	xmlDocSetRootElement(doc, root_node);

	buckets_node = xmlNewChild(root_node, NULL,
				   (const xmlChar *)"Buckets", NULL);
	list_for_each_entry_safe(b, t, &top, list) {
		list_del_init(&b->list);
		b_node = xmlNewChild(buckets_node, NULL,
				     (const xmlChar *)"Bucket", NULL);
		tm = localtime(&b->ctime);
		strftime(time_str, 64, "%FT%T%z", tm);
		xmlNewChild(b_node, NULL,
			    (const xmlChar *)"CreationDate",
			    (xmlChar *)time_str);
		xmlNewChild(b_node, NULL,
			    (const xmlChar *)"Name", (xmlChar *)b->name);
	}
	owner_node = xmlNewChild(root_node, NULL,
				 (const xmlChar *)"Owner", NULL);
	xmlNewChild(owner_node, NULL, (const xmlChar *)"ID",
		    (xmlChar *)req->owner);

	xmlDocDumpMemory(doc, &xml, &xml_len);
	xmlFreeDoc(doc);

	ret = asprintf(&hdr, "HTTP/1.1 %d %s\r\n"
		       "Content-Length: %d\r\n",
		       s, http_status_str(s), xml_len);
	if (ret < 0) {
		free(xml);
		return NULL;
	}
	len = ret + xml_len + 3;
	buf = malloc(len);
	if (!buf) {
		free(xml);
		free(hdr);
		return NULL;
	}

	ret = sprintf(buf, "%s\r\n%s", hdr, xml);
	if (ret > 0)
		*outlen = ret;
	else {
		free(buf);
		buf = NULL;
	}
	free(xml);
	free(hdr);
	return buf;

out_error:
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n",
		       s, http_status_str(s));
	if (ret > 0) {
		*outlen = ret;
	} else {
		buf = NULL;
	}
	return buf;
}

char *check_bucket(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	enum http_status s = HTTP_STATUS_OK;
	char *buf;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = dir_find_buckets(req, &top);
	if (ret < 0) {
		if (ret == -EPERM)
			s = HTTP_STATUS_FORBIDDEN;
		else
			s = HTTP_STATUS_NOT_FOUND;
		goto out_error;
	}
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "x-amz-bucket-region: %s\r\n",
		       s, http_status_str(s), req->region);
	if (ret < 0)
		buf = NULL;
	else
		*outlen = ret;
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
