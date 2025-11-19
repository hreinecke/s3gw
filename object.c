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

static xmlChar xmlns[] =
	"xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"";

char *create_object(struct s3gw_request *req, int *outlen)
{
	struct s3gw_object obj;
	int ret;

	memset(&obj, 0, sizeof(obj));
	req->status = HTTP_STATUS_OK;
	ret = dir_fetch_object(req, &obj);
	if (ret < 0) {
		switch (ret) {
		case -EEXIST:
			req->status = HTTP_STATUS_CONFLICT;
			break;
		default:
			req->status = HTTP_STATUS_BAD_REQUEST;
			break;
		}
	}
	clear_object(&obj);
	return NULL;
}

char *delete_object(struct s3gw_request *req, int *outlen)
{
	int ret;

	req->status = HTTP_STATUS_NO_CONTENT;
	ret = dir_delete_object(req);
	if (ret < 0) {
		switch (ret) {
		case -EEXIST:
			req->status = HTTP_STATUS_CONFLICT;
			break;
		default:
			req->status = HTTP_STATUS_BAD_REQUEST;
			break;
		}
	}
	return NULL;
}

char *list_objects(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	struct s3gw_object *o, *t;
	struct s3gw_header *q;
	xmlDoc *doc;
	xmlNsPtr ns;
	xmlNode *root_node, *c_node, *o_node;
	char *buf, *prefix = NULL;
	xmlChar *xml;
	char *line;
	int ret, cur = 0, num, line_len, xml_len;
	unsigned long max_keys = 0;

	INIT_LINKED_LIST(&top);
	num = dir_find_objects(req, &top, prefix);
	if (num < 0) {
		if (num == -EPERM)
			req->status = HTTP_STATUS_FORBIDDEN;
		else
			req->status = HTTP_STATUS_NOT_FOUND;
		return NULL;
	}
	printf("found %d objects\n", num);

	list_for_each_entry(q, &req->query_list, list) {
		if (!strcmp(q->key, "max-keys")) {
			max_keys = strtoul(q->value, NULL, 10);
		}
		if (!strcmp(q->key, "prefix"))
			prefix = q->value;
	}
	doc = xmlNewDoc((const xmlChar *)"1.0");
	root_node = xmlNewDocNode(doc, NULL,
				  (const xmlChar *)"ListBucketResult", NULL);
	ns = xmlNewNs(root_node, xmlns, NULL);
	xmlSetNs(root_node, ns);
	xmlDocSetRootElement(doc, root_node);
	xmlNewChild(root_node, NULL, (const xmlChar *)"Name",
		    (xmlChar *)req->bucket);
	xmlNewChild(root_node, NULL, (const xmlChar *)"Prefix",
		    (xmlChar *)prefix);
	xmlNewChild(root_node, NULL, (const xmlChar *)"Marker", NULL);
	if (max_keys)
		asprintf(&line, "%lu", max_keys);
	else
		line = NULL;
	xmlNewChild(root_node, NULL, (const xmlChar *)"MaxKeys",
		    (xmlChar *)line);
	free(line);
	xmlNewChild(root_node, NULL, (const xmlChar *)"IsTruncated",
		    (const xmlChar *)"false");
	     
	list_for_each_entry_safe(o, t, &top, list) {
		char time_str[64];
		struct tm *tm;

		list_del(&o->list);
		if (max_keys && cur > max_keys) {
			goto clear;
		}
		c_node = xmlNewChild(root_node, NULL,
				     (const xmlChar *)"Contents", NULL);
		xmlNewChild(c_node, NULL, (const xmlChar *)"Key",
			    (xmlChar *)o->key);
		tm = localtime(&o->mtime);
		strftime(time_str, 64, "%FT%T%z", tm);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"LastModified",
			    (xmlChar *)time_str);
		line = bin2hex(o->etag, 16, (size_t *)&line_len);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"ETag",
			    (xmlChar *)line);
		free(line);
		line_len = asprintf(&line, "%lu", o->size);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"Size",
			    (xmlChar *)line);
		free(line);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"StorageClass",
			    (xmlChar *)"STANDARD");
		o_node = xmlNewChild(c_node, NULL,
			    (const xmlChar *)"Owner", NULL);
		xmlNewChild(o_node, NULL, (const xmlChar *)"ID",
			    (xmlChar *)req->owner);
	clear:
		clear_object(o);
		free(o);
		cur++;
	}
	asprintf(&line, "%u", num);
	xmlNewChild(root_node, NULL, (const xmlChar *)"KeyCount",
		    (xmlChar *)line);
	free(line);
	xmlDocDumpMemory(doc, &xml, &xml_len);
	xmlFreeDoc(doc);
	req->status = HTTP_STATUS_OK;

	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "Content-Length: %d\r\n\r\n%s",
		       req->status, http_status_str(req->status),
		       xml_len, xml);
	if (ret < 0) {
		free(xml);
		return NULL;
	}
	*outlen = ret;
	free(xml);
	return buf;
}

static char object_template[]=
	"HTTP/1.1 %d %s\r\n"
	"Date: %s\r\n"
	"Last-Modified: %s\r\n"
	"Content-Length: %lu\r\n"
	"ETag: %s\r\n"
	"Content-Type: application/binary\r\n"
	"Connection: close\r\n"
	"Server: s3gw\r\n";

char *get_object(struct s3gw_request *req, int *outlen)
{
	struct s3gw_object *obj;
	char cur_time_str[64], mod_time_str[64];
	time_t now = time(NULL);
	struct tm *tm;
	char *buf;
	int ret;
	char *etag;
	size_t etag_len;

	obj = malloc(sizeof(*obj));
	if (!obj) {
		req->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		return NULL;
	}
	ret = dir_fetch_object(req, obj);
	if (ret < 0) {
		if (ret == -EPERM)
			req->status = HTTP_STATUS_FORBIDDEN;
		else
			req->status = HTTP_STATUS_NOT_FOUND;
		goto out_free_obj;
	}
	req->status = HTTP_STATUS_OK;

	tm = localtime(&obj->mtime);
	strftime(mod_time_str, 64, "%FT%T%z", tm);
	tm = localtime(&now);
	strftime(cur_time_str, 64, "%FT%T%z", tm);
	etag = bin2hex(obj->etag, 16, &etag_len);
	if (!etag) {
		req->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto out_free_obj;
	}
	ret = asprintf(&buf, object_template,
		       req->status, http_status_str(req->status),
		       cur_time_str, mod_time_str, obj->size, etag);
	if (ret > 0) {
		if (req->op == S3_OP_GetObject) {
			req->obj = obj;
			obj = NULL;
		}
		*outlen = ret;
	} else {
		req->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		buf = NULL;
	}
	free(etag);
out_free_obj:
	if (obj) {
		clear_object(obj);
		free(obj);
	}
	return buf;
}

void reset_object(struct s3gw_object *obj)
{
	memset(obj, 0, sizeof(*obj));
	INIT_LINKED_LIST(&obj->list);
}

void clear_object(struct s3gw_object *obj)
{
	if (obj->map) {
		munmap(obj->map, obj->size);
		obj->map =  NULL;
		obj->size = 0;
	}

	if (obj->key) {
		free(obj->key);
		obj->key = NULL;
	}
	if (obj->etag) {
		free(obj->etag);
		obj->etag = NULL;
		obj->etag_len = 0;
	}
	obj->bucket = NULL;
}
