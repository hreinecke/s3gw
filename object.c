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

char *list_objects(struct s3gw_request *req, int *outlen)
{
	struct linked_list top;
	struct s3gw_object *o, *t;
	struct s3gw_header *q;
	xmlDoc *doc;
	xmlNsPtr ns;
	xmlNode *root_node, *c_node, *o_node;
	char *buf, *prefix;
	xmlChar *xml;
	char *line;
	enum http_status s = HTTP_STATUS_OK;
	int ret, cur = 0, num, line_len, xml_len;
	unsigned long max_keys = 0;

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
	     
	INIT_LINKED_LIST(&top);
	num = find_objects(req, &top, prefix);
	if (num < 0) {
		if (num != -EPERM) {
			ret = num;
			s = HTTP_STATUS_NOT_FOUND;
			goto out_error;
		}
		num = 0;
	}
	printf("found %d objects\n", num);
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

	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "Content-Length: %d\r\n\r\n%s",
		       s, http_status_str(s), xml_len, xml);
	if (ret < 0) {
		free(xml);
		return NULL;
	}
	*outlen = ret;
	free(xml);
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
