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
	"http://s3.amazonaws.com/doc/2006-03-01/";

void create_object(struct s3gw_request *req, struct s3gw_response *resp)
{
	char *etag;
	size_t etag_len;
	int ret;

	if (!req->payload_len && !resp->obj) {
		resp->status = HTTP_STATUS_BAD_REQUEST;
		return;
	}
	if (!resp->obj) {
		resp->obj = malloc(sizeof(*resp->obj));
		if (!resp->obj) {
			resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			return;
		}
		memset(resp->obj, 0, sizeof(*resp->obj));
		ret = dir_create_object(req, resp->obj, req->key);
		resp->status = HTTP_STATUS_CONTINUE;
	} else {
		ret = dir_fetch_object(req, resp->obj, req->key);
		resp->status = HTTP_STATUS_OK;
	}
	if (ret < 0) {
		switch (ret) {
		case -EEXIST:
			resp->status = HTTP_STATUS_CONFLICT;
			break;
		default:
			resp->status = HTTP_STATUS_BAD_REQUEST;
			break;
		}
		goto out_free_obj;
	}
	if (resp->status == HTTP_STATUS_CONTINUE)
		return;

	etag = bin2hex(resp->obj->etag, 16, &etag_len);
	if (!etag) {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto out_free_obj;
	}
	put_response_header(resp, "ETag", etag);
	free(etag);

out_free_obj:
	clear_object(resp->obj);
	free(resp->obj);
	resp->obj = NULL;
}

void delete_object(struct s3gw_request *req, struct s3gw_response *resp)
{
	int ret;

	ret = dir_delete_object(req, req->bucket, req->key);
	if (ret < 0) {
		switch (ret) {
		case -EEXIST:
			resp->status = HTTP_STATUS_CONFLICT;
			break;
		default:
			resp->status = HTTP_STATUS_BAD_REQUEST;
			break;
		}
		return;
	}
	resp->status = HTTP_STATUS_NO_CONTENT;
	put_response_header(resp, "x-amz-delete-marker", "true");
}

void xml_delete_list(struct s3gw_request *req, xmlNode *root,
		     struct linked_list *head)
{
	xmlNode *del_node, *obj_node, *node;
	struct s3gw_object *obj;
	int ret;

	del_node = find_node(root, (const xmlChar *)"Delete");
	if (!del_node)
		return;

	for(obj_node = del_node; obj_node; obj_node = obj_node->next) {
		if (xmlStrcmp(obj_node->name, (const xmlChar *)"Object"))
			continue;
		obj = malloc(sizeof(*obj));
		if (!obj)
			continue;
		memset(obj, 0, sizeof(*obj));
		node = find_node(obj_node->children, (const xmlChar *)"Key");
		if (!node) {
			free(obj);
			continue;
		}
		list_add(&obj->list, head);
		if (node) {
			ret = dir_fetch_object(req, obj,
					       (const char *)node->content);
			if (ret < 0)
				obj->error = ret;
		}
		node = find_node(obj_node, (const xmlChar *)"ETag");
		if (node) {
			unsigned char *etag;
			size_t etag_len;

			etag = hex2bin((char *)node->content, &etag_len);
			if (memcmp(etag, obj->etag, etag_len)) {
				obj->error = -ENOKEY;
			}
		}
		node = find_node(obj_node, (const xmlChar *)"Size");
		if (node) {
			unsigned long size;
			char *p, *eptr;

			p = (char *)node->content;
			size = strtoul(p, &eptr, 10);
			if (p == eptr)
				size = 0;
			if (size && size != obj->size) {
				obj->error = -E2BIG;
			}
		}
	}
}

void delete_objects(struct s3gw_request *req, struct s3gw_response *resp)
{
	struct linked_list top;
	struct s3gw_object *obj, *tmp;
	xmlDoc *doc;
	xmlNs *ns;
	xmlNode *root, *node;
	int xml_len, ret;

	INIT_LINKED_LIST(&top);
	if (!req->xml) {
		if (!req->payload) {
			resp->status = HTTP_STATUS_BAD_REQUEST;
			return;
		}
		req->xml = xmlParseMemory((char *)req->payload,
					  req->payload_len);
		if (!req->xml) {
			resp->status = HTTP_STATUS_BAD_REQUEST;
			return;
		}
	}
	root = xmlDocGetRootElement(req->xml);
	xml_delete_list(req, root, &top);
	xmlFreeDoc(req->xml);
	req->xml = NULL;

	doc = xmlNewDoc((const xmlChar *)"1.0");
	root = xmlNewDocNode(doc, NULL,
			     (const xmlChar *)"DeleteResult", NULL);
	ns = xmlNewNs(root, xmlns, NULL);
	xmlSetNs(root, ns);
	xmlDocSetRootElement(doc, root);
	list_for_each_entry_safe(obj, tmp, &top, list) {
		if (obj->error) {
			printf("%s: Skip object %s, error %d\n", __func__,
			       obj->key, obj->error);
			continue;
		}
		ret = dir_delete_object(req, req->bucket, obj->key);
		if (ret < 0) {
			printf("%s: failed to delete object\n", obj->key);
			obj->error = ret;
			continue;
		}
		list_del_init(&obj->list);
		node = xmlNewChild(root, NULL,
				   (const xmlChar *)"Deleted", NULL);
		xmlNewChild(node, NULL,
			    (const xmlChar *)"Key", (xmlChar *)obj->key);
		clear_object(obj);
		free(obj);
	}
	list_for_each_entry_safe(obj, tmp, &top, list) {
		xmlChar *code, *desc;

		list_del_init(&obj->list);
		node = xmlNewChild(root, NULL,
				   (const xmlChar *)"Error", NULL);
		xmlNewChild(node, NULL,
			    (const xmlChar *)"Key", (xmlChar *)obj->key);
		switch (obj->error) {
		case -EPERM:
			code = (xmlChar *)"AccessDenied";
			desc = (xmlChar *)"Access Denied";
			break;
		case -ENOENT:
			code = (xmlChar *)"NoSuchKey";
			desc = (xmlChar *)"The specified key does not exist";
			break;
		default:
			code = (xmlChar *)"InternalError";
			desc = (xmlChar *)"We encountered an internal error. Please try again.";
			break;
		}
		xmlNewChild(node, NULL, code, desc);
		clear_object(obj);
		free(obj);
	}
	xmlDocDumpMemory(doc, &resp->payload, &xml_len);
	resp->payload_len = xml_len;
	xmlFreeDoc(doc);
	resp->status = HTTP_STATUS_OK;
}

void list_objects(struct s3gw_request *req, struct s3gw_response *resp)
{
	struct linked_list objects, buckets;
	struct s3gw_object *o, *t;
	struct s3gw_header *q;
	xmlDoc *doc;
	xmlNsPtr ns;
	xmlNode *root_node, *c_node, *o_node;
	char *prefix = NULL, *delim = NULL, *marker = NULL;
	char line[64];
	int cur = 0, num_objs, num_buckets = 0, line_len, xml_len;
	unsigned long max_keys = 0;
	struct tm *tm;

	list_for_each_entry(q, &req->query_list, list) {
		if (!strcmp(q->key, "max-keys"))
			max_keys = strtoul(q->value, NULL, 10);
		if (!strcmp(q->key, "prefix"))
			prefix = q->value;
		if (!strcmp(q->key, "delimiter"))
			delim = q->value;
		if (!strcmp(q->key, "marker"))
			marker = q->value;
	}

	INIT_LINKED_LIST(&objects);
	num_objs = dir_find_objects(req, &objects, prefix, delim, marker);
	if (num_objs < 0) {
		if (num_objs == -EPERM)
			resp->status = HTTP_STATUS_FORBIDDEN;
		else
			resp->status = HTTP_STATUS_NOT_FOUND;
		return;
	}
	printf("found %d objects\n", num_objs);

	INIT_LINKED_LIST(&buckets);
	if (delim || prefix) {
		num_buckets = dir_find_prefix(req, &buckets,
					      prefix, delim, marker);
		if (num_buckets < 0) {
			if (num_buckets == -EPERM)
				resp->status = HTTP_STATUS_FORBIDDEN;
			else
				resp->status = HTTP_STATUS_NOT_FOUND;
			return;
		}
		printf("found %d buckets\n", num_buckets);
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
	xmlNewChild(root_node, NULL, (const xmlChar *)"Marker",
		    (xmlChar *)marker);
	if (delim)
		xmlNewChild(root_node, NULL, (const xmlChar *)"Delimiter",
			    (xmlChar *)delim);
	if (max_keys) {
		sprintf(line, "%lu", max_keys);
		xmlNewChild(root_node, NULL, (const xmlChar *)"MaxKeys",
			    (xmlChar *)line);
	} else
		xmlNewChild(root_node, NULL, (const xmlChar *)"MaxKeys", NULL);

	if (max_keys > 0 && max_keys < num_objs)
		num_objs = max_keys;
	xmlNewChild(root_node, NULL, (const xmlChar *)"IsTruncated",
		    (const xmlChar *)"false");
	     
	list_for_each_entry_safe(o, t, &objects, list) {
		char *etag;

		list_del(&o->list);
		if (cur > num_objs) {
			goto clear;
		}
		c_node = xmlNewChild(root_node, NULL,
				     (const xmlChar *)"Contents", NULL);
		xmlNewChild(c_node, NULL, (const xmlChar *)"Key",
			    (xmlChar *)o->key);
		tm = localtime(&o->mtime);
		strftime(line, 64, "%FT%T%z", tm);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"LastModified",
			    (xmlChar *)line);
		etag = bin2hex(o->etag, 16, (size_t *)&line_len);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"ETag",
			    (xmlChar *)etag);
		free(etag);
		sprintf(line, "%lu", o->size);
		xmlNewChild(c_node, NULL,
			    (const xmlChar *)"Size",
			    (xmlChar *)line);
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
	if (num_buckets) {
		struct s3gw_bucket *b, *t_b;

		list_for_each_entry_safe(b, t_b, &buckets, list) {
			c_node = xmlNewChild(root_node, NULL,
				     (const xmlChar *)"CommonPrefixes", NULL);
			xmlNewChild(c_node, NULL, (const xmlChar *)"Prefix",
				    (xmlChar *)b->name);
			list_del_init(&b->list);
			free(b->name);
			free(b);
		}
	}
		
	xmlDocDumpMemory(doc, &resp->payload, &xml_len);
	resp->payload_len = xml_len;
	xmlFreeDoc(doc);
	resp->status = HTTP_STATUS_OK;
}

void get_object(struct s3gw_request *req, struct s3gw_response *resp)
{
	struct s3gw_object *obj = NULL;
	char line[64], *range;
	struct tm *tm;
	unsigned long start = 0, end = 0, size = 0;
	int ret, range_len;
	char *etag;
	size_t etag_len;

	obj = malloc(sizeof(*obj));
	if (!obj) {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		return;
	}
	memset(obj, 0, sizeof(*obj));
	ret = dir_fetch_object(req, obj, req->key);
	if (ret < 0) {
		if (ret == -EPERM)
			resp->status = HTTP_STATUS_FORBIDDEN;
		else
			resp->status = HTTP_STATUS_NOT_FOUND;
		goto out_free_obj;
	}
	resp->status = HTTP_STATUS_OK;

	range = fetch_request_header(req, "Range", &range_len);
	if (range) {
		char *s, *e, *eptr;

		if (strncmp(range, "bytes", 5)) {
			fprintf(stderr, "Only byte ranges are supported\n");
			resp->status = HTTP_STATUS_BAD_REQUEST;
			goto out_free_obj;
		}
		s = strdup(range + 6);
		e = strchr(s, '-');
		if (e)
			*e++ = '\0';
		start = strtoul(s, &eptr, 10);
		if (s == eptr) {
			fprintf(stderr, "Invalid range '%s'\n", range);
			resp->status = HTTP_STATUS_BAD_REQUEST;
			goto out_free_obj;
		}
		if (e && strlen(e)) {
			end = strtoul(e, &eptr, 10);
			if (e == eptr) {
				fprintf(stderr, "Invalid range '%s'\n",
					range);
				resp->status = HTTP_STATUS_BAD_REQUEST;
				goto out_free_obj;
			}
			if (end < start) {
				fprintf(stderr, "Invalid range '%s'\n",
					range);
				resp->status = HTTP_STATUS_BAD_REQUEST;
				goto out_free_obj;
			}
			size = start - end;
		}
		free(s);
	}

	tm = localtime(&obj->mtime);
	strftime(line, 64, "%FT%T%z", tm);
	put_response_header(resp, "Last-Modified", line);
	if (obj->etag) {
		etag = bin2hex(obj->etag, 16, &etag_len);
		if (!etag) {
			resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
			goto out_free_obj;
		}
		put_response_header(resp, "ETag", etag);
		free(etag);
	}
	if (req->op == S3_OP_GetObject) {
		if (!end)
			size = obj->size - start;
		else if (end - start < obj->size)
			size = end - start;
		else
			size = obj->size;
		resp->obj = obj;
		resp->payload = resp->obj->map + start;
		resp->payload_len = size;
		obj = NULL;
	} else {
		resp->payload_len = obj->size;
		resp->obj = NULL;
	}
out_free_obj:
	if (obj) {
		clear_object(obj);
		free(obj);
	}
}

void copy_object(struct s3gw_request *req, struct s3gw_response *resp,
		 const char *source)
{
	struct s3gw_object *obj;
	char *bucket, *b, *o, *e, *save;
	char line[64];
	xmlDoc *doc;
	xmlNs *ns;
	xmlNode *root;
	struct tm *tm;
	int ret, xml_len;
	char *etag;
	size_t etag_len;

	obj = malloc(sizeof(*obj));
	if (!obj) {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		return;
	}
	memset(obj, 0, sizeof(*obj));

	bucket = strdup(source);
	b = strtok_r(bucket, "/", &save);
	if (!b) {
		resp->status = HTTP_STATUS_NOT_FOUND;
		free(bucket);
		goto out_free_obj;
	}
	o = strtok_r(NULL, "/", &save);
	if (!o) {
		b = req->bucket;
		o = b;
	}
	e = strtok_r(NULL, "/", &save);
	if (e) {
		resp->status = HTTP_STATUS_NOT_FOUND;
		free(bucket);
		goto out_free_obj;
	}

	ret = dir_splice_objects(req, b, o, req->bucket, req->key);
	if (ret < 0) {
		resp->status = HTTP_STATUS_NOT_FOUND;
		free(bucket);
		goto out_free_obj;
	}
	free(bucket);
	ret = dir_fetch_object(req, obj, req->bucket);
	if (ret < 0) {
		if (ret == -EPERM)
			resp->status = HTTP_STATUS_FORBIDDEN;
		else
			resp->status = HTTP_STATUS_NOT_FOUND;
		goto out_free_obj;
	}
	resp->status = HTTP_STATUS_OK;

	etag = bin2hex(obj->etag, 16, &etag_len);
	if (!etag) {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		goto out_free_obj;
	}

	doc = xmlNewDoc((const xmlChar *)"1.0");
	root = xmlNewDocNode(doc, NULL,
			     (const xmlChar *)"CopyObjectResult", NULL);
	ns = xmlNewNs(root, xmlns, NULL);
	xmlSetNs(root, ns);
	xmlDocSetRootElement(doc, root);
	tm = localtime(&obj->mtime);
	strftime(line, 64, "%FT%T%z", tm);
	xmlNewChild(root, NULL, (const xmlChar *)"LastModified",
		    (xmlChar *)line);
	etag = bin2hex(obj->etag, 16, &etag_len);
	xmlNewChild(root, NULL, (const xmlChar *)"ETag",
		    (xmlChar *)etag);
	free(etag);
	xmlDocDumpMemory(doc, &resp->payload, &xml_len);
	xmlFreeDoc(doc);
	resp->payload_len = xml_len;
out_free_obj:
	clear_object(obj);
	free(obj);
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
