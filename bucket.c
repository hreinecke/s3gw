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

xmlNode *find_node(xmlNode *top, const xmlChar *key)
{
	xmlNode *node;

	for (node = top; node; node = node->next) {
		if (node->type == XML_ELEMENT_NODE) {
			if (!xmlStrcmp(node->name, key)) {
				return node->children;
			}
		}
	}
	return NULL;
}

char *create_bucket(struct s3gw_request *req, struct s3gw_response *resp,
		    int *outlen)
{
	char *buf;
	const char *location = NULL;
	int ret;

	if (req->xml) {
		xmlNode *root, *node, *conf, *constraint;

		root = xmlDocGetRootElement(req->xml);
		conf = find_node(root, (const xmlChar *)"CreateBucketConfiguration");
		if (conf) {
			constraint = find_node(conf, (const xmlChar *)"LocationConstraint");
			for (node = constraint; node; node = node->next) {
				if (node->type == XML_TEXT_NODE) {
					location = (const char *)node->content;
				}
			}
		}
	}
	if (location && strcmp(req->region, location)) {
		fprintf(stderr, "Cannot create bucket in location '%s'\n",
			location);
		resp->status = HTTP_STATUS_FORBIDDEN;
		return NULL;
	}
	ret = dir_create_bucket(req, req->bucket);
	if (ret < 0) {
		resp->status = HTTP_STATUS_BAD_REQUEST;
		if (ret == -EEXIST) {
			resp->status = HTTP_STATUS_CONFLICT;
		}
		return NULL;
	}
	resp->status = HTTP_STATUS_OK;
	if (location)
		ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
			       "x-amz-bucket-region: %s\r\n"
			       "Location: /%s\r\n"
			       "Content-Length: 0\r\n"
			       "Connection: close\r\n",
			       resp->status, http_status_str(resp->status),
			       req->region, req->bucket);
	else
		ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
			       "Location: /%s\r\n"
			       "Content-Length: 0\r\n"
			       "Connection: close\r\n",
			       resp->status, http_status_str(resp->status),
			       req->bucket);
	if (ret > 0)
		*outlen = ret;
	else {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		buf = NULL;
	}
	return buf;
}

char *delete_bucket(struct s3gw_request *req, struct s3gw_response *resp,
		    int *outlen)
{
	char *buf;
	time_t now = time(NULL);
	struct tm *tm;
	char time_str[64];
	int ret;

	ret = dir_delete_bucket(req, req->bucket);
	if (ret < 0) {
		switch (ret) {
		case -EEXIST:
			resp->status = HTTP_STATUS_CONFLICT;
			break;
		case -ENOENT:
			resp->status = HTTP_STATUS_NOT_FOUND;
			break;
		case -ENOTEMPTY:
			resp->status = HTTP_STATUS_CONFLICT;
			break;
		default:
			resp->status = HTTP_STATUS_BAD_REQUEST;
			break;
		}
		return NULL;
	}
	resp->status = HTTP_STATUS_NO_CONTENT;
	tm = localtime(&now);
	strftime(time_str, 64, "%c", tm);
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "Date: %s\r\n"
		       "Connection: close\r\n",
		       resp->status, http_status_str(resp->status), time_str);
	if (ret > 0)
		*outlen = ret;
	else {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		buf = NULL;
	}
	return buf;
}

char *list_buckets(struct s3gw_request *req, struct s3gw_response *resp,
		   int *outlen)
{
	struct linked_list top;
	struct s3gw_bucket *b, *t;
	xmlDoc *doc;
	xmlNode *root_node, *buckets_node, *b_node, *owner_node;
	unsigned char *xml;
	int xml_len;
	char *buf;
	char time_str[64];
	struct tm *tm;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = dir_find_buckets(req, &top);
	if (ret < 0 && ret != -EPERM) {
		resp->status = HTTP_STATUS_NOT_FOUND;
		return NULL;
	}
	printf("found %d buckets\n", ret);
	resp->status = HTTP_STATUS_OK;

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

	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "Content-Length: %d\r\n\r\n%s",
		       resp->status, http_status_str(resp->status),
		       xml_len, xml);
	if (ret > 0)
		*outlen = ret;
	else {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		buf = NULL;
	}

	free(xml);
	return buf;
}

char *check_bucket(struct s3gw_request *req, struct s3gw_response *resp,
		   int *outlen)
{
	struct linked_list top;
	char *buf;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = dir_find_buckets(req, &top);
	if (ret < 0) {
		if (ret == -EPERM)
			resp->status = HTTP_STATUS_FORBIDDEN;
		else
			resp->status = HTTP_STATUS_NOT_FOUND;
		return NULL;
	}
	resp->status = HTTP_STATUS_OK;
	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "x-amz-bucket-region: %s\r\n",
		       resp->status, http_status_str(resp->status),
		       req->region);
	if (ret > 0)
		*outlen = ret;
	else {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		buf = NULL;
	}
	return buf;
}

char *bucket_versioning(struct s3gw_request *req, struct s3gw_response *resp,
			int *outlen)
{
	xmlDoc *doc;
	xmlNode *node;
	unsigned char *xml;
	int xml_len, ret;
	char *buf;

	doc = xmlNewDoc((const xmlChar *)"1.0");
	node = xmlNewDocNode(doc, NULL,
			     (const xmlChar *)"VersioningConfiguration",
			     NULL);
	xmlDocSetRootElement(doc, node);
	xmlDocDumpMemory(doc, &xml, &xml_len);
	xmlFreeDoc(doc);
	resp->status = HTTP_STATUS_OK;

	ret = asprintf(&buf, "HTTP/1.1 %d %s\r\n"
		       "Content-Length: %d\r\n\r\n%s",
		       resp->status, http_status_str(resp->status),
		       xml_len, xml);
	if (ret > 0)
		*outlen = ret;
	else {
		resp->status = HTTP_STATUS_INTERNAL_SERVER_ERROR;
		buf = NULL;
	}

	free(xml);
	return buf;
}
