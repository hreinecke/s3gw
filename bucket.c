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

void create_bucket(struct s3gw_request *req, struct s3gw_response *resp)
{
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
		return;
	}
	ret = dir_create_bucket(req, req->bucket);
	if (ret < 0) {
		resp->status = HTTP_STATUS_BAD_REQUEST;
		if (ret == -EEXIST) {
			resp->status = HTTP_STATUS_CONFLICT;
		}
		return;
	}
	resp->status = HTTP_STATUS_OK;
	if (location)
		put_response_header(resp, "x-amz-bucket-region",
				    (char *)location);
	put_response_header(resp, "Location", req->bucket);
}

void delete_bucket(struct s3gw_request *req, struct s3gw_response *resp)
{
	int ret;

	resp->status = HTTP_STATUS_NO_CONTENT;
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
	}
}

void list_buckets(struct s3gw_request *req, struct s3gw_response *resp)
{
	struct linked_list top;
	struct s3gw_bucket *b, *t;
	xmlDoc *doc;
	xmlNode *root_node, *buckets_node, *b_node, *owner_node;
	int xml_len;
	char line[64];
	struct tm *tm;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = dir_find_buckets(req, &top);
	if (ret < 0 && ret != -EPERM) {
		resp->status = HTTP_STATUS_NOT_FOUND;
		return;
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
		strftime(line, 64, "%FT%T%z", tm);
		xmlNewChild(b_node, NULL,
			    (const xmlChar *)"CreationDate",
			    (xmlChar *)line);
		xmlNewChild(b_node, NULL,
			    (const xmlChar *)"Name", (xmlChar *)b->name);
	}
	owner_node = xmlNewChild(root_node, NULL,
				 (const xmlChar *)"Owner", NULL);
	xmlNewChild(owner_node, NULL, (const xmlChar *)"ID",
		    (xmlChar *)req->owner);

	xmlDocDumpMemory(doc, &resp->payload, &xml_len);
	resp->payload_len = xml_len;
	xmlFreeDoc(doc);
}

void check_bucket(struct s3gw_request *req, struct s3gw_response *resp)
{
	struct linked_list top;
	int ret;

	INIT_LINKED_LIST(&top);
	ret = dir_find_buckets(req, &top);
	if (ret < 0) {
		if (ret == -EPERM)
			resp->status = HTTP_STATUS_FORBIDDEN;
		else
			resp->status = HTTP_STATUS_NOT_FOUND;
		return;
	}
	resp->status = HTTP_STATUS_OK;
	put_response_header(resp, "x-amz-bucket-region", req->region);
}

void bucket_versioning(struct s3gw_request *req, struct s3gw_response *resp)
{
	xmlDoc *doc;
	xmlNode *node;
	int xml_len;

	doc = xmlNewDoc((const xmlChar *)"1.0");
	node = xmlNewDocNode(doc, NULL,
			     (const xmlChar *)"VersioningConfiguration",
			     NULL);
	xmlDocSetRootElement(doc, node);
	xmlDocDumpMemory(doc, &resp->payload, &xml_len);
	resp->payload_len = xml_len;
	xmlFreeDoc(doc);
	resp->status = HTTP_STATUS_OK;
}

void bucket_policy_status(struct s3gw_request *req, struct s3gw_response *resp)
{
	xmlDoc *doc;
	xmlNode *node;
	int xml_len;

	doc = xmlNewDoc((const xmlChar *)"1.0");
	node = xmlNewDocNode(doc, NULL,
			     (const xmlChar *)"PolicyStatus",
			     NULL);
	xmlDocSetRootElement(doc, node);
	xmlNewChild(node, NULL, (const xmlChar *)"IsPublic",
		    (xmlChar *)"False");
	xmlDocDumpMemory(doc, &resp->payload, &xml_len);
	resp->payload_len = xml_len;
	xmlFreeDoc(doc);
	resp->status = HTTP_STATUS_OK;
}
