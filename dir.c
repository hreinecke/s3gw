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

static int find_bucket(char *dirname, char *name, struct linked_list *head)
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

int find_buckets(struct s3gw_request *req, struct linked_list *head)
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
		return -EPERM;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		printf("checking %s type %d\n",
		       se->d_name, se->d_type);
		if (se->d_type == DT_DIR) {
			ret = find_bucket(dirname, se->d_name, head);
			if (ret < 0)
				break;
			num++;
		}
	}	
	closedir(sd);
	free(dirname);

	return num;
}

static int find_object(char *dirname, char *name, struct linked_list *head)
{
	struct s3gw_object *o;
	char *pathname;
	unsigned char *etag;
	struct stat st;
	void *addr;
	int fd, ret, etag_len;

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
	fd = open(pathname, O_RDONLY);
	if (fd < 0) {
		ret = -errno;
		goto out;
	}
	addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (addr == MAP_FAILED) {
		close(fd);
		ret = -EIO;
		goto out;
	}
	close(fd);
	etag = md5sum(addr, st.st_size, &etag_len);
	munmap(addr, st.st_size);

	if (!etag) {
		fprintf(stderr, "md5sum calculation failed\n");
		etag_len = 0;
	}
	o = malloc(sizeof(*o));
	if (!o) {
		ret = -ENOMEM;
		goto out;
	}
	o->key = strdup(name);
	o->mtime = st.st_mtime;
	o->size = st.st_size;
	o->etag = etag;
	o->etag_len = etag_len;
	list_add(&o->list, head);
	printf("Found object '%s'\n", o->key);
out:		
	free(pathname);
	return ret;
}

void clear_object(struct s3gw_object *obj)
{
	if (obj->key) {
		free(obj->key);
		obj->key = NULL;
	}
	if (obj->etag) {
		free(obj->etag);
		obj->etag = NULL;
	}
}

int find_objects(struct s3gw_request *req, struct linked_list *head)
{
	char *dirname;
	int ret, num = 0;
	struct dirent *se;
	DIR *sd;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->ctx->owner,
		       req->bucket);
	if (ret < 0)
		return -ENOMEM;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open bucket dir '%s'\n", dirname);
		free(dirname);
		return -EPERM;
	}
	while ((se = readdir(sd))) {
		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		printf("checking %s type %d\n",
		       se->d_name, se->d_type);
		if (se->d_type == DT_REG) {
			if (req->object &&
			    strcmp(req->object, se->d_name))
				continue;
			ret = find_object(dirname, se->d_name, head);
			if (ret < 0)
				break;
			num++;
		}
	}
	closedir(sd);
	free(dirname);

	return num;
}
