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
#include <sys/xattr.h>

#include "s3_api.h"
#include "s3gw.h"

int create_owner_secret(struct s3gw_ctx *ctx, char *owner_id, char *secret)
{
	int set_secret_key = 1;
	const char skey[] = "user.secret_access_key";
	struct stat st;
	char *pathname;
	char value[128];
	size_t value_size = 128;
	int ret;

	ret = asprintf(&pathname, "%s/%s",
		       ctx->base_dir, owner_id);
	if (ret < 0)
		return -ENOMEM;
	if (!secret)
		return -EINVAL;

	ret = stat(pathname, &st);
	if (!ret) {
		ret = getxattr(pathname, skey, value, value_size);
		if (ret > 0) {
			value_size = ret;
			if (strncmp(secret, value, value_size)) {
				printf("secret key mismatch for %s\n",
					owner_id);
				set_secret_key = 2;
			} else
				set_secret_key = 0;
		}
	} else {
		ret = mkdir(pathname, 0755);
		if (ret < 0) {
			fprintf(stderr, "failed to create directoy %s\n",
				pathname);
			return -errno;
		}
	}
	if (set_secret_key) {
		const char *op = set_secret_key > 1 ? "update" : "set";
		int flags = set_secret_key > 1 ?
			XATTR_REPLACE : XATTR_CREATE;

		printf("%s secret key for %s\n", op, owner_id);
		ret = setxattr(pathname, skey, secret, strlen(secret), flags);
		if (ret < 0) {
			fprintf(stderr, "cannot %s secret key for %s\n",
				op, owner_id);
			return -errno;
		}
	}
	return 0;
}

char *get_owner_secret(struct s3gw_ctx *ctx, char *owner_id, int *out_len)
{
	const char skey[] = "user.secret_access_key";
	char *pathname, *value;
	size_t value_size = 128;
	int ret;

	ret = asprintf(&pathname, "%s/%s",
		       ctx->base_dir, owner_id);
	if (ret < 0)
		return NULL;

	value = malloc(value_size);
	if (!value) {
		free(pathname);
		return NULL;
	}
	memset(value, 0, value_size);
	ret = getxattr(pathname, skey, value, value_size);
	if (ret < 0) {
		fprintf(stderr, "cannot get secret key from %s, errno %d\n",
			pathname, errno);
		free(value);
		value = NULL;
	} else
		*out_len = ret;
	free(pathname);
	return value;
}

int dir_create_bucket(struct s3gw_request *req)
{
	char *pathname;
	int ret;

	if (!req->owner) {
		fprintf(stderr, "No owner set\n");
		return -EINVAL;
	}
	if (!req->bucket) {
		fprintf(stderr, "No bucket specified\n");
		return -EINVAL;
	}
	ret = asprintf(&pathname, "%s/%s/%s",
		       req->ctx->base_dir, req->owner, req->bucket);
	if (ret < 0)
		return -errno;

	ret = mkdir(pathname, 0755);
	if (ret < 0) {
		fprintf(stderr, "%s: bucket %s error %d\n",
			__func__, pathname, errno);
		ret = -errno;
	}

	free(pathname);
	return ret;
}

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

int dir_find_buckets(struct s3gw_request *req, struct linked_list *head)
{
	char *dirname;
	int ret, num = 0;
	struct dirent *se;
	DIR *sd;

	if (!req->owner) {
		fprintf(stderr, "No owner set\n");
		return -EINVAL;
	}
	ret = asprintf(&dirname, "%s/%s",
		       req->ctx->base_dir,
		       req->owner);
	if (ret < 0)
		return -ENOMEM;
	sd = opendir(dirname);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", dirname);
		free(dirname);
		return -EPERM;
	}
	printf("reading directory %s\n", dirname);
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

int dir_find_objects(struct s3gw_request *req, struct linked_list *head,
		     char *prefix)
{
	char *dirname;
	int ret, num = 0;
	struct dirent *se;
	DIR *sd;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner,
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
			if (prefix && strncmp(se->d_name, prefix,
					      strlen(prefix)))
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
