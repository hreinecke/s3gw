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

int dir_delete_bucket(struct s3gw_request *req)
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

	ret = rmdir(pathname);
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

static int fill_object(struct s3gw_object *obj, char *dirname, char *name,
		       unsigned char *payload, size_t payload_len)
{
	char *pathname;
	unsigned char *etag;
	struct stat st;
	void *addr;
	int fd, ret, etag_len;

	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return -errno;

	if (payload)
		fd = open(pathname, O_RDWR | O_CREAT, 0644);
	else
		fd = open(pathname, O_RDONLY);
	if (fd < 0) {
		fprintf(stderr, "%s: object %s open error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out;
	}
	ret = fstat(fd, &st);
	if (ret < 0) {
		fprintf(stderr, "%s: object %s stat error %d\n",
			__func__, pathname, errno);
		close(fd);
		ret = -errno;
		goto out;
	}
	if (payload && payload_len) {
		ret = write(fd, payload, payload_len);
		if (ret < 0) {
			fprintf(stderr, "%s: object %s write error %d\n",
				__func__, pathname, errno);
			close(fd);
			ret = -errno;
			goto out;
		}
	}
	addr = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	close(fd);
	if (addr == MAP_FAILED) {
		ret = -EIO;
		goto out;
	}
	etag = md5sum(addr, st.st_size, &etag_len);
	munmap(addr, st.st_size);

	if (!etag) {
		fprintf(stderr, "md5sum calculation failed\n");
		etag_len = 0;
	}
	obj->key = strdup(name);
	obj->mtime = st.st_mtime;
	obj->size = st.st_size;
	obj->etag = etag;
	obj->etag_len = etag_len;

	printf("Found object '%s'\n", obj->key);
out:		
	free(pathname);
	return ret;
}

int dir_create_object(struct s3gw_request *req, struct s3gw_object *obj)
{
	char *dirname;
	int ret, fd;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner,
		       req->bucket);
	if (ret < 0)
		return -ENOMEM;

	ret = fill_object(obj, dirname, req->object,
			  req->payload, req->payload_len);
	if (ret < 0) {
		fprintf(stderr, "Cannot create object '%s', error %d\n",
			req->object, -errno);
		ret = -errno;
	}
	free(dirname);
	return ret;
}

int dir_delete_object(struct s3gw_request *req)
{
	char *pathname;
	int ret;

	ret = asprintf(&pathname, "%s/%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner,
		       req->bucket,
		       req->object);
	if (ret < 0)
		return -ENOMEM;

	ret = unlink(pathname);
	if (ret < 0) {
		fprintf(stderr, "Cannot unlink object '%s', error %d\n",
			pathname, -errno);
		ret = -errno;
	}
	free(pathname);
	return ret;
}

int dir_find_objects(struct s3gw_request *req, struct linked_list *head,
		     char *prefix)
{
	char *dirname;
	struct s3gw_object *obj = NULL;
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
			if (!obj) {
				obj = malloc(sizeof(*obj));
				if (!obj)
					break;
			}
			ret = fill_object(obj, dirname, se->d_name, NULL, 0);
			if (!ret) {
				list_add(&obj->list, head);
				obj = NULL;
			}
			num++;
		}
	}
	closedir(sd);
	free(dirname);

	return num;
}
