#define _GNU_SOURCE
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

int dir_create_bucket(struct s3gw_request *req, const char *bucket)
{
	char *pathname;
	int ret;

	if (!req->owner) {
		fprintf(stderr, "No owner set\n");
		return -EINVAL;
	}
	if (!bucket) {
		fprintf(stderr, "No bucket specified\n");
		return -EINVAL;
	}
	ret = asprintf(&pathname, "%s/%s/%s",
		       req->ctx->base_dir, req->owner, bucket);
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

int dir_delete_bucket(struct s3gw_request *req, const char *bucket)
{
	char *pathname;
	int ret;

	if (!req->owner) {
		fprintf(stderr, "No owner set\n");
		return -EINVAL;
	}
	if (!bucket) {
		fprintf(stderr, "No bucket specified\n");
		return -EINVAL;
	}
	ret = asprintf(&pathname, "%s/%s/%s",
		       req->ctx->base_dir, req->owner, bucket);
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

static int fill_bucket(char *dirname, char *name, const char *delim,
		       struct linked_list *head)
{
	struct s3gw_bucket *b;
	char *pathname;
	struct stat st;
	int ret;

	ret = asprintf(&pathname, "%s%s%s", dirname, delim, name);
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
	ret = asprintf(&b->name, "%s%s", name, delim);
	if (ret < 0)
		goto out;
	b->ctime = st.st_ctime;
	list_add_tail(&b->list, head);
	printf("Found bucket '%s'\n", b->name);
out:		
	free(pathname);
	return ret;
}

int find_bucket(char *base, char *key, const char *prefix, const char *delim,
		struct linked_list *head)
{
	struct dirent *se;
	char *path;
	DIR *sd;
	int ret, num = 0;

	ret = asprintf(&path, "%s%s%s", base,
		       key ? delim : "",
		       key ? key : "");
	sd = opendir(path);
	if (!sd) {
		fprintf(stderr, "Cannot open %s\n", path);
		free(path);
		return -EPERM;
	}
	printf("reading directory %s\n", path);
	while ((se = readdir(sd))) {
		char *new_key;

		if (!strcmp(se->d_name, ".") ||
		    !strcmp(se->d_name, ".."))
			continue;
		if (prefix && strncmp(se->d_name, prefix, strlen(prefix))) {
			printf("skipping %s (%s)\n", se->d_name, path);
			continue;
		}
		ret = asprintf(&new_key, "%s%s%s",
			       key ? key : "", key ? delim : "", se->d_name);
		printf("checking %s (%s) type %d\n",
		       se->d_name, path, se->d_type);
		if (se->d_type == DT_DIR) {
			ret = find_bucket(base, new_key, prefix,
					  delim, head);
			if (ret < 0)
				goto next_bucket;

			num += ret;
			ret = fill_bucket(base, new_key, delim, head);
			if (ret < 0)
				goto next_bucket;
			num++;
		}
	next_bucket:
		free(new_key);
	}
	closedir(sd);
	return num;
}

int dir_find_buckets(struct s3gw_request *req, const char *prefix,
		     struct linked_list *head)
{
	char *dirname;
	int ret;

	if (!req->owner) {
		fprintf(stderr, "No owner set\n");
		return -EINVAL;
	}
	ret = asprintf(&dirname, "%s/%s",
		       req->ctx->base_dir,
		       req->owner);
	if (ret < 0)
		return -ENOMEM;

	ret = find_bucket(dirname, NULL, prefix, "/", head);
	free(dirname);
	return ret;
}

static int _create_object(struct s3gw_object *obj, const char *dirname,
			  const char *name, size_t payload_len)
{
	char *pathname;
	int fd, ret;

	if (!payload_len)
		return -EINVAL;

	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return -errno;

	fd = open(pathname, O_RDWR | O_CREAT, 0644);
	if (fd < 0) {
		fprintf(stderr, "%s: object %s open error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out_free;
	}
	if (lseek(fd, payload_len - 1, SEEK_SET) < 0) {
		fprintf(stderr, "%s: object %s seek error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out_close;
	}
	if (write(fd, "", 1) < 0) {
		fprintf(stderr, "%s: object %s extend error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out_close;
	}
	obj->map = mmap(NULL, payload_len, PROT_READ | PROT_WRITE,
			MAP_SHARED, fd, 0);
	if (obj->map == MAP_FAILED) {
		fprintf(stderr, "%s: object %s mmap error\n",
			__func__, pathname);
		ret = -EIO;
		obj->map = NULL;
		goto out_close;
	}
	obj->size = payload_len;
	obj->key = strdup(name);
	printf("Found object '%s'\n", obj->key);
out_close:
	close(fd);
out_free:
	free(pathname);
	return ret;
}

int dir_create_object(struct s3gw_request *req, struct s3gw_object *obj,
		      const char *key)
{
	char *dirname;
	int ret;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner, req->bucket);
	if (ret < 0)
		return -ENOMEM;

	ret = _create_object(obj, dirname, key,
			     req->payload_len);
	free(dirname);
	return ret;
}

static int _fill_object(struct s3gw_object *obj, const char *dirname,
			const char *name)
{
	char *pathname;
	unsigned char *etag;
	struct stat st;
	int fd, ret, etag_len;

	ret = asprintf(&pathname, "%s/%s", dirname, name);
	if (ret < 0)
		return -errno;

	if (obj->map) {
		msync(obj->map, obj->size, MS_SYNC | MS_INVALIDATE);
		munmap(obj->map, obj->size);
		obj->map = NULL;
		obj->size = 0;
	}
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
	if ((st.st_mode & S_IFMT) == S_IFREG) {
		obj->size = st.st_size;
		obj->map = mmap(NULL, obj->size, PROT_READ, MAP_PRIVATE, fd, 0);
		close(fd);
		if (obj->map == MAP_FAILED) {
			fprintf(stderr, "%s: object %s map error\n",
				__func__, pathname);
			obj->map = NULL;
			ret = -EIO;
			goto out;
		}
		etag = md5sum(obj->map, st.st_size, &etag_len);

		if (!etag) {
			fprintf(stderr, "md5sum calculation failed\n");
			etag_len = 0;
		}
		obj->etag = etag;
		obj->etag_len = etag_len;
	} else {
		close(fd);
	}
	obj->mtime = st.st_mtime;

	if (!obj->key)
		obj->key = strdup(name);
	printf("Found object '%s'\n", obj->key);
out:		
	free(pathname);
	return ret;
}

int dir_fetch_object(struct s3gw_request *req, struct s3gw_object *obj,
		     const char *object)
{
	char *dirname;
	int ret;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner, req->bucket);
	if (ret < 0)
		return -ENOMEM;

	ret = _fill_object(obj, dirname, object);
	free(dirname);
	return ret;
}

int dir_splice_objects(struct s3gw_request *req,
		       char *s_bucket, char *s_obj,
		       char *d_bucket, char *d_obj)
{
	char *pathname;
	struct stat st;
	int s_fd, d_fd, ret;
	void *s_map, *d_map;

	ret = asprintf(&pathname, "%s/%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner, s_bucket, s_obj);
	if (ret < 0)
		return -errno;

	s_fd = open(pathname, O_RDONLY);
	if (s_fd < 0) {
		fprintf(stderr, "%s: source object %s open error %d\n",
			__func__, pathname, errno);
		free(pathname);
		return -errno;
	}
	ret = fstat(s_fd, &st);
	if (ret < 0) {
		fprintf(stderr, "%s: source object %s stat error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out_close_source;
	}

	free(pathname);
	ret = asprintf(&pathname, "%s/%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner, d_bucket, d_obj);
	if (ret < 0) {
		close(s_fd);
		return -errno;
	}

	d_fd = open(pathname, O_RDWR | O_CREAT, 0644);
	if (d_fd < 0) {
		fprintf(stderr, "%s: destination object %s open error %d\n",
			__func__, pathname, errno);
		ret = -errno;
		goto out_close_source;
	}
	ret = splice(s_fd, NULL, d_fd, NULL, st.st_size, 0);
	if (ret > 0)
		goto out_close_dest;

	if (errno != EINVAL) {
		fprintf(stderr, "%s: splice object %s/%s to %s/%s error %d\n",
			__func__, s_bucket, s_obj, d_bucket, d_obj, errno);
		ret = -errno;
		goto out_close_dest;
	}
	/* Not supported, try mmap */
	s_map = mmap(NULL, st.st_size, PROT_READ,
		     MAP_PRIVATE, s_fd, 0);
	if (s_map == MAP_FAILED) {
		fprintf(stderr, "%s: mmap source object %s/%s error %d\n",
			__func__, s_bucket, s_obj, errno);
		goto out_close_dest;
	}
	if (lseek(d_fd, st.st_size - 1, SEEK_SET) < 0) {
		fprintf(stderr, "%s: lseek destination object %s/%s error %d\n",
			__func__, d_bucket, d_obj, errno);
		goto out_close_dest;
	}
	ret = write(d_fd, "", 1);
	if (ret < 0) {
		fprintf(stderr, "%s: extend destination object %s/%s error %d\n",
			__func__, d_bucket, d_obj, errno);
		goto out_close_dest;
	}
	d_map = mmap(NULL, st.st_size, PROT_WRITE | PROT_READ,
		     MAP_SHARED, d_fd, 0);
	if (d_map == MAP_FAILED) {
		fprintf(stderr, "%s: mmap destination object %s/%s error %d\n",
			__func__, d_bucket, d_obj, errno);
		goto out_unmap_source;
	}
	memcpy(d_map, s_map, st.st_size);
	msync(d_map, st.st_size, MS_SYNC | MS_INVALIDATE);
	munmap(d_map, st.st_size);
out_unmap_source:
	munmap(s_map, st.st_size);
out_close_dest:
	close(d_fd);
out_close_source:
	close(s_fd);
	free(pathname);
	return ret;
}

int dir_delete_object(struct s3gw_request *req, const char *bucket,
		      const char *object)
{
	char *pathname;
	int ret;

	ret = asprintf(&pathname, "%s/%s/%s/%s",
		       req->ctx->base_dir, req->owner,
		       bucket, object);
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
		     char *prefix, char *delim, char *marker)
{
	char *dirname;
	struct s3gw_object *obj = NULL;
	int ret, num = 0;
	struct dirent *se;
	DIR *sd;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner, req->bucket);
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
			if (req->key &&
			    strcmp(req->key, se->d_name))
				continue;
			if (prefix && strncmp(se->d_name, prefix,
					      strlen(prefix)))
				continue;
			if (!obj) {
				obj = malloc(sizeof(*obj));
				if (!obj)
					break;
				memset(obj, 0, sizeof(*obj));
			}
			ret = _fill_object(obj, dirname, se->d_name);
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

int dir_find_prefix(struct s3gw_request *req, struct linked_list *head,
		    char *prefix, char *delim, char *marker)
{
	char *dirname;
	int ret;

	ret = asprintf(&dirname, "%s/%s/%s",
		       req->ctx->base_dir,
		       req->owner, req->bucket);
	if (ret < 0)
		return -ENOMEM;
	ret = find_bucket(dirname, NULL, prefix, delim, head);
	free(dirname);
	return ret;
}
