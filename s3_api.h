#ifndef _S3_API_H
#define _S3_API_H

struct s3_bucket {
	const char *arn;
	const char *name;
	const char *region;
	time_t tstamp;
};

enum s3_csum_type {
	CSUM_TYPE_COMPOSITE,
	CSUM_TYPE_FULL_OBJECT,
};

enum s3_api_ops {
	API_OPS_UNKNOWN,
	IMDS_GET_METADATA_VERSIONS,
	IMDS_GET_CREDENTIALS,
};

enum s3_csum_algo {
	CSUM_ALGO_CRC32,
	CSUM_ALGO_CRC32C,
	CSUM_ALGO_SHA1,
	CSUM_ALGO_SHA256,
	CSUM_ALGO_CRC64NVME,
};

enum s3_storage_class {
	STORAGE_CLASS_STANDARD,
	STORAGE_CLASS_REDUCED_REDUNDANCY,
	STORAGE_CLASS_GLACIER,
	STORAGE_CLASS_STANDARD_IA,
	STORAGE_CLASS_ONEZONE_IA,
	STORAGE_CLASS_INTELLIGENT_TIERING,
	STORAGE_CLASS_DEEP_ARCHIVE,
	STORAGE_CLASS_OUTPOSTS,
	STORAGE_CLASS_GLACIER_IR,
	STORAGE_CLASS_SNOW,
	STORAGE_CLASS_EXPRESS_ONEZONE,
	STORAGE_CLASS_FSX_OPENZFS,
};

struct s3_owner {
	char *display_name;
	char *id;
};

struct s3_restore_status {
	bool in_progress;
	time_t expiry_date;
};

struct s3_object {
	char *key;
	char *etag;
	size_t size;
	enum s3_storage_class storage_class;
	enum s3_csum_algo csum_alg;
	enum s3_csum_type csum_type;
	time_t last_modified;
	struct s3_owner *owner;
	struct s3_restore_status *restore_status;
};

#endif /* _S3_API_H */
