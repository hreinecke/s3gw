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
	S3_OP_Unknown,
	S3_OP_CreateBucket,
	S3_OP_HeadBucket,
	S3_OP_ListBuckets,
	S3_OP_ListObjects,
	S3_OP_ListObjectsV2,
	S3_OP_ListMultipartUploads,
	S3_OP_DeleteBucket,
	S3_OP_PutBucketPolicy,
	S3_OP_GetBucketPolicy,
	S3_OP_DeleteBucketPolicy,
	S3_OP_GetBucketPolicyStatus,
	S3_OP_PutObject,
	S3_OP_CopyObject,
	S3_OP_RestoreObject,
	S3_OP_GetObject,
	S3_OP_HeadObject,
	S3_OP_DeleteObject,
	S3_OP_DeleteObjects,
	S3_OP_CreateMultipartUpload,
	S3_OP_CompleteMultipartUpload,
	S3_OP_AbortMultipartUpload,
	S3_OP_UploadPart,
	S3_OP_UploadPartCopy,
	S3_OP_ListParts,
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
