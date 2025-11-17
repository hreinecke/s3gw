#include <stdio.h>
#include <stdbool.h>
#include <string.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "s3_api.h"
#include "s3gw.h"

unsigned char *md5sum(char *input, int input_len, int *out_len)
{
	OSSL_LIB_CTX *ctx;
	const char *option_properties = NULL;
	EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned int output_len;
	unsigned char *output = NULL;

	ctx = OSSL_LIB_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
		return NULL;
	}

	md = EVP_MD_fetch(ctx, "MD5", option_properties);
	if (md == NULL) {
		fprintf(stderr, "EVP_MD_fetch could not find MD5.");
		goto cleanup_ctx;
	}
	/* Determine the length of the fetched digest type */
	output_len = EVP_MD_get_size(md);
	if (output_len <= 0) {
		fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
		goto cleanup_md;
	}

	output = malloc(output_len);
	if (output == NULL) {
		fprintf(stderr, "No memory.\n");
		goto cleanup;
	}
	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL) {
		fprintf(stderr, "EVP_MD_CTX_new failed.\n");
		goto err_free;
	}
	if (EVP_DigestInit(md_ctx, md) != 1) {
		fprintf(stderr, "EVP_DigestInit failed.\n");
		goto err_free;
	}
	if (EVP_DigestUpdate(md_ctx, input, input_len) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
		goto err_free;
	}
	if (EVP_DigestFinal(md_ctx, output, &output_len) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
		goto err_free;
	}
cleanup:
	EVP_MD_CTX_free(md_ctx);
cleanup_md:
	EVP_MD_free(md);
cleanup_ctx:
	OSSL_LIB_CTX_free(ctx);
	return output;
err_free:
	free(output);
	output = NULL;
	goto cleanup;
}

unsigned char *auth_string_to_sign(struct s3gw_request *req, int *out_len)
{
	OSSL_LIB_CTX *ctx;
	const char *option_properties = NULL;
	EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned int output_len;
	unsigned char *output = NULL;
	struct s3gw_header *hdr;
	char *tstamp, *scope, *hash, *input;

	ctx = OSSL_LIB_CTX_new();
	if (ctx == NULL) {
		fprintf(stderr, "OSSL_LIB_CTX_new() returned NULL\n");
		return NULL;
	}

	md = EVP_MD_fetch(ctx, "SHA256", option_properties);
	if (md == NULL) {
		fprintf(stderr, "EVP_MD_fetch could not find MD5.");
		goto cleanup_ctx;
	}
	/* Determine the length of the fetched digest type */
	output_len = EVP_MD_get_size(md);
	if (output_len <= 0) {
		fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
		goto cleanup_md;
	}

	output = malloc(output_len);
	if (output == NULL) {
		fprintf(stderr, "No memory.\n");
		goto cleanup;
	}
	md_ctx = EVP_MD_CTX_new();
	if (md_ctx == NULL) {
		fprintf(stderr, "EVP_MD_CTX_new failed.\n");
		goto err_free;
	}
	if (EVP_DigestInit(md_ctx, md) != 1) {
		fprintf(stderr, "EVP_DigestInit failed.\n");
		goto err_free;
	}
	/* Construct string to sign */
	list_for_each_entry(hdr, &req->hdr_list, list) {
		if (!strcmp(hdr->key, "X-Amz-Date"))
			tstamp = hdr->value;
		if (!strcmp(hdr->key, "X-Amz-Content-SHA256"))
			hash = hdr->value;
	}
	list_for_each_entry(hdr, &req->auth_list, list) {
		if (!strcmp(hdr->key, "Credential"))
			scope = hdr->value;
	}
	asprintf(&input, "%s\n%s\n%s\n%s\n", "AWS4-HMAC-SHA256",
		 tstamp, scope, hash);
	printf("%s", input);
	if (EVP_DigestUpdate(md_ctx, input, strlen(input)) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
		goto err_free;
	}
	if (EVP_DigestFinal(md_ctx, output, &output_len) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
		goto err_free;
	}
cleanup:
	EVP_MD_CTX_free(md_ctx);
cleanup_md:
	EVP_MD_free(md);
cleanup_ctx:
	OSSL_LIB_CTX_free(ctx);
	return output;
err_free:
	free(output);
	output = NULL;
	goto cleanup;
}

unsigned char *hmac_sha256(const void *key, int keylen,
			   const unsigned char *data, int datalen,
			   unsigned char *result, unsigned int *resultlen) {
	return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}
