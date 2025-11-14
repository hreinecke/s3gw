#include <stdio.h>

#include <openssl/err.h>
#include <openssl/evp.h>

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
