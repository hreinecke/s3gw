#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include "s3_api.h"
#include "s3gw.h"

char *bin2hex(unsigned char *input, int input_len, size_t *out_len)
{
	char *output, *p;
	int output_len, i;

	output_len = input_len * 2 + 1;
	output = malloc(output_len);
	if (!output)
		return NULL;
	memset(output, 0, output_len);

	for (i = 0; i < input_len; i++) {
		p = &output[i * 2];
		sprintf(p, "%02x", input[i]);
	}
	*out_len = output_len;
	return output;
}

static int hex_to_bin(unsigned char ch)
{
	if (ch >= '0' && ch <= '9')
		return ch - '0' + 1;
	if (ch >= 'A' && ch <= 'F')
		return ch - 'A' + 1;
	if (ch >= 'a' && ch <= 'f')
		return ch - 'a' + 1;
	return -1;
}

unsigned char *hex2bin(char *input, size_t *out_len)
{
	size_t count = strlen(input);
	unsigned char *output, *p;
	int output_len;

	output_len = count >> 1;
	output = malloc(output_len);
	if (!output)
		return NULL;
	memset(output, 0, output_len);
	p = output;
	while (count--) {
		int hi, lo;

		hi = hex_to_bin(*input++);
		if (hi < 0)
			break;
		lo = hex_to_bin(*input++);
		if (lo < 0)
			break;
		*p++ = (hi << 4) | lo;
	}
	if (!count)
		*out_len = output_len;
	else {
		free(output);
		output = NULL;
	}
	return output;
}

/*
 * auth_uri_encode - URI encode a string
 *
 * Following the rules from AWS S3:
 * Signature Calculations for the Authorization Header:
 * Transferring Payload in a Single Chunk (AWS Signature Version 4)
 *
 * URI encode every byte. UriEncode() must enforce the following rules:
 * -  URI encode every byte except the unreserved characters:
 *    'A'-'Z', 'a'-'z', '0'-'9', '-', '.', '_', and '~'.
 *
 * - The space character is a reserved character and must be encoded as
 *   "%20" (and not as "+").
 *
 * - Each URI encoded byte is formed by a '%' and the two-digit hexadecimal
 *   value of the byte.
 *
 * - Letters in the hexadecimal value must be uppercase, for example "%1A".
 *
 * - Encode the forward slash character, '/', everywhere except in the object
 *   key name. For example, if the object key name is photos/Jan/sample.jpg,
 *   the forward slash in the key name is not encoded.
 */
char *uri_encode(const char *value, bool encode_slash)
{
	size_t len = strlen(value), off = 0;
	char *p, *enc;

	if (!value)
		return strdup("");

	while (off < strlen(value)) {
		if ((value[off] >= 'A' && value[off] <= 'Z') ||
		    (value[off] >= 'a' && value[off] <= 'z') ||
		    (value[off] >= '0' && value[off] <= '9') ||
		    value[off] == '-' || value[off] == '.' ||
		    value[off] == '_' || value[off] == '~')
			len++;
		else if (!encode_slash && value[off] == '/')
			len++;
		else
			len += 3;
		off ++;
	}
	enc = malloc(len + 1);
	if (!enc)
		return NULL;
	memset(enc, 0, len + 1);
	off = 0;
	p = enc;
	while (off < strlen(value)) {
		if ((value[off] >= 'A' && value[off] <= 'Z') ||
		    (value[off] >= 'a' && value[off] <= 'z') ||
		    (value[off] >= '0' && value[off] <= '9') ||
		    value[off] == '-' || value[off] == '.' ||
		    value[off] == '_' || value[off] == '~')
			*p++ = value[off];
		else if (!encode_slash && value[off] == '/')
			*p++ = value[off];
		else {
			sprintf(p, "%%%02X", value[off]);
			p += 3;
		}
		off ++;
	}
	return enc;
}

char *uri_decode(const char *value)
{
	size_t len = strlen(value), off = 0;
	char *p, *dec;

	dec = malloc(len + 1);
	if (!dec)
		return NULL;
	memset(dec, 0, len + 1);
	p = dec;
	while (off < len) {
		if (value[off] == '%') {
			int hi, lo;

			off++;
			hi = hex_to_bin(value[off]);
			if (hi < 0)
				goto decode_err;
			off++;
			lo = hex_to_bin(value[off]);
			if (lo < 0)
				goto decode_err;
			*p++ = (hi << 4) | lo;
		} else
			*p++ = value[off];
		off ++;
	}
	return dec;
decode_err:
	free(dec);
	return NULL;
}

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

char *auth_string_to_sign(struct s3gw_request *req, int *out_len)
{
	OSSL_LIB_CTX *ctx;
	const char *option_properties = NULL;
	EVP_MD *md = NULL;
	EVP_MD_CTX *md_ctx = NULL;
	unsigned int request_len;
	size_t hash_len, off = 0;
	char *output = NULL;
	struct s3gw_header *hdr;
	char *tstamp = NULL, *scope = NULL, *sig_hdr = NULL;
	char *payload_hash = NULL, *input, *save;
	unsigned char *request_hash = NULL;
	char *hdrlist = NULL, *hdr_key, *query;
	int ret;

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
	request_len = EVP_MD_get_size(md);
	if (request_len <= 0) {
		fprintf(stderr, "EVP_MD_get_size returned invalid size.\n");
		goto cleanup_md;
	}

	request_hash = malloc(request_len);
	if (request_hash == NULL) {
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
	/* Construct SHA256 hash of the canonical request */
	list_for_each_entry(hdr, &req->hdr_list, list) {
		if (!strcasecmp(hdr->key, "x-amz-date"))
			tstamp = hdr->value;
		if (!strcasecmp(hdr->key, "x-amz-content-sha256"))
			payload_hash = hdr->value;
	}
	if (!payload_hash) {
		fprintf(stderr, "No payload hash\n");
		goto err_free;
	}
	if (!tstamp) {
		fprintf(stderr, "No timestamp\n");
		goto err_free;
	}
	list_for_each_entry(hdr, &req->auth_list, list) {
		if (!strcmp(hdr->key, "Credential")) {
			/* Skip access key id */
			scope = strchr(hdr->value, '/');
			if (scope)
				scope++;
		}
		if (!strcmp(hdr->key, "SignedHeaders")) {
			hdrlist = strdup(hdr->value);
			sig_hdr = hdr->value;
		}
	}
	if (!hdrlist) {
		fprintf(stderr, "No credentials\n");
		goto err_free;
	}
	if (req->query) {
		query = malloc(strlen(req->query) + 1);
		off = 0;
		list_for_each_entry(hdr, &req->query_list, list) {
			char *value = uri_encode(hdr->value, true);

			ret = sprintf(query + off, "%s%s=%s",
				      off == 0 ? "" : "&",
				      hdr->key, value);
			free(value);
			off += ret;
		}
	} else {
		query = NULL;
	}
	asprintf(&input, "%s\n%s\n%s\n", http_method_str(req->http.method),
		 req->url, query ? query : "");
	printf("query: %s\n", query);
	if (query)
		free(query);
	if (EVP_DigestUpdate(md_ctx, input, strlen(input)) != 1) {
		fprintf(stderr, "EVP_DigestUpdate(hamlet_1) failed.\n");
		goto err_free;
	}
	free(input);
	hdr_key = strtok_r(hdrlist, ";", &save);
	while (hdr_key) {
		list_for_each_entry(hdr, &req->hdr_list, list) {
			if (!strncasecmp(hdr_key, hdr->key, strlen(hdr->key))) {
				asprintf(&input, "%s:%s\n",
					 hdr_key, hdr->value);
				EVP_DigestUpdate(md_ctx, input, strlen(input));
				free(input);
			}
		}
		hdr_key = strtok_r(NULL, ";", &save);
	}
	asprintf(&input, "\n%s\n", sig_hdr);
	EVP_DigestUpdate(md_ctx, input, strlen(input));
	free(input);
	EVP_DigestUpdate(md_ctx, payload_hash, strlen(payload_hash));

	if (EVP_DigestFinal(md_ctx, request_hash, &request_len) != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed.\n");
		goto err_free;
	}
	payload_hash = bin2hex(request_hash, request_len, &hash_len);
	asprintf(&output, "%s\n%s\n%s\n%s", "AWS4-HMAC-SHA256",
		 tstamp, scope, payload_hash);
	*out_len = strlen(output);
	free(payload_hash);
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
			   unsigned char *result, unsigned int *resultlen)
{
	return HMAC(EVP_sha256(), key, keylen, data, datalen, result, resultlen);
}

char *auth_sign_str(struct s3gw_request *req, char *str_to_sign, int *out_len)
{
	struct s3gw_header *hdr;
	char *output = NULL;
	unsigned char date_key[32], service_key[32], region_key[32];
	unsigned char sign_key[32], signature[32];
	unsigned int date_key_len = 32, service_key_len = 32;
	unsigned int region_key_len = 32;
	unsigned int sign_key_len = 32, signature_len = 32;
	char *cred = NULL, *secret;
	char *p, *service, *key, *sign_str;
	int secret_len;
	size_t output_len;

	list_for_each_entry(hdr, &req->auth_list, list) {
		if (!strcmp(hdr->key, "Credential")) {
			cred = hdr->value;
			break;
		}
	}
	if (!cred) {
		fprintf(stderr, "no credentials found\n");
		return NULL;
	}

	req->owner = strdup(cred);
	if (!req->owner)
		return NULL;
	p = strchr(req->owner, '/');
	if (!p)
		goto out_free;
	*p = '\0';
	p++;
	req->tstamp = p;
	p = strchr(req->tstamp, '/');
	if (!p)
		goto out_free;
	*p = '\0';
	p++;
	req->region = p;
	p = strchr(req->region, '/');
	if (!p)
		goto out_free;
	*p = '\0';
	p++;
	service = p;
	p = strchr(service, '/');
	if (!p)
		goto out_free;
	*p = '\0';
	sign_str = p + 1;

	secret = get_owner_secret(req->ctx, req->owner, &secret_len);
	if (!secret) {
		fprintf(stderr, "No secret found for owner '%s'\n",
			req->owner);
		goto out_free;
	}

	asprintf(&key, "AWS4%s", secret);
	if (!hmac_sha256((const unsigned char *)key, strlen(key),
			 (const unsigned char *)req->tstamp,
			 strlen(req->tstamp), date_key, &date_key_len)) {
		fprintf(stderr, "Failed to generate date key\n");
		goto out_free;
	}
	free(key);
	if (!hmac_sha256(date_key, date_key_len,
			 (const unsigned char *)req->region,
			 strlen(req->region), region_key, &region_key_len)) {
		fprintf(stderr, "Failed to generate region key\n");
		goto out_free;
	}
	if (!hmac_sha256(region_key, region_key_len,
			 (const unsigned char *)service, strlen(service),
			 service_key, &service_key_len)) {
		fprintf(stderr, "Failed to generage service key\n");
		goto out_free;
	}
	if (!hmac_sha256(service_key, service_key_len,
			 (const unsigned char *)sign_str, strlen(sign_str),
			 sign_key, &sign_key_len)) {
		fprintf(stderr, "Failed to generate signining key\n");
		goto out_free;
	}
	if (!hmac_sha256(sign_key, sign_key_len,
			 (const unsigned char *)str_to_sign,
			 strlen(str_to_sign),
			 signature, &signature_len)) {
		fprintf(stderr, "Failed generate signature\n");
		goto out_free;
	}
	output = bin2hex(signature, signature_len, &output_len);
	if (output)
		*out_len = output_len;

out_free:
	if (!output) {
		free(req->owner);
		req->owner = NULL;
		req->tstamp = NULL;
		req->region = NULL;
	}
	return output;
}

int check_authorization(struct s3gw_request *req)
{
	struct s3gw_header *hdr;
	const char auth_str[] = "AWS4-HMAC-SHA256";
	char *auth, *p, *save, *buf;
	char *hdr_sig = NULL, *gen_sig = NULL;
	struct s3gw_header *auth_hdr;
	int buflen, siglen, ret = 0;

	list_for_each_entry(hdr, &req->hdr_list, list) {
		if (hdr->key && !strcmp("Authorization", hdr->key)) {
			auth = strdup(hdr->value);
			break;
		}
	}
	if (!auth)
		return -EPERM;
	p = strtok_r(auth, " ", &save);
	if (!p)
		return -EINVAL;
	if (strcmp(p, auth_str)) {
		fprintf(stderr, "Unhandled authentication method '%s'\n", p);
		return -EINVAL;
	}
	while ((p = strtok_r(NULL, ", ", &save)) != NULL) {
		char *key, *value = NULL;

		auth_hdr = malloc(sizeof(*auth_hdr));
		if (!auth_hdr) {
			free(auth);
			return -ENOMEM;
		}
		memset(auth_hdr, 0, sizeof(*auth_hdr));
		key = p;
		value = strchr(key, '=');
		if (value) {
			*value = '\0';
			value++;
		}
		auth_hdr->key = strdup(key);
		if (!auth_hdr->key) {
			free(auth);
			return -ENOMEM;
		}
		auth_hdr->value = strdup(value);
		if (!auth_hdr->value) {
			free(auth_hdr->key);
			free(auth);
			return -ENOMEM;
		}
		if (!strcmp(auth_hdr->key, "Signature"))
			hdr_sig = auth_hdr->value;
		list_add(&auth_hdr->list, &req->auth_list);
	}
	free(auth);
	buf = auth_string_to_sign(req, &buflen);
	if (!buf) {
		fprintf(stderr, "Failed to generate string t sign\n");
		return -EPERM;
	}

	gen_sig = auth_sign_str(req, buf, &siglen);
	if (!gen_sig) {
		fprintf(stderr, "Failed to generate signature\n");
		ret = -EPERM;
		goto out_free_str;
	}
	if (strcmp(hdr_sig, gen_sig)) {
		fprintf(stderr, "signature mismatch\nhdr: %s\ngen: %s\n",
			hdr_sig, gen_sig);
		ret = -EPERM;
	}
	free(gen_sig);
out_free_str:
	free(buf);
	return ret;
}
