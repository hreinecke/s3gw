#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include "s3_api.h"
#include "s3gw.h"

const char test_request[] =
	"GET /test.txt HTTP/1.1\r\n"
	"Host: examplebucket.s3.amazonaws.com"
	"Authorization: SignatureToBeCalculated"
	"Range: bytes=0-9 \r\n"
	"X-Amz-Content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\r\n"
	"A-Amz-Date: 20130524T000000Z\r\n";

const char default_owner[] =
	"AKIAIOSFODNN7EXAMPLE";

const char default_secret[] =
	"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";

const char default_region[] =
	"us-east-1";

int main(int argc, char **argv)
{
	struct s3gw_ctx ctx;
	struct s3gw_request req;
	struct s3gw_header *hdr;
	const char test_data[] = "what do ya want for nothing?";
	unsigned char output[32], *hash;
	unsigned int out_len = 32;
	char *tmp;
	size_t tmp_len;

	printf("test hmac-sha256\n");
	hash = hmac_sha256("Jefe", 4, (const unsigned char *)test_data,
			   strlen(test_data), output, &out_len);
	if (!hash) {
		fprintf(stderr, "hmac failed\n");
		exit(1);
	}
	tmp = bin2hex(output, 32, &tmp_len);
	printf("output: %s\n", tmp);
	free(tmp);
	ctx.owner = default_owner;
	ctx.secret = default_secret;
	ctx.region = default_region;
	init_request(&ctx, &req);
	req.http.method = HTTP_GET;
	req.url = strdup("/test.txt");
	hdr = malloc(sizeof(*hdr));
	hdr->key = strdup("Host");
	hdr->value = strdup("examplebucket.s3.amazonaws.com");
	list_add(&hdr->list, &req.hdr_list);
	hdr = malloc(sizeof(*hdr));
	hdr->key = strdup("Range");
	hdr->value = strdup("bytes=0-9");
	list_add(&hdr->list, &req.hdr_list);
	hdr = malloc(sizeof(*hdr));
	hdr->key = strdup("X-Amz-Content-SHA256");
	hdr->value = strdup("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
	list_add(&hdr->list, &req.hdr_list);
	hdr = malloc(sizeof(*hdr));
	hdr->key = strdup("X-Amz-Date");
	hdr->value = strdup("20130524T000000Z");
	list_add(&hdr->list, &req.hdr_list);

	hdr = malloc(sizeof(*hdr));
	hdr->key = "Authorization";
	hdr->value = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41";
	list_add(&hdr->list, &req.hdr_list);

	check_authorization(&req);
	return 0;
}
