/*
 *  Copyright 2025 Hannes Reinecke, SUSE
 */

#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/select.h>

#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <uuid/uuid.h>

#include "http_parser.h"

#include "s3_api.h"
#include "s3gw.h"

static char default_region[] = "eu-west-2";
static char default_base_dir[] = "/tmp/s3";
static char default_owner[] = "AIDACKEVSQ6C2EXAMPLE";

int main(int argc, char *argv[])
{
	char *default_cert = "server-cert.pem";
	char *default_key = "server-key.pem";
	struct s3gw_ctx *ctx = NULL;
	bool use_tls = false;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	ctx->cert = default_cert;
	ctx->key = default_key;
	ctx->region = default_region;
	ctx->owner = default_owner;
	ctx->base_dir = default_base_dir;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s <url>\n", argv[0]);
		free(ctx);
		exit(1);
	}
	if (!strncmp(argv[1], "https://", 8)) {
		ctx->hostport = strdup(argv[1] + 8);
		use_tls = true;
	} else if (!strncmp(argv[1], "http://", 7)) {
		ctx->hostport = strdup(argv[1] + 7);
		use_tls = false;
	} else {
		fprintf(stderr, "invalid url %s\n", argv[1]);
		free(ctx);
		exit(1);
	}

	if (use_tls)
		tls_loop(ctx);
	else
		tcp_loop(ctx);
	return 0;
}
