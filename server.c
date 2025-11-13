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

int main(int argc, char *argv[])
{
	char *default_cert = "server-cert.pem";
	char *default_key = "server-key.pem";
	struct s3gw_ctx *ctx = NULL;

	ctx = malloc(sizeof(*ctx));
	if (!ctx) {
		fprintf(stderr, "Out of memory\n");
		exit(1);
	}
	ctx->cert = default_cert;
	ctx->key = default_key;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s [host:]port\n", argv[0]);
		free(ctx);
		exit(1);
	}
	ctx->hostport = argv[1];

	tls_loop(ctx);
	return 0;
}
