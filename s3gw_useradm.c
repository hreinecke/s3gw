#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include "s3_api.h"
#include "s3gw.h"

static char default_base_dir[] = "/home/kvm/s3";

int main(int argc, char **argv)
{
	struct s3gw_ctx ctx;
	char *access_id, *access_key;
	int ret;

	ctx.base_dir = default_base_dir;

	if (argc < 3) {
		printf("usage: %s <access_id> <access_secret>\n", argv[0]);
		return 1;
	}
	access_id = argv[1];
	access_key = argv[2];

	ret = create_owner_secret(&ctx, access_id, access_key);
	if (ret < 0)
		return 1;
	return 0;
}
