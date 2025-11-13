#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

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

#define BACKLOG 16

static int tcp_listen(struct s3gw_ctx *ctx)
{
	struct addrinfo *ai, hints;
	char default_port[] = "7878";
	char *host, *port, *p = NULL;
	int listenfd, reuse = 1, ret;
	sa_family_t adrfam = AF_INET;

	host = strdup(ctx->hostport);
	p = strrchr(host, ':');
	if (!p) {
		fprintf(stderr, "no port number, defaulting to %s\n",
			default_port);
		port = strdup(default_port);
	} else if (p == host) {
		fprintf(stderr, "invalid host '%s'\n", host);
		return -EINVAL;
	} else {
		*p = '\0';
		p++;
		port = strdup(p);
	}
		
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = adrfam;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_NUMERICSERV | AI_PASSIVE;

	ret = getaddrinfo(host, port, &hints, &ai);
	if (ret != 0) {
		fprintf(stderr, "getaddrinfo() on %s:%s failed: %s\n",
			 host, port, gai_strerror(ret));
		return -EINVAL;
	}
	if (!ai) {
		fprintf(stderr, "no results from getaddrinfo()\n");
		return -EHOSTUNREACH;
	}
	listenfd = socket(ai->ai_family, ai->ai_socktype,
			 ai->ai_protocol);
	if (listenfd < 0) {
		fprintf(stderr, "socket error %d\n", errno);
		ret = -errno;
		goto err_free;
	}
	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR,
		       &reuse, sizeof(int)) < 0) {
		fprintf(stderr, "setsockopt SO_REUSEADDR error %d\n", errno);
		ret = -errno;
		goto err_close;
	}
	ret = bind(listenfd, ai->ai_addr, ai->ai_addrlen);
	if (ret < 0) {
		fprintf(stderr, "socket %s:%s bind error %d\n",
			host, port, errno);
		ret = -errno;
		goto err_close;
	}
	if (ai->ai_next)
		fprintf(stderr, "duplicate addresses\n");
	freeaddrinfo(ai);

	ret = listen(listenfd, BACKLOG);
	if (ret < 0) {
		fprintf(stderr, "socket listen error %d\n", errno);
		ret = -errno;
		close(listenfd);
	} else {
		printf("listening on %s:%s", host, port);
		ctx->fd = listenfd;
		ret = 0;
	}
	return ret;
err_close:
	close(listenfd);
err_free:
	freeaddrinfo(ai);
	return ret;
}

static int tcp_wait_for_connection(struct s3gw_ctx *ctx)
{
	int ret = -ESHUTDOWN;

	while (ctx->fd > 0) {
		fd_set rfd;
		struct timeval tmo;

		FD_ZERO(&rfd);
		FD_SET(ctx->fd, &rfd);
		tmo.tv_sec = 1;
		tmo.tv_usec = 0;
		ret = select(ctx->fd + 1, &rfd, NULL, NULL, &tmo);
		if (ret < 0) {
			fprintf(stderr, "select error %d", errno);
			ret = -errno;
			break;
		}
		if (ret > 0)
			break;
	}

	return ret;
}

static int tcp_accept(struct s3gw_ctx *ctx, struct s3gw_request *req)
{
	int sockfd;
	int ret;

	sockfd = accept(ctx->fd, (struct sockaddr *)NULL, NULL);
	if (sockfd < 0) {
		if (errno != EAGAIN)
			fprintf(stderr, "accept error %d\n", errno);
		ret = -EAGAIN;
	} else
		req->fd = sockfd;
	return ret;
}

static void tcp_close(struct s3gw_request *req)
{
	close(req->fd);
}

static void tcp_free(struct s3gw_ctx *ctx)
{
	close(ctx->fd);
	free(ctx);
}

void tcp_loop(struct s3gw_ctx *ctx)
{
	tcp_listen(ctx);

	/* Wait for incoming connection */
	for (;;) {
		struct s3gw_request req;
		size_t total;

		if (tcp_wait_for_connection(ctx) <= 0) {
			/* Client went away before we accepted the connection */
			continue;
		}

		memset(&req, 0, sizeof(req));
		req.op = API_OPS_UNKNOWN;
		http_parser_init(&req.http, HTTP_REQUEST);
		req.http.data = &req;

		if (tcp_accept(ctx, &req) <= 0)
			continue;

		total = handle_request(&req);

		fprintf(stderr, "Client connection closed, %zu bytes sent\n",
			total);
		tcp_close(&req);
	}

	tcp_free(ctx);
}
