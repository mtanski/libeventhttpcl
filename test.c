/* libc */
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
/* libevent */
#include <event-config.h>
#include <event.h>
/* openssl */
#include <openssl/bio.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "http_client.h"

void callback(struct http_client *api, struct http_request *req, struct http_response *response, void *baton)
{
  printf("%.*s", response->body_len, response->body);
}

int main(int argc, char *argv[])
{
  bool          do_ssl = false;
  const char   *url = argv[1];

  const char   *domain = argv[1];
  const char   *port = argv[2];
  const char   *uri = argv[3];

  if (argc < 4) {
    printf("ERROR: Need url, port and uri\n");
    return 1;
  }

  SSL_load_error_strings();
  ERR_load_BIO_strings();
  OpenSSL_add_all_algorithms();

  event_init();

  struct http_client   *client = http_client_new(domain, port, NULL);
  struct http_request  *req = http_client_request(client, HTTP_METHOD_GET, strlen(uri), uri);

  http_client_request_dispatch(req, callback, NULL);

  event_loop(0);

  return 1;
}
