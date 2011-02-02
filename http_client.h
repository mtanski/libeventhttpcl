#ifndef __HTTP_CLIENT_H__
#define __HTTP_CLIENT_H__

#include <sys/queue.h>

enum http_method
{
  HTTP_METHOD_GET,
  HTTP_METHOD_POST,
  HTTP_METHOD_HEAD,
  HTTP_METHOD_PUT,
  HTTP_METHOD_DELETE,
};

struct http_client;

struct http_header
{
  size_t      key_len;
  const char *key;

  size_t      value_len;
  const char *value;

  TAILQ_ENTRY(http_header) entry;
};

struct http_response
{
  struct http_request *request;

  uint16_t          status;
    
  size_t            url_len;
  const char       *url;

  size_t            body_len;
  const char       *body;

  TAILQ_HEAD(,http_header) headers;
};

struct http_request;

/* Callback functions */
typedef void (*cb_http_response)(struct http_client *, struct http_request *, struct http_response *, void *baton);
typedef void (*cb_http_disconnect)(struct http_client *, void *baton);

/** 
 * New http_client connection instance 
 * 
 * @param hostname  Hostname or ip address of web server.
 * @param port 
 * @param ssl 
 * 
 * @return struct http_client* Client connection handle.
 */
struct http_client *http_client_new(const char *hostname, const char *port, SSL_CTX* ssl_ctx);

/**
 * Close http_client connection, cancel all pending requests.
 * 
 * @param api 
 */
void http_client_free(struct http_client *api);

/**
 * Queue a new HTTP client request.
 * 
 * @param api 
 * @param method 
 * @param uri_len 
 * @param uri 
 * 
 * @return struct http_request* 
 */
struct http_request *http_client_request(struct http_client *api, enum http_method method, size_t uri_len,
                                         const char *uri);

int http_client_request_add_header(struct http_request *request, const char *key, const char *value);

int http_client_request_add_body(struct http_request *request, size_t body_len, const char *body);

/**
 * Make this request pending.
 * 
 * @param request 
 * @return int success / failure flag.
 */
int http_client_request_dispatch(struct http_request *request, cb_http_response callback, void *baton);

/* TODO: */
int http_client_cancel(struct http_request *request);

#endif /* __HTTP_CLIENT_H__ */
