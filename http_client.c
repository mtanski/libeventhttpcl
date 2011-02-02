/* libc */
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
/* libevent */
#include <event-config.h>
#include <event.h>
/* openssl */
#include <openssl/bio.h>
#include <openssl/ssl.h>
/* http_client */
#include "http_client.h"

#define VERSION_MAJOR 0
#define VERSION_MINOR 1


#define FLAGS_HAVE_USER_AGENT       0x0001
#define FLAGS_HAVE_CONTENT_LENGTH   0x0002
#define FLAGS_HAVE_HOST             0x0004
#define FLAGS_HAVE_KEEP_ALIVE       0x0008


enum connection_fault
{
  FAULT_OKAY,
  FAULT_CLOSE,
  FAULT_ERROR,
  FAULT_FREE,
};

enum parse_state
{
  PARSE_ERROR       = -1,
  PARSE_MORE_DATA   = 0,
  PARSE_NEXT_STATE  = 1,
};

enum http_state {
  HTTP_NOT_CONNECTED,
  HTTP_CONNECTING,
  HTTP_IDLE,
  HTTP_READING_STATUS_LINE,
  HTTP_READING_HEADERS,
  HTTP_READING_BODY,
  HTTP_READING_DONE,
  HTTP_SENDING,
};


struct http_request
{
  struct http_client *api;

  struct evbuffer    *output;

  enum http_method    method;
  
  size_t              uri_len;
  const char         *uri;

  TAILQ_HEAD(,http_header) headers;

  size_t              body_len;
  const char         *body;
 
  /* User per request baton. */
  cb_http_response    callback;
  void               *baton;

  TAILQ_ENTRY(http_request) entry;
};

struct http_client
{
  uint16_t              version[2];
  const char*           host;

  struct {
    const char         *hostname;
    const char         *port;

    SSL_CTX*            ssl_ctx;
    SSL*                ssl;
    BIO*                buffer_io;

    struct event        ev;
  } connection;

  enum http_state       state;

  cb_http_disconnect    cb_disconnect;

  TAILQ_HEAD(, http_request) pending_request;

  struct http_response *current;
  struct evbuffer      *input;

  void *baton;
};

/*======================================================================================================================
 * 
 *  Function prototypes
 * 
 *====================================================================================================================== 
 */

static void     libevent_interopt(int fd, short what, void *baton);
static int      read_data(struct http_client *api);
static int      write_request(struct http_client *api);
static void     connection_fault(struct http_client *api, enum connection_fault fault);
static int      next_request(struct http_client *api);
static BIO*     connect_remote_host(struct http_client *api);


/*======================================================================================================================
 * 
 *  Util functions.
 * 
 *====================================================================================================================== 
 */

static
void *memdup(const void *src, size_t len)
{
  void *output;

  if ((output = malloc(len)) == NULL) {
    return NULL;
  }

  return memcpy(output, src, len);
}

static
void reschedule_event(struct event *ev, int fd, short what, void *baton)
{
  event_del(ev);
  event_set(ev, fd, what, libevent_interopt, baton);
  event_add(ev, NULL);
}


static
const char *get_method_str(enum http_method method)
{
  switch (method) {
    case HTTP_METHOD_GET:
      return "GET";
    case HTTP_METHOD_POST:
      return "POST";
    default:
      return NULL;
  }
}

static
struct http_header* find_header(struct http_response *response, const char *name)
{
  struct http_header *cur;

  TAILQ_FOREACH(cur, &response->headers, entry) {
    if (strncmp(cur->key, name, cur->key_len) == 0)
      return cur;
  }

  return NULL;
}

/*======================================================================================================================
 * 
 *  Request / response creation destruction.
 * 
 *====================================================================================================================== 
 */

static
struct http_header* new_header(const char *key, size_t key_len, const char *value, size_t value_len)
{
  struct http_header* header = calloc(1, sizeof(*header));

  if (header == NULL) {
    goto FAIL;
  }

  header->key_len = key_len;
  header->value_len = value_len;

  if ((header->key = strndup(key, key_len)) == NULL) {
    goto FAIL_TWO;
  }

  if ((header->value = strndup(value, value_len)) == NULL) {
    goto FAIL_TWO;
  }

  return header;

FAIL_TWO:
  free((void *) header->key);
  free((void *) header->value);
FAIL:
  free(header);
  return NULL;
}

static
struct http_response* new_response(struct http_request *request)
{
  struct http_response *response = calloc(1, sizeof(*response));

  if (response == NULL) {
    return NULL;
  }

  response->request = request;
  TAILQ_INIT(&response->headers);

  return response;

FAIL:
  free(response);
  return NULL;
}

static
void free_response(struct http_response *response)
{
  while (!TAILQ_EMPTY(&response->headers)) {
    struct http_header *cur = TAILQ_FIRST(&response->headers);
    TAILQ_REMOVE(&response->headers, cur, entry);
    free(cur);
  }

  free(response);
}

static
struct http_request* new_request(struct http_client *api)
{
  struct http_request *request;

  if ((request = calloc(1, sizeof(*request))) == NULL)
    goto FAIL_ONE;

  if ((request->output = evbuffer_new()) == NULL)
    goto FAIL_TWO;

  TAILQ_INIT(&request->headers);
  request->api = api;

  return request;

FAIL_TWO:
  free(request);
FAIL_ONE:
  return NULL;
}

static
void free_request(struct http_request *request)
{
  while (!TAILQ_EMPTY(&request->headers)) {
    struct http_header *cur = TAILQ_FIRST(&request->headers);
    TAILQ_REMOVE(&request->headers, cur, entry);
    free(cur);
  }

  free((void *) request->uri);
  free((void *) request->body);

  evbuffer_free(request->output);
  free(request);
}


/*======================================================================================================================
 * 
 *  Parse response
 * 
 *====================================================================================================================== 
 */

static
bool is_connection_close(struct http_client *api, struct http_response *response)
{
  struct http_header *header = find_header(response, "Connection");

  if (header == NULL) {
    goto SKIP;
  }

  if (api->version[VERSION_MINOR] == 1) {
    if (header && strncasecmp(header->value, "Close", header->value_len))
      return false;
  } else if (api->version[VERSION_MINOR] == 0) {
    if (strncasecmp(header->value, "Keep-Alive", header->value_len) == 0)
      return true;
  }

SKIP:
  return (api->version[VERSION_MINOR] == 1);
}

static
ssize_t get_body_len(struct http_response *response)
{
  struct http_header *header = find_header(response, "Content-Length");

  if (header)
    return atoi(header->value);

  return -1;
}

static
bool is_response_chunked(struct http_client *api, struct http_response *response)
{
  return false;
}

int find_body_len(struct http_client *api, struct http_response *response)
{
  if (is_response_chunked(api, response)) {
    response->body_chunked = true;
    return 0;
  }

  ssize_t body_len = get_body_len(response);

  if (body_len < 0) {
    return -1;
  }
  
  response->body_len = body_len;

  return 0;
}

static
enum parse_state read_status_line(struct http_client *api, struct http_response *response)
{
  enum parse_state  status;
  char             *line = evbuffer_readln(api->input, NULL, EVBUFFER_EOL_CRLF_STRICT);
  char             *token = line;

  /* Need more data. */
  if (line == NULL) {
    return PARSE_MORE_DATA;
  }

  char *protocol = strsep(&token, " ");
  char *status_code = strsep(&token, " ");

  if (protocol == NULL || status_code == NULL) {
    status = PARSE_ERROR;
    goto DONE;
  }

  if (strcmp(protocol, "HTTP/1.0") == 0) {
    api->version[VERSION_MINOR] = 0;
  } else if (strcmp(protocol, "HTTP/1.1") == 0) {
    api->version[VERSION_MINOR] = 1;
  } else {
    /* Unknow protocol version. */
    status = PARSE_ERROR;
  }

  response->status = atoi(status_code);

  status = PARSE_NEXT_STATE;

DONE:
  free(line);
  return status;
}

static
enum parse_state read_header_line(struct http_client *api, struct http_response *response)
{
  char *line, *sep, *value;

  do {
    line = evbuffer_readln(api->input, NULL, EVBUFFER_EOL_CRLF_STRICT);

    if (line == NULL) {
      /* Need more data. */
      free(line);
      return PARSE_MORE_DATA;
    } else if (*line == '\t' || *line == ' ') {
      /* Header contination. */
      /* TODO: */
    } else if (*line == '\0') {
      /* Header / body boundry. */
      free(line);

      /* Figure out the body we should be looking for. */
      if (find_body_len(api, response) == -1)
        return PARSE_ERROR;

      return PARSE_NEXT_STATE;
    }

    if ((sep = index(line, ':')) == NULL)
      return PARSE_ERROR;

    for (value = sep + 1; value != '\0'; value++) {
      if (*value == ' ' || *value == '\t') {
        continue;
      } else {
        break;
      }
    }

    struct http_header* header = new_header(line, sep - line, value, strlen(value));

    if (header == NULL) {
      return PARSE_ERROR;
    }

    TAILQ_INSERT_TAIL(&response->headers, header, entry);

    free(line);
  } while (1);
}

static
enum parse_state read_body(struct http_client *api, struct http_response *response)
{
  /* Special case that cannot have a body:
   *   - 1xx status
   *   - 204 status
   *   - 304 status
   *   - HEAD method
   */
  if ((response->status >= 100 && response->status <= 199) ||
      response->status == 204 ||
      response->status == 304 ||
      response->request->method == HTTP_METHOD_HEAD)
  {
    return PARSE_NEXT_STATE;
  }

  /* Chunked encomding. */
  if (0) 
    return PARSE_MORE_DATA; 

  return (EVBUFFER_LENGTH(api->input) >= response->body_len) ? PARSE_NEXT_STATE : PARSE_MORE_DATA;
}

static
int dispatch_response(struct http_client *api, struct http_response *response)
{
  struct http_request *request = TAILQ_FIRST(&api->pending_request);

  TAILQ_REMOVE(&api->pending_request, request, entry);

  /* Tempoary pointer into the evbuffer. */
  response->body = EVBUFFER_DATA(api->input);

  if (request->callback != NULL) {
    request->callback(api, request, response, request->baton);
  }

  /* Get rid of the body from the buffer. */
  evbuffer_drain(api->input, response->body_len);


  if (response->body_chunked == true) {
    /* Chunked, already closed connection */
  } else if (is_connection_close(api, response)) {
    if (response != NULL) {
      connection_fault(api, FAULT_CLOSE);
    }
  } else {
    api->state = HTTP_IDLE;
  }

  /* Free response & request. */
  free_response(response);
  free_request(request);

  api->current = NULL;

  return 0;
}

static
int read_response(struct http_client *api)
{
  enum parse_state result; 

  do {
    switch (api->state) {
      case HTTP_READING_STATUS_LINE:
        result = read_status_line(api, api->current);
        break;
      case HTTP_READING_HEADERS:
        result = read_header_line(api, api->current);
        break;
      case HTTP_READING_BODY:
        result = read_body(api, api->current);
        break;
      case HTTP_READING_DONE:
        if ((result = dispatch_response(api, api->current)) == 0) {
          next_request(api);
          return 0;
        }
    }

    switch (result) {
      /* Need more data. */
      case PARSE_MORE_DATA: break;
      /* Increment FSM to next state. */
      case PARSE_NEXT_STATE:
        api->state++;
        break;
      /* Error. */
      case PARSE_ERROR:
      default:
        connection_fault(api, FAULT_ERROR);
        return -1;
    }
  } while (result == 1);
}

/*======================================================================================================================
 * 
 *  Create request buffer
 * 
 *====================================================================================================================== 
 */

static
int add_req_line(struct http_request *request)
{
  const char *method_str = get_method_str(request->method);

  return evbuffer_add_printf(request->output, "%s %.*s HTTP/%i.%i\r\n", method_str, request->uri_len, request->uri, 
                                              request->api->version[VERSION_MAJOR], 
                                              request->api->version[VERSION_MINOR]);
}

static
int add_header(struct evbuffer *buffer, struct http_header *header)
{
  return evbuffer_add_printf(buffer, "%.*s: %.*s\r\n", header->key_len, header->key_len, header->value_len,
                                     header->value);
}

static
int add_headers(struct http_request *request)
{
  int flags = 0;

  /* Add other headers */
  struct http_header *cur;
  TAILQ_FOREACH(cur, &request->headers, entry) {

    if (strncmp(cur->key, "Host", cur->key_len) == 0)
      flags |= FLAGS_HAVE_HOST;
    else if (strncmp(cur->key, "Content-Length", cur->key_len) == 0)
      flags |= FLAGS_HAVE_CONTENT_LENGTH;
    else if (strncmp(cur->key, "User-Agent", cur->key_len) == 0)
      flags |= FLAGS_HAVE_USER_AGENT;
    else if (strncmp(cur->key, "Connection", cur->key_len) == 0)
      flags |= FLAGS_HAVE_KEEP_ALIVE;

    add_header(request->output, cur);
  }

  if (!(flags & FLAGS_HAVE_HOST)) {
    evbuffer_add_printf(request->output, "Host: %s\r\n", request->api->connection.hostname);
  }

  if (!(flags & FLAGS_HAVE_CONTENT_LENGTH) && request->body_len > 0) {
    evbuffer_add_printf(request->output, "Conntent-Length: %i\r\n", request->body_len);
  }

  if (!(flags & FLAGS_HAVE_USER_AGENT)) {
    evbuffer_add_printf(request->output, "User-Agent: Admeld http_client\r\n");
  }

  if (!(flags & FLAGS_HAVE_KEEP_ALIVE)) {
    evbuffer_add_printf(request->output, "Connection: Keep-Alive\r\n");
  }

  return 0;
}

static
int add_body(struct http_request *request)
{
  if (request->body_len > 0) {
    evbuffer_add(request->output, request->body, request->body_len);
  }

  return 0;
}

static
int next_request(struct http_client *api)
{         
  if (TAILQ_EMPTY(&api->pending_request)) {
    event_del(&api->connection.ev);
    api->state = HTTP_IDLE;
    return 0;
  }

  /* Schedule write. */
  if (event_pending(&api->connection.ev, EV_READ|EV_WRITE, NULL)) {
    reschedule_event(&api->connection.ev, api->connection.ev.ev_fd, EV_WRITE, api);
  } else {
    int fd;
    BIO_get_fd(api->connection.buffer_io, &fd);

    event_set(&api->connection.ev, fd, EV_WRITE, libevent_interopt, api);
    event_add(&api->connection.ev, NULL);
  }

  api->state = HTTP_SENDING;

  return 0;
}


/*======================================================================================================================
 * 
 *  Connection write, read, parse state machine.
 * 
 *====================================================================================================================== 
 */

static
void connection_fault(struct http_client *api, enum connection_fault fault)
{
  /* Fault all pending request. */
  if (fault != FAULT_CLOSE) {
    struct http_request *request;
    for (request = TAILQ_FIRST(&api->pending_request); request != NULL; request = TAILQ_FIRST(&api->pending_request)) {

      /* Run callback, with an error response. */
      if (request->callback != NULL)
        request->callback(api, request, NULL, request->baton);

      TAILQ_REMOVE(&api->pending_request, request, entry);
      free_request(request);
    }
  }

  if (fault == FAULT_CLOSE && api->current) {
    if (api->current->body_chunked == true) {
      /* Set the length, it's the whole buffer. */
      api->current->body_len = EVBUFFER_LENGTH(api->input);

      dispatch_response(api, api->current);
    }

    /* TODO: Error, cancel pending request / response. */
  }

  /* Run disconnect callback. */
  if (api->cb_disconnect != NULL)
    api->cb_disconnect(api, api->baton);

  /* TODO: close connection. */

  /* Set status FSM. */
  api->state = HTTP_NOT_CONNECTED;

  /* Reset BIO but try to keep resume SSL session on reconnect. */
  if (api->connection.ssl_ctx) {
    BIO_reset(api->connection.buffer_io);
  }

  /* Process remaning requests. */
  if (fault == FAULT_CLOSE && !TAILQ_EMPTY(&api->pending_request)) {
    if ((api->connection.buffer_io = connect_remote_host(api)) == NULL) {
      /* Error, dump the queue. */
      connection_fault(api, FAULT_ERROR);
    }
  }
}

static
int ssl_negociate(struct http_client *api)
{
  /* Do handshake. */

  /* Verify ceficate. */
  if(SSL_get_verify_result(api->connection.ssl) != X509_V_OK)
    return -1;

  /* Wait till we can write out request out. */ 
  reschedule_event(&api->connection.ev, api->connection.ev.ev_fd, EV_WRITE, api);

  return 0;
}

static
void libevent_interopt(int fd, short what, void *baton)
{
  int                 result;
  struct http_client *api = (struct http_client *) baton;

  switch (api->state) {
    case HTTP_CONNECTING:
      if (api->connection.ssl_ctx) {
        if (ssl_negociate(api) == -1) {

        }

        return;
      } else {
        api->state = HTTP_SENDING;
        /* And fall through. */
      }
    case HTTP_SENDING:
      /* Write the data out. */
      write_request(api);
      return;
    case HTTP_READING_STATUS_LINE:
    case HTTP_READING_HEADERS:
    case HTTP_READING_BODY:
      do {
        /* Read into evbuffer */
        if ((result = read_data(api)) == -1) return;
      } while (result == 1);

      /* Do the read callback. */
      read_response(api);
      return;
    case HTTP_IDLE:
      /*  */
      ;
  }
}

/*======================================================================================================================
 * 
 *  Network IO
 * 
 *====================================================================================================================== 
 */


static
int write_request(struct http_client *api)
{
  struct http_request *request;

  if (TAILQ_EMPTY(&api->pending_request)) {
    return 0;
  }

  request = TAILQ_FIRST(&api->pending_request);

  int result = BIO_write(api->connection.buffer_io, EVBUFFER_DATA(request->output), EVBUFFER_LENGTH(request->output));

  if (result < 1) {
    if (BIO_should_retry(api->connection.buffer_io)) {
      return 0;
    }

    connection_fault(api, FAULT_ERROR);
    return -1;
  }

  /* Drain the data we wrote out. */
  evbuffer_drain(request->output, result);

  if (EVBUFFER_LENGTH(request->output) == 0) {
    if ((api->current = new_response(request)) == NULL)
      return -1;

    api->state = HTTP_READING_STATUS_LINE;

    /* Turn off write notification and turn on read notification. */
    reschedule_event(&api->connection.ev, api->connection.ev.ev_fd, EV_READ, api);
  }

  return 0;
}

static
int read_data(struct http_client *api)
{
  char buffer[1024];

  int result = BIO_read(api->connection.buffer_io, buffer, sizeof(buffer));

  if (result > 0) {
    evbuffer_add(api->input, buffer, result);
    return (result >= sizeof(buffer));
  } else if (result == 0) {
    /* Other side closed the connection */
    connection_fault(api, FAULT_CLOSE);
    return -1;
  }

  /* We'll try again in the future again. */
  if (BIO_should_retry(api->connection.buffer_io)) {
    return 0;
  }

  /* Error */
  connection_fault(api, FAULT_ERROR);
  return -1;
}

static
BIO* connect_remote_host(struct http_client *api)
{
  BIO *result;

  if (api->connection.ssl_ctx != NULL) {
    result = BIO_new_ssl_connect(api->connection.ssl_ctx);

    if (result) {
      BIO_set_conn_hostname(result, api->connection.hostname);
      BIO_get_ssl(result, &api->connection.ssl);
      SSL_set_mode(api->connection.ssl, SSL_MODE_AUTO_RETRY);
    }

  } else {
    result = BIO_new_connect((char *) api->connection.hostname);
  }

  if (result == NULL) {
    goto FAIL_ONE;
  }

  BIO_set_conn_port(result, api->connection.port);

  /* Set it to non-blocking mode. */
  BIO_set_nbio(result, 1);

  if (BIO_do_connect(result) == -1) {

    if (BIO_should_retry(result)) {
      int reason = BIO_get_retry_reason(result);
    } else {
      goto FAIL_TWO;
    }
  }

  int fd;
  BIO_get_fd(result, &fd);
  short what = (api->connection.ssl_ctx) ? EV_READ : EV_WRITE;

  event_set(&api->connection.ev, fd, what, libevent_interopt, api);
  event_add(&api->connection.ev, NULL);

  api->state = HTTP_CONNECTING;

  return result;

FAIL_TWO:
  BIO_free_all(result);
FAIL_ONE:
  return NULL;
}

static
int setup_ssl(struct http_client *api, SSL_CTX* ctx)
{
  api->connection.ssl_ctx = ctx;
  api->connection.ssl = NULL;
}

/*======================================================================================================================
 * 
 *  Public API 
 * 
 *====================================================================================================================== 
 */

struct http_client *http_client_new(const char *hostname, const char *port, SSL_CTX* ssl_ctx)
{
  struct http_client *api = calloc(1, sizeof(*api));

  if (api == NULL) {
    goto FAIL_ONE;
  }

  api->version[VERSION_MAJOR] = 1;
  api->version[VERSION_MINOR] = 1;

  api->state = HTTP_NOT_CONNECTED;

  TAILQ_INIT(&api->pending_request);

  if ((api->connection.hostname = strdup(hostname)) == NULL)
    goto FAIL_TWO;
  if ((api->connection.port = strdup(port)) == NULL)
    goto FAIL_TWO;

  if (ssl_ctx != NULL) {
    if (setup_ssl(api, ssl_ctx) == -1)
      goto FAIL_TWO;
  }

  if ((api->input = evbuffer_new()) == NULL) {
    goto FAIL_THREE;
  }

  return api;

FAIL_THREE:
  evbuffer_free(api->input);
FAIL_TWO:
  free((void *) api->connection.hostname);
  free((void *) api->connection.port);
  free(api);
FAIL_ONE:
  return NULL;
}

void http_client_free(struct http_client *api)
{
  BIO_free_all(api->connection.buffer_io);

  connection_fault(api, FAULT_FREE);

  free(api);
}

struct http_request *http_client_request(struct http_client *api, enum http_method method, size_t uri_len,
                                         const char *uri)
{
  struct http_request *request = new_request(api);

  if (request == NULL)
    return NULL;

  request->method = method;
  request->uri_len = uri_len;

  if ((request->uri = memdup(uri, uri_len)) == NULL) {
    goto FAIL;
  }

  return request;

FAIL:
  free_request(request);
  return NULL;
}

int http_client_request_add_header(struct http_request *request, const char *key, const char *value)
{
  struct http_header *header = malloc(sizeof(*header));

  if (header == NULL) {
    goto FAIL_ONE;
  }

  header->key_len = strlen(key);
  header->value_len = strlen(value);

  if ((header->key = memdup(key, header->key_len)) == NULL) {
    goto FAIL_TWO;
  }

  if ((header->value = memdup(value, header->value_len)) == NULL) {
    goto FAIL_THREE;
  }

  TAILQ_INSERT_TAIL(&request->headers, header, entry);
  return 0;

FAIL_THREE:
  free((void *) header->key);
FAIL_TWO:
  free(header);
FAIL_ONE:
  return -1;
}

int http_client_request_add_body(struct http_request *request, size_t body_len, const char *body)
{
  if ((request->body = malloc(body_len)) == NULL) {
    return -1;
  }

  memcpy((void *) request->body, body, body_len);
  request->body_len = body_len;

  return 0;
}

int http_client_request_dispatch(struct http_request *request, cb_http_response callback, void *baton)
{
  struct http_client *api = request->api;
  BIO *bio;

  request->callback = callback;
  request->baton = baton;

  if (add_req_line(request) == -1) {
    return -1;
  }

  if (add_headers(request) == -1) {
    return -1;
  }

  if (add_body(request) == -1) {
    return -1;
  }

  if (evbuffer_add_printf(request->output, "\r\n") == -1)
    return -1;

  /* Stick in the stack for sending it out. */
  TAILQ_INSERT_TAIL(&request->api->pending_request, request, entry);

  switch (request->api->state) {
    case HTTP_NOT_CONNECTED:
      if ((bio = connect_remote_host(request->api)) == NULL) {
        return -1; 
      }

      api->connection.buffer_io = bio;
      return 0;
    case HTTP_IDLE:
      /* Schedule processing of the next request. */
      next_request(api);
  }

  return 0;
}

