/*
 * Copyright (c) 2026 Yuichi Nakamura (@yunkya2)
 *
 * The MIT License (MIT)
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <stdbool.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#if defined(USE_SSL) && USE_SSL
#include "ssl.h"
#else
typedef void *SSL_CTX;
#endif
#include "iconv_mini.h"

//****************************************************************************
// Macros and definitions
//****************************************************************************

#define BUF_SIZE        16384
#define MAX_URL_LEN     8192

#ifdef __human68k__
int _stack_size = 128 * 1024;
#endif

//****************************************************************************
// Data structures
//****************************************************************************

typedef struct {
    char scheme[8];
    char host[256];
    int port;
    char path[8192];
    char user[128];
    char pass[128];
    bool has_auth;
} Url;

typedef struct {
    int fd;
#if defined(USE_SSL) && USE_SSL
    SSL *ssl;
#endif
    bool use_ssl;
} Conn;

typedef struct {
    int status;
    long content_length;
    bool chunked;
    char location[MAX_URL_LEN];
    char content_type[128];
} HttpMeta;

typedef struct {
    bool enabled;
    char pending[4];
    size_t pending_len;
} TextConvState;

//****************************************************************************
// Utility functions
//****************************************************************************

/**
 * die - Print error message and exit
 * @fmt: printf-style format string
 * @...: variable arguments for format string
 *
 * Prints error message to stderr and exits with status 1.
 */
static void die(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
    exit(1);
}

/**
 * warn_msg - Print warning message
 * @fmt: printf-style format string
 * @...: variable arguments for format string
 *
 * Prints warning message to stderr without exiting.
 */
static void warn_msg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    fputc('\n', stderr);
}

/**
 * starts_with - Check if string starts with prefix
 * @s: string to check
 * @prefix: prefix to look for
 *
 * Return: true if s starts with prefix, false otherwise
 */
static bool starts_with(const char *s, const char *prefix)
{
    return strncmp(s, prefix, strlen(prefix)) == 0;
}

/**
 * copy_cstr_or_die - Copy C string with bounds checking
 * @dst: destination buffer
 * @dst_len: size of destination buffer
 * @src: source string
 * @ctx: context name for error messages
 *
 * Copies src to dst, exiting if it doesn't fit.
 */
static void copy_cstr_or_die(char *dst, size_t dst_len, const char *src, const char *ctx)
{
    size_t n = strlen(src);
    if (n >= dst_len) {
        die("%s too long", ctx);
    }
    memcpy(dst, src, n + 1);
}

/**
 * append_cstr_or_die - Append C string with bounds checking
 * @dst: destination buffer (must already contain a string)
 * @dst_len: size of destination buffer
 * @src: source string to append
 * @ctx: context name for error messages
 *
 * Appends src to dst, exiting if result doesn't fit.
 */
static void append_cstr_or_die(char *dst, size_t dst_len, const char *src, const char *ctx)
{
    size_t used = strlen(dst);
    size_t add = strlen(src);
    if (used + add >= dst_len) {
        die("%s too long", ctx);
    }
    memcpy(dst + used, src, add + 1);
}

/**
 * append_port_or_die - Append port number as string
 * @dst: destination buffer (must already contain a string)
 * @dst_len: size of destination buffer
 * @port: port number to append
 * @ctx: context name for error messages
 *
 * Converts port to string and appends to dst, exiting if it doesn't fit.
 */
static void append_port_or_die(char *dst, size_t dst_len, int port, const char *ctx)
{
    char tmp[16];
    int n = snprintf(tmp, sizeof(tmp), "%d", port);
    if (n <= 0 || (size_t)n >= sizeof(tmp)) {
        die("invalid port in %s", ctx);
    }
    append_cstr_or_die(dst, dst_len, tmp, ctx);
}

//****************************************************************************
// URL parsing functions
//****************************************************************************

/**
 * url_init - Initialize URL structure with defaults
 * @u: URL structure to initialize
 *
 * Sets default values (HTTP, port 80, path /).
 */
static void url_init(Url *u)
{
    memset(u, 0, sizeof(*u));
    strcpy(u->scheme, "http");
    strcpy(u->host, "");
    u->port = 80;
    strcpy(u->path, "/");
    u->has_auth = false;
}

/**
 * addr_to_ip - Convert addrinfo to IP address string
 * @ai: addrinfo structure from getaddrinfo
 * @buf: buffer to store IP address string
 * @buf_len: size of buffer
 *
 * Converts IPv4 address to dotted decimal notation.
 */
static void addr_to_ip(const struct addrinfo *ai, char *buf, size_t buf_len)
{
    void *addr_ptr = NULL;

    if (ai->ai_family == AF_INET) {
        struct sockaddr_in *sa = (struct sockaddr_in *)ai->ai_addr;
        addr_ptr = &sa->sin_addr;
    } else {
        buf[0] = '\0';
        return;
    }

    if (!inet_ntop(ai->ai_family, addr_ptr, buf, buf_len)) {
        buf[0] = '\0';
    }
}

/**
 * open_tcp_connection - Open TCP connection to host:port
 * @host: hostname or IP address
 * @port: TCP port number
 * @quiet: if true, suppress output
 *
 * Resolves hostname and establishes TCP connection.
 * Return: file descriptor on success, exits on failure
 */
static int open_tcp_connection(const char *host, int port, bool quiet)
{
    struct addrinfo hints;
    struct addrinfo *res = NULL;
    char port_str[16];

    snprintf(port_str, sizeof(port_str), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int rc = getaddrinfo(host, port_str, &hints, &res);
    if (rc != 0) {
        die("getaddrinfo failed: %d", rc);
    }

    char first_ip[128];
    first_ip[0] = '\0';
    if (res) {
        addr_to_ip(res, first_ip, sizeof(first_ip));
    }
    if (!quiet) {
        if (first_ip[0] != '\0') {
            fprintf(stderr, "Resolving %s... %s\n", host, first_ip);
        } else {
            fprintf(stderr, "Resolving %s...\n", host);
        }
    }

    int fd = -1;
    struct addrinfo *p;
    for (p = res; p; p = p->ai_next) {
        char ip[128];
        ip[0] = '\0';
        addr_to_ip(p, ip, sizeof(ip));
        if (!quiet) {
            if (ip[0] != '\0') {
                fprintf(stderr, "Connecting to %s |%s|:%d... ", host, ip, port);
            } else {
                fprintf(stderr, "Connecting to %s:%d... ", host, port);
            }
        }
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd < 0) {
            if (!quiet) fprintf(stderr, "failed\n");
            continue;
        }
        if (connect(fd, p->ai_addr, p->ai_addrlen) == 0) {
            if (!quiet) fprintf(stderr, "connected.\n");
            break;
        }
        if (!quiet) fprintf(stderr, "failed: %s\n", strerror(errno));
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);

    if (fd < 0) {
        die("connect failed: %s", strerror(errno));
    }
    return fd;
}

/**
 * parse_url - Parse URL string into components
 * @s: URL string (http://, https://, or ftp://)
 * @u: URL structure to fill
 *
 * Parses scheme, host, port, path, and optional authentication.
 * Return: true on success, false if URL is invalid
 */
static bool parse_url(const char *s, Url *u)
{
    url_init(u);
    if (starts_with(s, "http://")) {
        strcpy(u->scheme, "http");
        s += 7;
        u->port = 80;
    } else if (starts_with(s, "https://")) {
        strcpy(u->scheme, "https");
        s += 8;
        u->port = 443;
    } else if (starts_with(s, "ftp://")) {
        strcpy(u->scheme, "ftp");
        s += 6;
        u->port = 21;
    } else {
        return false;
    }

    const char *slash = strchr(s, '/');
    const char *auth_end = slash ? slash : s + strlen(s);
    const char *auth_start = s;
    const char *at = memchr(auth_start, '@', auth_end - auth_start);

    if (at) {
        const char *userinfo = auth_start;
        size_t userinfo_len = (size_t)(at - userinfo);
        const char *sep = memchr(userinfo, ':', userinfo_len);
        if (sep) {
            size_t ulen = (size_t)(sep - userinfo);
            size_t plen = (size_t)(userinfo + userinfo_len - (sep + 1));
            if (ulen >= sizeof(u->user) || plen >= sizeof(u->pass)) return false;
            memcpy(u->user, userinfo, ulen);
            u->user[ulen] = '\0';
            memcpy(u->pass, sep + 1, plen);
            u->pass[plen] = '\0';
        } else {
            if (userinfo_len >= sizeof(u->user)) return false;
            memcpy(u->user, userinfo, userinfo_len);
            u->user[userinfo_len] = '\0';
            u->pass[0] = '\0';
        }
        u->has_auth = true;
        auth_start = at + 1;
    }

    const char *host_end = auth_end;
    const char *colon = memchr(auth_start, ':', host_end - auth_start);

    if (colon) {
        size_t host_len = (size_t)(colon - auth_start);
        if (host_len >= sizeof(u->host)) return false;
        memcpy(u->host, auth_start, host_len);
        u->host[host_len] = '\0';
        u->port = atoi(colon + 1);
        if (u->port <= 0) return false;
    } else {
        size_t host_len = (size_t)(host_end - auth_start);
        if (host_len >= sizeof(u->host)) return false;
        memcpy(u->host, auth_start, host_len);
        u->host[host_len] = '\0';
    }

    if (slash) {
        strncpy(u->path, slash, sizeof(u->path) - 1);
        u->path[sizeof(u->path) - 1] = '\0';
    } else {
        strcpy(u->path, "/");
    }

    return true;
}

/**
 * resolve_location - Resolve relative/absolute redirect URL
 * @base: base URL for relative resolution
 * @loc: Location header value
 * @out: buffer to store resolved URL
 * @out_len: size of output buffer
 *
 * Handles absolute URLs, absolute paths, and relative paths.
 */
static void resolve_location(const Url *base, const char *loc, char *out, size_t out_len)
{
    if (starts_with(loc, "http://") || starts_with(loc, "https://")) {
        copy_cstr_or_die(out, out_len, loc, "redirect URL");
        return;
    }

    if (loc[0] == '/') {
        out[0] = '\0';
        append_cstr_or_die(out, out_len, base->scheme, "redirect URL");
        append_cstr_or_die(out, out_len, "://", "redirect URL");
        append_cstr_or_die(out, out_len, base->host, "redirect URL");
        append_cstr_or_die(out, out_len, ":", "redirect URL");
        append_port_or_die(out, out_len, base->port, "redirect URL");
        append_cstr_or_die(out, out_len, loc, "redirect URL");
        return;
    }

    char dir[1024];
    strncpy(dir, base->path, sizeof(dir) - 1);
    dir[sizeof(dir) - 1] = '\0';
    char *last = strrchr(dir, '/');
    if (last) {
        *(last + 1) = '\0';
    } else {
        strcpy(dir, "/");
    }
    out[0] = '\0';
    append_cstr_or_die(out, out_len, base->scheme, "redirect URL");
    append_cstr_or_die(out, out_len, "://", "redirect URL");
    append_cstr_or_die(out, out_len, base->host, "redirect URL");
    append_cstr_or_die(out, out_len, ":", "redirect URL");
    append_port_or_die(out, out_len, base->port, "redirect URL");
    append_cstr_or_die(out, out_len, dir, "redirect URL");
    append_cstr_or_die(out, out_len, loc, "redirect URL");
}

//****************************************************************************
// File I/O functions
//****************************************************************************

/**
 * open_output_file_with_mode - Open output file for writing
 * @path: file path
 * @append: if true, append; if false, truncate
 *
 * Return: file descriptor on success, -1 on error
 */
static int open_output_file_with_mode(const char *path, bool append)
{
    int flags = O_CREAT | O_WRONLY | (append ? O_APPEND : O_TRUNC);
#ifdef __human68k__
    flags |= O_BINARY;
#endif
    return open(path, flags, 0644);
}

/**
 * get_existing_file_size - Get size of existing file
 * @path: file path
 *
 * Return: file size in bytes, or 0 if file doesn't exist or on error
 */
static long get_existing_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    if (!S_ISREG(st.st_mode)) return 0;
    if (st.st_size < 0) return 0;
    if (st.st_size > LONG_MAX) return LONG_MAX;
    return (long)st.st_size;
}

/**
 * ensure_dir - Create directory if it doesn't exist
 * @dir: directory path
 *
 * Creates directory with permissions 0755, exits on failure.
 */
static void ensure_dir(const char *dir)
{
    struct stat st;
    if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode)) return;
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        die("mkdir failed: %s", strerror(errno));
    }
}

/**
 * pick_output_name - Determine output filename
 * @u: parsed URL
 * @out_path: explicit output path (or NULL)
 * @out_dir: output directory (or NULL)
 * @result: buffer to store result
 * @result_len: size of result buffer
 *
 * Determines output filename from -O option, -P option, or URL path.
 */
static void pick_output_name(const Url *u, const char *out_path, const char *out_dir,
                             char *result, size_t result_len)
{
    if (out_path && out_path[0] != '\0') {
        strncpy(result, out_path, result_len - 1);
        result[result_len - 1] = '\0';
        return;
    }

    const char *path = u->path;
    const char *path_end = strpbrk(path, "?#");
    size_t path_len = path_end ? (size_t)(path_end - path) : strlen(path);

    const char *name = "index.html";
    size_t name_len = strlen(name);
    if (path_len > 0) {
        const char *last_slash = NULL;
        for (size_t i = 0; i < path_len; i++) {
            if (path[i] == '/') last_slash = path + i;
        }
        const char *cand = last_slash ? (last_slash + 1) : path;
        size_t cand_len = (size_t)((path + path_len) - cand);
        if (cand_len > 0) {
            name = cand;
            name_len = cand_len;
        }
    }

    char name_buf[1024];
    if (name_len >= sizeof(name_buf)) {
        name_len = sizeof(name_buf) - 1;
    }
    memcpy(name_buf, name, name_len);
    name_buf[name_len] = '\0';

    if (out_dir && out_dir[0] != '\0') {
        ensure_dir(out_dir);
        result[0] = '\0';
        append_cstr_or_die(result, result_len, out_dir, "output path");
        append_cstr_or_die(result, result_len, "/", "output path");
        append_cstr_or_die(result, result_len, name_buf, "output path");
    } else {
        strncpy(result, name_buf, result_len - 1);
        result[result_len - 1] = '\0';
    }
}

//****************************************************************************
// Network connection functions
//****************************************************************************

/**
 * conn_open - Open connection (TCP or TLS)
 * @u: parsed URL
 * @quiet: if true, suppress output
 * @ssl_ctx: SSL context (if HTTPS)
 *
 * Opens TCP connection and performs TLS handshake if needed.
 * Return: connection structure
 */
static Conn conn_open(const Url *u,
                      bool quiet,
                      SSL_CTX *ssl_ctx)
{
    Conn c;
    memset(&c, 0, sizeof(c));
    int fd = open_tcp_connection(u->host, u->port, quiet);

    c.fd = fd;
    c.use_ssl = (strcmp(u->scheme, "https") == 0);
    if (c.use_ssl) {
#if defined(USE_SSL) && USE_SSL
        if (!ssl_ctx) die("SSL context not initialized");
        SSL_EXTENSIONS *ext = NULL;
        ext = ssl_ext_new();
        c.ssl = ssl_client_new(ssl_ctx, fd, NULL, 0, ext);
        if (!c.ssl) die("ssl_client_new failed");

        int r = ssl_handshake_status(c.ssl);
        if (r != SSL_OK) {
            die("SSL_connection failed. status=%d", r);
        }
#else
        (void)ssl_ctx;
        close(fd);
        die("https URL requested but this build was compiled with USE_SSL=0");
#endif
    }

    return c;
}

/**
 * conn_close - Close connection and free resources
 * @c: connection to close
 *
 * Closes SSL session (if active) and TCP socket.
 */
static void conn_close(Conn *c)
{
    (void)c;
#if defined(USE_SSL) && USE_SSL
    if (c->use_ssl && c->ssl) {
        ssl_free(c->ssl);
        c->ssl = NULL;
    }
#endif
    if (c->fd >= 0) {
        close(c->fd);
        c->fd = -1;
    }
}

#if defined(USE_SSL) && USE_SSL
/**
 * SSL_read - Read data from SSL connection (axTLS wrapper)
 * @ssl: SSL connection
 * @buf: buffer to read into
 * @num: maximum bytes to read
 *
 * Reads data from axTLS, handling partial reads with static buffer.
 * Return: number of bytes read, or error code
 */
static int SSL_read(SSL *ssl, void *buf, int num)
{
    static uint8_t *pending_buf = NULL;
    static int pending_len = 0;
    static int pending_offset = 0;
    uint8_t *read_buf;
    int ret;
    int copied = 0;

    // First, return any pending data from previous read
    if (pending_len > 0) {
        int to_copy = pending_len < num ? pending_len : num;
        memcpy(buf, pending_buf + pending_offset, to_copy);
        pending_offset += to_copy;
        pending_len -= to_copy;
        if (pending_len == 0) {
            pending_buf = NULL;
            pending_offset = 0;
        }
        return to_copy;
    }

    // Read new data from SSL
    while ((ret = ssl_read(ssl, &read_buf)) == SSL_OK);

    if (ret > SSL_OK)
    {
        int to_copy = ret < num ? ret : num;
        memcpy(buf, read_buf, to_copy);
        copied = to_copy;

        // Store remaining data for next read
        if (ret > num) {
            pending_buf = read_buf;
            pending_offset = num;
            pending_len = ret - num;
        }
        return copied;
    }

    return ret;
}

/**
 * SSL_write - Write data to SSL connection (axTLS wrapper)
 * @ssl: SSL connection
 * @buf: data to write
 * @num: number of bytes to write
 *
 * Return: number of bytes written, or error code
 */
static int SSL_write(SSL *ssl, const void *buf, int num)
{
    return ssl_write(ssl, buf, num);
}
#endif

/**
 * conn_read - Read from connection (SSL or plain)
 * @c: connection
 * @buf: buffer to read into
 * @len: maximum bytes to read
 *
 * Return: number of bytes read, or -1 on error
 */
static ssize_t conn_read(Conn *c, void *buf, size_t len)
{
    (void)c;
#if defined(USE_SSL) && USE_SSL
    if (c->use_ssl) return SSL_read(c->ssl, buf, (int)len);
#endif
    return read(c->fd, buf, len);
}

/**
 * conn_write - Write to connection (SSL or plain)
 * @c: connection
 * @buf: data to write
 * @len: number of bytes to write
 *
 * Return: number of bytes written, or -1 on error
 */
static ssize_t conn_write(Conn *c, const void *buf, size_t len)
{
    (void)c;
#if defined(USE_SSL) && USE_SSL
    if (c->use_ssl) return SSL_write(c->ssl, buf, (int)len);
#endif
    return write(c->fd, buf, len);
}

/**
 * write_all_or_die - Write all data or exit
 * @fd: file descriptor
 * @data: data to write
 * @len: number of bytes to write
 *
 * Writes all data, retrying on EINTR. Exits on error.
 */
static void write_all_or_die(int fd, const void *data, size_t len)
{
    const char *p = (const char *)data;
    size_t left = len;
    while (left > 0) {
        ssize_t n = write(fd, p, left);
        if (n < 0) {
            if (errno == EINTR) continue;
            die("write failed: %s", strerror(errno));
        }
        p += n;
        left -= (size_t)n;
    }
}

//****************************************************************************
// HTTP protocol functions
//****************************************************************************

/**
 * read_headers - Read HTTP headers from connection
 * @c: connection
 * @out_len: pointer to store header length
 *
 * Reads until \r\n\r\n sequence is found.
 * Return: allocated buffer with headers, or NULL on error
 */
static char *read_headers(Conn *c, size_t *out_len)
{
    size_t cap = 4096;
    size_t len = 0;
    char *buf = malloc(cap);
    if (!buf) die("malloc failed");

    while (true) {
        char ch;
        ssize_t n = conn_read(c, &ch, 1);
        if (n <= 0) break;

        if (len + 2 > cap) {
            size_t new_cap = cap * 2;
            if (new_cap <= cap) {
                free(buf);
                die("header too large");
            }
            char *nbuf = realloc(buf, new_cap);
            if (!nbuf) {
                free(buf);
                die("realloc failed");
            }
            buf = nbuf;
            cap = new_cap;
        }

        buf[len++] = ch;
        buf[len] = '\0';

        if (len >= 4 &&
            buf[len - 4] == '\r' &&
            buf[len - 3] == '\n' &&
            buf[len - 2] == '\r' &&
            buf[len - 1] == '\n') {
            *out_len = len;
            return buf;
        }
    }

    free(buf);
    return NULL;
}

/**
 * parse_headers - Parse HTTP response headers
 * @hdrs: header string
 * @meta: structure to fill with parsed metadata
 *
 * Extracts status code, Content-Length, Transfer-Encoding, Location, etc.
 */
static void parse_headers(const char *hdrs, HttpMeta *meta)
{
    memset(meta, 0, sizeof(*meta));
    meta->status = 0;
    meta->content_length = -1;
    meta->chunked = false;
    meta->location[0] = '\0';
    meta->content_type[0] = '\0';

    const char *line = hdrs;
    const char *end = strstr(line, "\r\n");
    if (end) {
        int status = 0;
        if (sscanf(line, "HTTP/%*s %d", &status) == 1) meta->status = status;
        line = end + 2;
    }

    while ((end = strstr(line, "\r\n")) != NULL) {
        if (end == line) break;
        size_t len = (size_t)(end - line);
        char key[128];
        char val[1024];
        memset(key, 0, sizeof(key));
        memset(val, 0, sizeof(val));

        const char *colon = memchr(line, ':', len);
        if (colon) {
            size_t klen = (size_t)(colon - line);
            if (klen >= sizeof(key)) klen = sizeof(key) - 1;
            memcpy(key, line, klen);
            const char *vstart = colon + 1;
            while (*vstart == ' ' || *vstart == '\t') vstart++;
            size_t vlen = (size_t)(line + len - vstart);
            if (vlen >= sizeof(val)) vlen = sizeof(val) - 1;
            memcpy(val, vstart, vlen);

            for (char *p = key; *p; p++) *p = (char)tolower(*p);
            if (strcmp(key, "content-length") == 0) {
                meta->content_length = atol(val);
            } else if (strcmp(key, "transfer-encoding") == 0) {
                if (strstr(val, "chunked")) meta->chunked = true;
            } else if (strcmp(key, "location") == 0) {
                strncpy(meta->location, val, sizeof(meta->location) - 1);
                meta->location[sizeof(meta->location) - 1] = '\0';
            } else if (strcmp(key, "content-type") == 0) {
                strncpy(meta->content_type, val, sizeof(meta->content_type) - 1);
                meta->content_type[sizeof(meta->content_type) - 1] = '\0';
            }
        }

        line = end + 2;
    }
}

/**
 * http_status_text - Get text description of HTTP status code
 * @status: HTTP status code
 *
 * Return: status text string, or empty string if unknown
 */
static const char *http_status_text(int status)
{
    switch (status) {
        case 200: return "OK";
        case 206: return "Partial Content";
        case 301: return "Moved Permanently";
        case 302: return "Found";
        case 303: return "See Other";
        case 307: return "Temporary Redirect";
        case 308: return "Permanent Redirect";
        case 404: return "Not Found";
        case 416: return "Range Not Satisfiable";
        default: return "";
    }
}

//****************************************************************************
// Progress display functions
//****************************************************************************

/**
 * print_timestamped_url - Print URL with timestamp (wget-style)
 * @url_str: URL to print
 * @quiet: if true, suppress output
 */
static void print_timestamped_url(const char *url_str, bool quiet)
{
    if (quiet) return;
    time_t now = time(NULL);
    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);
    fprintf(stderr, "--%s--  %s\n", ts, url_str);
}

/**
 * print_length_line - Print Content-Length and type (wget-style)
 * @meta: HTTP metadata
 * @quiet: if true, suppress output
 */
static void print_length_line(const HttpMeta *meta, bool quiet)
{
    if (quiet) return;
    if (meta->content_length < 0) {
        fprintf(stderr, "Length: unspecified");
    } else {
        double kib = (double)meta->content_length / 1024.0;
        fprintf(stderr, "Length: %ld (%.0fK)", meta->content_length, kib);
    }
    if (meta->content_type[0] != '\0') {
        fprintf(stderr, " [%s]", meta->content_type);
    }
    fputc('\n', stderr);
}

/**
 * format_wget_size - Format byte size in human-readable form
 * @bytes: size in bytes
 * @buf: output buffer
 * @buf_len: size of output buffer
 *
 * Formats as K, M, or G with appropriate precision.
 */
static void format_wget_size(double bytes, char *buf, size_t buf_len)
{
    const char *unit = "";
    if (bytes >= 1024.0 * 1024.0 * 1024.0) {
        bytes /= 1024.0 * 1024.0 * 1024.0;
        unit = "G";
    } else if (bytes >= 1024.0 * 1024.0) {
        bytes /= 1024.0 * 1024.0;
        unit = "M";
    } else if (bytes >= 1024.0) {
        bytes /= 1024.0;
        unit = "K";
    }

    if (unit[0] == '\0') {
        snprintf(buf, buf_len, "%.0f", bytes);
    } else if (bytes < 100.0) {
        snprintf(buf, buf_len, "%.2f%s", bytes, unit);
    } else {
        snprintf(buf, buf_len, "%.0f%s", bytes, unit);
    }
}

/**
 * format_elapsed_seconds - Format elapsed time
 * @elapsed: time in seconds
 * @buf: output buffer
 * @buf_len: size of output buffer
 */
static void format_elapsed_seconds(double elapsed, char *buf, size_t buf_len)
{
    if (elapsed < 0.01) elapsed = 0.01;
    snprintf(buf, buf_len, "%.2fs", elapsed);
}

/**
 * format_rate_gnu - Format transfer rate (GNU wget style)
 * @bytes_per_sec: transfer rate in bytes per second
 * @buf: output buffer
 * @buf_len: size of output buffer
 *
 * Formats as B/s, KB/s, MB/s, or GB/s.
 */
static void format_rate_gnu(double bytes_per_sec, char *buf, size_t buf_len)
{
    const char *unit = "B/s";
    double value = bytes_per_sec;
    if (value >= 1024.0 * 1024.0 * 1024.0) {
        value /= 1024.0 * 1024.0 * 1024.0;
        unit = "GB/s";
    } else if (value >= 1024.0 * 1024.0) {
        value /= 1024.0 * 1024.0;
        unit = "MB/s";
    } else if (value >= 1024.0) {
        value /= 1024.0;
        unit = "KB/s";
    }

    if (value < 10.0) {
        snprintf(buf, buf_len, "%.2f %s", value, unit);
    } else if (value < 100.0) {
        snprintf(buf, buf_len, "%.1f %s", value, unit);
    } else {
        snprintf(buf, buf_len, "%.0f %s", value, unit);
    }
}

/**
 * print_progress - Display download progress bar
 * @out_file: output filename
 * @downloaded: bytes downloaded so far
 * @total: total bytes (or -1 if unknown)
 * @quiet: if true, suppress output
 * @start_time: download start time
 * @initial_downloaded: bytes already downloaded before this session (for resume)
 *
 * Shows progress bar with percentage and size. Long filenames are scrolled
 * left-to-right in the display field (GNU wget style).
 */
static void print_progress(const char *out_file, long downloaded, long total, bool quiet,
                           time_t start_time, long initial_downloaded)
{
    if (quiet) return;

    static char last_file[1024] = "";
    static int scroll_offset = 0;

    const char *full_name = out_file ? out_file : "output";
    const int name_width = 20;

    // Reset scroll offset when file changes
    if (strcmp(last_file, full_name) != 0) {
        strncpy(last_file, full_name, sizeof(last_file) - 1);
        last_file[sizeof(last_file) - 1] = '\0';
        scroll_offset = 0;
    }

    // Create display name with scrolling
    char name_buf[32];
    size_t name_len = strlen(full_name);

    if (name_len <= name_width) {
        // Short name - display as is
        strncpy(name_buf, full_name, sizeof(name_buf) - 1);
        name_buf[sizeof(name_buf) - 1] = '\0';
    } else {
        // Long name - scroll it
        if (scroll_offset + name_width <= name_len) {
            memcpy(name_buf, full_name + scroll_offset, name_width);
            name_buf[name_width] = '\0';
        } else {
            // Reached end, wrap around
            scroll_offset = 0;
            memcpy(name_buf, full_name, name_width);
            name_buf[name_width] = '\0';
        }
        // Advance offset for next call
        scroll_offset++;
        if (scroll_offset > name_len - name_width) {
            scroll_offset = 0;
        }
    }

    const char *name = name_buf;

    time_t now = time(NULL);
    double elapsed = difftime(now, start_time);
    if (elapsed < 0.01) elapsed = 0.01;

    char downloaded_buf[32];
    format_wget_size((double)downloaded, downloaded_buf, sizeof(downloaded_buf));
    char elapsed_line[32];
    format_elapsed_seconds(elapsed, elapsed_line, sizeof(elapsed_line));

    // Calculate current session download speed
    long current_session_bytes = downloaded - initial_downloaded;
    if (current_session_bytes < 0) current_session_bytes = 0;
    double speed = (double)current_session_bytes / elapsed;
    char speed_buf[32];
    format_rate_gnu(speed, speed_buf, sizeof(speed_buf));

    if (total > 0) {
        int pct = (int)((downloaded * 100) / total);
        if (pct < 0) pct = 0;
        if (pct > 100) pct = 100;

        const int bar_width = 20;
        int filled = (pct * bar_width) / 100;
        if (filled < 0) filled = 0;
        if (filled > bar_width) filled = bar_width;

        bool show_arrow = false;
        if (pct >= 100) {
            filled = bar_width - 1;
            show_arrow = true;
        } else if (filled > 0) {
            filled--;
            show_arrow = true;
        }

        fprintf(stderr, "\r%-20s %3d%%[", name, pct);
        for (int i = 0; i < bar_width; i++) {
            if (i < filled) {
                fputc('=', stderr);
            } else if (show_arrow && i == filled) {
                fputc('>', stderr);
            } else {
                fputc(' ', stderr);
            }
        }
        if (pct >= 100) {
            fprintf(stderr, "] %7s  %-11s in %-7s", downloaded_buf, speed_buf, elapsed_line);
        } else {
            fprintf(stderr, "] %7s  %-11s", downloaded_buf, speed_buf);
        }
    } else {
        fprintf(stderr, "\r%-20s %ld", name, downloaded);
    }
    fflush(stderr);
}

/**
 * print_saved_summary - Print download completion summary
 * @out_file: output filename
 * @downloaded: total bytes downloaded
 * @quiet: if true, suppress output
 * @start_time: download start time
 *
 * Shows timestamp, average speed, and bytes saved.
 */
static void print_saved_summary(const char *out_file, long downloaded, bool quiet,
                                time_t start_time)
{
    if (quiet) return;
    time_t now = time(NULL);
    double elapsed = difftime(now, start_time);
    if (elapsed < 0.01) elapsed = 0.01;

    char speed_buf[32];
    format_rate_gnu((double)downloaded / elapsed, speed_buf, sizeof(speed_buf));

    struct tm tmv;
    localtime_r(&now, &tmv);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tmv);

    fprintf(stderr, "%s (%s) - '%s' saved [%ld/%ld]\n",
            ts, speed_buf, out_file, downloaded, downloaded);
}

/**
 * textconv_init - Initialize text conversion state
 * @state: conversion state object
 * @enabled: true to enable UTF-8 -> Shift_JIS conversion
 */
static void textconv_init(TextConvState *state, bool enabled)
{
    state->enabled = enabled;
    state->pending_len = 0;
}

/**
 * textconv_write - Convert UTF-8 bytes to Shift_JIS and write
 * @out_fd: output file descriptor
 * @data: source bytes
 * @len: source byte count
 * @state: conversion state (pending UTF-8 bytes between chunks)
 *
 * If conversion fails for a byte sequence, it falls back to passthrough
 * byte-by-byte so download does not abort on malformed input.
 */
static void textconv_write(int out_fd, const char *data, size_t len, TextConvState *state)
{
    if (!state || !state->enabled) {
        write_all_or_die(out_fd, data, len);
        return;
    }

    if (len == 0) {
        return;
    }

    char src_buf[BUF_SIZE + 8];
    char dst_buf[(BUF_SIZE + 8) * 2];
    size_t src_len = state->pending_len + len;
    if (src_len > sizeof(src_buf)) {
        die("conversion source buffer overflow");
    }

    memcpy(src_buf, state->pending, state->pending_len);
    memcpy(src_buf + state->pending_len, data, len);
    state->pending_len = 0;

    char *src_ptr = src_buf;
    size_t src_left = src_len;
    char *dst_ptr = dst_buf;
    size_t dst_left = sizeof(dst_buf);

    while (src_left > 0) {
        char *in_ptr = src_ptr;
        size_t in_left = src_left;
        char *out_ptr = dst_ptr;
        size_t out_left = dst_left;
        int rc = iconv_u2s(&in_ptr, &in_left, &out_ptr, &out_left);

        size_t consumed = (size_t)(in_ptr - src_ptr);
        src_ptr = in_ptr;
        src_left = in_left;
        dst_ptr = out_ptr;
        dst_left = out_left;

        if (rc == 0) {
            break;
        }

        if (consumed > 0) {
            continue;
        }

        if (src_left <= 2) {
            memcpy(state->pending, src_ptr, src_left);
            state->pending_len = src_left;
            src_left = 0;
            break;
        }

        if (dst_left == 0) {
            die("conversion destination buffer overflow");
        }
        *dst_ptr++ = *src_ptr++;
        dst_left--;
        src_left--;
    }

    size_t produced = (size_t)(dst_ptr - dst_buf);
    if (produced > 0) {
        write_all_or_die(out_fd, dst_buf, produced);
    }
}

/**
 * textconv_flush - Flush pending bytes in conversion state
 * @out_fd: output file descriptor
 * @state: conversion state
 */
static void textconv_flush(int out_fd, TextConvState *state)
{
    if (!state || !state->enabled || state->pending_len == 0) {
        return;
    }

    char *src_ptr = state->pending;
    size_t src_left = state->pending_len;
    char dst_buf[16];
    char *dst_ptr = dst_buf;
    size_t dst_left = sizeof(dst_buf);

    while (src_left > 0) {
        char *in_ptr = src_ptr;
        size_t in_left = src_left;
        char *out_ptr = dst_ptr;
        size_t out_left = dst_left;
        int rc = iconv_u2s(&in_ptr, &in_left, &out_ptr, &out_left);

        size_t consumed = (size_t)(in_ptr - src_ptr);
        src_ptr = in_ptr;
        src_left = in_left;
        dst_ptr = out_ptr;
        dst_left = out_left;

        if (rc == 0) {
            break;
        }

        if (consumed > 0) {
            continue;
        }

        if (dst_left == 0) {
            break;
        }
        *dst_ptr++ = *src_ptr++;
        dst_left--;
        src_left--;
    }

    size_t produced = (size_t)(dst_ptr - dst_buf);
    if (produced > 0) {
        write_all_or_die(out_fd, dst_buf, produced);
    }

    state->pending_len = 0;
}

//****************************************************************************
// FTP protocol functions
//****************************************************************************

/**
 * read_line - Read line from connection (CRLF terminated)
 * @c: connection
 * @buf: buffer to read into
 * @max_len: maximum buffer size
 *
 * Return: line length on success, -1 on error
 */
static int read_line(Conn *c, char *buf, size_t max_len)
{
    size_t len = 0;
    while (len + 1 < max_len) {
        char ch;
        ssize_t n = conn_read(c, &ch, 1);
        if (n <= 0) return -1;
        buf[len++] = ch;
        if (len >= 2 && buf[len - 2] == '\r' && buf[len - 1] == '\n') {
            buf[len - 2] = '\0';
            return (int)len;
        }
    }
    buf[max_len - 1] = '\0';
    return (int)len;
}

/**
 * read_line_fd - Read line from file descriptor (CRLF terminated)
 * @fd: file descriptor
 * @buf: buffer to read into
 * @max_len: maximum buffer size
 *
 * Return: line length on success, -1 on error
 */
static int read_line_fd(int fd, char *buf, size_t max_len)
{
    size_t len = 0;
    while (len + 1 < max_len) {
        char ch;
        ssize_t n = read(fd, &ch, 1);
        if (n <= 0) return -1;
        buf[len++] = ch;
        if (len >= 2 && buf[len - 2] == '\r' && buf[len - 1] == '\n') {
            buf[len - 2] = '\0';
            return (int)len;
        }
    }
    buf[max_len - 1] = '\0';
    return (int)len;
}

/**
 * ftp_read_response - Read FTP server response
 * @fd: FTP control connection file descriptor
 * @msg: buffer to store last response line
 * @msg_len: size of message buffer
 *
 * Handles single-line and multi-line FTP responses.
 * Return: FTP response code, or -1 on error
 */
static int ftp_read_response(int fd, char *msg, size_t msg_len)
{
    char line[1024];
    int code = -1;
    int expect_code = -1;
    bool multiline = false;

    while (true) {
        if (read_line_fd(fd, line, sizeof(line)) < 0) {
            return -1;
        }
        if (msg && msg_len > 0) {
            strncpy(msg, line, msg_len - 1);
            msg[msg_len - 1] = '\0';
        }

        if (strlen(line) >= 3 && isdigit((unsigned char)line[0]) &&
            isdigit((unsigned char)line[1]) && isdigit((unsigned char)line[2])) {
            int this_code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
            if (code < 0) {
                code = this_code;
                if (line[3] == '-') {
                    multiline = true;
                    expect_code = this_code;
                } else {
                    return this_code;
                }
            } else if (multiline && this_code == expect_code && line[3] == ' ') {
                return this_code;
            }
        }
    }
}

/**
 * ftp_send_cmd - Send FTP command
 * @fd: FTP control connection file descriptor
 * @fmt: printf-style format string
 * @...: variable arguments for format string
 *
 * Formats command and sends with CRLF terminator.
 */
static void ftp_send_cmd(int fd, const char *fmt, ...)
{
    char cmd[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(cmd, sizeof(cmd), fmt, ap);
    va_end(ap);

    char line[1100];
    snprintf(line, sizeof(line), "%s\r\n", cmd);
    write_all_or_die(fd, line, strlen(line));
}

/**
 * ftp_try_size - Try to get file size via FTP SIZE command
 * @fd: FTP control connection file descriptor
 * @path: file path
 *
 * Return: file size in bytes, or -1 if SIZE not supported
 */
static long ftp_try_size(int fd, const char *path)
{
    char msg[1024];
    ftp_send_cmd(fd, "SIZE %s", path[0] ? path : "/");
    int code = ftp_read_response(fd, msg, sizeof(msg));
    if (code != 213) return -1;
    char *p = msg + 4;
    while (*p == ' ') p++;
    return atol(p);
}

/**
 * ftp_open_pasv_data - Open FTP passive mode data connection
 * @url: parsed URL
 * @ctrl_fd: FTP control connection file descriptor
 * @quiet: if true, suppress output
 *
 * Sends PASV command and connects to data port.
 * Return: data connection file descriptor
 */
static int ftp_open_pasv_data(const Url *url, int ctrl_fd, bool quiet)
{
    char msg[1024];
    ftp_send_cmd(ctrl_fd, "PASV");
    int code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    if (code != 227) {
        die("FTP PASV failed: %s", msg);
    }

    char *lp = strchr(msg, '(');
    char *rp = strchr(msg, ')');
    if (!lp || !rp || rp <= lp + 1) {
        die("FTP PASV parse failed: %s", msg);
    }

    int h1, h2, h3, h4, p1, p2;
    if (sscanf(lp + 1, "%d,%d,%d,%d,%d,%d", &h1, &h2, &h3, &h4, &p1, &p2) != 6) {
        die("FTP PASV parse failed: %s", msg);
    }

    char host[64];
    snprintf(host, sizeof(host), "%d.%d.%d.%d", h1, h2, h3, h4);
    int port = p1 * 256 + p2;
    (void)url;
    return open_tcp_connection(host, port, quiet);
}

/**
 * ftp_download - Download file via FTP
 * @url: parsed FTP URL
 * @out_path: explicit output path (or NULL)
 * @out_dir: output directory (or NULL)
 * @quiet: if true, suppress output
 * @continue_mode: if true, resume download
 *
 * Handles FTP login, passive mode transfer, and resume.
 * Return: 0 on success
 */
static int ftp_download(const Url *url, const char *out_path, const char *out_dir,
                        bool quiet, bool continue_mode, bool convert_u2s)
{
    char out_file[1024];
    pick_output_name(url, out_path, out_dir, out_file, sizeof(out_file));

    long resume_from = 0;
    if (continue_mode) {
        resume_from = get_existing_file_size(out_file);
    }

    int ctrl_fd = open_tcp_connection(url->host, url->port, quiet);
    char msg[1024];

    int code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    if (code != 220) {
        close(ctrl_fd);
        die("FTP greeting failed: %s", msg);
    }

    const char *user = url->has_auth && url->user[0] ? url->user : "anonymous";
    const char *pass = url->has_auth ? url->pass : "anonymous@";

    ftp_send_cmd(ctrl_fd, "USER %s", user);
    code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    if (code == 331) {
        ftp_send_cmd(ctrl_fd, "PASS %s", pass);
        code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    }
    if (code != 230) {
        close(ctrl_fd);
        die("FTP login failed: %s", msg);
    }

    ftp_send_cmd(ctrl_fd, "TYPE I");
    code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    if (code != 200) {
        close(ctrl_fd);
        die("FTP TYPE failed: %s", msg);
    }

    char retr_path[1024];
    if (url->path[0] == '\0') {
        strcpy(retr_path, "/");
    } else {
        strncpy(retr_path, url->path, sizeof(retr_path) - 1);
        retr_path[sizeof(retr_path) - 1] = '\0';
    }

    long total = ftp_try_size(ctrl_fd, retr_path);
    if (resume_from > 0 && total > 0 && resume_from >= total) {
        if (!quiet) fprintf(stderr, "Already complete: %s\n", out_file);
        ftp_send_cmd(ctrl_fd, "QUIT");
        (void)ftp_read_response(ctrl_fd, msg, sizeof(msg));
        close(ctrl_fd);
        return 0;
    }

    bool rest_ok = false;
    if (resume_from > 0) {
        ftp_send_cmd(ctrl_fd, "REST %ld", resume_from);
        code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
        if (code == 350) {
            rest_ok = true;
            if (!quiet) fprintf(stderr, "Resuming FTP at byte %ld\n", resume_from);
        } else {
            if (!quiet) fprintf(stderr, "FTP resume not supported, restarting\n");
            resume_from = 0;
        }
    }

    int data_fd = ftp_open_pasv_data(url, ctrl_fd, quiet);
    ftp_send_cmd(ctrl_fd, "RETR %s", retr_path);
    code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    if (code != 150 && code != 125) {
        close(data_fd);
        close(ctrl_fd);
        die("FTP RETR failed: %s", msg);
    }

    int out_fd = open_output_file_with_mode(out_file, rest_ok);
    if (out_fd < 0) {
        int saved_errno = errno;
        close(data_fd);
        close(ctrl_fd);
        die("open output failed: %s", strerror(saved_errno));
    }

    if (!quiet) fprintf(stderr, "Saving to: '%s'\n\n", out_file);

    char buf[BUF_SIZE];
    long downloaded = rest_ok ? resume_from : 0;
    long initial_downloaded = downloaded;
    time_t last = 0;
    time_t start_time = time(NULL);
    TextConvState conv_state;
    textconv_init(&conv_state, convert_u2s);
    if (!quiet && total > 0 && downloaded == 0) {
        print_progress(out_file, 0, total, quiet, start_time, initial_downloaded);
    }
    while (true) {
        ssize_t n = read(data_fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR) continue;
            close(out_fd);
            close(data_fd);
            close(ctrl_fd);
            die("FTP data read failed: %s", strerror(errno));
        }
        if (n == 0) break;
        textconv_write(out_fd, buf, (size_t)n, &conv_state);
        downloaded += n;
        time_t now = time(NULL);
        if (now != last) {
            print_progress(out_file, downloaded, total > 0 ? total : -1, quiet, start_time, initial_downloaded);
            last = now;
        }
    }
    textconv_flush(out_fd, &conv_state);
    if (total > 0 && downloaded < total) {
        downloaded = total;
    }
    print_progress(out_file, downloaded, total > 0 ? total : -1, quiet, start_time, initial_downloaded);
    if (!quiet) fprintf(stderr, "\n\n");
    print_saved_summary(out_file, downloaded, quiet, start_time);
    if (!quiet) fprintf(stderr, "\n");

    close(out_fd);
    close(data_fd);

    code = ftp_read_response(ctrl_fd, msg, sizeof(msg));
    if (code != 226 && code != 250) {
        close(ctrl_fd);
        die("FTP transfer finalize failed: %s", msg);
    }

    ftp_send_cmd(ctrl_fd, "QUIT");
    (void)ftp_read_response(ctrl_fd, msg, sizeof(msg));
    close(ctrl_fd);
    return 0;
}

//****************************************************************************
// Download functions
//****************************************************************************

/**
 * write_body_bytes - Write downloaded bytes and refresh progress display
 * @out_fd: output file descriptor
 * @buf: byte buffer to write
 * @n: number of bytes to write
 * @downloaded: pointer to total downloaded bytes
 * @total: expected total bytes, or -1 if unknown
 * @quiet: if true, suppress output
 * @start_time: download start time
 * @initial_downloaded: bytes already downloaded before this session
 * @last: pointer to last progress update timestamp
 * @out_file: output filename (for progress display)
 */
static void write_body_bytes(int out_fd, const char *buf, size_t n,
                             long *downloaded, long total, bool quiet,
                             time_t start_time, long initial_downloaded,
                             time_t *last, const char *out_file,
                             TextConvState *conv_state)
{
    textconv_write(out_fd, buf, n, conv_state);
    *downloaded += (long)n;

    time_t now = time(NULL);
    if (now != *last) {
        print_progress(out_file, *downloaded, total, quiet, start_time, initial_downloaded);
        *last = now;
    }
}

/**
 * download_body - Download HTTP response body
 * @c: connection
 * @meta: parsed HTTP metadata
 * @hdrs: response headers (unused)
 * @hdr_len: header length (unused)
 * @out_fd: output file descriptor
 * @quiet: if true, suppress output
 * @initial_downloaded: bytes already downloaded (for resume)
 * @out_file: output filename (for progress display)
 *
 * Handles chunked and non-chunked transfer encodings.
 */
static void download_body(Conn *c, const HttpMeta *meta, const char *hdrs, size_t hdr_len,
                          int out_fd, bool quiet, long initial_downloaded,
                          const char *out_file, bool convert_u2s)
{
    (void)hdrs;
    (void)hdr_len;
    long downloaded = initial_downloaded;
    long total = (meta->content_length > 0) ? (meta->content_length + initial_downloaded) : -1;
    time_t last = 0;
    time_t start_time = time(NULL);
    char buf[BUF_SIZE];
    TextConvState conv_state;
    textconv_init(&conv_state, convert_u2s);
    if (!quiet && total > 0 && downloaded == 0) {
        print_progress(out_file, 0, total, quiet, start_time, initial_downloaded);
    }

    if (meta->chunked) {
        char line[128];
        while (true) {
            int rc = read_line(c, line, sizeof(line));
            if (rc < 0) break;
            long chunk = strtol(line, NULL, 16);
            if (chunk == 0) {
                read_line(c, line, sizeof(line));
                break;
            }
            long remaining = chunk;
            while (remaining > 0) {
                size_t to_read = (remaining > (long)sizeof(buf)) ? sizeof(buf) : (size_t)remaining;
                ssize_t n = conn_read(c, buf, to_read);
                if (n <= 0) break;
                write_body_bytes(out_fd, buf, (size_t)n,
                                 &downloaded, total, quiet,
                                 start_time, initial_downloaded,
                                 &last, out_file, &conv_state);
                remaining -= n;
            }
            read_line(c, line, sizeof(line));
        }
        textconv_flush(out_fd, &conv_state);
        if (!quiet) fprintf(stderr, "\n");
        return;
    }

    while (true) {
        ssize_t n = conn_read(c, buf, sizeof(buf));
        if (n <= 0) break;
        write_body_bytes(out_fd, buf, (size_t)n,
                         &downloaded, total, quiet,
                         start_time, initial_downloaded,
                         &last, out_file, &conv_state);
        if (total > 0 && downloaded >= total) break;
    }
    textconv_flush(out_fd, &conv_state);
    if (total > 0 && downloaded < total) {
        downloaded = total;
    }
    print_progress(out_file, downloaded, total > 0 ? total : -1, quiet, start_time, initial_downloaded);
    if (!quiet) fprintf(stderr, "\n\n");
    print_saved_summary(out_file, downloaded, quiet, start_time);
    if (!quiet) fprintf(stderr, "\n");
}

//****************************************************************************
// SSL initialization functions
//****************************************************************************

/**
 * ssl_init_once - Initialize SSL library (placeholder)
 *
 * This is a no-op for axTLS.
 */
static void ssl_init_once(void)
{
}

/**
 * ssl_create_ctx - Create SSL context
 *
 * Initializes axTLS context for client connections.
 * Return: SSL_CTX pointer (or NULL if SSL disabled)
 */
static SSL_CTX *ssl_create_ctx(void)
{
#if defined(USE_SSL) && USE_SSL
    SSL_CTX *ctx = ssl_ctx_new(SSL_SERVER_VERIFY_LATER, SSL_DEFAULT_CLNT_SESS);
    if (!ctx) die("SSL_CTX_new failed");
    return ctx;
#else
    return NULL;
#endif
}

//****************************************************************************
// Program entry
//****************************************************************************

/**
 * usage - Print usage message
 * @argv0: program name
 */
static void usage(const char *argv0)
{
    fprintf(stderr,
            "Wget-X68k version (" GIT_REPO_VERSION ")\n"
            "Usage: %s [Options] URL\n"
            "\n"
            "Options:\n"
            "  -O FILE   Write output to FILE\n"
            "  -P DIR    Save output in DIR\n"
            "  -q        Quiet (no progress)\n"
            "  -c        Continue/resume partially downloaded file\n"
            "  -U        Convert UTF-8 response to Shift_JIS while saving\n"
            "  -t N      Max redirects (default 5)\n",
            argv0);
}

/**
 * main - Program entry point
 * @argc: argument count
 * @argv: argument vector
 *
 * Parses command line, downloads file via HTTP/HTTPS/FTP.
 * Return: 0 on success, 1 on error
 */
int main(int argc, char **argv)
{
    const char *out_path = NULL;
    const char *out_dir = NULL;
    bool quiet = false;
    bool continue_mode = false;
    bool convert_u2s = false;
    int max_redirects = 5;

    int opt;
    while ((opt = getopt(argc, argv, "O:P:qcUt:")) != -1) {
        switch (opt) {
            case 'O': out_path = optarg; break;
            case 'P': out_dir = optarg; break;
            case 'q': quiet = true; break;
            case 'c': continue_mode = true; break;
            case 'U': convert_u2s = true; break;
            case 't': max_redirects = atoi(optarg); break;
            default:
                usage(argv[0]);
                return 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *url_str = argv[optind];
    Url url;
    if (!parse_url(url_str, &url)) {
        die("Invalid URL: %s", url_str);
    }

    if (strcmp(url.scheme, "ftp") == 0) {
        return ftp_download(&url, out_path, out_dir, quiet, continue_mode, convert_u2s);
    }

    ssl_init_once();
    SSL_CTX *ssl_ctx = ssl_create_ctx();

    char out_file[1024];
    pick_output_name(&url, out_path, out_dir, out_file, sizeof(out_file));

    for (int redirects = 0; redirects <= max_redirects; redirects++) {
        long resume_from = continue_mode ? get_existing_file_size(out_file) : 0;

        char current_url[MAX_URL_LEN];
        current_url[0] = '\0';
        append_cstr_or_die(current_url, sizeof(current_url), url.scheme, "request URL");
        append_cstr_or_die(current_url, sizeof(current_url), "://", "request URL");
        append_cstr_or_die(current_url, sizeof(current_url), url.host, "request URL");
        append_cstr_or_die(current_url, sizeof(current_url), url.path, "request URL");
        print_timestamped_url(current_url, quiet);

        Conn c = conn_open(&url, quiet, ssl_ctx);

        char request[2304];
        if (resume_from > 0) {
            snprintf(request, sizeof(request),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: wget-x68k/1.0\r\n"
                     "Connection: close\r\n"
                     "Accept: */*\r\n"
                     "Range: bytes=%ld-\r\n\r\n",
                     url.path, url.host, resume_from);
        } else {
            snprintf(request, sizeof(request),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: wget-x68k/1.0\r\n"
                     "Connection: close\r\n"
                     "Accept: */*\r\n\r\n",
                     url.path, url.host);
        }

        if (conn_write(&c, request, strlen(request)) <= 0) {
            conn_close(&c);
            die("write request failed");
        }

        size_t hdr_len = 0;
        char *hdrs = read_headers(&c, &hdr_len);
        if (!hdrs) {
            conn_close(&c);
            die("failed to read headers");
        }

        HttpMeta meta;
        parse_headers(hdrs, &meta);

        if (!quiet) {
            const char *status_txt = http_status_text(meta.status);
            if (status_txt[0] != '\0') {
                fprintf(stderr, "HTTP request sent, awaiting response... %d %s\n",
                        meta.status, status_txt);
            } else {
                fprintf(stderr, "HTTP request sent, awaiting response... %d\n", meta.status);
            }
        }

        if (meta.status >= 300 && meta.status < 400 && meta.location[0] != '\0') {
            char next_url[MAX_URL_LEN];
            resolve_location(&url, meta.location, next_url, sizeof(next_url));
            if (!quiet) warn_msg("Redirecting to %s", next_url);
            free(hdrs);
            conn_close(&c);
            if (!parse_url(next_url, &url)) {
                die("Invalid redirect URL: %s", next_url);
            }
            continue;
        }

        if (meta.status < 200 || meta.status >= 300) {
            if (resume_from > 0 && meta.status == 416) {
                free(hdrs);
                conn_close(&c);
                if (!quiet) fprintf(stderr, "Already complete: %s\n", out_file);
                #if defined(USE_SSL) && USE_SSL
                ssl_ctx_free(ssl_ctx);
                #endif
                return 0;
            }
            free(hdrs);
            conn_close(&c);
            die("HTTP status %d", meta.status);
        }

        bool append = false;
        long initial_downloaded = 0;
        if (resume_from > 0 && meta.status == 206) {
            append = true;
            initial_downloaded = resume_from;
            if (!quiet) fprintf(stderr, "Resuming HTTP at byte %ld\n", resume_from);
        } else if (resume_from > 0 && meta.status == 200) {
            if (!quiet) fprintf(stderr, "HTTP resume not supported, restarting\n");
        }

        int out_fd = open_output_file_with_mode(out_file, append);
        if (out_fd < 0) {
            int saved_errno = errno;
            free(hdrs);
            conn_close(&c);
            die("open output failed: %s", strerror(saved_errno));
        }

        print_length_line(&meta, quiet);
        if (!quiet) fprintf(stderr, "Saving to: '%s'\n\n", out_file);
        download_body(&c, &meta, hdrs, hdr_len, out_fd, quiet, initial_downloaded,
                  out_file, convert_u2s);

        close(out_fd);
        free(hdrs);
        conn_close(&c);
        #if defined(USE_SSL) && USE_SSL
        ssl_ctx_free(ssl_ctx);
        #endif
        return 0;
    }

    #if defined(USE_SSL) && USE_SSL
    ssl_ctx_free(ssl_ctx);
    #endif
    die("Too many redirects");
    return 1;
}
