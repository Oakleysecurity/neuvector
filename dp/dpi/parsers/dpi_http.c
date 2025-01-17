#include <string.h>
#include <ctype.h>

#include "dpi/dpi_module.h"

#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

#define HTTP_HEADER_COMPLETE_TIMEOUT 3
#define HTTP_BODY_FIRST_TIMEOUT      30
#define HTTP_BODY_INTERVAL_TIMEOUT   3

typedef struct http_wing_ {   //定义了http流量的元数据
    uint32_t seq;
    uint32_t content_len;
#define HTTP_FLAGS_CONTENT_LEN  0x01
#define HTTP_FLAGS_CHUNKED      0x02
#define HTTP_FLAGS_CONN_CLOSE   0x04
#define HTTP_FLAGS_REQUEST      0x08
#define HTTP_FLAGS_NEGATIVE_LEN 0x10
    uint8_t flags;
#define HTTP_SECTION_NONE       0
#define HTTP_SECTION_REQ_RESP   1
#define HTTP_SECTION_HEADER     2
#define HTTP_SECTION_FIRST_BODY 3
#define HTTP_SECTION_BODY       4
    uint8_t section:3,
#define HTTP_CHUNK_LENGTH     0
#define HTTP_CHUNK_CONTENT    1
#define HTTP_CHUNK_LAST       2
            chunk:  2;
#define HTTP_CTYPE_NONE                0
#define HTTP_CTYPE_APPLICATION_XML     1
    uint8_t ctype:  3,
#define HTTP_ENCODE_NONE      0
#define HTTP_ENCODE_GZIP      1
#define HTTP_ENCODE_COMPRESS  2
#define HTTP_ENCODE_DEFLATE   3
            encode: 2;
    uint32_t cmd_start;
    uint32_t body_start;
    uint32_t hdr_start;
} http_wing_t;

typedef struct http_data_ {   //包含了http请求/响应的解析信息
    http_wing_t client, server;
    uint16_t status:10,
#define HTTP_METHOD_NONE   0
#define HTTP_METHOD_GET    1
#define HTTP_METHOD_POST   2
#define HTTP_METHOD_PUT    3
#define HTTP_METHOD_DELETE 4
#define HTTP_METHOD_HEAD   5
             method:4,  //表示HTTP请求方法类型，占用4个二进制位。可以使用预定义的宏HTTP_METHOD_NONE、HTTP_METHOD_GET、HTTP_METHOD_POST等来赋值。
#define HTTP_PROTO_NONE 0
#define HTTP_PROTO_HTTP 1
#define HTTP_PROTO_SIP  2 //SIP（Session Initiation Protocol，会话发起协议）是一种用于建立、修改和终止多媒体会话的网络协议。
#define HTTP_PROTO_RTSP 3 //RTSP（Real-Time Streaming Protocol，实时流媒体协议）是一种用于控制互联网上多媒体服务器的应用层协议。
             proto :2;  //表示HTTP协议类型，占用2个二进制位。
    uint16_t body_buffer_len; // TODO: temp. way to buffer body in some cases. //表示临时缓存HTTP请求/响应消息主体的长度，单位为字节。
    uint32_t url_start_tick;  //HTTP请求URL开始时间
    uint32_t last_body_tick;  //HTTP请求URL最后一次接收到HTTP消息主体的时间戳。
    uint8_t *body_buffer; // TODO: temp. way to buffer body in some cases.  //表示HTTP请求/响应消息主体的缓存指针。
} http_data_t;

typedef struct http_ctx_ {  //包含了指向DPI数据包、http_data和http_wing的指针
    dpi_packet_t *p;
    http_data_t *data;
    http_wing_t *w;
} http_ctx_t;

typedef struct http_method_ {   //包含了http方法的信息，如名称、长度、协议等
    char *name;
    uint8_t len;
    uint8_t proto;
    uint8_t method;
} http_method_t;

//包含了预定义的HTTP方法信息。每个数组元素表示一种HTTP方法，包括方法名称、名称长度、协议和方法类型等信息。
//这个数组可以在HTTP协议解析时使用，用于判断HTTP请求或响应消息的方法类型。
static http_method_t http_method[] = {
    {"GET",     3, HTTP_PROTO_HTTP, HTTP_METHOD_GET},  //方法名，长度，协议，方法类型
    {"PUT",     3, HTTP_PROTO_HTTP, HTTP_METHOD_PUT},
    {"POST",    4, HTTP_PROTO_HTTP, HTTP_METHOD_POST},
    {"DELETE",  6, HTTP_PROTO_HTTP, HTTP_METHOD_DELETE},
    {"HEAD",    4, HTTP_PROTO_HTTP, HTTP_METHOD_HEAD},
    {"CONNECT", 7, HTTP_PROTO_HTTP, HTTP_METHOD_NONE},
};

/*
typedef struct couchbase_handle_ {
    char *name;
    uint8_t len;
} couchbase_handle_t;

const static  couchbase_handle_t couchbase_headers[] = {
    {"/createIndex",            sizeof("/createIndex")},
    {"/dropIndex",              sizeof("/dropIndex")},
    {"/getLocalIndexMetadata",  sizeof("/getLocalIndexMetadata")},
    {"/getIndexMetadata",       sizeof("/getIndexMetadata")},
    {"/restoreIndexMetadata",   sizeof("/restoreIndexMetadata")},
    {"/getIndexStatus",         sizeof("/getIndexStatus")},
    {"/api/indexes",            sizeof("/api/indexes")},
    {"/api/index/",             sizeof("/api/index/")},
    //{"/settings",               sizeof("/settings")},
    {"/triggerCompaction",      sizeof("/triggerCompaction")}
    //{"/stats",                  sizeof("/stats")},
    //{"/pools",                  sizeof("/pools")}
};

static bool is_couchbase_request(uint8_t * ptr, int len)
{
    int i;

    for (i=0; i < sizeof(couchbase_headers)/sizeof(couchbase_headers[0]); i++) {
        if ((couchbase_headers[i].len-1) > len) {
            continue;
        }
        if ( memcmp(ptr, couchbase_headers[i].name, couchbase_headers[i].len-1) == 0) {
            DEBUG_LOG(DBG_PARSER, NULL, "Couchbase request: %s\n", couchbase_headers[i].name);
            return true;
        }
    }
    return false;
}
*/

//用于检测HTTP请求/响应消息是否超时。
//dpi_session_t类型的指针s和void类型的指针parser_data，parser_data实际上指向http_data_t类型的结构体数据。
int dpi_http_tick_timeout(dpi_session_t *s, void *parser_data)
{
    http_data_t *data = parser_data;

    DEBUG_LOG_FUNC_ENTRY(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL);

    if (data->url_start_tick > 0) {  //根据data中的时间戳(http请求url开始时间)信息判断HTTP消息是否超时。如果url_start_tick大于0，则表示正在解析HTTP请求URL
        if (th_snap.tick - data->url_start_tick >= HTTP_HEADER_COMPLETE_TIMEOUT) { //检查从开始解析到当前时间的持续时间是否超过HTTP_HEADER_COMPLETE_TIMEOUT（以秒为单位）。如果持续时间超过阈值，则记录日志并返回DPI_SESS_TICK_RESET，表示需要重置会话计时器。
            DEBUG_LOG(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL,
                      "Header duration=%us, threshold=%us\n",
                      th_snap.tick - data->url_start_tick, HTTP_HEADER_COMPLETE_TIMEOUT);
            dpi_threat_log_by_session(DPI_THRT_HTTP_SLOWLORIS, s,
                      "Header duration=%us, threshold=%us",
                      th_snap.tick - data->url_start_tick, HTTP_HEADER_COMPLETE_TIMEOUT);
            return DPI_SESS_TICK_RESET;
        }
    } else if (data->last_body_tick > 0) { //如果last_body_tick大于0，则表示正在接收HTTP消息主体数据。
        switch (data->client.section) {
        case HTTP_SECTION_FIRST_BODY:
            if (th_snap.tick - data->last_body_tick >= HTTP_BODY_FIRST_TIMEOUT) { //函数根据client.section字段的值（表示HTTP消息主体的段）来判断相应的超时阈值。如果是第一个消息主体段，检查从上一次数据到达到当前时间的间隔是否超过HTTP_BODY_FIRST_TIMEOUT；
                DEBUG_LOG(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL,  //如果是后续的消息主体段，则按照HTTP_BODY_INTERVAL_TIMEOUT的阈值进行检查。如果超时，记录日志并返回DPI_SESS_TICK_RESET，表示需要重置会话计时器。
                          "First body packet interval=%us, threshold=%us\n",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                dpi_threat_log_by_session(DPI_THRT_HTTP_SLOWLORIS, s,
                          "First body packet interval=%us, threshold=%us",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                return DPI_SESS_TICK_RESET;
            }
            break;
        case HTTP_SECTION_BODY:
            /* Easy to get false positive, maybe 3s is too short.
            if (th_snap.tick - data->last_body_tick >= HTTP_BODY_INTERVAL_TIMEOUT) {
                DEBUG_LOG(DBG_SESSION | DBG_PARSER | DBG_TIMER, NULL,
                          "Body packet interval=%us, threshold=%us\n",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                dpi_threat_log_by_session(DPI_THRT_HTTP_SLOWLORIS, s,
                          "Body packet interval=%us, threshold=%us",
                          th_snap.tick - data->last_body_tick, HTTP_BODY_INTERVAL_TIMEOUT);
                return DPI_SESS_TICK_RESET;
            }
            */
            break;
        }
    }

    return DPI_SESS_TICK_CONTINUE;
}

//用于检测慢速攻击（slowloris）中的请求主体攻击
//*data  一个指向http数据结构的指针
//*w 一个指向http报文头部的指针
//主体攻击（Body Attack）是一种网络攻击方法，通常用于针对Web服务器。攻击者使用该方法发送大量的HTTP请求，使服务器在处理每个请求时都需要读取和接收数据，从而耗尽服务器资源并导致服务不可用。
static inline bool to_detect_slowloris_body_attack(http_data_t *data, http_wing_t *w)
{
    return data->method != HTTP_METHOD_GET && data->method != HTTP_METHOD_HEAD &&
           (w->flags & HTTP_FLAGS_CONTENT_LEN) && w->content_len > 0;
}

//用于判断给定字符是否为HTTP请求分隔符。
static inline bool is_request_delimiter(char c)
{
    return (c == ' ' || c == '\t');
}

//用于判断给定HTTP翼（wing）是否为HTTP请求
//http翼也就是http报文头部（header）
static inline bool is_request(http_wing_t *w)
{
    return FLAGS_TEST(w->flags, HTTP_FLAGS_REQUEST); //如果该HTTP翼的标志位中包含“HTTP_FLAGS_REQUEST”标记，则认为该HTTP翼为HTTP请求。
}


//这段代码是HTTP响应解析器的一部分，用于解析HTTP响应中的状态行，并返回状态行的长度。
// *ctx  指向http上下文结构体的指针
// *ptr  一个指向待解析数据块的指针
// len  数据块长度
static int http_parse_response(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    int status = 0;
    char *cptr = (char *)ptr;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    if (unlikely(len < 4)) return 0; //判断可读取的字节数是否小于4个字节，如果是，则返回0表示无法解析状态行。
    if (likely(strncmp(cptr, "HTTP", 4) == 0 || strncmp(cptr, "RTSP", 4) == 0 ||
               strncmp(cptr, "SIP", 3) == 0)) { //如果前四个字节为"HTTP"、"RTSP"或"SIP"之一，则开始解析状态行。其中，HTTP是最常见的协议类型，而RTSP和SIP则分别代表媒体流传输协议和会话发起协议。
        uint8_t *l = ptr, *end = ptr + len;
        uint8_t *status_ptr = NULL;
        int version_end = 0;

        while (l < end) {
            if (!isprint(*l)) {  // *l 如果为不可打印字符，则说明http响应错误
                return -1;
            }

            if (isblank(*l)) {  // *l 所指字符是否为空白字符
                //找到空格字符后，将已经扫描过的字符视为状态行的协议版本号部分，并将剩余的字符视为状态码和原因短语部分。
                if (status_ptr != NULL) {
                    // Valid status line
                    int eols;
                    uint8_t *eol = consume_line(l, end - l, &eols);
                    if (eol != NULL) {
                        ctx->data->status = status;
                        return eol - ptr;
                    } else {
                        // Wait for eol
                        return 0;
                    }
                } else {
                    version_end = l - ptr;
                }
            } else if (version_end > 0) {
                // Parse status code
                if (!isdigit(*l)) {
                    return -1;
                }

                if (status_ptr == NULL) {
                    status_ptr = l;
                } else if (l - status_ptr >= 3) {
                    return -1;
                }

                status = status * 10 + ctoi(*l);
            }

            l ++;
        }

        // EOL is not reached, wait.
        return 0;
    }

    return -1;
}

//用于解析HTTP请求中的请求行，并返回当前行的结尾指针位置。
//http_ctx_t类型的指针ctx  表示HTTP上下文
//无符号字符型指针ptr  HTTP响应消息缓存指针
//整型变量len  HTTP响应消息长度
static int http_parse_request(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    int i;
    uint8_t *l = ptr, *end = ptr + len, *eol = NULL;
    uint8_t proto = HTTP_PROTO_NONE;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    for (i = 0; i < sizeof(http_method) / sizeof(http_method[0]); i ++) {
        http_method_t *m = &http_method[i];
        if (len > m->len + 1 && is_request_delimiter(ptr[m->len]) &&
            strncasecmp((char *)ptr, m->name, m->len) == 0) {
            proto = m->proto;
            ctx->data->method = m->method;
            break;
        }
    }

    struct {
        uint8_t *start, *end;
    } part[3];
    int n = 0;

    part[0].start = ptr; part[1].start = part[2].start = NULL;
    part[0].end = part[1].end = part[2].end = NULL;

    while (l < end) {
        if (is_request_delimiter(*l)) {
            if (n >= 2) return -1;      // At most 3 parts
            if (l - ptr < 3) return -1; // Shortest method is 3-char
            while (l+1 < end && is_request_delimiter(*(l+1))) l ++; //skip consecutive delimiter

            if (part[n].end == NULL) {
                part[n].end = l;
                n ++;
            }
        } else if (*l == '\n') {
            if (part[n].end == NULL) {
                part[n].end = *(l - 1) == '\r' ? l - 1 : l;
            }

            eol = l + 1;
            break;
        } else {
            if (part[n].start == NULL) {
                part[n].start = l;
            }
            if (n == 2 && l - part[n].start > 8) return -1;
            if (n == 0 && l - part[n].start > 16) return -1;
        }

        l ++;
    }

    if (eol == NULL) return 0;
    if (n == 0) return -1;
    if (part[n].start == NULL || part[n].start == part[n].end) n --; // "GET \r\n", "GET /abc \r\n"
    if (n == 0) return -1;
    if (n == 1 && proto == HTTP_PROTO_NONE) return -1;
    if (n == 2) {
        if (part[2].end - part[2].start <= 5) return -1;

        if (strncmp((char *)part[2].start, "HTTP/", 5) == 0) {
            proto = HTTP_PROTO_HTTP;
        } else if (strncmp((char *)part[2].start, "RTSP/", 5) == 0) {
            proto = HTTP_PROTO_RTSP;
        } else if (strncmp((char *)part[2].start, "SIP/", 4) == 0) {
            proto = HTTP_PROTO_SIP;
        } else if (proto == HTTP_PROTO_NONE) {
            return -1;
        }
    }

    ctx->data->proto = proto;

    // TODO: move to signature
    //如果请求URL包含"/wp-content/"字符串，则将应用程序标识符设置为DPI_APP_WORDPRESS
    if (part[1].end - part[1].start > 12 && memcmp(part[1].start, "/wp-content/", 12) == 0) {
        dpi_ep_set_app(ctx->p, 0, DPI_APP_WORDPRESS);
    }

    // check couchbase
    /* If server side ep is already marked as couchbase, ep's applicaiton should be already assigned.
    if ((ctx->p->ep->couchbase_svr && (ctx->p->session->flags & DPI_SESS_FLAG_INGRESS)) &&
        is_couchbase_request(part[1].start, part[1].end - part[1].start)) {
        dpi_ep_set_app(ctx->p, 0, DPI_APP_COUCHBASE);
    }
    */
//最后，函数返回当前行的结尾指针位置，表示成功解析一行HTTP请求/响应消息头。
    return eol - ptr;
}

//将标志位重置，表示请求体已完成；
static void set_body_done(http_wing_t *w)
{
    w->flags &= ~(HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CONN_CLOSE | HTTP_FLAGS_CHUNKED |
                  HTTP_FLAGS_NEGATIVE_LEN);
    w->content_len = 0;
}

//将连接关闭标志位设置为1,并重置其他标志位和内容长度；
static void set_body_conn_close(http_wing_t *w)
{
    w->flags |= HTTP_FLAGS_CONN_CLOSE;
    w->flags &= ~(HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CHUNKED);
    w->content_len = 0;
}

//将分块传输标志位设置为1，并重置其他标志位和内容长度；
static void set_body_chunked(http_wing_t *w)
{
    w->flags |= HTTP_FLAGS_CHUNKED;
    w->flags &= ~(HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CONN_CLOSE);
    w->content_len = 0;
}

//将指定内容长度标志位置为1，并清除其他标志位。
static void set_body_content_length(http_wing_t *w)
{
    w->flags |= HTTP_FLAGS_CONTENT_LEN;
    w->flags &= ~(HTTP_FLAGS_CONN_CLOSE | HTTP_FLAGS_CHUNKED);
}

//用于解析HTTP请求头中的Content-Length字段，提取其中的内容长度并存储在http_wing_t结构体的content_len字段中。
static int http_header_content_length_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    register uint8_t *l = ptr, *end = ptr + len;
    int clen = 0;

    if (unlikely(*l == '-')) {
        ctx->w->flags |= HTTP_FLAGS_NEGATIVE_LEN;
        return CONSUME_TOKEN_SKIP_LINE;
    } else if (unlikely(*l == '+')) {
        l ++;
    }

    while (l < end) {
        if (likely(isdigit(*l))) {
            clen = clen * 10 + ctoi(*l);
        }

        l ++;
    }

    ctx->w->content_len = clen;
    return CONSUME_TOKEN_SKIP_LINE;
}

//用于处理HTTP请求头中的Content-Length字段。
//该函数会调用consume_tokens()函数解析Content-Length字段，并使用解析出来的长度更新http_wing_t结构体的content_len字段。
//如果Content-Length字段是负数，就会触发DPI威胁并关闭连接；如果同时有Content-Length和分块传输标志位被设置，也会触发DPI威胁并关闭连接；
//如果存在两个Content-Length字段且长度不同，也会触发DPI威胁并关闭连接。否则，将指定内容长度标志位置为1。同时，根据注释，还有部分逻辑被禁用了。
static void http_header_content_length(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    dpi_packet_t *p = ctx->p;
    http_wing_t *w = ctx->w;
    int content_len = w->content_len;

    consume_tokens(ptr, len, http_header_content_length_token, ctx);
    if (w->flags & HTTP_FLAGS_NEGATIVE_LEN) {
        dpi_threat_trigger(DPI_THRT_HTTP_NEG_LEN, p, "Content-Length header has negative value");
        set_body_conn_close(w);
    /* Disable this logic because some apps may send both content-length and chunked-encoding together
    } else if ((w->flags & HTTP_FLAGS_CHUNKED)) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, p, "Both Content-Length and chunked headers present");
        set_body_conn_close(w);
    */
    } else if ((w->flags & HTTP_FLAGS_CONTENT_LEN) && content_len != w->content_len) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, p, "Two Content-Length headers with different values");
        set_body_conn_close(w);
    /* Disable this logic because GET with data is pretty common today.
    } else if (ctx->data->method == HTTP_METHOD_GET && is_request(w) && dpi_is_client_pkt(p) && w->content_len > 0) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, p, "GET request's Content-Length header has non-zero value");
        set_body_conn_close(w);
    */
    } else {
        DEBUG_LOG(DBG_PARSER, p, "len=%u\n", w->content_len);

        set_body_content_length(w);
    }
}

//用于解析HTTP响应头中的Content-Type字段，并识别出消息体的MIME类型。
static int http_header_content_type_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    if (strncasecmp((char *)ptr, "application/xml", 15) == 0) {
        http_ctx_t *ctx = param;
        http_wing_t *w = ctx->w;

        w->ctype = HTTP_CTYPE_APPLICATION_XML;
        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

//用于解析HTTP响应头中的Content-Type字段，并将结果存储在HTTP上下文结构体中
static void http_header_content_type(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_content_type_token, ctx);
}

//用于解析HTTP响应头中的Content-Encoding字段，并识别出消息体的编码方式。
static int http_header_content_encoding_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    http_wing_t *w = ctx->w;

    if (strncmp((char *)ptr, "gzip", 4) == 0 || strncmp((char *)ptr, "x-gzip", 6) == 0) {
        w->ctype = HTTP_ENCODE_GZIP;
        return CONSUME_TOKEN_SKIP_LINE;
    } else if (strncmp((char *)ptr, "compress", 8) == 0) {
        w->ctype = HTTP_ENCODE_COMPRESS;
        return CONSUME_TOKEN_SKIP_LINE;
    } else if (strncmp((char *)ptr, "deflate", 7) == 0) {
        w->ctype = HTTP_ENCODE_DEFLATE;
        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

//用于解析HTTP响应头中的Content-Encoding字段
static void http_header_content_encoding(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_content_encoding_token, ctx);
}

//用于解析HTTP响应头中的Connection字段
static int http_header_connection_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    if (strncasecmp((char *)ptr, "close", 5) == 0) {
        http_ctx_t *ctx = param;
        http_wing_t *w = ctx->w;

        if ((w->flags & HTTP_FLAGS_CHUNKED) ||
            ((w->flags & HTTP_FLAGS_CONTENT_LEN) && w->content_len > 0)) {
            // Ignore connection close flag
        } else {
            DEBUG_LOG(DBG_PARSER, ctx->p, "close\n");
            set_body_conn_close(w);
        }

        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

//用于解析HTTP响应头中的Connection字段
static void http_header_connection(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_connection_token, ctx);
}

//用于解析HTTP响应头中的Transfer-Encoding字段
static int http_header_xfr_encoding_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;

    if (len == 7 && strncasecmp((char *)ptr, "chunked", 7) == 0) {
        DEBUG_LOG(DBG_PARSER, ctx->p, "chunked\n");

        ctx->w->flags |= HTTP_FLAGS_CHUNKED;
        return CONSUME_TOKEN_SKIP_LINE;
    }

    return 0;
}

//用于解析HTTP响应头中的Transfer-Encoding字段，并根据该字段的值设置HTTP翅膀结构体中的标志位，以便后续处理。
static void http_header_xfr_encoding(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    http_wing_t *w = ctx->w;

    consume_tokens(ptr, len, http_header_xfr_encoding_token, ctx);
    if ((w->flags & HTTP_FLAGS_CHUNKED)) {
        set_body_chunked(w);
    }
    /* Disable this logic because some apps may send both content-length and chunked-encoding together
    if ((w->flags & HTTP_FLAGS_CHUNKED) &&
        (w->flags & HTTP_FLAGS_CONTENT_LEN) && w->content_len > 0) {
        dpi_threat_trigger(DPI_THRT_HTTP_SMUGGLING, ctx->p, "Both Content-Length and chunked headers present");
        set_body_conn_close(w);
    } else {
        set_body_chunked(w);
    }
    */
}

//用于解析HTTP请求头中的X-Forwarded-Port字段，并将解析结果保存到会话结构体dpi_session_t中。
static int http_header_xforwarded_port_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;
    register uint8_t *l = ptr, *end = ptr + len;
    uint16_t xffport = 0;

    while (l < end) {
        if (likely(isdigit(*l))) {
            xffport = xffport * 10 + ctoi(*l);
        }
        l ++;
    }

    s->xff_port = xffport;

    DEBUG_LOG(DBG_PARSER, p, "X-Forwarded-Port: %d\n",s->xff_port);

    return CONSUME_TOKEN_SKIP_LINE;
}

//用于解析HTTP请求头中的X-Forwarded-Port字段
//X-Forwarded-Port字段表示客户端与代理服务器之间传输HTTP请求时使用的端口号
static void http_header_xforwarded_port(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_xforwarded_port_token, ctx);
}

//用于解析HTTP请求头中的X-Forwarded-Proto字段
//X-Forwarded-Proto字段表示客户端与代理服务器之间传输HTTP请求时使用的协议（例如，HTTP或HTTPS）
static int http_header_xforwarded_proto_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;

    if (strncmp((char *)ptr, "https", 5) == 0) {
        s->xff_app = DPI_APP_SSL;
    } else if (strncmp((char *)ptr, "http", 4) == 0) {
        s->xff_app = DPI_APP_HTTP;
    }

    DEBUG_LOG(DBG_PARSER, p, "X-Forwarded-Proto: %d\n",s->xff_app);

    return CONSUME_TOKEN_SKIP_LINE;
}

//用于解析HTTP请求头中的X-Forwarded-Proto字段
static void http_header_xforwarded_proto(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_xforwarded_proto_token, ctx);
}

//用于解析HTTP请求头中的X-Forwarded-For字段
static int http_header_xforwarded_for_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;
    dpi_session_t *s = p->session;
    char *ip_str;
    int ip_str_len;
    register uint8_t *l = ptr, *end = ptr + len;

    while (l < end) {
        if (unlikely(*l == ',')) {
            break;
        }
        l ++;
    }
    ip_str_len = l-ptr+1;

    ip_str = (char *) calloc(ip_str_len, sizeof(char));
    if (ip_str == NULL) {
        return CONSUME_TOKEN_SKIP_LINE;
    }
    strlcpy(ip_str, (char *)ptr, ip_str_len);
    s->xff_client_ip = inet_addr(ip_str);
    if (s->xff_client_ip == (uint32_t)(-1)) {
        DEBUG_LOG(DBG_PARSER, p, "ipv6 or wrong format ipv4: %s, ip=0x%08x\n",ip_str, s->xff_client_ip);
        s->xff_client_ip = 0;
        return CONSUME_TOKEN_SKIP_LINE;
    }
    s->flags |= DPI_SESS_FLAG_XFF;

    DEBUG_LOG(DBG_PARSER, p, "X-Forwarded-For: %s, ip=0x%08x, sess flags=0x%04x\n",ip_str, s->xff_client_ip, s->flags);

    free(ip_str);
    return CONSUME_TOKEN_SKIP_LINE;
}

//用于从HTTP请求头中获取X-Forwarded-For字段的值，并将其传入到回调函数http_header_xforwarded_for_token()进行解析。
static void http_header_xforwarded_for(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_xforwarded_for_token, ctx);
}

//用于识别HTTP请求头中的Server字段，并根据字段内容设置相应的应用程序类型。
//具体来说，该函数通过对指定长度内的字符串进行比较，判断当前请求使用的服务器类型是Apache、Nginx、Jetty、Couchbase还是CouchDB，并将对应的应用程序类型写入dpi_packet_t结构体对象中，同时将版本信息写入该对象的另一个成员变量。
static int http_header_server_token(void *param, uint8_t *ptr, int len, int token_idx)
{
    http_ctx_t *ctx = param;
    dpi_packet_t *p = ctx->p;

    if (len >= 6 && strncasecmp((char *)ptr, "apache", 6) == 0) {
        dpi_ep_set_app(p, DPI_APP_APACHE, 0);
    } else if (len >= 5 && strncasecmp((char *)ptr, "nginx", 5) == 0) {
        dpi_ep_set_app(p, DPI_APP_NGINX, 0);
    } else if (len >= 5 && strncasecmp((char *)ptr, "jetty", 5) == 0) {
        dpi_ep_set_app(p, DPI_APP_JETTY, 0);
    } else if (len >= 9 && strncasecmp((char *)ptr, "couchbase", 9) == 0) {
        dpi_ep_set_app(p, 0, DPI_APP_COUCHBASE);
        DEBUG_LOG(DBG_PARSER, p, "http: couchbase server\n");
    } else if (len >= 7 && strncasecmp((char *)ptr, "couchdb", 7) == 0) {
        dpi_ep_set_app(p, 0, DPI_APP_COUCHDB);
        DEBUG_LOG(DBG_PARSER, p, "http: couchdb server\n");
    }

    dpi_ep_set_server_ver(p, (char *)ptr, len);

    return CONSUME_TOKEN_SKIP_LINE;
}

//通过调用consume_tokens()函数，将传入的HTTP请求头数据进行解析，并调用回调函数http_header_server_token()处理解析后的结果
static void http_header_server(http_ctx_t *ctx, uint8_t *ptr, int len)
{
    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, ctx->p);

    consume_tokens(ptr, len, http_header_server_token, ctx);
}

//通过利用循环不断读取HTTP请求头信息，对请求头内部的各个字段进行解析，并调用相应的处理函数进行处理。
//该函数可以解析Content-Length、Content-Type、Content-Encoding、Connection、Transfer-Encoding、X-Etcd-Cluster-Id、X-Forwarded-Proto、X-Forwarded-Port、X-Forwarded-For和Server等HTTP请求头字段，并根据字段内容调用相应的处理函数进行处理。
static int http_parse_header(http_ctx_t *ctx, uint8_t *ptr, int len, bool *done)
{
    dpi_packet_t *p = ctx->p;
    uint8_t *end = ptr + len;
    int consume = 0;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, p);

    *done = false;
    while (true) {
        int eols, shift;
        uint8_t *eol = consume_line(ptr, end - ptr, &eols);

        if (eol == NULL) return consume;

        shift = eol - ptr;
        if (shift == eols) {
            // Empty line, end of header
            DEBUG_LOG(DBG_PARSER, ctx->p, "done\n");
            *done = true;
            return consume + shift;
        }

        // TODO: replace this to keyword parser
        if (shift > 15 && strncasecmp((char *)ptr, "Content-Length:", 15) == 0) {
            http_header_content_length(ctx, ptr + 15, shift - eols - 15);
        } else
        if (shift > 13 && strncasecmp((char *)ptr, "Content-Type:", 13) == 0) {
            http_header_content_type(ctx, ptr + 13, shift - eols - 13);
        } else
        if (shift > 17 && strncasecmp((char *)ptr, "Content-Encoding:", 17) == 0) {
            http_header_content_encoding(ctx, ptr + 17, shift - eols - 17);
        } else
        if (shift > 11 && strncasecmp((char *)ptr, "Connection:", 11) == 0) {
            http_header_connection(ctx, ptr + 11, shift - eols - 11);
        } else
        if (shift > 18 && strncasecmp((char *)ptr, "Transfer-Encoding:", 18) == 0) {
            http_header_xfr_encoding(ctx, ptr + 18, shift - eols - 18);
        } else
        if (shift > 18 && strncasecmp((char *)ptr, "X-Etcd-Cluster-Id:", 18) == 0) {
            dpi_ep_set_app(ctx->p, 0, DPI_APP_ETCD);
        } else
        if (shift > 17 && strncasecmp((char *)ptr, "X-Forwarded-Port:", 17) == 0) {
            http_header_xforwarded_port(ctx, ptr + 17, shift - eols - 17);
        } else
        if (shift > 18 && strncasecmp((char *)ptr, "X-Forwarded-Proto:", 18) == 0) {
            http_header_xforwarded_proto(ctx, ptr + 18, shift - eols - 18);
        } else
        if (shift > 16 && strncasecmp((char *)ptr, "X-Forwarded-For:", 16) == 0) {
            http_header_xforwarded_for(ctx, ptr + 16, shift - eols - 16);
        } else if (!is_request(ctx->w)) {
            // TODO: move to signature
            if (shift > 7 && strncasecmp((char *)ptr, "Server:", 7) == 0) {
                http_header_server(ctx, ptr + 7, shift - eols - 7);
            }
        }

        len -= shift;
        ptr = eol;
        consume += shift;
    }

    return consume;
}


//通过循环读取HTTP请求体内部数据，对请求体进行解析，并根据请求体内部的内容切分成不同的chunk块。
//具体来说，该函数可以解析chunked编码的HTTP请求体，并将其拆分成多个不定长度的chunk块进行处理。
//这里的chunk是HTTP协议中传输编码（Transfer-Encoding）中使用的一种方式，即Chunked Transfer Encoding。该编码方式在传输数据时将数据分为多个块（chunk），每个块由长度和内容两部分组成，长度字段用十六进制数表示，紧接着是一个CRLF，然后是实际的数据内容，最后再次以CRLF结尾。多个chunk可以依次传输，每个chunk的长度都可以不同，在最后一个空chunk中使用长度字段0来标识整个请求体传输结束。
    //在 HTTP/1.1 协议中，如果请求头中没有指定Content-Length，则可以使用Chunked Transfer Encoding方式进行数据传输。在HTTP请求头中通过"Transfer-Encoding: chunked"来启用该传输编码方式。
static int http_body_chunk(http_ctx_t *ctx, uint8_t *ptr, int len, bool *done)
{
    dpi_packet_t *p = ctx->p;
    http_wing_t *w = ctx->w;
    uint8_t *end = ptr + len, *eol;
    int consume = 0, shift, eols;

    *done = false;
    while (ptr < end) {
        switch (w->chunk) {
        case HTTP_CHUNK_LENGTH:
            eol = consume_line(ptr, end - ptr, &eols);
            if (eol == NULL) return consume;
            shift = eol - ptr;

            w->content_len = 0;
            while (ptr < eol) {
                int8_t hex = c2hex(*ptr);
                if (hex == -1) break;
                w->content_len = (w->content_len << 4) + hex;
                ptr ++;
            }

            DEBUG_LOG(DBG_PARSER, p, "len=%u\n", w->content_len);

            ptr = eol;
            len -= shift;
            consume += shift;

            if (w->content_len == 0) {
                w->chunk = HTTP_CHUNK_LAST;
            } else {
                if (w->content_len & 0x80000000) {
                    dpi_threat_trigger(DPI_THRT_HTTP_NEG_LEN, p, "Content-length header has negative value");
                }

                w->chunk = HTTP_CHUNK_CONTENT;
            }

            break;
        case HTTP_CHUNK_CONTENT:
            if (w->content_len > 0) {
                if (len < w->content_len) {
                    DEBUG_LOG(DBG_PARSER, p, "consume=%u\n", len);
                    w->content_len -= len;
                    return consume + len;
                } else {
                    DEBUG_LOG(DBG_PARSER, p, "chunk done, consume=%u\n", w->content_len);

                    ptr += w->content_len;
                    len -= w->content_len;
                    consume += w->content_len;

                    w->content_len = 0;
                }
            } else {
                eol = consume_line(ptr, end - ptr, &eols);
                if (eol == NULL) return consume;
                shift = eol - ptr;

                ptr = eol;
                len -= shift;
                consume += shift;

                w->chunk = HTTP_CHUNK_LENGTH;
            }

            break;
        case HTTP_CHUNK_LAST:
            eol = consume_line(ptr, end - ptr, &eols);
            if (eol == NULL) return consume;
            shift = eol - ptr;

            DEBUG_LOG(DBG_PARSER, p, "chunk last\n");

            w->chunk = HTTP_CHUNK_LENGTH;
            *done = true;

            return consume + shift;
        }
    }

    return consume;
}

#define APACHE_STRUTS_PCRE "class=[\"']java\\.lang\\.ProcessBuilder[\"']>[\\s\\n\\r]*<command>[\\s\\n\\r]*<string>\\/bin\\/sh<\\/string>"
static pcre2_code *apache_struts_re;

// TODO: temp. way to buffer body in some cases.
//主要用于对HTTP消息体内容进行缓存，并对特定的威胁进行检测。
//具体来说，如果HTTP请求体为XML格式且未经过编码，则将其缓存在内存中，然后使用PCRE2正则表达式引擎匹配该请求体是否包含Apache Struts远程代码执行漏洞（CVE-2017-9805）相关的字符串，以便提前检测到该威胁类型。
static void buffer_body(http_ctx_t *ctx, uint8_t *ptr, int len) {
    http_wing_t *w = ctx->w;

    // This is to specifically detect threats in client-side XML, e.g. CVE-2017-9805
    if (unlikely(is_request(w) && w->ctype == HTTP_CTYPE_APPLICATION_XML && w->encode == HTTP_ENCODE_NONE)) {
        http_data_t *data = ctx->data;
        if (data->body_buffer == NULL) {
            data->body_buffer = malloc(2048);
        }
        if (data->body_buffer != NULL && data->body_buffer_len < 2048) {
            int copy = min(len, 2048 - data->body_buffer_len);
            memcpy(&data->body_buffer[data->body_buffer_len], ptr, copy);
            data->body_buffer_len += copy;

            if (unlikely(th_apache_struts_re_data == NULL)) {
                th_apache_struts_re_data  = pcre2_match_data_create_from_pattern(apache_struts_re, NULL);
            }

            if (likely(th_apache_struts_re_data != NULL)) {
                int rc = pcre2_match(apache_struts_re,
                        (PCRE2_SPTR)data->body_buffer, data->body_buffer_len,
                        0, 0, th_apache_struts_re_data, NULL);
                if (rc >= 0) {
                    dpi_threat_trigger(DPI_THRT_APACHE_STRUTS_RCE, ctx->p, NULL);
                }
            }
        }
    }
}

//通过判断HTTP请求头部分是否包含Content-Length或Transfer-Encoding字段，来确定HTTP请求体的长度以及数据传输方式。
//如果Content-Length字段存在，则通过该字段的值计算出整个请求体的长度，然后读取对应长度的数据进行处理；如果Transfer-Encoding字段为chunked，则使用chunked编码方式解析请求体内容。
static int http_parse_body(http_ctx_t *ctx, uint8_t *ptr, int len, bool *done)
{
    dpi_packet_t *p = ctx->p;
    http_wing_t *w = ctx->w;

    DEBUG_LOG_FUNC_ENTRY(DBG_PARSER, p);

    *done = false;
    if (w->flags & HTTP_FLAGS_CONN_CLOSE) {
        DEBUG_LOG(DBG_PARSER, p, "consume all=%u\n", len);
        return len;
    } else if (w->flags & HTTP_FLAGS_CHUNKED) {
        return http_body_chunk(ctx, ptr, len, done);
    } else {
        if (len < w->content_len) {
            DEBUG_LOG(DBG_PARSER, p, "consume=%u\n", len);
            buffer_body(ctx, ptr, len);
            w->content_len -= len;
            return len;
        } else {
            DEBUG_LOG(DBG_PARSER, p, "body done. consume=%u\n", w->content_len);
            buffer_body(ctx, ptr, w->content_len);
            *done = true;
            return w->content_len;
        }
    }
}

//主要用于检测当前流量是否满足Slowloris攻击的特征。
//Slowloris攻击是一种针对Web服务器的网络攻击方式，它利用HTTP/1.x协议中的一个特性——在不关闭连接的情况下可以发送多个请求，从而让服务器进入半连接状态，使得其他合法客户端无法建立连接。该攻击方式的特点是使用少量的连接和持久的HTTP头部信息来耗尽服务器资源（如CPU、内存等），从而导致服务器无法正常响应请求。
static inline bool is_slowloris_on_for_wing(dpi_session_t *s, http_wing_t *w)
{
    return is_request(w) && dpi_session_check_tick(s, DPI_SESS_TICK_FLAG_SLOWLORIS); //如果当前处理的是HTTP请求，且会话已经开启了Slowloris检测机制，则返回true；否则返回false。
}

static inline void overwrite_base_app(dpi_packet_t *p, uint16_t app)
{
    dpi_session_t *s = p->session;

    if (s->base_app != app) {
        s->base_app = app;
        dpi_ep_set_proto(p, app);
    }
}

//用于解析HTTP协议的函数
//该函数接收一个DPI（Deep Packet Inspection）数据包作为参数，并根据其中的HTTP协议内容进行解析。
//具体来说，它会按照HTTP协议的各个部分（请求行、请求头部、请求正文、响应头部、响应正文等）逐步解析数据包中的内容，并将解析结果存储在相关的结构体中。
static void http_parser(dpi_packet_t *p)
{
    http_ctx_t ctx;
    dpi_session_t *s = p->session;
    http_data_t *data;
    http_wing_t *w;
    uint8_t *ptr, *end;
    uint32_t len;

    if (unlikely((data = dpi_get_parser_data(p)) == NULL)) {
        if (!dpi_is_client_pkt(p)) {
            DEBUG_LOG(DBG_PARSER, p, "Not HTTP: First packet from server\n");
            dpi_fire_parser(p);
            return;
        }

        if ((data = calloc(1, sizeof(*data))) == NULL) {
            dpi_fire_parser(p);
            return;
        }

        data->client.seq = s->client.init_seq;
        data->server.seq = s->server.init_seq;

        dpi_put_parser_data(p, data);
    }

    w = dpi_is_client_pkt(p) ? &data->client : &data->server;
    if (w->seq == p->this_wing->init_seq) {
        ptr = dpi_pkt_ptr(p);
        len = dpi_pkt_len(p);
    } else if (dpi_is_seq_in_pkt(p, w->seq)) {
        uint32_t shift = u32_distance(dpi_pkt_seq(p), w->seq);
        ptr = dpi_pkt_ptr(p) + shift;
        len = dpi_pkt_len(p) - shift;
    } else {
        dpi_fire_parser(p);
        return;
    }

    ctx.p = p; ctx.data = data; ctx.w = w;

    end = ptr + len;
    while (ptr < end) {
        int shift;
        bool done;

        switch (w->section) {
        case HTTP_SECTION_NONE:
            if (isalpha(*ptr)) {
                w->section = HTTP_SECTION_REQ_RESP;
            } else if (dpi_is_client_pkt(p)) {
                dpi_fire_parser(p);
                return;
            } else {
                // Take all as body
                w->section = HTTP_SECTION_BODY;
                set_body_conn_close(w);
            }
            break;
        case HTTP_SECTION_REQ_RESP:
            if (dpi_is_client_pkt(p)) {
                FLAGS_SET(w->flags, HTTP_FLAGS_REQUEST);
                w->cmd_start = dpi_ptr_2_seq(p, ptr);
                w->hdr_start = 0;
                w->body_start = 0;
            } else {
                w->cmd_start = 0;
                w->hdr_start = 0;
                w->body_start = dpi_ptr_2_seq(p, ptr);
                FLAGS_UNSET(w->flags, HTTP_FLAGS_REQUEST);
            }
            if (unlikely(data->proto == HTTP_PROTO_RTSP)) {
                if (len <= 5) return;
                if (strncmp((char *)ptr, "RTSP/", 5) == 0) {
                    FLAGS_SET(w->flags, HTTP_FLAGS_REQUEST);
                } else {
                    FLAGS_UNSET(w->flags, HTTP_FLAGS_REQUEST);
                }
            }

            if (is_request(w)) {
                shift = http_parse_request(&ctx, ptr, len);
                if (shift == -1) {
                    dpi_fire_parser(p);
                    return;
                } else if (shift == 0) {
                    return;
                }

                dpi_finalize_parser(p);
            } else {
                shift = http_parse_response(&ctx, ptr, len);
                if (shift == -1) {
                    // Take all as body
                    w->section = HTTP_SECTION_BODY;
                    set_body_conn_close(w);
                } else if (shift == 0) {
                    return;
                }

                switch (data->proto) {
                case HTTP_PROTO_HTTP: overwrite_base_app(p, DPI_APP_HTTP); break;
                case HTTP_PROTO_RTSP: overwrite_base_app(p, DPI_APP_RTSP); break;
                case HTTP_PROTO_SIP:  overwrite_base_app(p, DPI_APP_SIP);  break;
                }
            }

            ptr += shift;
            len -= shift;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);
            if (shift > 0) {
                //offset to cmd_start
                w->hdr_start = w->seq;
                if (is_request(w)) {
                    dpi_dlp_area_t *dlparea = &p->dlp_area[DPI_SIG_CONTEXT_TYPE_URI_ORIGIN];
                    dlparea->dlp_start = w->cmd_start;
                    dlparea->dlp_end  = w->hdr_start;
                    dlparea->dlp_ptr = dpi_pkt_ptr(p) + dlparea->dlp_start - dpi_pkt_seq(p);
                    dlparea->dlp_offset = 0;
                    dlparea->dlp_len = dlparea->dlp_end - dlparea->dlp_start - dlparea->dlp_offset;
                }
            }

            w->section = HTTP_SECTION_HEADER;

            // Set short timeout to detect slowloris header attack
            if (is_request(w) && dpi_threat_status(DPI_THRT_HTTP_SLOWLORIS)) {
                DEBUG_LOG(DBG_SESSION | DBG_PARSER, p,
                          "Start HTTP slowerloris detection in header\n");

                data->url_start_tick = th_snap.tick;
                dpi_session_start_tick_for(s, DPI_SESS_TICK_FLAG_SLOWLORIS, p);
            }

            break;
        case HTTP_SECTION_HEADER:
            shift = http_parse_header(&ctx, ptr, len, &done);

            ptr += shift;
            len -= shift;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);

            p->dlp_area[DPI_SIG_CONTEXT_TYPE_HEADER].dlp_start = w->hdr_start;
            p->dlp_area[DPI_SIG_CONTEXT_TYPE_HEADER].dlp_end  = w->seq;

            if (!done) return;

            w->body_start = w->seq;
            w->section = HTTP_SECTION_FIRST_BODY;

            data->body_buffer_len = 0;

            // start slowloris body attack detection
            if (is_slowloris_on_for_wing(s, w)) {
                data->url_start_tick = 0;

                if (unlikely(to_detect_slowloris_body_attack(data, w))) {
                    DEBUG_LOG(DBG_SESSION | DBG_PARSER, p,
                              "Start HTTP slowerloris detection in body\n");

                    // Try to detect HTTP slowloris body attack. Between header and first body, 30s.
                    data->last_body_tick = th_snap.tick;
                } else {
                    DEBUG_LOG(DBG_SESSION | DBG_PARSER, p, "Stop HTTP slowerloris detection\n");

                    // stop slowloris detection
                    dpi_session_stop_tick_for(s, DPI_SESS_TICK_FLAG_SLOWLORIS, p);
                }
            }

            // If neither 'content-length' nor 'chunked' is set, take all the rest as body
            // unless we are sure the type of request or response has no body entity.
            if (unlikely(!(w->flags & (HTTP_FLAGS_CONTENT_LEN | HTTP_FLAGS_CHUNKED)))) {
                if (is_request(w)) {
                    if (data->method == HTTP_METHOD_GET) {
                    } else {
                        set_body_conn_close(w);
                    }
                } else {
                    if (data->method == HTTP_METHOD_HEAD || data->status == 204 ||
                        (data->status / 100 != 2 && data->status < 500)) { // 1xx, 3xx, 4xx
                    } else {
                        set_body_conn_close(w);
                    }
                }
            }

            // As body can be empty, we must let body parsing function run at least once
            // to complete state transition.

            // Fall through.
        case HTTP_SECTION_FIRST_BODY:
        case HTTP_SECTION_BODY:
            if (unlikely(is_slowloris_on_for_wing(s, w))) {
                data->last_body_tick = th_snap.tick;
            }

            shift = http_parse_body(&ctx, ptr, len, &done);
            if (shift == 0) {
                // This happens when http chunk length section doesn't give a full line.
                w->section = HTTP_SECTION_BODY;
                return;
            }

            ptr += shift;
            len -= shift;
            w->seq = dpi_ptr_2_seq(p, ptr);
            dpi_set_asm_seq(p, w->seq);

            p->dlp_area[DPI_SIG_CONTEXT_TYPE_BODY].dlp_start = w->body_start;
            p->dlp_area[DPI_SIG_CONTEXT_TYPE_BODY].dlp_end  = w->seq;

            if (done) {
                if (unlikely(is_slowloris_on_for_wing(s, w))) {
                    dpi_session_stop_tick_for(s, DPI_SESS_TICK_FLAG_SLOWLORIS, p);
                }

                set_body_done(w);
                w->section = HTTP_SECTION_NONE;
            } else if (unlikely(w->section == HTTP_SECTION_FIRST_BODY)) {
                w->section = HTTP_SECTION_BODY;
            }

            break;
        }
    }
}

//用于创建新的HTTP会话
static void http_new_session(dpi_packet_t *p)
{
    dpi_hire_parser(p);  //将数据包中的HTTP协议内容交给解析器进行处理，从而开始对HTTP协议的解析过程。
}

//用于释放HTTP协议解析过程中动态分配的内存
static void http_delete_data(void *data)
{
    free(((http_data_t *)data)->body_buffer);
    free(data);
}

//这是一个定义了HTTP协议解析器的数据结构对象
//该对象使用了C语言中结构体字面量（Struct Literal）的语法形式进行初始化。
static dpi_parser_t dpi_parser_http = {
    new_session: http_new_session,
    delete_data: http_delete_data,
    parser:      http_parser,
    name:        "http",
    ip_proto:    IPPROTO_TCP,
    type:        DPI_PARSER_HTTP,
};

//用于获取HTTP协议解析器
dpi_parser_t *dpi_http_tcp_parser(void)
{
    int pcre_errno;
    PCRE2_SIZE pcre_erroroffset;

    if (apache_struts_re == NULL) { //首先会检查apache_struts_re是否为NULL，如果为NULL则会调用pcre2_compile()函数对APACHE_STRUTS_PCRE进行编译（这里使用了正则表达式），并将结果存储在apache_struts_re中。
        apache_struts_re = pcre2_compile((PCRE2_SPTR)APACHE_STRUTS_PCRE,
                                         PCRE2_ZERO_TERMINATED,
                                         0,
                                         &pcre_errno,
                                         &pcre_erroroffset,
                                         NULL);
        if (apache_struts_re == NULL) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(pcre_errno, buffer, sizeof(buffer));
            DEBUG_ERROR(DBG_PARSER, "ERROR: PCRE2 compilation for (%s) failed at offset %d: %s\n",
                                    APACHE_STRUTS_PCRE, pcre_errno, buffer);
        }
    }

    return &dpi_parser_http;
    //返回指向全局变量dpi_parser_http的指针，该变量已经在前面定义过，并初始化为一个HTTP协议解析器对象。由于该解析器类型为DPI_PARSER_HTTP，因此可以通过调用这个函数来获得一个可用于解析HTTP协议的解析器对象。
}
