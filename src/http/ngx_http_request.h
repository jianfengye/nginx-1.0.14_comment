
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_REQUEST_H_INCLUDED_
#define _NGX_HTTP_REQUEST_H_INCLUDED_


#define NGX_HTTP_MAX_URI_CHANGES           10
#define NGX_HTTP_MAX_SUBREQUESTS           50

/* must be 2^n */
#define NGX_HTTP_LC_HEADER_LEN             32


#define NGX_HTTP_DISCARD_BUFFER_SIZE       4096
#define NGX_HTTP_LINGERING_BUFFER_SIZE     4096


#define NGX_HTTP_VERSION_9                 9
#define NGX_HTTP_VERSION_10                1000
#define NGX_HTTP_VERSION_11                1001

#define NGX_HTTP_UNKNOWN                   0x0001
#define NGX_HTTP_GET                       0x0002
#define NGX_HTTP_HEAD                      0x0004
#define NGX_HTTP_POST                      0x0008
#define NGX_HTTP_PUT                       0x0010
#define NGX_HTTP_DELETE                    0x0020
#define NGX_HTTP_MKCOL                     0x0040
#define NGX_HTTP_COPY                      0x0080
#define NGX_HTTP_MOVE                      0x0100
#define NGX_HTTP_OPTIONS                   0x0200
#define NGX_HTTP_PROPFIND                  0x0400
#define NGX_HTTP_PROPPATCH                 0x0800
#define NGX_HTTP_LOCK                      0x1000
#define NGX_HTTP_UNLOCK                    0x2000
#define NGX_HTTP_PATCH                     0x4000
#define NGX_HTTP_TRACE                     0x8000

#define NGX_HTTP_CONNECTION_CLOSE          1
#define NGX_HTTP_CONNECTION_KEEP_ALIVE     2


#define NGX_NONE                           1


#define NGX_HTTP_PARSE_HEADER_DONE         1

#define NGX_HTTP_CLIENT_ERROR              10
#define NGX_HTTP_PARSE_INVALID_METHOD      10
#define NGX_HTTP_PARSE_INVALID_REQUEST     11
#define NGX_HTTP_PARSE_INVALID_09_METHOD   12

#define NGX_HTTP_PARSE_INVALID_HEADER      13


/* unused                                  1 */
#define NGX_HTTP_SUBREQUEST_IN_MEMORY      2
#define NGX_HTTP_SUBREQUEST_WAITED         4
#define NGX_HTTP_LOG_UNSAFE                8


#define NGX_HTTP_OK                        200
#define NGX_HTTP_CREATED                   201
#define NGX_HTTP_ACCEPTED                  202
#define NGX_HTTP_NO_CONTENT                204
#define NGX_HTTP_PARTIAL_CONTENT           206

#define NGX_HTTP_SPECIAL_RESPONSE          300
#define NGX_HTTP_MOVED_PERMANENTLY         301
#define NGX_HTTP_MOVED_TEMPORARILY         302
#define NGX_HTTP_SEE_OTHER                 303
#define NGX_HTTP_NOT_MODIFIED              304
#define NGX_HTTP_TEMPORARY_REDIRECT        307

#define NGX_HTTP_BAD_REQUEST               400
#define NGX_HTTP_UNAUTHORIZED              401
#define NGX_HTTP_FORBIDDEN                 403
#define NGX_HTTP_NOT_FOUND                 404
#define NGX_HTTP_NOT_ALLOWED               405
#define NGX_HTTP_REQUEST_TIME_OUT          408
#define NGX_HTTP_CONFLICT                  409
#define NGX_HTTP_LENGTH_REQUIRED           411
#define NGX_HTTP_PRECONDITION_FAILED       412
#define NGX_HTTP_REQUEST_ENTITY_TOO_LARGE  413
#define NGX_HTTP_REQUEST_URI_TOO_LARGE     414
#define NGX_HTTP_UNSUPPORTED_MEDIA_TYPE    415
#define NGX_HTTP_RANGE_NOT_SATISFIABLE     416


/* Our own HTTP codes */

/* The special code to close connection without any response */
#define NGX_HTTP_CLOSE                     444

#define NGX_HTTP_NGINX_CODES               494

#define NGX_HTTP_REQUEST_HEADER_TOO_LARGE  494

#define NGX_HTTPS_CERT_ERROR               495
#define NGX_HTTPS_NO_CERT                  496

/*
 * We use the special code for the plain HTTP requests that are sent to
 * HTTPS port to distinguish it from 4XX in an error page redirection
 */
#define NGX_HTTP_TO_HTTPS                  497

/* 498 is the canceled code for the requests with invalid host name */

/*
 * HTTP does not define the code for the case when a client closed
 * the connection while we are processing its request so we introduce
 * own code to log such situation when a client has closed the connection
 * before we even try to send the HTTP header to it
 */
#define NGX_HTTP_CLIENT_CLOSED_REQUEST     499


#define NGX_HTTP_INTERNAL_SERVER_ERROR     500
#define NGX_HTTP_NOT_IMPLEMENTED           501
#define NGX_HTTP_BAD_GATEWAY               502
#define NGX_HTTP_SERVICE_UNAVAILABLE       503
#define NGX_HTTP_GATEWAY_TIME_OUT          504
#define NGX_HTTP_INSUFFICIENT_STORAGE      507


#define NGX_HTTP_LOWLEVEL_BUFFERED         0xf0
#define NGX_HTTP_WRITE_BUFFERED            0x10
#define NGX_HTTP_GZIP_BUFFERED             0x20
#define NGX_HTTP_SSI_BUFFERED              0x01
#define NGX_HTTP_SUB_BUFFERED              0x02
#define NGX_HTTP_COPY_BUFFERED             0x04


typedef enum {
    NGX_HTTP_INITING_REQUEST_STATE = 0,
    NGX_HTTP_READING_REQUEST_STATE,
    NGX_HTTP_PROCESS_REQUEST_STATE,

    NGX_HTTP_CONNECT_UPSTREAM_STATE,
    NGX_HTTP_WRITING_UPSTREAM_STATE,
    NGX_HTTP_READING_UPSTREAM_STATE,

    NGX_HTTP_WRITING_REQUEST_STATE,
    NGX_HTTP_LINGERING_CLOSE_STATE,
    NGX_HTTP_KEEPALIVE_STATE
} ngx_http_state_e;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
    ngx_http_header_handler_pt        handler;
} ngx_http_header_t;


typedef struct {
    ngx_str_t                         name;
    ngx_uint_t                        offset;
} ngx_http_header_out_t;


typedef struct {
    ngx_list_t                        headers;

    ngx_table_elt_t                  *host;
    ngx_table_elt_t                  *connection;
    ngx_table_elt_t                  *if_modified_since;
    ngx_table_elt_t                  *if_unmodified_since;
    ngx_table_elt_t                  *user_agent;
    ngx_table_elt_t                  *referer;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_type;

    ngx_table_elt_t                  *range;
    ngx_table_elt_t                  *if_range;

    ngx_table_elt_t                  *transfer_encoding;
    ngx_table_elt_t                  *expect;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                  *accept_encoding;
    ngx_table_elt_t                  *via;
#endif

    ngx_table_elt_t                  *authorization;

    ngx_table_elt_t                  *keep_alive;

#if (NGX_HTTP_PROXY || NGX_HTTP_REALIP || NGX_HTTP_GEO)
    ngx_table_elt_t                  *x_forwarded_for;
#endif

#if (NGX_HTTP_REALIP)
    ngx_table_elt_t                  *x_real_ip;
#endif

#if (NGX_HTTP_HEADERS)
    ngx_table_elt_t                  *accept;
    ngx_table_elt_t                  *accept_language;
#endif

#if (NGX_HTTP_DAV)
    ngx_table_elt_t                  *depth;
    ngx_table_elt_t                  *destination;
    ngx_table_elt_t                  *overwrite;
    ngx_table_elt_t                  *date;
#endif

    ngx_str_t                         user;
    ngx_str_t                         passwd;

    ngx_array_t                       cookies; //cookie

    ngx_str_t                         server;
    off_t                             content_length_n;
    time_t                            keep_alive_n;

    unsigned                          connection_type:2;
    unsigned                          msie:1;  //浏览器类型
    unsigned                          msie6:1;
    unsigned                          opera:1;
    unsigned                          gecko:1;
    unsigned                          chrome:1;
    unsigned                          safari:1;
    unsigned                          konqueror:1;
} ngx_http_headers_in_t;


//ngx_http_headers_out_t 代表输出的相应头
typedef struct {
    //待发送的HTTP头部链表。
    ngx_list_t                        headers;

    ngx_uint_t                        status; //http相应状态，比如200
    ngx_str_t                         status_line; //相应的状态行，比如“HTTP/1.1 201 CREATED”

    //下面成员都是RFC1616中定义的HTTP头部。
    ngx_table_elt_t                  *server;
    ngx_table_elt_t                  *date;
    ngx_table_elt_t                  *content_length;
    ngx_table_elt_t                  *content_encoding;
    ngx_table_elt_t                  *location;
    ngx_table_elt_t                  *refresh;
    ngx_table_elt_t                  *last_modified;
    ngx_table_elt_t                  *content_range;
    ngx_table_elt_t                  *accept_ranges;
    ngx_table_elt_t                  *www_authenticate;
    ngx_table_elt_t                  *expires;
    ngx_table_elt_t                  *etag;

    ngx_str_t                        *override_charset;

    //可以调用ngx_http_set_content_type(r)方法帮助我们设置Content-Type头部，
    //这个方法会根据URI中的文件扩展名并对应者mime.type来设置Content-type值
    size_t                            content_type_len;
    ngx_str_t                         content_type;
    ngx_str_t                         charset;
    u_char                           *content_type_lowcase;
    ngx_uint_t                        content_type_hash;

    ngx_array_t                       cache_control;

    //这里指定过content_length_n后，不用再到ngx_table_elt_t中设置了
    off_t                             content_length_n;
    time_t                            date_time;
    time_t                            last_modified_time;
} ngx_http_headers_out_t;

//ngx_http_headers_out_t使用示例：
/*
ngx_table_elt_t *h = ngx_list_push(&r->headers_out.headers)
if(h == NULL) {
    return NGX_ERROR;
}

h->hash=1
h->key.len = sizeof("TestHead") - 1;
h->key.data = (u_char *) "TestHead";
h->value.len = sizeof("TestValue") - 1;
h->value.data = (u_char *) "TestValue";

这样会在相应中增加一个HTTP头部
TestHead: TestValue\r\n
*/

typedef void (*ngx_http_client_body_handler_pt)(ngx_http_request_t *r);

typedef struct {
    // 存放HTTP包体的临时文件
    ngx_temp_file_t                  *temp_file;

    // 接收HTTP包体的缓冲区链表。当包体需要全部存放在内存中时，如果一块ngx_buf_t缓冲区无法存放完，这时就需要使用ngx_chain_t链表存放
    ngx_chain_t                      *bufs;

    // 直接接收HTTP包体的缓存
    ngx_buf_t                        *buf;

    // 根据content-length头部和已接收到的包体长度，计算出的还需要接收的包体长度
    off_t                             rest;

    // 该缓冲区链表存放着将要写入文件的包体
    ngx_chain_t                      *to_write;

    // HTTP包体接收完毕后执行的回调方法，也就是ngx_http_read_client_request_body 方法传递的第二个参数
    ngx_http_client_body_handler_pt   post_handler;
} ngx_http_request_body_t;


typedef struct {
    ngx_http_request_t               *request;

    ngx_buf_t                       **busy;
    ngx_int_t                         nbusy;

    ngx_buf_t                       **free;
    ngx_int_t                         nfree;

    ngx_uint_t                        pipeline;    /* unsigned  pipeline:1; */
} ngx_http_connection_t;


typedef struct ngx_http_server_name_s  ngx_http_server_name_t;


typedef struct {
     ngx_hash_combined_t              names;

     ngx_uint_t                       nregex;
     ngx_http_server_name_t          *regex;
} ngx_http_virtual_names_t;


typedef void (*ngx_http_cleanup_pt)(void *data);

typedef struct ngx_http_cleanup_s  ngx_http_cleanup_t;

struct ngx_http_cleanup_s {
    ngx_http_cleanup_pt               handler;
    void                             *data;
    ngx_http_cleanup_t               *next;
};


typedef ngx_int_t (*ngx_http_post_subrequest_pt)(ngx_http_request_t *r,
    void *data, ngx_int_t rc);

typedef struct {
    ngx_http_post_subrequest_pt       handler;
    void                             *data;
} ngx_http_post_subrequest_t;


typedef struct ngx_http_postponed_request_s  ngx_http_postponed_request_t;

struct ngx_http_postponed_request_s {
    ngx_http_request_t               *request;
    ngx_chain_t                      *out;
    ngx_http_postponed_request_t     *next;
};


typedef struct ngx_http_posted_request_s  ngx_http_posted_request_t;

struct ngx_http_posted_request_s {
    // 指向当前待处理子请求的ngx_http_request_t结构体
    ngx_http_request_t               *request;

    // 指向下一个子请求，如果没有，则为NULL
    ngx_http_posted_request_t        *next;
};


typedef ngx_int_t (*ngx_http_handler_pt)(ngx_http_request_t *r);
typedef void (*ngx_http_event_handler_pt)(ngx_http_request_t *r);

//这个结构定义了一个HTTP请求。
struct ngx_http_request_s {
    uint32_t                          signature;         /* "HTTP" */

    // 这个请求对应的客户端连接
    ngx_connection_t                 *connection;  //当前request的连接

    // 指向存放所有HTTP模块的上下文结构体的指针数组
    void                            **ctx;  //上下文

    // 指向请求对应的存放main级别配置结构体的指针数组
    void                            **main_conf; //main配置

    // 指向请求对应的存放srv级别配置结构体的指针数组
    void                            **srv_conf;  //srv配置

    // 指向请求对应的存放loc级别配置结构体的指针数组
    void                            **loc_conf;  //loc配置

    /*
    在接收完HTTP头部，第一次在业务上处理HTTP请求时，HTTP框架提供的处理方法是ngx_http_process_request。
    但如果该方法无法一次处理完该请求的全部业务，在归还控制权到epoll事件模块后，该请求再次被回调时，将通过ngx_http_request_handler方法来处理，
    而这个方法中对于可读事件的处理就是调用read_event_handler处理请求。也就是说，HTTP模块希望在底层处理请求的读事件，重新实现read_evet_handler方法。
    */
    ngx_http_event_handler_pt         read_event_handler;

    /*
    与read_event_handler回调方法类似，如果ngx_http_request_handler方法判断当前事件是可写事件，则调用write_event_handler处理请求。
    */
    ngx_http_event_handler_pt         write_event_handler;

#if (NGX_HTTP_CACHE)
    ngx_http_cache_t                 *cache;
#endif

    // upstream机制用到的结构体
    ngx_http_upstream_t              *upstream;  //load-balance，如果模块是load-balance的话设置这个
    ngx_array_t                      *upstream_states;
                                         /* of ngx_http_upstream_state_t */

    /*
    表示这个请求的内存池，在ngx_http_free_request 方法中销毁。它与ngx_connection_t中的内存池意义不同，当请求释放时，
    TCP连接可能并没有关闭，这时请求的内存池会销毁，但ngx_connection_t的内存池不会销毁
    */
    ngx_pool_t                       *pool;     //连接池

    // 用于接收HTTP请求内容的缓冲区，主要用于接收HTTP头部
    ngx_buf_t                        *header_in;

    /*
    ngx_http_prcess_request_headers 方法在接收，解析完HTTP请求的头部后，会把解析完的每个HTTP头部加入到headers_in的headers连表中，
    同时会构造headers_in中的其他成员
    */
    ngx_http_headers_in_t             headers_in; //request的header
    /*
    HTTP模块会把想要发送到HTTP相应信息放到headers_out中，期望HTTP框架将headers_out中的成员序列化为HTTP相应包发送给用户
    */
    ngx_http_headers_out_t            headers_out; //response的header，使用ngx_http_send_header发送

    // 接收HTTP请求中包体的数据结构
    ngx_http_request_body_t          *request_body; //response的body

    // 延迟关闭连接的时间
    time_t                            lingering_time;

    /*
    当前请求初始化时的时间。如果这个请求是子请求，则该时间是自请求的生成时间；如果这个请求是用户发来的请求，则是建立起TCP连接后，第一次接收到可读事件时的时间
    */
    time_t                            start_sec;

    // 与start_sec配合使用，表示相对于start_sec秒的毫秒偏移量
    ngx_msec_t                        start_msec;

    ngx_uint_t                        method;
    ngx_uint_t                        http_version; //http的版本

    ngx_str_t                         request_line;
    ngx_str_t                         uri;  //请求的路径 eg '/query.php'
    ngx_str_t                         args; //请求的参数 eg 'name=john'
    ngx_str_t                         exten; 
    ngx_str_t                         unparsed_uri;

    ngx_str_t                         method_name;
    ngx_str_t                         http_protocol;

    /*
    表示需要发送给客户端的HTTP相应。out中保存着由headers_out中序列化后的表示HTTP头部的TCP流。在调用ngx_http_output_filter方法后，
    out中还会保存待发送的HTTP包体，它是实现异步发送的HTTP相应的关键
    */
    ngx_chain_t                      *out; //输出的chain

    /*
    当前请求既可能是用户发来的请求，也可能是派生出的子请求，而main则标识一系列相关的派生子请求的原始请求，
    我们一般可以通过main和当前请求的地址是否相等来判断当前请求是否为用户发来的原始请求。
    */
    ngx_http_request_t               *main;

    // 当前请求的父请求。注意，父请求未必是原始请求
    ngx_http_request_t               *parent;

    // 与subrequest子请求相关的功能。
    ngx_http_postponed_request_t     *postponed;
    ngx_http_post_subrequest_t       *post_subrequest;

    /*
    所有自请求都是通过posted_requests这个单链表来链接起来的，执行post子请求时调用的ngx_http_run_posted_requests
    方法就是通过遍历该单链表来执行子请求的。
    */
    ngx_http_posted_request_t        *posted_requests;

    ngx_http_virtual_names_t         *virtual_names;

    /*
    全局的ngx_http_phase_engine_t结构体中定义了一个ngx_http_phase_handler_t 回调方法组成的数组，
    而phase_handler成员则与该数组配合使用，表示请求下次应当执行以phase_handler作为序号指定的数组中的回调方法。
    HTTP框架正是以这种方式把各个HTTP模块集成起来处理请求的。
    */
    ngx_int_t                         phase_handler;

    /*
    表示NGX_HTTP_CONTENT_PHASE阶段提供给HTTP模块处理请求的一种方式，content_handler指向HTTP模块实现的请求处理方法。
    */
    ngx_http_handler_pt               content_handler;

    /*
    在NGX_HTTP_ACCESS_PHASE阶段需要判断请求是否具有访问权限时，通过access_code来传递HTTP模块的handler回调方法的返回值，
    如果access_code为0，则表示请求具备访问权限，反之则说明请求不具备访问权限
    */ 
    ngx_uint_t                        access_code;

    ngx_http_variable_value_t        *variables;

#if (NGX_PCRE)
    ngx_uint_t                        ncaptures;
    int                              *captures;
    u_char                           *captures_data;
#endif

    size_t                            limit_rate;

    /* used to learn the Apache compatible response length without a header */
    size_t                            header_size;

    // HTTP请求的全部长度，包括HTTP包体
    off_t                             request_length;

    ngx_uint_t                        err_status;

    ngx_http_connection_t            *http_connection;

    ngx_http_log_handler_pt           log_handler;

    // 在这个请求中，如果打开了某些资源，并需要在请求结束时释放，那么都需要在把定义的释放资源方法添加到cleanup成员中。
    ngx_http_cleanup_t               *cleanup;

    unsigned                          subrequests:8;

    /*
    表示当前请求的引用次数。例如，在使用subrequest功能时，依附在这个请求上的自请求数目会返回到count上，每增加一个子请求，
    count数就要加1。其中任何一个自请求派生出新的子请求时，对应的原始请求（main指针指向的请求）的count值都要加1.又如，
    当我们接收HTTP包体的时候，由于这也是一个异步调用，所以count上也需要加1，这样在结束请求时，就不会在count引用计数未清零时销毁请求。
    */
    unsigned                          count:8;

    // 标志位，目前仅由aio使用
    unsigned                          blocked:8;

    // 标志位，为1表示当前请求正在使用异步文件IO
    unsigned                          aio:1;

    unsigned                          http_state:4;

    /* URI with "/." and on Win32 with "//" */
    unsigned                          complex_uri:1;

    /* URI with "%" */
    unsigned                          quoted_uri:1;

    /* URI with "+" */
    unsigned                          plus_in_uri:1;

    /* URI with " " */
    unsigned                          space_in_uri:1;

    unsigned                          invalid_header:1;

    unsigned                          add_uri_to_alias:1;
    unsigned                          valid_location:1;
    unsigned                          valid_unparsed_uri:1;

    // 标志位，为1表示URL发生过rewrite重写
    unsigned                          uri_changed:1;

    /*
    表示使用rewrite重写URL的次数。因为目前最多可以更改10次，所以uri_changes初始化为11，而每重写URL一次就把uri_changes减1，
    一旦uri_changes等于0，则向用户返回失败
    */
    unsigned                          uri_changes:4;

    unsigned                          request_body_in_single_buf:1;
    unsigned                          request_body_in_file_only:1;
    unsigned                          request_body_in_persistent_file:1;
    unsigned                          request_body_in_clean_file:1;
    unsigned                          request_body_file_group_access:1;
    unsigned                          request_body_file_log_level:3;

    unsigned                          subrequest_in_memory:1;
    unsigned                          waited:1;

#if (NGX_HTTP_CACHE)
    unsigned                          cached:1;
#endif

#if (NGX_HTTP_GZIP)
    unsigned                          gzip_tested:1;
    unsigned                          gzip_ok:1;
    unsigned                          gzip_vary:1;
#endif

    unsigned                          proxy:1;
    unsigned                          bypass_cache:1;
    unsigned                          no_cache:1;

    /*
     * instead of using the request context data in
     * ngx_http_limit_zone_module and ngx_http_limit_req_module
     * we use the single bits in the request structure
     */
    unsigned                          limit_zone_set:1;
    unsigned                          limit_req_set:1;

#if 0
    unsigned                          cacheable:1;
#endif

    unsigned                          pipeline:1;
    unsigned                          plain_http:1;
    unsigned                          chunked:1;
    unsigned                          header_only:1;

    // 标志位，为1表示当前请求是keepalive请求
    unsigned                          keepalive:1;

    // 延迟关闭标志位，为1表示需要延迟关闭。例如在接收完HTTP头部时如果发现包体存在，该标志位会设置1，而放弃接收包体会设为0
    unsigned                          lingering_close:1;

    // 标志位，为1表示正在丢弃HTTP请求中的包体
    unsigned                          discard_body:1;

    // 标志位，为1表示请求的当前状态是在做内部跳转
    unsigned                          internal:1;
    unsigned                          error_page:1;
    unsigned                          ignore_content_encoding:1;
    unsigned                          filter_finalize:1;
    unsigned                          post_action:1;
    unsigned                          request_complete:1;
    unsigned                          request_output:1;

    // 标志位，为1表示发送给客户端的HTTP相应头部已经发送。在调用ngx_http_send_header方法后，若已经成功地启动相应头部发送流程，
    // 该标志位就会置1，用来防止反复地发送头部。
    unsigned                          header_sent:1;
    unsigned                          expect_tested:1;
    unsigned                          root_tested:1;
    unsigned                          done:1;
    unsigned                          logged:1;

    // 表示缓冲中是否有待发送内容的标志位
    unsigned                          buffered:4;

    unsigned                          main_filter_need_in_memory:1;
    unsigned                          filter_need_in_memory:1;
    unsigned                          filter_need_temporary:1;
    unsigned                          allow_ranges:1;

#if (NGX_STAT_STUB)
    unsigned                          stat_reading:1;
    unsigned                          stat_writing:1;
#endif

    /* used to parse HTTP headers */

    // 状态机解析HTTP时使用stats来表示当前的解析状态。
    ngx_uint_t                        state;

    ngx_uint_t                        header_hash;
    ngx_uint_t                        lowcase_index;
    u_char                            lowcase_header[NGX_HTTP_LC_HEADER_LEN];

    u_char                           *header_name_start;
    u_char                           *header_name_end;
    u_char                           *header_start;
    u_char                           *header_end;

    /*
     * a memory that can be reused after parsing a request line
     * via ngx_http_ephemeral_t
     */

    u_char                           *uri_start;
    u_char                           *uri_end;
    u_char                           *uri_ext;
    u_char                           *args_start;
    u_char                           *request_start;
    u_char                           *request_end;
    u_char                           *method_end;
    u_char                           *schema_start;
    u_char                           *schema_end;
    u_char                           *host_start;
    u_char                           *host_end;
    u_char                           *port_start;
    u_char                           *port_end;

    unsigned                          http_minor:16;
    unsigned                          http_major:16;
};


typedef struct {
    ngx_http_posted_request_t         terminal_posted_request;
#if (NGX_HAVE_AIO_SENDFILE)
    u_char                            aio_preload;
#endif
} ngx_http_ephemeral_t;


extern ngx_http_header_t       ngx_http_headers_in[];
extern ngx_http_header_out_t   ngx_http_headers_out[];


#endif /* _NGX_HTTP_REQUEST_H_INCLUDED_ */