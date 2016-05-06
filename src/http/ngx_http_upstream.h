
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000100
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000200
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00000400
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00000800
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100


typedef struct {
    ngx_msec_t                       bl_time;
    ngx_uint_t                       bl_state;

    ngx_uint_t                       status;
    time_t                           response_sec;
    ngx_uint_t                       response_msec;
    off_t                            response_length;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);

//该结构体定义了load_balance模块的入口，有两个回调函数，用来初始化load_balance模块
typedef struct {
    ngx_http_upstream_init_pt        init_upstream;//配置解析时初始化
    ngx_http_upstream_init_peer_pt   init;//请求时初始化
    void                            *data;//服务器列表指针
} ngx_http_upstream_peer_t;

//存放upstream配置块中每个服务器的信息
typedef struct {
    ngx_addr_t                      *addrs;//服务器地址数组
    ngx_uint_t                       naddrs;//地址数组的长度
    ngx_uint_t                       weight;//权重
    ngx_uint_t                       max_fails;//允许的最大失败次数
    time_t                           fail_timeout;//失败的时间区间

    unsigned                         down:1;//服务器是否下线
    unsigned                         backup:1;//是否是备份服务器
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020

//upstream框架的配置数据结构
struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;//初始化结构体
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t动态数组，保存upstream配置快中的所有服务器信息 */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    in_port_t                        default_port;
};

//ngx_http_upstrean_conf_t结构设置upstream框架连接上游服务器的参数
typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream;

    // 连接上游服务器的超时时间，单位为毫秒
    ngx_msec_t                       connect_timeout;
    // 发送TCP包到上游服务器的超时时间，单位为毫秒
    ngx_msec_t                       send_timeout;
    // 接收TCP包到上游服务器的超时时间，单位为毫秒
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       timeout;

    size_t                           send_lowat;
    size_t                           buffer_size;//缓冲区大小

    size_t                           busy_buffers_size;
    size_t                           max_temp_file_size;
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    ngx_bufs_t                       bufs; //缓冲区数量限制

    ngx_uint_t                       ignore_headers;
    ngx_uint_t                       next_upstream;
    ngx_uint_t                       store_access;
    ngx_flag_t                       buffering;//是否使用接收缓冲区
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    ngx_flag_t                       ignore_client_abort;
    ngx_flag_t                       intercept_errors;
    ngx_flag_t                       cyclic_temp_file;

    ngx_path_t                      *temp_path;

    ngx_hash_t                       hide_headers_hash;
    ngx_array_t                     *hide_headers;
    ngx_array_t                     *pass_headers;

    ngx_addr_t                      *local;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *no_cache;
#endif

    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;
#endif

    ngx_str_t                        module;
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    off_t                            content_length_n;

    ngx_array_t                      cache_control;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    // 地址个数
    ngx_uint_t                       naddrs;
    in_addr_t                       *addrs;

    // 上游服务器的地址
    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    ngx_http_upstream_handler_pt     read_event_handler;
    ngx_http_upstream_handler_pt     write_event_handler;

    /*用于描述与对端(上游)连接的结构体，包括对端网络终端的IP地址，端口等参数*/
    ngx_peer_connection_t            peer;

    ngx_event_pipe_t                *pipe;

    /*request_bufs决定发送什么样的请求给上游服务器，在实现create_request方法时需要设置它 */
    ngx_chain_t                     *request_bufs;

    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    /*用于描述与上游服务器连接配置的结构体，例如TCP timeout时间等等*/
    ngx_http_upstream_conf_t        *conf;

    ngx_http_upstream_headers_in_t   headers_in;

    /* 通过resolved可以直接指定上游服务器地址 */
    ngx_http_upstream_resolved_t    *resolved;

    /* buffer成员存储接收自上游服务器发来的相应内容 */
    ngx_buf_t                        buffer;
    size_t                           length;

    ngx_chain_t                     *out_bufs;//从上游接收到的数据
    ngx_chain_t                     *busy_bufs;
    ngx_chain_t                     *free_bufs;
	//处理上游服务器响应数据的回调函数
    ngx_int_t                      (*input_filter_init)(void *data);
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    /* 构造发往上游服务器的请求内容 */
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);

    /* 收到上游服务器的相应后就会回调process_header方法。如果process_header返回NGX_AGAIN，那么是在告诉upstream还没有收到完整的响应包头，
    此时，对于本次upstream请求来说，再次接受到上游服务器发来的TCP流时，还会调用process_header方法处理，直到process_header函数返回非NGX_AGAIN
    值这一阶段才会停止 */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    void                           (*abort_request)(ngx_http_request_t *r);

    /* 销毁upstream请求时调用 */
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);

    ngx_msec_t                       timeout;

    ngx_http_upstream_state_t       *state;

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;

    ngx_http_cleanup_pt             *cleanup;

    unsigned                         store:1;
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    // 是否基于SSL协议访问上游服务器
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    /* 在向客户端转发上游服务器的包体时才有用。
    当buffering为1时，表示使用多个缓冲区以及磁盘文件来转发上游的相应包体。当nginx与上游间的网速远大于nginx与下游客户端间的网速时，
    让nginx开辟更多的内存甚至使用磁盘文件来缓存上游的相应包体，这是有意义的，它可以减轻上游服务器的并发压力。
    当buffering为0时，表示只适用上面的这一个buffer缓冲区来向下游转发响应包体。 */
    unsigned                         buffering:1;

    unsigned                         request_sent:1;//是否已经发送请求
    unsigned                         header_sent:1;//是否已经发送响应头
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


ngx_int_t ngx_http_upstream_header_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];


#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
