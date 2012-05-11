
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */
 //缓冲区资料：
 //http://hi.baidu.com/langwan/blog/item/822b758d5d1d9a1ab31bbaf8.html


#ifndef _NGX_BUF_H_INCLUDED_
#define _NGX_BUF_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef void *            ngx_buf_tag_t;

typedef struct ngx_buf_s  ngx_buf_t;

struct ngx_buf_s {
    u_char          *pos;       //缓冲区数据的起始位置
    u_char          *last;      //缓冲区数据的结束位置
    off_t            file_pos;  //缓冲区文件数据的起始位置
    off_t            file_last; //缓冲区文件数据的结束位置

    u_char          *start;         /* start of buffer */
    u_char          *end;           /* end of buffer */
    ngx_buf_tag_t    tag;
    ngx_file_t      *file;
    ngx_buf_t       *shadow;

    /* the buf's content could be changed */
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    unsigned         memory:1; //是否在内存中

    /* the buf's content is mmap()ed and must not be changed */
    unsigned         mmap:1; //内存中的文件映射

    unsigned         recycled:1;    //被回收
    unsigned         in_file:1;     //文件缓冲
    unsigned         flush:1;       //被清除
    unsigned         sync:1;        //异步
    unsigned         last_buf:1;    //是否是最后一个buffer
    unsigned         last_in_chain:1;  //链表的尾部

    unsigned         last_shadow:1;
    unsigned         temp_file:1;   //是否是临时文件中的缓冲

    /* STUB */ int   num;
};


struct ngx_chain_s {
    ngx_buf_t    *buf; //链表对应的buffer
    ngx_chain_t  *next; //链表下一个元素
};


typedef struct {
    ngx_int_t    num;
    size_t       size;
} ngx_bufs_t;


typedef struct ngx_output_chain_ctx_s  ngx_output_chain_ctx_t;

typedef ngx_int_t (*ngx_output_chain_filter_pt)(void *ctx, ngx_chain_t *in);

#if (NGX_HAVE_FILE_AIO)
typedef void (*ngx_output_chain_aio_pt)(ngx_output_chain_ctx_t *ctx,
    ngx_file_t *file);
#endif

//参考：
//http://simohayha.iteye.com/blog/662327
struct ngx_output_chain_ctx_s {
    ngx_buf_t                   *buf;           //保存临时的buf
    ngx_chain_t                 *in;            //保存了将要发送的chain
    ngx_chain_t                 *free;          //保存了已经发送完毕的chain，以便于重复利用
    ngx_chain_t                 *busy;          //保存了还未发送的chain

    unsigned                     sendfile:1;    //sendfile标记
    unsigned                     directio:1;    //directio标记
#if (NGX_HAVE_ALIGNED_DIRECTIO)
    unsigned                     unaligned:1;
#endif
    unsigned                     need_in_memory:1;  //是否需要在内存中保存一份(使用sendfile的话，内存中没有文件的拷贝的，而我们有时需要处理文件，此时就需要设置这个标记)
    unsigned                     need_in_temp:1;    //是否存在的buf复制一份，这里不管是存在在内存还是文件
#if (NGX_HAVE_FILE_AIO)
    unsigned                     aio:1;

    ngx_output_chain_aio_pt      aio_handler;
#endif

    off_t                        alignment;

    ngx_pool_t                  *pool;              //缓存池
    ngx_int_t                    allocated;         //已经allocated的大小
    ngx_bufs_t                   bufs;              //对应的bufs的大小，这个值就是我们loc conf中设置的bufs
    ngx_buf_tag_t                tag;               //表示现在处于那个模块（因为upstream也会调用output_chain) 

    ngx_output_chain_filter_pt   output_filter;     //这个值一般是ngx_http_next_filter,也就是继续调用filter链 
    void                        *filter_ctx;        //当前filter的上下文，这里也是由于upstream也会调用output_chain
};


typedef struct {
    ngx_chain_t                 *out;
    ngx_chain_t                **last;
    ngx_connection_t            *connection;
    ngx_pool_t                  *pool;
    off_t                        limit;
} ngx_chain_writer_ctx_t;


#define NGX_CHAIN_ERROR     (ngx_chain_t *) NGX_ERROR


#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)

#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))

ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);


#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
#define ngx_free_chain(pool, cl)                                             \
    cl->next = pool->chain;                                                  \
    pool->chain = cl



ngx_int_t ngx_output_chain(ngx_output_chain_ctx_t *ctx, ngx_chain_t *in);
ngx_int_t ngx_chain_writer(void *ctx, ngx_chain_t *in);

ngx_int_t ngx_chain_add_copy(ngx_pool_t *pool, ngx_chain_t **chain,
    ngx_chain_t *in);
ngx_chain_t *ngx_chain_get_free_buf(ngx_pool_t *p, ngx_chain_t **free);
void ngx_chain_update_chains(ngx_chain_t **free, ngx_chain_t **busy,
    ngx_chain_t **out, ngx_buf_tag_t tag);


#endif /* _NGX_BUF_H_INCLUDED_ */
