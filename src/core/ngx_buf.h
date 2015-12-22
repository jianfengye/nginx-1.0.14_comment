
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

// ngx_buf_s是nginx用于处理大数据的关键数据结构
// 它既应用于内存数据，也应用于磁盘数据。
struct ngx_buf_s {
    // 处理内存数据
    u_char          *pos;       //告知需要处理的内存数据的起始位置
    u_char          *last;      //告知需要处理的内存数据的结束位置，即希望处理的数据为[pos,last)

    // 处理文件数据
    off_t            file_pos;  //告知需要处理的文件数据的起始位置
    off_t            file_last; //告知需要处理的文件数据的结束位置

    // 处理内存数据
    u_char          *start;      //当一整块内存被包含在多个buf中的时候，那么这些buf里面的start和end都指向这块内存的起始位置和终止位置，和pos不同，pos会大于等于start
    u_char          *end;        //见start分析，和last不同，last会小于等于end

    ngx_buf_tag_t    tag;        //当前缓冲区的类型。例如由哪个模块使用，就指向这个模块ngx_module_t变量的地址
    ngx_file_t      *file;       //文件数据所引用的文件

    // 当前缓冲区的影子缓冲区，这个成员很少使用到。
	//当一个buf完整的copy另一buf的所有字段的时候，那么这两个buf指向的实际上是同一个内存或者同一个文件。
	//此时的两个buf的shadow是相互指向对方的，那么对于这样的两个buf在释放的时候需要特别小心。
    ngx_buf_t       *shadow;

    /* the buf's content could be changed */
    //临时内存标志位，1表示数据在临时内存中，且这段数据可以修改
    unsigned         temporary:1;

    /*
     * the buf's content is in a memory cache or in a read only memory
     * and must not be changed
     */
    //内存标志位，1表示数据在内存中，且这段数据不能被修改
    unsigned         memory:1;

    /* the buf's content is mmap()ed and must not be changed */
    // 标志位，1表示这段内存是用mmap系统调用映射过来的，不可以被修改
    unsigned         mmap:1; 
	
	//标志位，1表示可以被回收，通常配合shadow字段一起使用；
	//当使用ngx_create_temp_buf函数创建的buf同时也是另一个buf的shadow的时候，表示这个buf是可释放的
    unsigned         recycled:1;  

	
    unsigned         in_file:1;     //标志位，1表示是处理文件数据，而不是内存数据
	
	
	//遇到有flush字段被设置为1的buf的chain，则该chain的数据即使不是最后结束的数据也会进行输出；
	//不会受postpone_output配置的限制。
    unsigned         flush:1;

    //标志位，对于操作这个缓冲区时是否使用同步方式，需要谨慎考虑。
    //这有可能会阻塞nginx进程，nginx中所有操作几乎都是异步的。
    unsigned         sync:1; 

    // 标志位，是否是最后一块缓冲区。nginx_buf_t可以由ngx_chain_t链表串联起来
    // 1代表是最后一块待处理的缓冲区
    unsigned         last_buf:1; 

    //标志位，是否是ngx_chain_t中的最后一块缓冲区
    unsigned         last_in_chain:1; 

    //标志位，是否是最后一个影子缓冲区，与shadow配合使用，通常不建议使用；
	//在创建一个buf的shadow的时候，通常将新创建的一个buf的last_shadow设置为1.
    unsigned         last_shadow:1;

    //标志位，是否属于临时文件
	//由于受到内存使用的限制，有时候一些buf的内容需要被写到磁盘上的临时文件。
    unsigned         temp_file:1;

    /* STUB */ int   num;
};

// nginx链表数据结构，比如当用户发送HTTP包体的时候，就需要传入ngx_chain_t链表对象。
// 如果是最后一个ngx_chain_t，则next必须为null，否则永远不会发送成功
struct ngx_chain_s {
    ngx_buf_t    *buf; //链表对应的buffer
    ngx_chain_t  *next; //链表下一个元素
};


typedef struct {
    ngx_int_t    num;   //缓冲区的数量
    size_t       size;  //缓冲区的大小
} ngx_bufs_t; //创建链表的参数结构，用于一次创建多个缓冲区


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

//检查标志位，确定缓冲区是否在内存中
#define ngx_buf_in_memory(b)        (b->temporary || b->memory || b->mmap)
#define ngx_buf_in_memory_only(b)   (ngx_buf_in_memory(b) && !b->in_file)
//检查是否特殊控制作用的标志位
#define ngx_buf_special(b)                                                   \
    ((b->flush || b->last_buf || b->sync)                                    \
     && !ngx_buf_in_memory(b) && !b->in_file)

#define ngx_buf_sync_only(b)                                                 \
    (b->sync                                                                 \
     && !ngx_buf_in_memory(b) && !b->in_file && !b->flush && !b->last_buf)
//计算缓冲区的大小
#define ngx_buf_size(b)                                                      \
    (ngx_buf_in_memory(b) ? (off_t) (b->last - b->pos):                      \
                            (b->file_last - b->file_pos))
//从内存池中分配size大小的缓冲区
ngx_buf_t *ngx_create_temp_buf(ngx_pool_t *pool, size_t size);
ngx_chain_t *ngx_create_chain_of_bufs(ngx_pool_t *pool, ngx_bufs_t *bufs);

//直接从内存池中创建一个ngx_buf_t结构，然后手工指定成员
#define ngx_alloc_buf(pool)  ngx_palloc(pool, sizeof(ngx_buf_t))
#define ngx_calloc_buf(pool) ngx_pcalloc(pool, sizeof(ngx_buf_t))

ngx_chain_t *ngx_alloc_chain_link(ngx_pool_t *pool);
//从内存池中释放ngx_chinat_t对象
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
