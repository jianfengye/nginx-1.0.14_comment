
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

//参考：
//http://blog.csdn.net/livelylittlefish/article/details/6636229
//hash元素结构 
typedef struct {
    void             *value;    //value，即某个key对应的值，即<key,value>中的value 
    u_short           len;      //name长度
    u_char            name[1];  //某个要hash的数据(在nginx中表现为字符串)，即<key,value>中的key
} ngx_hash_elt_t;


//hash结构
typedef struct {
    ngx_hash_elt_t  **buckets; //hash桶(有size个桶) 
    ngx_uint_t        size;    //hash桶个数
} ngx_hash_t;


typedef struct {
    // 基本散列表
    ngx_hash_t        hash;
    // 当使用这个ngx_hash_wildcard_t通配符散列表作为某容器的元素时，可以使用这个value指针指向用户数据
    void             *value;
} ngx_hash_wildcard_t;


typedef struct {
    ngx_str_t         key;      //key，为nginx的字符串结构 
    ngx_uint_t        key_hash; //由该key计算出的hash值(通过hash函数如ngx_hash_key_lc())
    void             *value;    //该key对应的值，组成一个键-值对<key,value>
} ngx_hash_key_t;


typedef ngx_uint_t (*ngx_hash_key_pt) (u_char *data, size_t len);


typedef struct {
    // 用于精确匹配的基本散列表
    ngx_hash_t            hash;
    // 用于查询前置通配符的散列表
    ngx_hash_wildcard_t  *wc_head;
    // 用于查询后置通配符的散列表
    ngx_hash_wildcard_t  *wc_tail;
} ngx_hash_combined_t;


//hash初始化结构，用来将其相关数据封装起来作为参数传递给ngx_hash_init()或ngx_hash_wildcard_init()函数
typedef struct {
    ngx_hash_t       *hash;         //指向待初始化的hash结构 
    ngx_hash_key_pt   key;          //hash函数指针

    // 散列表中槽的最大数目
    ngx_uint_t        max_size;     //bucket的最大个数
    // 散列表中一个槽的空间大小，它限制了每个散列表元素关键字的最大长度
    ngx_uint_t        bucket_size;  //每个bucket的空间

    // 散列表的名称
    char             *name;         //该hash结构的名字(仅在错误日志中使用)  
    // 内存池，它分配散列表（最多3个，包括1个普通散列表，1个前置通配符散列表，1个后置通配符散列表）中的所有槽
    ngx_pool_t       *pool;         //该hash结构从pool指向的内存池中分配 
    // 临时内存池，它仅存在于初始化散列表之前。它主要用于分配一些临时的动态数组，带通配符的元素在初始化时需要用到这些数组。
    ngx_pool_t       *temp_pool;    //分配临时数据空间的内存池
} ngx_hash_init_t;


#define NGX_HASH_SMALL            1
#define NGX_HASH_LARGE            2

#define NGX_HASH_LARGE_ASIZE      16384
#define NGX_HASH_LARGE_HSIZE      10007

#define NGX_HASH_WILDCARD_KEY     1
#define NGX_HASH_READONLY_KEY     2


typedef struct {
    // 下面的keys_hash, dns_wc_head_hash,dns_wc_tail_hash都是简易散列表，而hsize指明了散列表的槽个数，其简易散列方法也需要对hsize求余
    ngx_uint_t        hsize;

    // 内存池，用于分配永久性内存，到目前的nginx版本为止，该pool成员没有任何意义
    ngx_pool_t       *pool;
    // 临时内存池，下面的动态数组需要的内存都有temp_pool内存池分配
    ngx_pool_t       *temp_pool;

    // 用动态数组以ngx_hash_key_t结构体保存着不含有通配符关键字的元素
    ngx_array_t       keys;
    /* 一个极其简易的散列表，它以数组的形式保存着hsize个元素，每个元素都是ngx_array_t动态数组，在用户添加的元素过程中，会根据关键码
    将用户的ngx_str_t类型的关键字添加到ngx_array_t 动态数组中，这里所有的用户元素的关键字都不可以带通配符，表示精确匹配 */
    ngx_array_t      *keys_hash;

    // 用动态数组以ngx_hash_key_t 结构体保存着含有前置通配符关键字的元素生成的中间关键字
    ngx_array_t       dns_wc_head;
    // 一个极其简易的散列表，它以数组的形式保存着hsize个元素，每个元素都是ngx_array_t 动态数组。在用户添加元素过程中，会根据关键码将用户的
    // ngx_str_t类型的关键字添加到ngx_array_t 动态数组中。这里所有的用户元素的关键字都带前置通配符。
    ngx_array_t      *dns_wc_head_hash;

    // 用动态数组以ngx_hash_key_t 结构体保存着含有前置通配符关键字的元素生成的中间关键字
    ngx_array_t       dns_wc_tail;
    /*
    一个极其建议的散列表，它以数组的形式保存着hsize个元素，每个元素都是ngx_array_t动态数组。在用户添加元素过程中，会根据关键码将用户
    的ngx_str_t 类型的关键字添加到ngx_array_t 动态数组中，这里所有的用户元素的关键字都带后置通配符。
    */
    ngx_array_t      *dns_wc_tail_hash;
} ngx_hash_keys_arrays_t;


// ngx_table_elt_t是一个key/value对，ngx_str_t类型的key和value
typedef struct {
    ngx_uint_t        hash; //当它是ngx_hash_t表的成员的时候，用于快速检索头部
    ngx_str_t         key;  //名字字符串
    ngx_str_t         value; //值字符串
    u_char           *lowcase_key; //全小写的key字符串
} ngx_table_elt_t;


//hash查找
void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);

ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);
ngx_int_t ngx_hash_wildcard_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

#define ngx_hash(key, c)   ((ngx_uint_t) key * 31 + c)
ngx_uint_t ngx_hash_key(u_char *data, size_t len);
//lc表示lower case，即字符串转换为小写后再计算hash值
ngx_uint_t ngx_hash_key_lc(u_char *data, size_t len);  
ngx_uint_t ngx_hash_strlow(u_char *dst, u_char *src, size_t n);


ngx_int_t ngx_hash_keys_array_init(ngx_hash_keys_arrays_t *ha, ngx_uint_t type);
ngx_int_t ngx_hash_add_key(ngx_hash_keys_arrays_t *ha, ngx_str_t *key,
    void *value, ngx_uint_t flags);


#endif /* _NGX_HASH_H_INCLUDED_ */