
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HASH_H_INCLUDED_
#define _NGX_HASH_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*
ngx_hash_t是nginx自己的hash表的实现。定义和实现位于src/core/ngx_hash.h|c中。ngx_hash_t的实现也与数据结构教科书上所描述的hash表的实现是大同小异。对于常用的解决冲突的方法有线性探测，二次探测和开链法等。ngx_hash_t使用的是最常用的一种，也就是开链法，这也是STL中的hash表使用的方法。

但是ngx_hash_t的实现又有其几个显著的特点:

ngx_hash_t不像其他的hash表的实现，可以插入删除元素，它只能一次初始化，就构建起整个hash表以后，既不能再删除，也不能在插入元素了。
ngx_hash_t的开链并不是真的开了一个链表，实际上是开了一段连续的存储空间，几乎可以看做是一个数组。这是因为ngx_hash_t在初始化的时候，会经历一次预计算的过程，提前把每个桶里面会有多少元素放进去给计算出来，这样就提前知道每个桶的大小了。那么就不需要使用链表，一段连续的存储空间就足够了。这也从一定程度上节省了内存的使用。
从上面的描述，我们可以看出来，这个值越大，越造成内存的浪费。就两步，首先是初始化，然后就可以在里面进行查找了。下面我们详细来看一下。
 */


//参考：
//1. http://blog.csdn.net/livelylittlefish/article/details/6636229
//2. http://blog.csdn.net/chen19870707/article/details/40794285
//3. http://my.oschina.net/chenzhuo/blog/177866
//4. http://tengine.taobao.org/book/chapter_02.html#ngx-hash-t-100
//hash元素结构
typedef struct {
    void             *value;    //value，即某个key对应的值，即<key,value>中的value
    u_short           len;      //name长度
    u_char            name[1];  //某个要hash的数据(在nginx中表现为字符串)，即<key,value>中的key
    // 这里数组长度为1，是一个小技巧。实现时，在具体分配ngx_hash_elt_t的大小时使用宏NGX_HASH_ELT_SIZE来确定(并且是内存对齐的)：
    // #define NGX_HASH_ELT_SIZE(name) (sizeof(void *) + ngx_align((name)->key.len + 2, sizeof(void *)))
} ngx_hash_elt_t;


//hash结构
typedef struct {
    ngx_hash_elt_t  **buckets; //hash桶(有size个桶)
    ngx_uint_t        size;    //hash桶个数
} ngx_hash_t;

/*
nginx为了处理带有通配符的域名的匹配问题，实现了ngx_hash_wildcard_t这样的hash表。
他可以支持两种类型的带有通配符的域名。
一种是通配符在前的，例如：“*.abc.com”，也可以省略掉星号，直接写成”.abc.com”。
这样的key，可以匹配www.abc.com，qqq.www.abc.com之类的。
另外一种是通配符在末尾的，例如：“mail.xxx.*”，请特别注意通配符在末尾的不像位于开始的通配符可以被省略掉。
这样的通配符，可以匹配mail.xxx.com、mail.xxx.com.cn、mail.xxx.net之类的域名。

有一点必须说明，就是一个ngx_hash_wildcard_t类型的hash表只能包含通配符在前的key或者是通配符在后的key。
不能同时包含两种类型的通配符的key。ngx_hash_wildcard_t类型变量的构建是通过函数ngx_hash_wildcard_init完成的，
而查询是通过函数ngx_hash_find_wc_head或者ngx_hash_find_wc_tail来做的。
ngx_hash_find_wc_head是查询包含通配符在前的key的hash表的，而ngx_hash_find_wc_tail是查询包含通配符在后的key的hash表的。
 */
typedef struct {
    // 基本散列表
    ngx_hash_t        hash;
    // 当使用这个ngx_hash_wildcard_t通配符散列表作为某容器的元素时，可以使用这个value指针指向用户数据
    void             *value;
} ngx_hash_wildcard_t;


// <key,value> 结构
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


/*
hash:	该字段如果为NULL，那么调用完初始化函数后，该字段指向新创建出来的hash表。如果该字段不为NULL，那么在初始的时候，所有的数据被插入了这个字段所指的hash表中。
key:	指向从字符串生成hash值的hash函数。nginx的源代码中提供了默认的实现函数ngx_hash_key_lc。
max_size:	hash表中的桶的个数。该字段越大，元素存储时冲突的可能性越小，每个桶中存储的元素会更少，则查询起来的速度更快。当然，这个值越大，越造成内存的浪费也越大，(实际上也浪费不了多少)。
bucket_size:	每个桶的最大限制大小，单位是字节。如果在初始化一个hash表的时候，发现某个桶里面无法存的下所有属于该桶的元素，则hash表初始化失败。
name:	该hash表的名字。
pool:	该hash表分配内存使用的pool。
temp_pool:	该hash表使用的临时pool，在初始化完成以后，该pool可以被释放和销毁掉。
 */
//hash初始化结构，用来将其相关数据封装起来作为参数传递给ngx_hash_init()或ngx_hash_wildcard_init()函数
typedef struct {
    ngx_hash_t       *hash;         //指向待初始化的hash结构。
    ngx_hash_key_pt   key;          //hash函数指针

    // 散列表中槽的最大数目
    ngx_uint_t        max_size;     //bucket的最大个数

    // 散列表中一个槽的空间大小，它限制了每个散列表元素关键字的最大长度，通过NGX_HASH_ELT_SIZE(name)计算每个element的大小。
    // 如果这个bucket_size设置较大，那么他就能够容纳多个element，这样一个bucket里存放多个element，进而导致查找速度下降。
    // 为了更好的查找速度，请将bucket_size设置为所有element长度最大的那个。
    ngx_uint_t        bucket_size;

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
//该结构主要用来表示HTTP头部信息，例如"server:nginx/1.8.0",就是key=server,value="nginx/1.8.0"
typedef struct {
    ngx_uint_t        hash; //当它是ngx_hash_t表的成员的时候，用于快速检索头部
    ngx_str_t         key;  //名字字符串
    ngx_str_t         value; //值字符串
    u_char           *lowcase_key; //全小写的key字符串
} ngx_table_elt_t;


//hash查找
void *ngx_hash_find(ngx_hash_t *hash, ngx_uint_t key, u_char *name, size_t len);


//该函数查询包含通配符在前的key的hash表的。
//hwc:	hash表对象的指针。
//name:	需要查询的域名，例如: www.abc.com。
//len:	name的长度。
//该函数返回匹配的通配符对应value。如果没有查到，返回NULL。
void *ngx_hash_find_wc_head(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);

//该函数查询包含通配符在末尾的key的hash表的。 参数及返回值请参加上个函数的说明。
void *ngx_hash_find_wc_tail(ngx_hash_wildcard_t *hwc, u_char *name, size_t len);
void *ngx_hash_find_combined(ngx_hash_combined_t *hash, ngx_uint_t key,
    u_char *name, size_t len);


ngx_int_t ngx_hash_init(ngx_hash_init_t *hinit, ngx_hash_key_t *names,
    ngx_uint_t nelts);

/*
该函数迎来构建一个可以包含通配符key的hash表。
hinit:	构造一个通配符hash表的一些参数的一个集合。关于该参数对应的类型的说明，请参见ngx_hash_t类型中ngx_hash_init函数的说明。
names:	构造此hash表的所有的通配符key的数组。
	特别要注意的是这里的key已经都是被预处理过的。
	例如：“*.abc.com”或者“.abc.com”被预处理完成以后，变成了“com.abc.”。
	而“mail.xxx.*”则被预处理为“mail.xxx.”。为什么会被处理这样？这里不得不简单地描述一下通配符hash表的实现原理。
	当构造此类型的hash表的时候，实际上是构造了一个hash表的一个“链表”，是通过hash表中的key“链接”起来的。
	比如：对于“*.abc.com”将会构造出2个hash表，第一个hash表中有一个key为com的表项，该表项的value包含有指向第二个hash表的指针，
	而第二个hash表中有一个表项abc，该表项的value包含有指向*.abc.com对应的value的指针。
	那么查询的时候，比如查询www.abc.com的时候，先查com，通过查com可以找到第二级的hash表，
	在第二级hash表中，再查找abc，依次类推，直到在某一级的hash表中查到的表项对应的value对应一个真正的值而非一个指向下一级hash表的指针的时候，查询过程结束。
	这里有一点需要特别注意的，就是names数组中元素的value值低两位bit必须为0（有特殊用途）。
	如果不满足这个条件，这个hash表查询不出正确结果。
nelts:	names数组元素的个数。
该函数执行成功返回NGX_OK，否则NGX_ERROR。
 */
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
