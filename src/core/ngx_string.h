
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_STRING_H_INCLUDED_
#define _NGX_STRING_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


// ngx_str_t来表示字符串，切记不能把data当做字符串处理，data并没有规定以\0结尾
// data+len 才代表字符串，所以如果把data当做字符串处理，有可能导致内存越界。
// 不使用字符串能有效降低内存使用量。
typedef struct {
    size_t      len;  //字符串的有效长度
    u_char     *data; //字符串的内容，指向字符串的起始位置
} ngx_str_t;


typedef struct {
    ngx_str_t   key;  //key-value结构
    ngx_str_t   value; //key-value结构
} ngx_keyval_t;

//参考资料：
//http://blog.csdn.net/dingyujie/article/details/7515904
typedef struct {
    unsigned    len:28;             //变量值的长度

    unsigned    valid:1;            //变量是否有效
    unsigned    no_cacheable:1;     /* 变量是否是可缓存的，一般来说，某些变量在第一次得到变量值后，后面再次用到时，可以直接使用上             
                                    * 次的值，而对于一些所谓的no_cacheable的变量，则需要在每次使用的时候，都要通过get_handler之  
                                    * 类操作，再次获取  
                                    */
    unsigned    not_found:1;        //变量没有找到，一般是指某个变量没用能够通过get获取到其变量值
    unsigned    escape:1;           //变量值是否需要作转义处理

    u_char     *data;               //变量值
} ngx_variable_value_t;

//通过一个以‘0’结尾的普通字符串str构造一个nginx的字符串。
//鉴于api中采用sizeof操作符计算字符串长度，因此该api的参数必须是一个常量字符串。
#define ngx_string(str)     { sizeof(str) - 1, (u_char *) str }

//声明变量时，初始化字符串为空字符串，符串的长度为0，data为NULL。
#define ngx_null_string     { 0, NULL }

//设置字符串str为text，text必须为常量字符串。
#define ngx_str_set(str, text)                                               \
    (str)->len = sizeof(text) - 1; (str)->data = (u_char *) text

//设置字符串str为空串，长度为0，data为NULL。
#define ngx_str_null(str)   (str)->len = 0; (str)->data = NULL

/*
ngx_string与ngx_null_string只能用于赋值时初始化
ngx_str_t str = ngx_string("hello world");
ngx_str_t str1 = ngx_null_string();

如果这样使用，就会有问题。
ngx_str_t str, str1;
str = ngx_string("hello world");    // 编译出错
str1 = ngx_null_string;                // 编译出错

这种情况，可以调用ngx_str_set与ngx_str_null这两个函数来做:
ngx_str_t str, str1;
ngx_str_set(&str, "hello world");
ngx_str_null(&str1);

不过要注意的是，ngx_string与ngx_str_set在调用时，传进去的字符串一定是常量字符串，否则会得到意想不到的错误(因为ngx_str_set内部使用了sizeof()，如果传入的是u_char*，那么计算的是这个指针的长度，而不是字符串的长度)。如：
ngx_str_t str;
u_char *a = "hello world";
ngx_str_set(&str, a);    // 问题产生
*/

#define ngx_tolower(c)      (u_char) ((c >= 'A' && c <= 'Z') ? (c | 0x20) : c)
#define ngx_toupper(c)      (u_char) ((c >= 'a' && c <= 'z') ? (c & ~0x20) : c)

//将src的前n个字符转换成小写存放在dst字符串当中
void ngx_strlow(u_char *dst, u_char *src, size_t n);
/*
调用者需要保证dst指向的空间大于等于n。操作不会对原字符串产生变动。如要更改原字符串，可以：

ngx_str_t str = ngx_string("hello world");
ngx_strlow(str->data, str->data, str->len);
*/

//区分大小写的字符串比较，只比较前n个字符。
#define ngx_strncmp(s1, s2, n)  strncmp((const char *) s1, (const char *) s2, n)


/* msvc and icc7 compile strcmp() to inline loop */
#define ngx_strcmp(s1, s2)  strcmp((const char *) s1, (const char *) s2)


#define ngx_strstr(s1, s2)  strstr((const char *) s1, (const char *) s2)
#define ngx_strlen(s)       strlen((const char *) s)

#define ngx_strchr(s1, c)   strchr((const char *) s1, (int) c)

static ngx_inline u_char *
ngx_strlchr(u_char *p, u_char *last, u_char c)
{
    while (p < last) {

        if (*p == c) {
            return p;
        }

        p++;
    }

    return NULL;
}


/*
 * msvc and icc7 compile memset() to the inline "rep stos"
 * while ZeroMemory() and bzero() are the calls.
 * icc7 may also inline several mov's of a zeroed register for small blocks.
 */
#define ngx_memzero(buf, n)       (void) memset(buf, 0, n)  //ngx_memzero使用的是memset原型，memset使用汇编进行编写
#define ngx_memset(buf, c, n)     (void) memset(buf, c, n)


#if (NGX_MEMCPY_LIMIT)

void *ngx_memcpy(void *dst, void *src, size_t n);
#define ngx_cpymem(dst, src, n)   (((u_char *) ngx_memcpy(dst, src, n)) + (n))

#else

/*
 * gcc3, msvc, and icc7 compile memcpy() to the inline "rep movs".
 * gcc3 compiles memcpy(d, s, 4) to the inline "mov"es.
 * icc8 compile memcpy(d, s, 4) to the inline "mov"es or XMM moves.
 */
#define ngx_memcpy(dst, src, n)   (void) memcpy(dst, src, n)
#define ngx_cpymem(dst, src, n)   (((u_char *) memcpy(dst, src, n)) + (n))

#endif


#if ( __INTEL_COMPILER >= 800 )

/*
 * the simple inline cycle copies the variable length strings up to 16
 * bytes faster than icc8 autodetecting _intel_fast_memcpy()
 */

static ngx_inline u_char *
ngx_copy(u_char *dst, u_char *src, size_t len)
{
    if (len < 17) {

        while (len) {
            *dst++ = *src++;
            len--;
        }

        return dst;

    } else {
        return ngx_cpymem(dst, src, len);
    }
}

#else

#define ngx_copy                  ngx_cpymem

#endif


#define ngx_memmove(dst, src, n)   (void) memmove(dst, src, n)
#define ngx_movemem(dst, src, n)   (((u_char *) memmove(dst, src, n)) + (n))


/* msvc and icc7 compile memcmp() to the inline loop */
#define ngx_memcmp(s1, s2, n)  memcmp((const char *) s1, (const char *) s2, n)


u_char *ngx_cpystrn(u_char *dst, u_char *src, size_t n);
u_char *ngx_pstrdup(ngx_pool_t *pool, ngx_str_t *src);

u_char * ngx_cdecl ngx_sprintf(u_char *buf, const char *fmt, ...);
u_char * ngx_cdecl ngx_snprintf(u_char *buf, size_t max, const char *fmt, ...);
u_char * ngx_cdecl ngx_slprintf(u_char *buf, u_char *last, const char *fmt,
    ...);
/*
上面这三个函数用于字符串格式化，ngx_snprintf的第二个参数max指明buf的空间大小，
ngx_slprintf则通过last来指明buf空间的大小。推荐使用第二个或第三个函数来格式化字符串，
ngx_sprintf函数还是比较危险的，容易产生缓冲区溢出漏洞。
在这一系列函数中，nginx在兼容glibc中格式化字符串的形式之外，
还添加了一些方便格式化nginx类型的一些转义字符，比如%V用于格式化ngx_str_t结构。

这里特别要提醒的是，我们最常用于格式化ngx_str_t结构，其对应的转义符是%V，传给函数的一定要是指针类型，否则程序就会coredump掉。这也是我们最容易犯的错。比如：

ngx_str_t str = ngx_string("hello world");
char buffer[1024];
ngx_snprintf(buffer, 1024, "%V", &str);    // 注意，str取地址
*/

u_char *ngx_vslprintf(u_char *buf, u_char *last, const char *fmt, va_list args);
#define ngx_vsnprintf(buf, max, fmt, args)                                   \
    ngx_vslprintf(buf, buf + (max), fmt, args)

//不区分大小写的不带长度的字符串比较。
ngx_int_t ngx_strcasecmp(u_char *s1, u_char *s2);
//不区分大小写的带长度的字符串比较，只比较前n个字符。
ngx_int_t ngx_strncasecmp(u_char *s1, u_char *s2, size_t n);

u_char *ngx_strnstr(u_char *s1, char *s2, size_t n);

u_char *ngx_strstrn(u_char *s1, char *s2, size_t n);
u_char *ngx_strcasestrn(u_char *s1, char *s2, size_t n);
u_char *ngx_strlcasestrn(u_char *s1, u_char *last, u_char *s2, size_t n);

ngx_int_t ngx_rstrncmp(u_char *s1, u_char *s2, size_t n);
ngx_int_t ngx_rstrncasecmp(u_char *s1, u_char *s2, size_t n);
ngx_int_t ngx_memn2cmp(u_char *s1, u_char *s2, size_t n1, size_t n2);
ngx_int_t ngx_dns_strcmp(u_char *s1, u_char *s2);

ngx_int_t ngx_atoi(u_char *line, size_t n);
ngx_int_t ngx_atofp(u_char *line, size_t n, size_t point);
ssize_t ngx_atosz(u_char *line, size_t n);
off_t ngx_atoof(u_char *line, size_t n);
time_t ngx_atotm(u_char *line, size_t n);
ngx_int_t ngx_hextoi(u_char *line, size_t n);

u_char *ngx_hex_dump(u_char *dst, u_char *src, size_t len);

//base64 编码／解码函数和宏
#define ngx_base64_encoded_length(len)  (((len + 2) / 3) * 4)
#define ngx_base64_decoded_length(len)  (((len + 3) / 4) * 3)

void ngx_encode_base64(ngx_str_t *dst, ngx_str_t *src);
ngx_int_t ngx_decode_base64(ngx_str_t *dst, ngx_str_t *src);
/*
这两个函数用于对str进行base64编码与解码，
调用前，需要保证dst中有足够的空间来存放结果，
如果不知道具体大小，
可先调用ngx_base64_encoded_length与ngx_base64_decoded_length来预估最大占用空间。
*/

ngx_int_t ngx_decode_base64url(ngx_str_t *dst, ngx_str_t *src);

//utf-8 编码／解码相关函数
uint32_t ngx_utf8_decode(u_char **p, size_t n);
size_t ngx_utf8_length(u_char *p, size_t n);
u_char *ngx_utf8_cpystrn(u_char *dst, u_char *src, size_t n, size_t len);


#define NGX_ESCAPE_URI            0
#define NGX_ESCAPE_ARGS           1
#define NGX_ESCAPE_URI_COMPONENT  2
#define NGX_ESCAPE_HTML           3
#define NGX_ESCAPE_REFRESH        4
#define NGX_ESCAPE_MEMCACHED      5
#define NGX_ESCAPE_MAIL_AUTH      6

#define NGX_UNESCAPE_URI       1
#define NGX_UNESCAPE_REDIRECT  2

//对src进行编码，根据type来按不同的方式进行编码，
//如果dst为NULL，则返回需要转义的字符的数量，由此可得到需要的空间大小。
uintptr_t ngx_escape_uri(u_char *dst, u_char *src, size_t size,
    ngx_uint_t type);

//对src进行反编码，type可以是0、NGX_UNESCAPE_URI、NGX_UNESCAPE_REDIRECT这三个值。
//如果是0，则表示src中的所有字符都要进行转码。
//如果是NGX_UNESCAPE_URI与NGX_UNESCAPE_REDIRECT，则遇到’?’后就结束了，后面的字符就不管了。
//而NGX_UNESCAPE_URI与NGX_UNESCAPE_REDIRECT之间的区别是NGX_UNESCAPE_URI对于遇到的需要转码的字符，
//都会转码，而NGX_UNESCAPE_REDIRECT则只会对非可见字符进行转码。
void ngx_unescape_uri(u_char **dst, u_char **src, size_t size, ngx_uint_t type);

//对html标签进行编码。
uintptr_t ngx_escape_html(u_char *dst, u_char *src, size_t size);


typedef struct {
    ngx_rbtree_node_t         node;
    ngx_str_t                 str;
} ngx_str_node_t;


void ngx_str_rbtree_insert_value(ngx_rbtree_node_t *temp,
    ngx_rbtree_node_t *node, ngx_rbtree_node_t *sentinel);
ngx_str_node_t *ngx_str_rbtree_lookup(ngx_rbtree_t *rbtree, ngx_str_t *name,
    uint32_t hash);


void ngx_sort(void *base, size_t n, size_t size,
    ngx_int_t (*cmp)(const void *, const void *));
#define ngx_qsort             qsort


#define ngx_value_helper(n)   #n
#define ngx_value(n)          ngx_value_helper(n)


#endif /* _NGX_STRING_H_INCLUDED_ */
