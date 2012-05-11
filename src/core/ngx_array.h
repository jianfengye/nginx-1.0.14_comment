
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

//数组定义参考：http://blog.csdn.net/sunhappy2200/article/details/5915189

#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


struct ngx_array_s {
    void        *elts;  //数组中具体的数据区域的指针
    ngx_uint_t   nelts; //数组中实际包含的元素数量
    size_t       size;  //数组中单个元素的大小（字节）
    ngx_uint_t   nalloc; //数组容量，即数组预先分配的内存大小
    ngx_pool_t  *pool;  //内存池
};

//从内存池中创建n个元素的数组，元素大小为size
ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);

//把数组分配到的内存释放到内存池
void ngx_array_destroy(ngx_array_t *a);

//返回将要添加到数组中元素的地址，如果数组已满，则重新分配两倍（nalloc*size)的内存空间，且nalloc更新为2*nalloc
void *ngx_array_push(ngx_array_t *a);

//返回将要添加n个元素到数组中其首个元素的地址
void *ngx_array_push_n(ngx_array_t *a, ngx_uint_t n);


static ngx_inline ngx_int_t
ngx_array_init(ngx_array_t *array, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    /*
     * set "array->nelts" before "array->elts", otherwise MSVC thinks
     * that "array->nelts" may be used without having been initialized
     */

    array->nelts = 0;
    array->size = size;
    array->nalloc = n;
    array->pool = pool;

    array->elts = ngx_palloc(pool, n * size);
    if (array->elts == NULL) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


#endif /* _NGX_ARRAY_H_INCLUDED_ */
