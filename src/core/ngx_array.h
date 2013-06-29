
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */

//Êý×é¶¨Òå²Î¿¼£ºhttp://blog.csdn.net/sunhappy2200/article/details/5915189

#ifndef _NGX_ARRAY_H_INCLUDED_
#define _NGX_ARRAY_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

// 动态数组
struct ngx_array_s {
    // elts指向数组的首地址
    void        *elts; 
    // nelts是数组中已经使用的元素个数
    ngx_uint_t   nelts; 
    // 每个数组元素占用的内存大小
    size_t       size;  
    // 当前数组中能够容纳元素个数的总大小
    ngx_uint_t   nalloc; 
    // 内存池对象
    ngx_pool_t  *pool;  
};

ngx_array_t *ngx_array_create(ngx_pool_t *p, ngx_uint_t n, size_t size);

void ngx_array_destroy(ngx_array_t *a);

void *ngx_array_push(ngx_array_t *a);

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
