
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

// 创建一个ngx_list_t链表
ngx_list_t *
ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    ngx_list_t  *list;

    // 先创建一个ngx_list_t指针
    list = ngx_palloc(pool, sizeof(ngx_list_t));
    if (list == NULL) {
        return NULL;
    }

    list->part.elts = ngx_palloc(pool, n * size);
    if (list->part.elts == NULL) {
        return NULL;
    }

    list->part.nelts = 0;
    list->part.next = NULL;
    list->last = &list->part;
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return list;
}

/*
ngx_list_create的使用示例：

ngx_list_t *testlist = ngx_list_create(r->pool, 4, sizeof(ngx_str_t));
if (testlist == NULL) {
    return NGX_ERROR;
} 
*/


// 往链表l中添加新的元素，返回的是新分配的元素的首地址
void *
ngx_list_push(ngx_list_t *l)
{
    void             *elt;
    ngx_list_part_t  *last;

    last = l->last;

    if (last->nelts == l->nalloc) {
        // 这里是last节点已经使用了nlloc的elts，所以必须新建一个last节点
        /* the last part is full, allocate a new list part */

        last = ngx_palloc(l->pool, sizeof(ngx_list_part_t));
        if (last == NULL) {
            return NULL;
        }

        last->elts = ngx_palloc(l->pool, l->nalloc * l->size);
        if (last->elts == NULL) {
            return NULL;
        }

        last->nelts = 0;
        last->next = NULL;

        l->last->next = last;
        l->last = last;
    }

    elt = (char *) last->elts + l->size * last->nelts;
    last->nelts++;

    return elt;
}

/*
ngx_list_push的使用实例：

ngx_str_t *str = ngx_list_push(testlist);
if (str == NULL) {
    return NGX_ERROR;
}

str->len = sizeof("Hello World");
str->value = "Hello World";
*/