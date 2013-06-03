
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

struct ngx_list_part_s {
    void             *elts; //可用列表空间的首地址
    ngx_uint_t        nelts; //当前已经使用的空间数量
    ngx_list_part_t  *next; //指向下一个列表节点
};


typedef struct {
    ngx_list_part_t  *last; //list中最后一个part
    ngx_list_part_t   part; //list中头部part
    size_t            size; //数组中每个元素的大小
    ngx_uint_t        nalloc; //已分配空间中可存放的元素个数
    ngx_pool_t       *pool; //当前list数据存放的内存池
} ngx_list_t;

//ngx_list_create和ngx_list_init功能是一样的都是创建一个list，只是返回值不一样...
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

static ngx_inline ngx_int_t
ngx_list_init(ngx_list_t *list, ngx_pool_t *pool, ngx_uint_t n, size_t size)
{
    list->part.elts = ngx_palloc(pool, n * size); //从内存池申请空间后，让elts指向可用空间
    if (list->part.elts == NULL) {
        return NGX_ERROR;
    }

    list->part.nelts = 0; //刚分配下来，还没使用，所以为0
    list->part.next = NULL;
    list->last = &list->part; //last开始的时候指向首节点
    list->size = size;
    list->nalloc = n;
    list->pool = pool;

    return NGX_OK;
}


/*
 *
 *  the iteration through the list:
 *
 *  part = &list.part;
 *  data = part->elts;
 *
 *  for (i = 0 ;; i++) {
 *
 *      if (i >= part->nelts) {
 *          if (part->next == NULL) {
 *              break;
 *          }
 *
 *          part = part->next;
 *          data = part->elts;
 *          i = 0;
 *      }
 *
 *      ...  data[i] ...
 *
 *  }
 */


void *ngx_list_push(ngx_list_t *list);


#endif /* _NGX_LIST_H_INCLUDED_ */
