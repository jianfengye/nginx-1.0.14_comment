
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_LIST_H_INCLUDED_
#define _NGX_LIST_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>


typedef struct ngx_list_part_s  ngx_list_part_t;

// 参考：nginx源码分析—链表结构ngx_list_t http://blog.csdn.net/livelylittlefish/article/details/6599065

/*
ngx_list_t是nginx中使用的链表结构，但与我们常说的链表结构(例如`std::list`)不太一样，
它符合list类型数据结构的一些特点，比如可以添加元素，实现动态自增长，不会像数组类型的数据结构，受到初始设定的数组容量的限制，
不同点就在于它的节点，`std::list`每个节点只能存放一个元素，ngx_list_t的节点却是一个固定大小的数组，可以存放多个元素。

在初始化的时候，我们需要设定单个元素所需要占用的内存空间大小，以及每个节点数组的容量大小。
在添加元素到这个list里面的时候，会在最尾部的节点里的数组上添加元素，如果这个节点的数组存满了，就再增加一个新的节点到这个list里面去。
 */

// ngx_list_part_s是代表ngx_list_t链表的一个节点。
// 它自身包含了一个数组，用来存放最终的元素
struct ngx_list_part_s {
    void             *elts; //链表元素elts数组,数组申请的空间大小为size*nalloc
    ngx_uint_t        nelts; //当前已使用的elts个数，一定要小于等于nalloc
    ngx_list_part_t  *next; //指向ngx_list_t中的下个链表part
};

// ngx_list_t结构是一个链表，链表中每个节点是ngx_list_part_t结构。
// 而ngx_list_part_t中有个elts是一个数组，储存了任意大小固定的元素，它是由ngx_pool_t分配的连续空间
typedef struct {
    ngx_list_part_t  *last; //指向链表中最后一个元素，其作用相当于尾指针。插入新的节点时，从此开始。
    ngx_list_part_t   part; //链表中第一个元素，其作用相当于头指针。遍历时，从此开始。
    size_t            size; //链表中每个元素的大小
    ngx_uint_t        nalloc; //链表的每个ngx_list_part_t中elts数组的所能容纳的最大元素个数
    ngx_pool_t       *pool; //当前list数据存放的内存池
} ngx_list_t;

//ngx_list_create和ngx_list_init功能是一样的都是创建一个list，只是返回值不一样...
ngx_list_t *ngx_list_create(ngx_pool_t *pool, ngx_uint_t n, size_t size);

// ngx_list_init是初始化了一个已有的链表
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
