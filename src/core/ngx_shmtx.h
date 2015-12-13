
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_SHMTX_H_INCLUDED_
#define _NGX_SHMTX_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>

/*[p]互斥锁结构 
ngx_shmtx_t结构涉及两个宏：NGX_HAVE_ATOMIC_OPS、NGX_HVE_POIX_SEM，这两个宏对应着互斥锁的3种不同实现。
第1种实现：当不支持原子操作时，会使用文件锁来实现ngx_hmtx_t互斥锁，这时它仅有fd和name成员。这两个成员使用上面介绍的文件锁来提供阻塞、非阻塞的互斥锁。
第2种实现，支持原子操作却又不支持信号量。
第3种实现，在支持原子操作的同时，操作系统也支持信号量。
*/
typedef struct {
#if (NGX_HAVE_ATOMIC_OPS)
	//[p]原子变量锁  
    ngx_atomic_t  *lock;
#if (NGX_HAVE_POSIX_SEM)
	//semaphore为1 时表示获取锁将可能使用到的信号量  
    ngx_uint_t     semaphore;
    sem_t          sem;
#endif
#else
	//[p]使用文件锁时fd表示使用的文件句柄  
    ngx_fd_t       fd;
    u_char        *name; //[p] 文件名
#endif
	//[p]自旋次数，表示在自旋状态下等待其他处理器结果中释放的时间。由文件锁实现，spin没有任何意义
    ngx_uint_t     spin;
} ngx_shmtx_t;


ngx_int_t ngx_shmtx_create(ngx_shmtx_t *mtx, void *addr, u_char *name);
void ngx_shmtx_destory(ngx_shmtx_t *mtx);
ngx_uint_t ngx_shmtx_trylock(ngx_shmtx_t *mtx);
void ngx_shmtx_lock(ngx_shmtx_t *mtx);
void ngx_shmtx_unlock(ngx_shmtx_t *mtx);


#endif /* _NGX_SHMTX_H_INCLUDED_ */
