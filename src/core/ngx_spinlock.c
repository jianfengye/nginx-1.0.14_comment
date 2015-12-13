
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#include <ngx_config.h>
#include <ngx_core.h>

/*[p] 自旋锁 注释来自：http://blog.csdn.net/walkerkalr/article/details/38237147?utm_source=tuicool&utm_medium=referral
lock参数就是原子变量表达的锁，当lock值为0时，表示锁是被释放的，而lock值不为0时则表示锁已经被某个进程持有了；
value参数表示希望当锁没有被任何进程持有时，把lock值设为value表示当前进程持有了锁；
spin参数表示在多处理器系统内，当ngx_spinlock方法没有拿到锁时，当前进程在内核的一次调度中，该方法等待其他处理器释放锁的时间。
*/
void
ngx_spinlock(ngx_atomic_t *lock, ngx_atomic_int_t value, ngx_uint_t spin)
{

#if (NGX_HAVE_ATOMIC_OPS) //[p]支持原子操作

    ngx_uint_t  i, n;
	//[p] 一直处于循环中，直到获取到锁
    for ( ;; ) {
		//[p] lock为0表示没有其他进程持有锁，这时将lock值设置为value参数表示当前进程持有了锁 ,ngx_atomic_cmp_set为原子操作
        if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
            return;
        }
		//[p]如果是多处理器系统
        if (ngx_ncpu > 1) {
			/*[p]在多处理器下，当发现锁被其他进程占用时，当前进程并不是立刻让出正在使用的CPU处理器，而是等待一段时间，看看其他处理器上的进程是否会释放锁，这会减少进程间切换的次数。*/
            for (n = 1; n < spin; n <<= 1) {
				//[p] 随着等待的次数越来越多，实际去检查锁的间隔时间越来越大  
                for (i = 0; i < n; i++) {
					//[p]ngx_cpu_pause是许多架构体系中专门为了自旋锁而提供的指令，它会告诉CPU现在处于自旋锁等待状态，通常一个CPU会将自己置于节能状态，降低功耗。但是当前进程并没有让出正在使用的处理器。
                    ngx_cpu_pause();
                }
				/*[p]检查锁是否被释放了，如果lock值为0且释放了锁后，就把它的值设为value，当前进程持有锁成功并返回 */
                if (*lock == 0 && ngx_atomic_cmp_set(lock, 0, value)) {
                    return;
                }
            }
        }
		/*[p]当前进程让出处理器，但仍然处于可执行状态，使得处理器优先调度其他可执行状态的进程，这样，在进程被内核再次调度时，在for循环代码中可以期望其他进程释放锁。*/
        ngx_sched_yield();
    }

#else

#if (NGX_THREADS)

#error ngx_spinlock() or ngx_atomic_cmp_set() are not defined !

#endif

#endif

}
