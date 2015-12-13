
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_CHANNEL_H_INCLUDED_
#define _NGX_CHANNEL_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
//[p]nginx对进程间消息的封装结构体
//master和worker之间传递的指令。master和worker是单向的，只能master向worker传递指令
typedef struct {
     ngx_uint_t  command;       //[p]worker要操作的指令,如NGX_CMD_OPEN_CHANNEL,NGX_CMD_CLOSE_CHANNEL,NGX_CMD_QUIT,NGX_CMD_TERMINATE,NGX_CMD_REOPEN
     ngx_pid_t   pid;           //worker进程id
     ngx_int_t   slot;          //worker进程在ngx_process中的索引
     ngx_fd_t    fd;            //有可能用到的文件描述符?
} ngx_channel_t;


ngx_int_t ngx_write_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_read_channel(ngx_socket_t s, ngx_channel_t *ch, size_t size,
    ngx_log_t *log);
ngx_int_t ngx_add_channel_event(ngx_cycle_t *cycle, ngx_fd_t fd,
    ngx_int_t event, ngx_event_handler_pt handler);
void ngx_close_channel(ngx_fd_t *fd, ngx_log_t *log);


#endif /* _NGX_CHANNEL_H_INCLUDED_ */
