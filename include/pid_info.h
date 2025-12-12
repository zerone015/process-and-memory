/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_PID_INFO_H
#define _UAPI_LINUX_PID_INFO_H

#include <linux/types.h>
#include <linux/limits.h>

enum pid_state {
	PID_STATE_RUNNING = 0, 
	PID_STATE_SLEEPING = 1,
	PID_STATE_ZOMBIE  = 2, 
};

struct pid_info {
    /* input */
    int *children;
    int cap_children;

    /* output */
    int nr_children;
    int nr_reported;
    int pid;
    int state;
    unsigned long sp;
    __u64 age;
    int parent;
    char root[PATH_MAX];
    char pwd[PATH_MAX];
};

#endif