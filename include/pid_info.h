/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
#ifndef _UAPI_LINUX_PID_INFO_H
#define _UAPI_LINUX_PID_INFO_H

#include <linux/types.h>
#include <linux/limits.h>

#define MAX_CHILDREN 128

enum pid_state {
	PID_STATE_RUNNING = 0, 
	PID_STATE_SLEEPING = 1,
	PID_STATE_ZOMBIE  = 2, 
};

struct pid_info {
    int pid;
    int state;
    unsigned long sp;
    __u64 age;
    int children[MAX_CHILDREN];
    int num_children;
    int parent;
    char root[PATH_MAX];
    char pwd[PATH_MAX];
};

#endif