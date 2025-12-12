#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <asm/unistd.h>
#include <sys/syscall.h>
#include <errno.h>
#include <string.h>
#include "pid_info.h"

#define __NR_get_pid_info 470
#define CHILD_BUF_SIZE    128

static const char *pid_state_to_string(int state)
{
    switch (state) {
    case PID_STATE_RUNNING:
        return "RUNNING";
    case PID_STATE_SLEEPING:
        return "SLEEPING";
    case PID_STATE_ZOMBIE:
        return "ZOMBIE";
    default:
        return "UNKNOWN";
    }
}

static long do_get_pid_info(int pid,
                            struct pid_info *info,
                            int *children_buf,
                            int cap_children_bytes)
{
    memset(info, 0, sizeof(*info));
    info->children     = children_buf;
    info->cap_children = cap_children_bytes;

    return syscall(__NR_get_pid_info, info, pid);
}

static long get_pid_info_simple(int pid, struct pid_info *info)
{
    return do_get_pid_info(pid, info, NULL, 0);
}

static long get_pid_info_with_children(int pid,
                                       struct pid_info *info,
                                       int *children_buf,
                                       int cap_children_elems)
{
    return do_get_pid_info(pid, info,
                           children_buf,
                           cap_children_elems * (int)sizeof(int));
}

static void format_age(char *buf, size_t sz, __u64 age_ns)
{
    unsigned long long sec  = age_ns / 1000000000ULL;
    unsigned long long nsec = age_ns % 1000000000ULL;

    snprintf(buf, sz, "%llu.%09llu s", sec, nsec);
}

static void print_pid_info(const struct pid_info *info, const char *title)
{
    char age_buf[64];

    format_age(age_buf, sizeof(age_buf), info->age);

    printf("=== %s ===\n", title);

    printf("  pid       : %d\n", info->pid);
    printf("  state     : %s\n", pid_state_to_string(info->state));
    printf("  stack ptr : %p\n", (void *)info->sp);
    printf("  age       : %s\n", age_buf);
    printf("  ppid      : %d\n", info->parent);
    printf("  root      : %s\n",
           info->root[0] ? info->root : "(none)");
    printf("  pwd       : %s\n",
           info->pwd[0] ? info->pwd : "(none)");
    printf("\n");
}

static void print_parent_chain(int ppid)
{
    struct pid_info info;

    printf("\n=== Parent chain ===\n\n");

    if (ppid <= 0) {
        printf("(no parents)\n\n");
        return;
    }

    while (ppid > 0) {
        if (get_pid_info_simple(ppid, &info) < 0) {
            fprintf(stderr, "get_pid_info(%d) failed: %s\n",
                    ppid, strerror(errno));
            exit(EXIT_FAILURE);
        }

        print_pid_info(&info, "Parent process");

        if (info.parent <= 0 || info.parent == ppid)
            break;
        ppid = info.parent;
    }

    printf("\n");
}

static void print_children(const struct pid_info *info)
{
    struct pid_info child_info;

    printf("\n=== Children of PID %d ===\n\n", info->pid);

    if (info->nr_children <= 0) {
        printf("No children.\n\n");
        return;
    }

    printf("Total children : %d\n", info->nr_children);
    printf("Reported       : %d\n", info->nr_reported);

    for (int i = 0; i < info->nr_reported; i++) {
        int cpid = info->children[i];

        if (get_pid_info_simple(cpid, &child_info) < 0) {
            fprintf(stderr, "get_pid_info(child=%d) failed: %s\n",
                    cpid, strerror(errno));
            exit(EXIT_FAILURE);
        }

        print_pid_info(&child_info, "Child process");
    }

    printf("\n");
}

int main(int argc, char **argv)
{
    int pid;
    struct pid_info info;
    int children_buf[CHILD_BUF_SIZE];

    if (argc >= 2) {
        pid = atoi(argv[1]);
        if (pid <= 0) {
            fprintf(stderr, "Invalid PID: %s\n", argv[1]);
            return EXIT_FAILURE;
        }
    } else {
        pid = getpid();
    }

    printf("Base PID = %d\n\n", pid);

    if (get_pid_info_with_children(pid, &info,
                                   children_buf,
                                   CHILD_BUF_SIZE) < 0) {
        fprintf(stderr, "get_pid_info(%d) failed: %s\n",
                pid, strerror(errno));
        return EXIT_FAILURE;
    }

    print_pid_info(&info, "Target process");
    print_parent_chain(info.parent);
    print_children(&info);

    return EXIT_SUCCESS;
}
