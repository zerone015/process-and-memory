#include <linux/syscalls.h>
#include <uapi/linux/pid_info.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/errno.h>
#include <linux/limits.h>

#define MAX_CHILDREN 128

struct pid_info {
    int pid;
    int state;
    unsigned long sp;           /* stack pointer */
    unsigned long age;
    int children[MAX_CHILDREN];
    int parent;
    char r_path[PATH_MAX];      /* process root directory */
    char pwd[PATH_MAX];
};

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, info, int, pid)
{
    struct task_struct *ts;

    if (pid < 0)
        return -EINVAL;

    rcu_read_lock();

    ts = find_task_by_vpid(pid);
    if (!ts) {
        rcu_read_unlock();
        return -ESRCH;
    }

    return 0;
}