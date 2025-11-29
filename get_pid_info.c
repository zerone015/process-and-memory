#include <linux/syscalls.h>
#include <uapi/linux/pid_info.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linut/sched/mm.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/rwlock.h>
#include <linux/sched/task.h>
#include <linux/list.h>

enum pid_state {
	PID_STATE_RUNNING = 0, 
	PID_STATE_SLEEPING = 1,
	PID_STATE_ZOMBIE  = 2, 
};

#define MAX_CHILDREN 128

struct pid_info {
    int pid;
    int state;
    unsigned long sp;           /* stack pointer */
    __u64 age;
    int children[MAX_CHILDREN];
    int parent;
    char r_path[PATH_MAX];      /* process root directory */
    char pwd[PATH_MAX];
};

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, up, int, pid)
{
    struct task_struct *tsk, *parent, *child;
    struct pid_info *info;
    struct mm_struct *mm;
    int i;

    if (!up || pid < 0)
        return -EINVAL;

    info = kmalloc(sizeof(*info), GFP_KERNEL);
    if (!info)
		return -ENOMEM;
    memset(info, 0, sizeof(*info));

    rcu_read_lock();

    tsk = find_task_by_vpid(pid);
    if (!tsk) {
        rcu_read_unlock();
        kfree(info);
        return -ESRCH;
    }

    info->pid = pid;

    if (tsk->exit_state & EXIT_TRACE)
        info->state = PID_STATE_ZOMBIE;
    else if (tsk->__state == TASK_RUNNING)
        info->state = PID_STATE_RUNNING;
    else
        info->state = PID_STATE_SLEEPING;
    
    mm = get_task_mm(tsk);
    if (mm)
        info->sp = mm->start_stack;
    mmput(mm);

    info->age = ktime_get_ns() - tsk->start_time;

    i = 0;
    read_lock(&tasklist_lock)
    list_for_each_entry(child, &tsk->children, sibling) {
        if (i == MAX_CHILDREN)
            break;

        info->children[i++] = child->pid;
    }
    read_unlock(&tasklist_lock);
    
    parent = rcu_dereference(tsk->real_parent);
    info->parent = parent->pid;

    // path....

    rcu_read_unlock();

    // c t u..

    kfree(info);

    return 0;
}