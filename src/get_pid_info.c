/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/syscalls.h>
#include <linux/rcupdate.h>
#include <linux/sched.h>
#include <linux/sched/mm.h>
#include <linux/errno.h>
#include <linux/limits.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/timekeeping.h>
#include <linux/types.h>
#include <linux/rwlock.h>
#include <linux/sched/task.h>
#include <linux/list.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/uaccess.h>
#include <linux/err.h>
#include <linux/compiler.h>
#include <linux/fs_struct.h>
#include <uapi/linux/pid_info.h>

static void fill_pid(struct pid_info *info, int pid)
{
    info->pid = pid;
}

static void fill_state(struct pid_info *info, struct task_struct *tsk)
{
    if (READ_ONCE(tsk->exit_state) & EXIT_TRACE)
        info->state = PID_STATE_ZOMBIE;
    else if (READ_ONCE(tsk->__state) == TASK_RUNNING)
        info->state = PID_STATE_RUNNING;
    else
        info->state = PID_STATE_SLEEPING;
}

static void fill_sp(struct pid_info *info, struct task_struct *tsk)
{
    struct mm_struct *mm;

    mm = get_task_mm(tsk);

    if (!mm)
        return;

    info->sp = READ_ONCE(mm->start_stack);
    mmput(mm);
}

static void fill_age(struct pid_info *info, struct task_struct *tsk)
{
    u64 now = ktime_get_ns();

    info->age = now - tsk->start_time;
}

static void fill_children(struct pid_info *info, struct task_struct *tsk)
{
    struct task_struct *child;
    int i = 0;

    read_lock(&tasklist_lock);
    list_for_each_entry(child, &tsk->children, sibling) {
        if (i == MAX_CHILDREN)
            break;
        info->children[i++] = child->pid;
    }
    read_unlock(&tasklist_lock);

    info->num_children = i;
}

static void fill_parent(struct pid_info *info, struct task_struct *tsk)
{
    struct task_struct *parent;

    rcu_read_lock();
    parent = rcu_dereference(tsk->real_parent);
    if (likely(parent))
        info->parent = parent->pid;
    rcu_read_unlock();
}

static void fill_pathname(char *dst, const struct path *path)
{
	char *pathname;
    int len;
    
    pathname = d_path(path, dst, PATH_MAX);
	if (unlikely(IS_ERR(pathname))) {
		dst[0] = '\0';
        return;
	}
    
    if (pathname != dst) {
        len = dst + PATH_MAX - 1 - pathname;
		memmove(dst, pathname, len + 1);
	}
}

static void fill_root_and_pwd(struct pid_info *info, struct task_struct *tsk)
{
	struct fs_struct *fs;
	struct path root, pwd;

	task_lock(tsk);
	fs = tsk->fs;
    
	if (!fs) {
		task_unlock(tsk);
		return;
	}

	get_fs_root(fs, &root);
	get_fs_pwd(fs, &pwd);
	task_unlock(tsk);

    fill_pathname(info->root, &root);
    fill_pathname(info->pwd, &pwd);

    path_put(&root);
    path_put(&pwd);
}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, up, int, pid)
{
    struct pid_info *info;
    struct task_struct *tsk;
    long ret = 0;

    if (!up || pid <= 0)
        return -EINVAL;

    info = kzalloc(sizeof(*info), GFP_KERNEL);

    if (!info)
		return -ENOMEM;

    tsk = find_get_task_by_vpid(pid);

    if (!tsk) {
        ret = -ESRCH;
        goto out;
    }

    fill_pid(info, pid);
    fill_state(info, tsk);
    fill_sp(info, tsk);
    fill_age(info, tsk);
    fill_children(info, tsk);
    fill_parent(info, tsk);
    fill_root_and_pwd(info, tsk);

    if (copy_to_user(up, info, sizeof(*info)))
        ret = -EFAULT;

    put_task_struct(tsk);
    
out:
    kfree(info);

    return ret;
}
