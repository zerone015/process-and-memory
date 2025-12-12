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
#include <linux/minmax.h>

#define PID_INFO_INPUT_SIZE  offsetof(struct pid_info, nr_children)

static int task_children_count(struct task_struct *tsk)
{
    int ret;

    read_lock(&tasklist_lock);
    ret = list_count_nodes(&tsk->children);
    read_unlock(&tasklist_lock);
    return ret;
}

static int copy_children(struct pid_info *info, struct task_struct *tsk, int n) 
{
    struct task_struct *child;
    int *buf;
    int i = 0;
    int ret = 0;

    buf = kvmalloc_array(n, sizeof(int), GFP_KERNEL);
    if (!buf)
        return -ENOMEM;

    read_lock(&tasklist_lock);
    list_for_each_entry(child, &tsk->children, sibling) {
        if (i == n)
            break;
        buf[i++] = child->pid;
    }
    read_unlock(&tasklist_lock);

    if (copy_to_user(info->children, buf, i*sizeof(*buf))) {
        ret = -EFAULT;
        goto out;
    }
    info->nr_reported = i;

out:
    kvfree(buf);
    return ret;
}

static int fill_children(struct pid_info *info, struct task_struct *tsk)
{
    int nr, cap_elems, n;

    nr = task_children_count(tsk);
    info->nr_children = nr;

    if (!nr)
        return 0;
    
    if (!info->children)
        return 0;
    
    cap_elems = info->cap_children / sizeof(int);
    if (cap_elems <= 0)
        return 0;
    
    n = min_t(int, nr, cap_elems);

    return copy_children(info, tsk, n);
}

static void fill_pid(struct pid_info *info, struct task_struct *tsk)
{
    info->pid = tsk->pid;
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

static int fill_info(struct pid_info *info, struct task_struct *tsk, 
                    struct pid_info __user *up)
{
    int ret;

    if (copy_from_user(info, up, PID_INFO_INPUT_SIZE))
        return -EFAULT;

    ret = fill_children(info, tsk);
    if (ret)
        return ret;

    fill_pid(info, tsk);
    fill_state(info, tsk);
    fill_sp(info, tsk);
    fill_age(info, tsk);
    fill_parent(info, tsk);
    fill_root_and_pwd(info, tsk);

    return 0;
}

SYSCALL_DEFINE2(get_pid_info, struct pid_info __user *, up, int, pid)
{
    struct pid_info *info;
    struct task_struct *tsk;
    long ret = 0;
    
    if (!up || pid <= 0)
        return -EINVAL;

    tsk = find_get_task_by_vpid(pid);
    if (!tsk)
        return -ESRCH;
        
    info = kzalloc(sizeof(*info), GFP_KERNEL);
    if (!info) {
		ret = -ENOMEM;
        goto out;
    }

    ret = fill_info(info, tsk, up);
    if (ret)
        goto out_cleanup_info; 

    if (copy_to_user(up, info, sizeof(*info)))
        ret = -EFAULT;
    
out_cleanup_info:
    kfree(info);
out:
    put_task_struct(tsk);
    return ret;
}
