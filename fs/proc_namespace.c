// SPDX-License-Identifier: GPL-2.0
/*
 * fs/proc_namespace.c - handling of /proc/<pid>/{mounts,mountinfo,mountstats}
 *
 * In fact, that's a piece of procfs; it's *almost* isolated from
 * the rest of fs/proc, but has rather close relationships with
 * fs/namespace.c, thus here instead of fs/proc
 *
 */
#include <linux/mnt_namespace.h>
#include <linux/nsproxy.h>
#include <linux/security.h>
#include <linux/fs_struct.h>
#include <linux/sched/task.h>

#include "proc/internal.h" /* only for get_proc_task() in ->open() */

#include "pnode.h"
#include "internal.h"

/* --- SuSFS v2.0.0 التعديل الاحترافي لـ --- */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
#include <linux/susfs_def.h>
#endif

static unsigned mounts_poll(struct file *file, poll_table *wait)
{
	struct seq_file *m = file->private_data;
	struct proc_mounts *p = m->private;
	struct mnt_namespace *ns = p->ns;
	unsigned res = POLLIN | POLLRDNORM;
	int event;

	poll_wait(file, &p->ns->poll, wait);

	event = ACCESS_ONCE(ns->event);
	if (m->poll_event != event) {
		m->poll_event = event;
		res |= POLLERR | POLLPRI;
	}

	return res;
}

struct proc_fs_info {
	int flag;
	const char *str;
};

static int show_sb_opts(struct seq_file *m, struct super_block *sb)
{
	static const struct proc_fs_info fs_info[] = {
		{ SB_SYNCHRONOUS, ",sync" },
		{ SB_DIRSYNC, ",dirsync" },
		{ SB_MANDLOCK, ",mand" },
		{ SB_LAZYTIME, ",lazytime" },
		{ 0, NULL }
	};
	const struct proc_fs_info *fs;

	for (fs = fs_info; fs->str; fs++) {
		if (sb->s_flags & fs->flag)
			seq_puts(m, fs->str);
	}

	return 0;
}

static void show_mnt_opts(struct seq_file *m, struct vfsmount *mnt)
{
	static const struct proc_fs_info mnt_info[] = {
		{ MNT_NOSUID, ",nosuid" },
		{ MNT_NODEV, ",nodev" },
		{ MNT_NOEXEC, ",noexec" },
		{ MNT_NOATIME, ",noatime" },
		{ MNT_NODIRATIME, ",nodiratime" },
		{ MNT_RELATIME, ",relatime" },
		{ 0, NULL }
	};
	const struct proc_fs_info *fs;

	for (fs = mnt_info; fs->str; fs++) {
		if (mnt->mnt_flags & fs->flag)
			seq_puts(m, fs->str);
	}
}

static inline void mangle(struct seq_file *m, const char *s)
{
	seq_escape(m, s, " \t\n\\");
}

static int show_vfsmnt(struct seq_file *m, void *v)
{
	struct mount *r = list_entry(v, struct mount, mnt_list);
	struct path mnt_path = { .dentry = r->mnt.mnt_root, .mnt = &r->mnt };
	struct super_block *sb = mnt_path.dentry->d_sb;
	int err;

/* SuSFS: إخفاء مسارات الروت من قائمة الـ Mounts */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (likely(susfs_is_current_proc_umounted()) && r->mnt_id >= DEFAULT_KSU_MNT_ID) {
		return 0;
	}
#endif

	if (sb->s_op->show_devname) {
		err = sb->s_op->show_devname(m, mnt_path.dentry);
		if (err)
			goto out;
	} else {
		mangle(m, r->mnt_devname ? r->mnt_devname : "none");
	}
	seq_putc(m, ' ');
	seq_path_root(m, &mnt_path, &r->mnt_ns->root, " \t\n\\");
	seq_putc(m, ' ');
	mangle(m, sb->s_type->name);
	seq_puts(m, sb->s_flags & SB_RDONLY ? " ro" : " rw");
	err = show_sb_opts(m, sb);
	if (err)
		goto out;
	show_mnt_opts(m, &r->mnt);
	if (sb->s_op->show_options)
		err = sb->s_op->show_options(m, mnt_path.dentry);
	seq_puts(m, " 0 0\n");
out:
	return err;
}

static int show_mountinfo(struct seq_file *m, void *v)
{
	struct mount *r = list_entry(v, struct mount, mnt_list);
	struct super_block *sb = r->mnt.mnt_sb;
	struct mount *ms = r->mnt_parent;
	struct path mnt_path = { .dentry = r->mnt.mnt_root, .mnt = &r->mnt };
	int err;

/* SuSFS: إخفاء تفاصيل مسارات الروت من معلومات الـ Mountinfo */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (likely(susfs_is_current_proc_umounted()) && r->mnt_id >= DEFAULT_KSU_MNT_ID) {
		return 0;
	}
#endif

	seq_printf(m, "%i %i %u:%u ", r->mnt_id, ms->mnt_id,
		   MAJOR(sb->s_dev), MINOR(sb->s_dev));
	mangle(m, r->mnt.mnt_root->d_name.name);
	seq_putc(m, ' ');
	seq_path_root(m, &mnt_path, &r->mnt_ns->root, " \t\n\\");
	seq_puts(m, mnt_path.mnt->mnt_flags & MNT_READONLY ? " ro" : " rw");
	show_mnt_opts(m, mnt_path.mnt);

	/* tag list */
	if (IS_MNT_SHARED(r))
		seq_printf(m, " shared:%i", r->mnt_group_id);
	if (IS_MNT_SLAVE(r)) {
		int master = r->mnt_master->mnt_group_id;
		int dom = get_dominating_id(r, &r->mnt_ns->root);
		seq_printf(m, " master:%i", master);
		if (dom && dom != master)
			seq_printf(m, " propagate_from:%i", dom);
	}
	if (IS_MNT_UNBINDABLE(r))
		seq_puts(m, " unbindable");

	/* في 4.14 لا يوجد لدينا ميزة التحقق من المجلدات المهملة كما في 5.15، لذا نلتزم بالهيكل الأصلي */
	seq_puts(m, " - ");
	mangle(m, sb->s_type->name);
	seq_putc(m, ' ');
	if (sb->s_op->show_devname) {
		err = sb->s_op->show_devname(m, mnt_path.dentry);
		if (err)
			goto out;
	} else {
		mangle(m, r->mnt_devname ? r->mnt_devname : "none");
	}
	seq_putc(m, ' ');
	seq_puts(m, sb->s_flags & SB_RDONLY ? "ro" : "rw");
	err = show_sb_opts(m, sb);
	if (err)
		goto out;
	if (sb->s_op->show_options)
		err = sb->s_op->show_options(m, mnt_path.dentry);
	seq_putc(m, '\n');
out:
	return err;
}

static int show_vfsstat(struct seq_file *m, void *v)
{
	struct mount *r = list_entry(v, struct mount, mnt_list);
	struct path mnt_path = { .dentry = r->mnt.mnt_root, .mnt = &r->mnt };
	struct super_block *sb = mnt_path.dentry->d_sb;
	int err;

/* SuSFS: إخفاء إحصائيات مسارات الروت */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
	if (likely(susfs_is_current_proc_umounted()) && r->mnt_id >= DEFAULT_KSU_MNT_ID) {
		return 0;
	}
#endif

	if (sb->s_op->show_devname) {
		err = sb->s_op->show_devname(m, mnt_path.dentry);
		if (err)
			goto out;
	} else {
		mangle(m, r->mnt_devname ? r->mnt_devname : "none");
	}
	seq_putc(m, ' ');
	seq_path_root(m, &mnt_path, &r->mnt_ns->root, " \t\n\\");
	seq_putc(m, ' ');
	mangle(m, sb->s_type->name);
	seq_putc(m, ' ');
	show_mnt_opts(m, &r->mnt);
	if (sb->s_op->show_stats)
		err = sb->s_op->show_stats(m, mnt_path.dentry);
	seq_putc(m, '\n');
out:
	return err;
}

static int mounts_open_common(struct inode *inode, struct file *file,
			      int (*show)(struct seq_file *, void *))
{
	struct task_struct *task = get_proc_task(inode);
	struct nsproxy *nsp;
	struct mnt_namespace *ns = NULL;
	struct path root;
	struct proc_mounts *p;
	struct seq_file *m;
	int ret = -EINVAL;

	if (!task)
		goto err;

	task_lock(task);
	nsp = task->nsproxy;
	if (nsp) {
		ns = nsp->mnt_ns;
		if (ns)
			get_mnt_ns(ns);
	}
	task_unlock(task);
	if (!ns)
		goto err_put_task;

	ret = -EACCES;
	if (!ptrace_may_access(task, PTRACE_MODE_READ_FSCREDS))
		goto err_put_ns;

	get_fs_root(task->fs, &root);

	put_task_struct(task);

	ret = seq_open_private(file, &mounts_op, sizeof(struct proc_mounts));
	if (ret)
		goto err_put_path;

	m = file->private_data;
	m->poll_event = ns->event;

	p = m->private;
	p->ns = ns;
	p->root = root;
	p->show = show;
	p->cached_event = ~0ULL;

	return 0;

 err_put_path:
	path_put(&root);
 err_put_ns:
	put_mnt_ns(ns);
 err_put_task:
	put_task_struct(task);
 err:
	return ret;
}

static int mounts_release(struct inode *inode, struct file *file)
{
	struct seq_file *m = file->private_data;
	struct proc_mounts *p = m->private;
	path_put(&p->root);
	put_mnt_ns(p->ns);
	return seq_release_private(inode, file);
}

static int mounts_open(struct inode *inode, struct file *file)
{
	return mounts_open_common(inode, file, show_vfsmnt);
}

static int mountinfo_open(struct inode *inode, struct file *file)
{
	return mounts_open_common(inode, file, show_mountinfo);
}

static int mountstats_open(struct inode *inode, struct file *file)
{
	return mounts_open_common(inode, file, show_vfsstat);
}

const struct file_operations proc_mounts_operations = {
	.open		= mounts_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mounts_release,
	.poll		= mounts_poll,
};

const struct file_operations proc_mountinfo_operations = {
	.open		= mountinfo_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mounts_release,
	.poll		= mounts_poll,
};

const struct file_operations proc_mountstats_operations = {
	.open		= mountstats_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= mounts_release,
};

