// SPDX-License-Identifier: GPL-2.0
#include <linux/sched/signal.h>
#include <linux/errno.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/pid.h>
#include <linux/security.h>
#include <linux/file.h>
#include <linux/seq_file.h>
#include <linux/fs.h>

#include <linux/proc_fs.h>

/* إضافة تعريفات التخفي */
#if defined(CONFIG_KSU_SUSFS_SUS_MOUNT) || defined(CONFIG_KSU_SUSFS_OPEN_REDIRECT)
#include <linux/susfs_def.h>
#endif

#include "../mount.h"
#include "internal.h"
#include "fd.h"

/* تعريف الدوال الخارجية للتزييف */
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
extern int susfs_get_non_sus_mnt_id_from_mnt(struct mount *orig_mnt);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
extern int susfs_open_redirect_spoof_seq_show(struct inode *inode, int *out_mnt_id, unsigned long *out_ino);
#endif

static int seq_show(struct seq_file *m, void *v)
{
	struct files_struct *files = NULL;
	int f_flags = 0, ret = -ENOENT;
	struct file *file = NULL;
	struct task_struct *task;
	int mnt_id;
	unsigned long ino;

	task = get_proc_task(m->private);
	if (!task)
		return -ENOENT;

	files = get_files_struct(task);
	put_task_struct(task);

	if (files) {
		unsigned int fd = proc_fd(m->private);

		spin_lock(&files->file_lock);
		file = fcheck_files(files, fd);
		if (file) {
			struct fdtable *fdt = files_fdtable(files);

			f_flags = file->f_flags;
			if (close_on_exec(fd, fdt))
				f_flags |= O_CLOEXEC;

			mnt_id = real_mount(file->f_path.mnt)->mnt_id;
			ino = file_inode(file)->i_ino;

#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
			if (SUSFS_IS_INODE_OPEN_REDIRECT(file_inode(file))) {
				susfs_open_redirect_spoof_seq_show(file_inode(file), &mnt_id, &ino);
				goto skip_sus_mount_check;
			}
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
			if (SUSFS_IS_INODE_SUS_MOUNT(file_inode(file))) {
				mnt_id = susfs_get_non_sus_mnt_id_from_mnt(real_mount(file->f_path.mnt));
			}
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
skip_sus_mount_check:
#endif

			get_file(file);
			ret = 0;
		}
		spin_unlock(&files->file_lock);
		put_files_struct(files);
	}

	if (ret)
		return ret;

	seq_printf(m, "pos:\t%lli\nflags:\t0%o\nmnt_id:\t%i\n",
		   (long long)file->f_pos, f_flags, mnt_id);

	show_fd_locks(m, file, files);
	if (file->f_op->show_fdinfo)
		file->f_op->show_fdinfo(m, file);

	fput(file);

	return 0;
}

static int seq_open(struct inode *inode, struct file *file)
{
	return single_open(file, seq_show, inode);
}

static const struct file_operations proc_fdinfo_file_operations = {
	.open		= seq_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

static int
proc_fd_instantiate(struct inode *dir, struct dentry *dentry,
		    struct task_struct *task, const void *ptr)
{
	unsigned fd = (unsigned long)ptr;
	struct proc_inode *ei;
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task, S_IFLNK);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	ei->fd = fd;

	inode->i_op = &proc_pid_link_inode_operations;
	inode->i_size = 64;

	d_set_d_op(dentry, &tid_fd_dentry_operations);
	d_add(dentry, inode);

	/* Close the race of the process dying before we return the dentry */
	if (tid_fd_revalidate(dentry, 0))
		return 0;
 out:
	return -ENOENT;
}

static struct dentry *proc_lookupfd(struct inode *dir, struct dentry *dentry,
				   unsigned int flags)
{
	struct task_struct *task = get_proc_task(dir);
	int result = -ENOENT;
	unsigned fd = name_to_int(&dentry->d_name);

	if (!task)
		goto out_no_task;
	if (fd == ~0U)
		goto out;

	result = proc_fill_cache(NULL, NULL, NULL, 0,
				 proc_fd_instantiate, task,
				 (void *)(unsigned long)fd);
 out:
	put_task_struct(task);
 out_no_task:
	return ERR_PTR(result);
}

static int proc_readfd_common(struct file *file, struct dir_context *ctx,
			      instantiate_t instantiate)
{
	struct task_struct *p = get_proc_task(file_inode(file));
	struct files_struct *files;
	unsigned int fd;
#ifdef CONFIG_KSU_SUSFS_SUS_MAP
	struct inode *inode;
#endif

	if (!p)
		return -ENOENT;

	if (!dir_emit_dots(file, ctx))
		goto out;
	files = get_files_struct(p);
	if (!files)
		goto out;

	rcu_read_lock();
	for (fd = ctx->pos - 2;
	     fd < files_fdtable(files)->max_fds;
	     fd++, ctx->pos++) {
		struct file *f;
		const char *name;
		char buf[PROC_NUMBUF];
		int len;

		f = fcheck_files(files, fd);
		if (!f)
			continue;

#ifdef CONFIG_KSU_SUSFS_SUS_MAP
		inode = file_inode(f);
		if (SUSFS_IS_INODE_SUS_MAP(inode))
			continue;
#endif

		len = snprintf(buf, sizeof(buf), "%u", fd);
		name = buf;
		rcu_read_unlock();
		if (!proc_fill_cache(file, ctx, name, len,
				     instantiate, p, (void *)(unsigned long)fd)) {
			rcu_read_lock();
			break;
		}
		rcu_read_lock();
	}
	rcu_read_unlock();
	put_files_struct(files);

out:
	put_task_struct(p);
	return 0;
}

static int proc_readfd(struct file *file, struct dir_context *ctx)
{
	return proc_readfd_common(file, ctx, proc_fd_instantiate);
}

const struct file_operations proc_fd_operations = {
	.read		= generic_read_dir,
	.iterate_shared	= proc_readfd,
	.llseek		= generic_file_llseek,
};

static int
proc_fdinfo_instantiate(struct inode *dir, struct dentry *dentry,
			struct task_struct *task, const void *ptr)
{
	unsigned fd = (unsigned long)ptr;
	struct proc_inode *ei;
	struct inode *inode;

	inode = proc_pid_make_inode(dir->i_sb, task, S_IFREG | S_IRUSR);
	if (!inode)
		goto out;

	ei = PROC_I(inode);
	ei->fd = fd;

	inode->i_fop = &proc_fdinfo_file_operations;

	d_set_d_op(dentry, &tid_fd_dentry_operations);
	d_add(dentry, inode);

	/* Close the race of the process dying before we return the dentry */
	if (tid_fd_revalidate(dentry, 0))
		return 0;
 out:
	return -ENOENT;
}

static int proc_readfdinfo(struct file *file, struct dir_context *ctx)
{
	return proc_readfd_common(file, ctx, proc_fdinfo_instantiate);
}

const struct file_operations proc_fdinfo_operations = {
	.read		= generic_read_dir,
	.iterate_shared	= proc_readfdinfo,
	.llseek		= generic_file_llseek,
};

static struct dentry *
proc_lookupfdinfo(struct inode *dir, struct dentry *dentry, unsigned int flags)
{
	struct task_struct *task = get_proc_task(dir);
	int result = -ENOENT;
	unsigned fd = name_to_int(&dentry->d_name);

	if (!task)
		goto out_no_task;
	if (fd == ~0U)
		goto out;

	result = proc_fill_cache(NULL, NULL, NULL, 0,
				 proc_fdinfo_instantiate, task,
				 (void *)(unsigned long)fd);
 out:
	put_task_struct(task);
 out_no_task:
	return ERR_PTR(result);
}

const struct inode_operations proc_fdinfo_inode_operations = {
	.lookup		= proc_lookupfdinfo,
	.setattr	= proc_setattr,
};

static int fd_permission(struct inode *inode, int mask)
{
	struct task_struct *p;
	int rv = -EACCES;

	rcu_read_lock();
	p = pid_task(proc_pid(inode), PIDTYPE_PID);
	if (p && same_thread_group(p, current))
		rv = 0;
	rcu_read_unlock();

	return rv;
}

const struct inode_operations proc_fd_inode_operations = {
	.lookup		= proc_lookupfd,
	.permission\t= fd_permission,
	.setattr\t= proc_setattr,
};

