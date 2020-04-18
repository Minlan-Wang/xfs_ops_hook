#include <linux/init.h>
#include <linux/module.h>
#include <linux/ftrace.h>

#include <linux/aio.h>
#include <uapi/linux/uio.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/path.h>

#if 0
static char *mnt_path = NULL;
module_param(mnt_path, charp, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(mnt_path, "fs mount point base name");
#endif

unsigned long long super_block = 0;
module_param(super_block, ullong, S_IWUSR | S_IRUGO);
MODULE_PARM_DESC(super_block, "super block of file system");

unsigned dev_num = 0;
dev_t dev_num_enc = 0;
MODULE_PARM_DESC(dev_num, "Device number of file system");

module_param(dev_num, uint, S_IWUSR | S_IRUGO);

struct ftrace_hook {
	const char *name;
	void (*function)(struct pt_regs *regs);
	void *original;

	unsigned long address;
	struct ftrace_ops ops;
};

ssize_t
(*real_xfs_file_aio_read)(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos);

ssize_t
(*real_xfs_file_aio_write)(
	struct kiocb		*iocb,
	const struct iovec	*iovp,
	unsigned long		nr_segs,
	loff_t			pos);

void
fh_xfs_file_aio_read(struct pt_regs *regs)
{
	struct kiocb		*iocb = (struct kiocb *)regs->di;
#if 0
	const struct iovec	*iovp = (const struct iovec *)regs->si;
	unsigned long		nr_segs = (unsigned long )regs->dx;
	loff_t			pos = (loff_t)regs->cx;
#endif

	struct file		*file = iocb->ki_filp;
	struct inode		*inode = file->f_mapping->host;
	struct super_block	*sb = inode->i_sb;

	if ((dev_num_enc) && (sb->s_dev != dev_num_enc)) {
		//pr_warn("dev num mismatch: %x: %x\n", dev_num_enc, sb->s_dev);
		return;
	}

	pr_warn("[xfs read] %8d:%-16s %16lld:%-16lu %s\n",
		current->pid,
		current->comm,
		iocb->ki_pos,
		iocb->ki_nbytes,
		file->f_dentry->d_name.name);

	return;
}

void
fh_xfs_file_aio_write(struct pt_regs *regs)
{
	struct kiocb		*iocb = (struct kiocb *)regs->di;
#if 0
	const struct iovec	*iovp = (const struct iovec *)regs->si;
	unsigned long		nr_segs = (unsigned long)regs->dx;
	loff_t			pos = (unsigned long)regs->cx;
#endif

	struct file		*file = iocb->ki_filp;
	struct inode		*inode = file->f_mapping->host;
	struct super_block	*sb = inode->i_sb;

	if ((dev_num_enc) && (sb->s_dev != dev_num_enc)) {
		//pr_warn("dev num mismatch: %x: %x\n", dev_num_enc, sb->s_dev);
		return;
	}

	pr_warn("[xfs write] %8d:%-16s %16lld:%-16lu %s\n",
		current->pid,
		current->comm,
		iocb->ki_pos,
		iocb->ki_nbytes,
		file->f_dentry->d_name.name);

	return;
}


#define HOOK(_name, _function, _original) \
{					\
	.name = (_name),		\
	.function = (_function),	\
	.original = (_original),	\
}

static struct ftrace_hook hooked_functions[] = {
	HOOK("xfs_file_aio_read", fh_xfs_file_aio_read, &real_xfs_file_aio_read),
	HOOK("xfs_file_aio_write", fh_xfs_file_aio_write, &real_xfs_file_aio_write),
	//HOOK("xfs_vn_create", fh_xfs_vn_create, &real_xfs_vn_create),
};

static int resolve_hook_address(struct ftrace_hook *hook)
{
	hook->address = kallsyms_lookup_name(hook->name);

	if (!hook->address) {
		pr_debug("unresolved symbol: %s\n", hook->name);
		return -ENOENT;
	}

	*((unsigned long *)hook->original) = hook->address;

	return 0;
}

static void notrace fh_ftrace_thunk(unsigned long ip, unsigned long parent_ip, struct ftrace_ops *ops, struct pt_regs *regs)
{
	struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);

	hook->function(regs);
#if 0
	regs->ip = (unsigned long) hook->function;
#endif
	return;
}

int fh_install_hook(struct ftrace_hook *hook)
{
	int err;

	err = resolve_hook_address(hook);
	if (err)
		return err;

	hook->ops.func = fh_ftrace_thunk;
#if 0
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_IPMODIFY;
#else
	hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS;
#endif

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
	if (err) {
		pr_debug("ftrace_set_filter_ip() failed: %d\n", err);
		return err;
	}

	err = register_ftrace_function(&hook->ops);
	if (err) {
		pr_warn("register_ftrace_function() failed: %d\n", err);
		ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);

		return err;
	}

	pr_warn("hook for %s installed\n", hook->name);

	return 0;
}

void fh_remove_hook(struct ftrace_hook *hook)
{
	int err;

	err = unregister_ftrace_function(&hook->ops);
	if (err) {
		pr_warn("unregister_ftrace_function() failed: %d\n", err);
	}

	err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
	if (err) {
		pr_warn("ftrace_set_filter_ip() failed: %d\n", err);
	}

	pr_warn("hook for %s removed\n", hook->name);
}

static int xfs_file_op_init(void)
{
	int i;
	int cnt = 0;
	int ret;

	if (dev_num) {
		dev_num_enc = new_encode_dev(dev_num);
	}

	cnt = sizeof(hooked_functions) / sizeof(struct ftrace_hook);

	for (i = 0; i < cnt; i++) {
		ret = fh_install_hook(&hooked_functions[i]);
	}

	return ret;
}

static void xfs_file_op_exit(void)
{
	int i;
	int cnt = 0;

	cnt = sizeof(hooked_functions) / sizeof(struct ftrace_hook);

	for (i = 0; i < cnt; i++) {
		fh_remove_hook(&hooked_functions[i]);
	}
	return;
}

MODULE_LICENSE("GPL");

module_init(xfs_file_op_init);
module_exit(xfs_file_op_exit);
