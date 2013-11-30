/**
 * based on the shell image activator
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/exec.h>
#include <sys/imgact.h>
#include <sys/kernel.h>
#include <sys/sysent.h>
#include <sys/syscall.h>

#include <machine/frame.h>

#define MH_MAGIC_64	0xfeedfacf

#define FAT_MAGIC   0xcafebabe
#define FAT_CIGAM   0xbebafeca  /* NXSwapLong(FAT_MAGIC) */

#define OSX_BSD_SYSCALL_MASK	0x02000000

#define PSEUDO_SYS_set_proc_name	0xFFFFFFFF

static struct sysentvec *elf64_freebsd_sysvec = NULL;

int exec_mach_imgact(struct image_params *imgp);
int mach_fetch_syscall_args(struct thread *td, struct syscall_args *sa);

/**
 * patch the syscall (remove high byte)
 */
int mach_fetch_syscall_args(struct thread *td, struct syscall_args *sa) {
	struct trapframe *frame = td->td_frame;

	// we need this hack because the ELF image activator is called after us (since interpreted == 1)
	// do_execve will therefore set p->p_comm as the interpreter
	// loader will do this pseduo syscall with the desired command
	if (frame->tf_rax == PSEUDO_SYS_set_proc_name) {
		copyinstr((void *) frame->tf_rdi, td->td_proc->p_comm, MAXCOMLEN, NULL);
		return EJUSTRETURN; // this tells sv_set_syscall_retval handler to just return instread of retry
	}

	if (frame->tf_rax & OSX_BSD_SYSCALL_MASK) {
		//uprintf("Patching syscall: 0x%lx -> 0x%lx\n", frame->tf_rax, frame->tf_rax & ~OSX_BSD_SYSCALL_MASK);
		frame->tf_rax &= ~OSX_BSD_SYSCALL_MASK;
	}

	return cpu_fetch_syscall_args(td, sa);
}

int exec_mach_imgact(struct image_params *imgp) {
	const char *image_header = imgp->image_header;
	const uint32_t magic = *((const uint32_t *) image_header);

	if (magic != MH_MAGIC_64 &&
		magic != FAT_MAGIC &&
		magic != FAT_CIGAM) {
		return -1;
	}

	imgp->interpreted = 1;
	imgp->interpreter_name = DYLD;

	/**
	 * note that at this point we've just been fork'd
	 * thus imgp->proc->p_sysent was inherited from the parent
	 * and points to the native sysvec elf64_freebsd_sysvec
	 *
	 * this changes sv_fetch_syscall_args for ALL native ELFs since the sysvec is shared
	 */
	if (!elf64_freebsd_sysvec) {
		elf64_freebsd_sysvec = imgp->proc->p_sysent;
		elf64_freebsd_sysvec->sv_fetch_syscall_args = mach_fetch_syscall_args;
	}

	return 0;
}

/*
 * Tell kern_execve.c about it, with a little help from the linker.
 */
static struct execsw mach_execsw = { exec_mach_imgact, "Mach-O" };

static int mach_imgact_modevent(module_t mod, int type, void *data) {
	struct execsw *exec = (struct execsw *)data;
	int error = 0;
	switch (type) {
		case MOD_LOAD:
			error = exec_register(exec);
			if (error)
				printf("mach_imgact register failed\n");
			break;
			
		case MOD_UNLOAD:
			error = exec_unregister(exec);

			// don't forget to reset sv_fetch_syscall_args
			// or else it'll point to invalid address once we unload
			if (elf64_freebsd_sysvec) {
				elf64_freebsd_sysvec->sv_fetch_syscall_args = cpu_fetch_syscall_args;
			}

			if (error)
				printf("mach_imgact unregister failed\n");
			break;

		default:
			error = EOPNOTSUPP;
			break;
	}
	return error;
}

static moduledata_t mach_imgact_mod = {
	"mach_imgact",
	mach_imgact_modevent,
	(void *)&mach_execsw
};

DECLARE_MODULE_TIED(mach_imgact, mach_imgact_mod, SI_SUB_EXEC, SI_ORDER_ANY);

