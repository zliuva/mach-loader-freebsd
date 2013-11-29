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

#include <machine/frame.h>

#define MH_MAGIC_64				0xfeedfacf
#define OSX_BSD_SYSCALL_MASK	0x02000000

static struct sysentvec *elf64_freebsd_sysvec = NULL;

int exec_mach_imgact(struct image_params *imgp);
int mach_fetch_syscall_args(struct thread *td, struct syscall_args *sa);

/**
 * patch the syscall (remove high byte)
 */
int mach_fetch_syscall_args(struct thread *td, struct syscall_args *sa) {
	struct trapframe *frame = td->td_frame;

	if (frame->tf_rax & OSX_BSD_SYSCALL_MASK) {
		//uprintf("Patching syscall: 0x%lx -> 0x%lx\n", frame->tf_rax, frame->tf_rax & ~OSX_BSD_SYSCALL_MASK);
		frame->tf_rax &= ~OSX_BSD_SYSCALL_MASK;
	}

	return cpu_fetch_syscall_args(td, sa);
}

/**
 * Based on shell interpreter image activator.
 */
int exec_mach_imgact(struct image_params *imgp) {
	const char *image_header = imgp->image_header;
	const char *fname = NULL;
	int error, offset;
	size_t length;
	struct vattr vattr;
	struct sbuf *sname = NULL;

	/* a mach image? */
	if (((const uint32_t *)image_header)[0] != MH_MAGIC_64)
		return (-1);

	imgp->interpreted = 1;

	/*
	 * At this point we have the first page of the file mapped.
	 * However, we don't know how far into the page the contents are
	 * valid -- the actual file might be much shorter than the page.
	 * So find out the file size.
 	 */
	error = VOP_GETATTR(imgp->vp, &vattr, imgp->proc->p_ucred);
	if (error)
		return (error);

	if (imgp->args->fname != NULL) {
		fname = imgp->args->fname;
		sname = NULL;
	} else {
		sname = sbuf_new_auto();
		sbuf_printf(sname, "/dev/fd/%d", imgp->args->fd);
		sbuf_finish(sname);
		fname = sbuf_data(sname);
	}

	/*
	 * We need to "pop" (remove) the present value of arg[0], and "push"
	 * either two or three new values in the arg[] list.  To do this,
	 * we first shift all the other values in the `begin_argv' area to
	 * provide the exact amount of room for the values added.  Set up
	 * `offset' as the number of bytes to be added to the `begin_argv'
	 * area, and 'length' as the number of bytes being removed.
	 */
	offset = strlen(DYLD) + 1;			/* interpreter */
	offset += strlen(fname) + 1;			/* fname of script */
	length = (imgp->args->argc == 0) ? 0 :
	    strlen(imgp->args->begin_argv) + 1;		/* bytes to delete */

	if (offset > imgp->args->stringspace + length) {
		if (sname != NULL)
			sbuf_delete(sname);
		return (E2BIG);
	}

	bcopy(imgp->args->begin_argv + length, imgp->args->begin_argv + offset,
	    imgp->args->endp - (imgp->args->begin_argv + length));

	offset -= length;		/* calculate actual adjustment */
	imgp->args->begin_envv += offset;
	imgp->args->endp += offset;
	imgp->args->stringspace -= offset;

	/*
	 * If there was no arg[0] when we started, then the interpreter_name
	 * is adding an argument (instead of replacing the arg[0] we started
	 * with).  And we're always adding an argument when we include the
	 * full pathname of the original script.
	 */
	if (imgp->args->argc == 0)
		imgp->args->argc = 1;
	imgp->args->argc++;

	/*
	 * The original arg[] list has been shifted appropriately.  Copy in
	 * the interpreter name and options-string.
	 */
	length = strlen(DYLD);
	bcopy(DYLD, imgp->args->begin_argv, length);
	*(imgp->args->begin_argv + length) = '\0';
	offset = length + 1;

	/*
	 * Finally, add the filename onto the end for the interpreter to
	 * use and copy the interpreter's name to imgp->interpreter_name
	 * for exec to use.
	 */
	error = copystr(fname, imgp->args->begin_argv + offset,
	    imgp->args->stringspace, NULL);

	if (error == 0)
		imgp->interpreter_name = DYLD;

	if (sname != NULL)
		sbuf_delete(sname);

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

	return (error);
}

/*
 * Tell kern_execve.c about it, with a little help from the linker.
 */
static struct execsw mach_execsw = { exec_mach_imgact, "\xcf\xfa\xed\xfe" };

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

