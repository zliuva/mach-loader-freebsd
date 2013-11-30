	.text
	.globl set_proc_comm
	.align 2

set_proc_comm:
	# the name is already in RDI
	movq	$0xFFFFFFFF, %rax
	syscall
	ret

