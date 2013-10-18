/*
 * Copyright (c) 1999-2008 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Portions Copyright (c) 1999 Apple Computer, Inc.  All Rights
 * Reserved.  This file contains Original Code and/or Modifications of
 * Original Code as defined in and that are subject to the Apple Public
 * Source License Version 1.1 (the "License").  You may not use this file
 * except in compliance with the License.  Please obtain a copy of the
 * License at http://www.apple.com/publicsource and read it before using
 * this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON- INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * C runtime startup for ppc, ppc64, i386, x86_64
 *
 * Kernel sets up stack frame to look like:
 *
 *	       :
 *	| STRING AREA |
 *	+-------------+
 *	|      0      |	
 *	+-------------+	
 *	|  exec_path  | extra "apple" parameters start after NULL terminating env array
 *	+-------------+
 *	|      0      |
 *	+-------------+
 *	|    env[n]   |
 *	+-------------+
 *	       :
 *	       :
 *	+-------------+
 *	|    env[0]   |
 *	+-------------+
 *	|      0      |
 *	+-------------+
 *	| arg[argc-1] |
 *	+-------------+
 *	       :
 *	       :
 *	+-------------+
 *	|    arg[0]   |
 *	+-------------+
 *	|     argc    | argc is always 4 bytes long, even in 64-bit architectures
 *	+-------------+ <- sp
 *
 *	Where arg[i] and env[i] point into the STRING AREA
 */

	.text
	.globl boot
	.align 2

/**
 * rdi: argc
 * rsi: argv
 * rdx: envp
 * rcx: end of envp
 * r8:  entry point
 * r9:  is_lc_main
 */
boot:
	# apple
	pushq	$0			# NULL
	pushq	(%rsi)		# argv[0] as apple[0], stack gurad etc. ignored
	# envp
	pushq	$0			# NULL
	.Lenvp:
	subq	$8, %rcx
	pushq	(%rcx)
	cmpq	%rdx, %rcx
	jne	.Lenvp
	# argv
	movq	%rdi, %rax	# rax = argc
	salq	$3, %rax	# rax *= 8
	addq	%rsi, %rax	# rax += argv (rax now holds end of argv)
	pushq	$0			# NULL
	.Largv:
	subq	$8, %rax
	pushq	(%rax)
	cmpq	%rsi, %rax
	jne	.Largv
	# argc
	pushq	%rdi

	testq	%r9, %r9
	jne		crt0_start
	
	# LC_UNIX_THREAD
	# since we just set up the stack, this must be jmp (not call) so RSP is correct
	jmpq	*%r8

	# LC_MAIN
	# LC_MAIN requires stub in dyld and libdyld
	# temporary workaround: embed a crt0 stub in the loader
crt0_start:
	pushq	$0				# push a zero for debugger end of frames marker
	movq	%rsp, %rbp		# pointer to base of kernel frame
	andq	$-16, %rsp		# force SSE alignment
	movq	8(%rbp), %rdi	# put argc in %rdi
	leaq	16(%rbp), %rsi	# addr of arg[0], argv, into %rsi
	movl	%edi, %edx		# copy argc into %rdx
	addl	$1, %edx		# argc + 1 for zero word
	sall	$3, %edx		# * sizeof(char *)
	addq	%rsi, %rdx		# addr of env[0], envp, into %rdx
	movq	%rdx, %rcx
	jmp		.Lapple2
.Lapple:
	add		$8, %rcx
.Lapple2:
	cmpq	$0, (%rcx)		# look for NULL ending env[] array
	jne		.Lapple				
	add		$8, %rcx		# once found, next pointer is "apple" parameter now in %rcx
	call	*%r8
	movl	%eax, %edi		# pass result from main() to exit() 
	#call	_exit			# need to use call to keep stack aligned
	call	exit			# call the libc exit (note that Apple prepends a "_", the intention was to call libc's exit, _exit is the syscall (in OS X it would be __exit))
	hlt

