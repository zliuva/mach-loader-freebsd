/*
 * Copyright (c) 2008-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
 
#define MH_PARAM_BP			8
#define LP_PARAM_BP			16

#define RDI_SAVE			0
#define RSI_SAVE			8
#define RDX_SAVE			16
#define RCX_SAVE			24
#define R8_SAVE				32
#define R9_SAVE				40
#define RAX_SAVE			48
#define XMM0_SAVE			64    /* 16-byte align */
#define XMM1_SAVE			80
#define XMM2_SAVE			96
#define XMM3_SAVE			112
#define XMM4_SAVE			128
#define XMM5_SAVE			144
#define XMM6_SAVE			160
#define XMM7_SAVE			176
#define YMM0_SAVE			64
#define YMM1_SAVE			96
#define YMM2_SAVE			128
#define YMM3_SAVE			160
#define YMM4_SAVE			192
#define YMM5_SAVE			224
#define YMM6_SAVE			256
#define YMM7_SAVE			288
#define STACK_SIZE			320 
 

 /*    
 * sp+8	lazy binding info offset
 * sp+0	address of ImageLoader cache
 */
	.text
    .align 2,0x90
    .globl dyld_stub_binder
dyld_stub_binder:
	pushq		%rbp
	movq		%rsp,%rbp
	subq		$STACK_SIZE,%rsp	# at this point stack is 16-byte aligned because two meta-parameters where pushed
	movq		%rdi,RDI_SAVE(%rsp)	# save registers that might be used as parameters
	movq		%rsi,RSI_SAVE(%rsp)
	movq		%rdx,RDX_SAVE(%rsp)
	movq		%rcx,RCX_SAVE(%rsp)
	movq		%r8,R8_SAVE(%rsp)
	movq		%r9,R9_SAVE(%rsp)
	movq		%rax,RAX_SAVE(%rsp)
misaligned_stack_error_entering_dyld_stub_binder:
/*
	movq		$(_COMM_PAGE_CPU_CAPABILITIES), %rax
	movl		(%rax), %eax
	testl		$kHasAVX1_0, %eax
	jne		L2
*/
	movdqa		%xmm0,XMM0_SAVE(%rsp)
	movdqa		%xmm1,XMM1_SAVE(%rsp)
	movdqa		%xmm2,XMM2_SAVE(%rsp)
	movdqa		%xmm3,XMM3_SAVE(%rsp)
	movdqa		%xmm4,XMM4_SAVE(%rsp)
	movdqa		%xmm5,XMM5_SAVE(%rsp)
	movdqa		%xmm6,XMM6_SAVE(%rsp)
	movdqa		%xmm7,XMM7_SAVE(%rsp)
/*
	jmp		L3
L2:	vmovdqu		%ymm0,YMM0_SAVE(%rsp)	# stack is only 16-byte aligned, so must use unaligned stores for avx registers
	vmovdqu		%ymm1,YMM1_SAVE(%rsp)
	vmovdqu		%ymm2,YMM2_SAVE(%rsp)
	vmovdqu		%ymm3,YMM3_SAVE(%rsp)
	vmovdqu		%ymm4,YMM4_SAVE(%rsp)
	vmovdqu		%ymm5,YMM5_SAVE(%rsp)
	vmovdqu		%ymm6,YMM6_SAVE(%rsp)
	vmovdqu		%ymm7,YMM7_SAVE(%rsp)
*/
L3:
dyld_stub_binder_:
	movq		MH_PARAM_BP(%rbp),%rdi	# call dyld_stub_binder_impl(image_cache, lazyinfo)
	movq		LP_PARAM_BP(%rbp),%rsi
	call		dyld_stub_binder_impl
	movq		%rax,%r11		# save target
/*
	movq		$(_COMM_PAGE_CPU_CAPABILITIES), %rax
	movl		(%rax), %eax
	testl		$kHasAVX1_0, %eax
	jne		L4
*/
	movdqa		XMM0_SAVE(%rsp),%xmm0
	movdqa		XMM1_SAVE(%rsp),%xmm1
	movdqa		XMM2_SAVE(%rsp),%xmm2
	movdqa		XMM3_SAVE(%rsp),%xmm3
	movdqa		XMM4_SAVE(%rsp),%xmm4
	movdqa		XMM5_SAVE(%rsp),%xmm5
	movdqa		XMM6_SAVE(%rsp),%xmm6
	movdqa		XMM7_SAVE(%rsp),%xmm7
/*
	jmp		L5
L4:	vmovdqu		YMM0_SAVE(%rsp),%ymm0
	vmovdqu		YMM1_SAVE(%rsp),%ymm1
	vmovdqu		YMM2_SAVE(%rsp),%ymm2
	vmovdqu		YMM3_SAVE(%rsp),%ymm3
	vmovdqu		YMM4_SAVE(%rsp),%ymm4
	vmovdqu		YMM5_SAVE(%rsp),%ymm5
	vmovdqu		YMM6_SAVE(%rsp),%ymm6
	vmovdqu		YMM7_SAVE(%rsp),%ymm7
*/
L5: movq		RDI_SAVE(%rsp),%rdi
	movq		RSI_SAVE(%rsp),%rsi
	movq		RDX_SAVE(%rsp),%rdx
	movq		RCX_SAVE(%rsp),%rcx
	movq		R8_SAVE(%rsp),%r8
	movq		R9_SAVE(%rsp),%r9
	movq		RAX_SAVE(%rsp),%rax
	addq		$STACK_SIZE,%rsp
	popq		%rbp
	addq		$16,%rsp		# remove meta-parameters
	jmp		*%r11			# jmp to target

