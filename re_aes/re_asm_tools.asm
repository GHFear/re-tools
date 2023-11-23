.code

Get_RSP proc
mov rax, [rsp+rcx]
ret
Get_RSP endp


Get_RAX proc
mov rax, rax
ret
Get_RAX endp

Get_RBX proc
mov rax, rbx
ret
Get_RBX endp

Get_RCX proc
mov rax, rcx
ret
Get_RCX endp

Get_RDX proc
mov rax, rdx
ret
Get_RDX endp

Get_R8 proc
mov rax, r8
ret
Get_R8 endp

Get_R9 proc
mov rax, r9
ret
Get_R9 endp

Get_R10 proc
mov rax, r10
ret
Get_R10 endp

Get_R11 proc
mov rax, r11
ret
Get_R11 endp

Get_R12 proc
mov rax, r12
ret
Get_R12 endp

Get_R13 proc
mov rax, r13
ret
Get_R13 endp

Get_R14 proc
mov rax, r14
ret
Get_R14 endp

Get_R15 proc
mov rax, r15
ret
Get_R15 endp

; Move Single-Precision Floats
Get_XMM0 proc
movups xmm0, xmm0
ret
Get_XMM0 endp

Get_XMM1 proc
movups xmm0, xmm1
ret
Get_XMM1 endp

Get_XMM2 proc
movups xmm0, xmm2
ret
Get_XMM2 endp

Get_XMM3 proc
movups xmm0, xmm3
ret
Get_XMM3 endp

Get_XMM4 proc
movups xmm0, xmm4
ret
Get_XMM4 endp

Get_XMM5 proc
movups xmm0, xmm5
ret
Get_XMM5 endp

Get_XMM6 proc
movups xmm0, xmm6
ret
Get_XMM6 endp

Get_XMM7 proc
movups xmm0, xmm7
ret
Get_XMM7 endp

Get_XMM8 proc
movups xmm0, xmm8
ret
Get_XMM8 endp

Get_XMM9 proc
movups xmm0, xmm9
ret
Get_XMM9 endp

Get_XMM10 proc
movups xmm0, xmm10
ret
Get_XMM10 endp

Get_XMM11 proc
movups xmm0, xmm11
ret
Get_XMM11 endp

Get_XMM12 proc
movups xmm0, xmm12
ret
Get_XMM12 endp

Get_XMM13 proc
movups xmm0, xmm13
ret
Get_XMM13 endp

Get_XMM14 proc
movups xmm0, xmm14
ret
Get_XMM14 endp

Get_XMM15 proc
movups xmm0, xmm15
ret
Get_XMM15 endp

; Move Single-Precision Floats
Get_YMM0 proc
vmovups ymm0, ymm0
ret
Get_YMM0 endp

Get_YMM1 proc
vmovups ymm0, ymm1
ret
Get_YMM1 endp

Get_YMM2 proc
vmovups ymm0, ymm2
ret
Get_YMM2 endp

Get_YMM3 proc
vmovups ymm0, ymm3
ret
Get_YMM3 endp

Get_YMM4 proc
vmovups ymm0, ymm4
ret
Get_YMM4 endp

Get_YMM5 proc
vmovups ymm0, ymm5
ret
Get_YMM5 endp

Get_YMM6 proc
vmovups ymm0, ymm6
ret
Get_YMM6 endp

Get_YMM7 proc
vmovups ymm0, ymm7
ret
Get_YMM7 endp

Get_YMM8 proc
vmovups ymm0, ymm8
ret
Get_YMM8 endp

Get_YMM9 proc
vmovups ymm0, ymm9
ret
Get_YMM9 endp

Get_YMM10 proc
vmovups ymm0, ymm10
ret
Get_YMM10 endp

Get_YMM11 proc
vmovups ymm0, ymm11
ret
Get_YMM11 endp

Get_YMM12 proc
vmovups ymm0, ymm12
ret
Get_YMM12 endp

Get_YMM13 proc
vmovups ymm0, ymm13
ret
Get_YMM13 endp

Get_YMM14 proc
vmovups ymm0, ymm14
ret
Get_YMM14 endp

Get_YMM15 proc
vmovups ymm0, ymm15
ret
Get_YMM15 endp

; Move Single-Precision Floats
Get_ZMM0 proc
vmovups zmm0, zmm0
ret
Get_ZMM0 endp

Get_ZMM1 proc
vmovups zmm0, zmm1
ret
Get_ZMM1 endp

Get_ZMM2 proc
vmovups zmm0, zmm2
ret
Get_ZMM2 endp

Get_ZMM3 proc
vmovups zmm0, zmm3
ret
Get_ZMM3 endp

Get_ZMM4 proc
vmovups zmm0, zmm4
ret
Get_ZMM4 endp

Get_ZMM5 proc
vmovups zmm0, zmm5
ret
Get_ZMM5 endp

Get_ZMM6 proc
vmovups zmm0, zmm6
ret
Get_ZMM6 endp

Get_ZMM7 proc
vmovups zmm0, zmm7
ret
Get_ZMM7 endp

Get_ZMM8 proc
vmovups zmm0, zmm8
ret
Get_ZMM8 endp

Get_ZMM9 proc
vmovups zmm0, zmm9
ret
Get_ZMM9 endp

Get_ZMM10 proc
vmovups zmm0, zmm10
ret
Get_ZMM10 endp

Get_ZMM11 proc
vmovups zmm0, zmm11
ret
Get_ZMM11 endp

Get_ZMM12 proc
vmovups zmm0, zmm12
ret
Get_ZMM12 endp

Get_ZMM13 proc
vmovups zmm0, zmm13
ret
Get_ZMM13 endp

Get_ZMM14 proc
vmovups zmm0, zmm14
ret
Get_ZMM14 endp

Get_ZMM15 proc
vmovups zmm0, zmm15
ret
Get_ZMM15 endp

Get_ZMM16 proc
vmovups zmm0, zmm16
ret
Get_ZMM16 endp

Get_ZMM17 proc
vmovups zmm0, zmm17
ret
Get_ZMM17 endp

Get_ZMM18 proc
vmovups zmm0, zmm18
ret
Get_ZMM18 endp

Get_ZMM19 proc
vmovups zmm0, zmm19
ret
Get_ZMM19 endp

Get_ZMM20 proc
vmovups zmm0, zmm20
ret
Get_ZMM20 endp

Get_ZMM21 proc
vmovups zmm0, zmm21
ret
Get_ZMM21 endp

Get_ZMM22 proc
vmovups zmm0, zmm22
ret
Get_ZMM22 endp

Get_ZMM23 proc
vmovups zmm0, zmm23
ret
Get_ZMM23 endp

Get_ZMM24 proc
vmovups zmm0, zmm24
ret
Get_ZMM24 endp

Get_ZMM25 proc
vmovups zmm0, zmm25
ret
Get_ZMM25 endp

Get_ZMM26 proc
vmovups zmm0, zmm26
ret
Get_ZMM26 endp

Get_ZMM27 proc
vmovups zmm0, zmm27
ret
Get_ZMM27 endp

Get_ZMM28 proc
vmovups zmm0, zmm28
ret
Get_ZMM28 endp

Get_ZMM29 proc
vmovups zmm0, zmm29
ret
Get_ZMM29 endp

Get_ZMM30 proc
vmovups zmm0, zmm30
ret
Get_ZMM30 endp

Get_ZMM31 proc
vmovups zmm0, zmm31
ret
Get_ZMM31 endp

end