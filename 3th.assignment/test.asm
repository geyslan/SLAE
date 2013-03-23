global _start

	section .text

_start:
	cdq
	mul eax
	mul ebx
	mul ecx
	mov ecx, esp
	lea ecx, [esp]

	push 102
	pop eax
	mov eax, 102
	mov ax, 102
	mov al, 102
	mov bl, 4
	call eax
	call ebx
	call ecx
	call edx
	call esi
	call edi
	call esp
	call ebp

	dup_loop:
        mov al, 63
        int 0x80

        dec ecx
        jns dup_loop
	
	xchg eax, ecx
	xchg eax, ebx
	xchg ecx, ebx
	
	mov [esp+8], edx
	sub byte [esp+8], 7
	xor [esp+8], esi

	mov WORD bx, 4
	push bx
	push ebx
	mov esi, eax
	xchg eax, esi
	xchg esi, eax

	mov ebx, 2
	mov ebp, 3

	call $+5
	pop edi
	add edi, 30
	
	call edi

	mov eax, 2
	mov ebx, 4

	call edi

	mov eax, 5
	mov ebx, 6

	jmp final


interruption:

	xor eax, eax
	xor ebx, ebx
	;; ret
	ret
final:	

	mov eax, 1
	int 0x80
